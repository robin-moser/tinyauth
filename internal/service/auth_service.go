package service

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"
	"tinyauth/internal/config"
	"tinyauth/internal/model"
	"tinyauth/internal/utils"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type LoginAttempt struct {
	FailedAttempts int
	LastAttempt    time.Time
	LockedUntil    time.Time
}

type AuthServiceConfig struct {
	Users             []config.User
	OauthWhitelist    string
	SessionExpiry     int
	SecureCookie      bool
	CookieDomain      string
	LoginTimeout      int
	LoginMaxRetries   int
	SessionCookieName string
}

type AuthService struct {
	config        AuthServiceConfig
	docker        *DockerService
	loginAttempts map[string]*LoginAttempt
	loginMutex    sync.RWMutex
	ldap          *LdapService
	database      *gorm.DB
	ctx           context.Context
}

func NewAuthService(config AuthServiceConfig, docker *DockerService, ldap *LdapService, database *gorm.DB) *AuthService {
	return &AuthService{
		config:        config,
		docker:        docker,
		loginAttempts: make(map[string]*LoginAttempt),
		ldap:          ldap,
		database:      database,
	}
}

func (auth *AuthService) Init() error {
	auth.ctx = context.Background()
	return nil
}

func (auth *AuthService) SearchUser(username string) config.UserSearch {
	if auth.GetLocalUser(username).Username != "" {
		return config.UserSearch{
			Username: username,
			Type:     "local",
		}
	}

	if auth.ldap != nil {
		userDN, err := auth.ldap.Search(username)

		if err != nil {
			log.Warn().Err(err).Str("username", username).Msg("Failed to search for user in LDAP")
			return config.UserSearch{
				Type: "error",
			}
		}

		return config.UserSearch{
			Username: userDN,
			Type:     "ldap",
		}
	}

	return config.UserSearch{
		Type: "unknown",
	}
}

func (auth *AuthService) VerifyUser(search config.UserSearch, password string) bool {
	switch search.Type {
	case "local":
		user := auth.GetLocalUser(search.Username)
		return auth.CheckPassword(user, password)
	case "ldap":
		if auth.ldap != nil {
			err := auth.ldap.Bind(search.Username, password)
			if err != nil {
				log.Warn().Err(err).Str("username", search.Username).Msg("Failed to bind to LDAP")
				return false
			}

			err = auth.ldap.Bind(auth.ldap.Config.BindDN, auth.ldap.Config.BindPassword)
			if err != nil {
				log.Error().Err(err).Msg("Failed to rebind with service account after user authentication")
				return false
			}

			return true
		}
	default:
		log.Debug().Str("type", search.Type).Msg("Unknown user type for authentication")
		return false
	}

	log.Warn().Str("username", search.Username).Msg("User authentication failed")
	return false
}

func (auth *AuthService) GetLocalUser(username string) config.User {
	for _, user := range auth.config.Users {
		if user.Username == username {
			return user
		}
	}

	log.Warn().Str("username", username).Msg("Local user not found")
	return config.User{}
}

func (auth *AuthService) CheckPassword(user config.User, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)) == nil
}

func (auth *AuthService) IsAccountLocked(identifier string) (bool, int) {
	auth.loginMutex.RLock()
	defer auth.loginMutex.RUnlock()

	if auth.config.LoginMaxRetries <= 0 || auth.config.LoginTimeout <= 0 {
		return false, 0
	}

	attempt, exists := auth.loginAttempts[identifier]
	if !exists {
		return false, 0
	}

	if attempt.LockedUntil.After(time.Now()) {
		remaining := int(time.Until(attempt.LockedUntil).Seconds())
		return true, remaining
	}

	return false, 0
}

func (auth *AuthService) RecordLoginAttempt(identifier string, success bool) {
	if auth.config.LoginMaxRetries <= 0 || auth.config.LoginTimeout <= 0 {
		return
	}

	auth.loginMutex.Lock()
	defer auth.loginMutex.Unlock()

	attempt, exists := auth.loginAttempts[identifier]
	if !exists {
		attempt = &LoginAttempt{}
		auth.loginAttempts[identifier] = attempt
	}

	attempt.LastAttempt = time.Now()

	if success {
		attempt.FailedAttempts = 0
		attempt.LockedUntil = time.Time{} // Reset lock time
		return
	}

	attempt.FailedAttempts++

	if attempt.FailedAttempts >= auth.config.LoginMaxRetries {
		attempt.LockedUntil = time.Now().Add(time.Duration(auth.config.LoginTimeout) * time.Second)
		log.Warn().Str("identifier", identifier).Int("timeout", auth.config.LoginTimeout).Msg("Account locked due to too many failed login attempts")
	}
}

func (auth *AuthService) IsEmailWhitelisted(email string) bool {
	return utils.CheckFilter(auth.config.OauthWhitelist, email)
}

func (auth *AuthService) CreateSessionCookie(c *gin.Context, data *config.SessionCookie) error {
	uuid, err := uuid.NewRandom()

	if err != nil {
		return err
	}

	var expiry int

	if data.TotpPending {
		expiry = 3600
	} else {
		expiry = auth.config.SessionExpiry
	}

	session := model.Session{
		UUID:        uuid.String(),
		Username:    data.Username,
		Email:       data.Email,
		Name:        data.Name,
		Provider:    data.Provider,
		TOTPPending: data.TotpPending,
		OAuthGroups: data.OAuthGroups,
		Expiry:      time.Now().Add(time.Duration(expiry) * time.Second).Unix(),
		OAuthName:   data.OAuthName,
	}

	err = gorm.G[model.Session](auth.database).Create(auth.ctx, &session)

	if err != nil {
		return err
	}

	c.SetCookie(auth.config.SessionCookieName, session.UUID, expiry, "/", fmt.Sprintf(".%s", auth.config.CookieDomain), auth.config.SecureCookie, true)

	return nil
}

func (auth *AuthService) DeleteSessionCookie(c *gin.Context) error {
	cookie, err := c.Cookie(auth.config.SessionCookieName)

	if err != nil {
		return err
	}

	_, err = gorm.G[model.Session](auth.database).Where("uuid = ?", cookie).Delete(auth.ctx)

	if err != nil {
		return err
	}

	c.SetCookie(auth.config.SessionCookieName, "", -1, "/", fmt.Sprintf(".%s", auth.config.CookieDomain), auth.config.SecureCookie, true)

	return nil
}

func (auth *AuthService) GetSessionCookie(c *gin.Context) (config.SessionCookie, error) {
	cookie, err := c.Cookie(auth.config.SessionCookieName)

	if err != nil {
		return config.SessionCookie{}, err
	}

	session, err := gorm.G[model.Session](auth.database).Where("uuid = ?", cookie).First(auth.ctx)

	if err != nil {
		return config.SessionCookie{}, err
	}

	if errors.Is(err, gorm.ErrRecordNotFound) {
		return config.SessionCookie{}, fmt.Errorf("session not found")
	}

	currentTime := time.Now().Unix()

	if currentTime > session.Expiry {
		_, err = gorm.G[model.Session](auth.database).Where("uuid = ?", cookie).Delete(auth.ctx)
		if err != nil {
			log.Error().Err(err).Msg("Failed to delete expired session")
		}
		return config.SessionCookie{}, fmt.Errorf("session expired")
	}

	return config.SessionCookie{
		UUID:        session.UUID,
		Username:    session.Username,
		Email:       session.Email,
		Name:        session.Name,
		Provider:    session.Provider,
		TotpPending: session.TOTPPending,
		OAuthGroups: session.OAuthGroups,
		OAuthName:   session.OAuthName,
	}, nil
}

func (auth *AuthService) UserAuthConfigured() bool {
	return len(auth.config.Users) > 0 || auth.ldap != nil
}

func (auth *AuthService) IsResourceAllowed(c *gin.Context, context config.UserContext, acls config.App) bool {
	if context.OAuth {
		log.Debug().Msg("Checking OAuth whitelist")
		return utils.CheckFilter(acls.OAuth.Whitelist, context.Email)
	}

	if acls.Users.Block != "" {
		log.Debug().Msg("Checking blocked users")
		if utils.CheckFilter(acls.Users.Block, context.Username) {
			return false
		}
	}

	log.Debug().Msg("Checking users")
	return utils.CheckFilter(acls.Users.Allow, context.Username)
}

func (auth *AuthService) IsInOAuthGroup(c *gin.Context, context config.UserContext, requiredGroups string) bool {
	if requiredGroups == "" {
		return true
	}

	for id := range config.OverrideProviders {
		if context.Provider == id {
			log.Info().Str("provider", id).Msg("OAuth groups not supported for this provider")
			return true
		}
	}

	for userGroup := range strings.SplitSeq(context.OAuthGroups, ",") {
		if utils.CheckFilter(requiredGroups, strings.TrimSpace(userGroup)) {
			log.Trace().Str("group", userGroup).Str("required", requiredGroups).Msg("User group matched")
			return true
		}
	}

	log.Debug().Msg("No groups matched")
	return false
}

func (auth *AuthService) IsAuthEnabled(uri string, path config.AppPath) (bool, error) {
	// Check for block list
	if path.Block != "" {
		regex, err := regexp.Compile(path.Block)

		if err != nil {
			return true, err
		}

		if !regex.MatchString(uri) {
			return false, nil
		}
	}

	// Check for allow list
	if path.Allow != "" {
		regex, err := regexp.Compile(path.Allow)

		if err != nil {
			return true, err
		}

		if regex.MatchString(uri) {
			return false, nil
		}
	}

	return true, nil
}

// GetBasicAuth extracts basic authentication credentials from the request.
//
// This function supports two authentication headers:
//
//  1. Proxy-Authorization header (checked first):
//     Used when clients need to authenticate with Tinyauth while preserving
//     a separate Authorization header for the backend service. This is useful
//     for scenarios where:
//     - The backend service requires its own authentication (e.g., API keys, bearer tokens)
//     - Clients use tools like curl that need to pass through credentials to upstream services
//     - Applications have layered authentication requirements
//
//  2. Standard Authorization header (fallback):
//     The traditional HTTP Basic Auth header used when Proxy-Authorization is absent.
//
// Header Priority:
//   - If Proxy-Authorization is present and valid, it takes precedence
//   - If Proxy-Authorization is absent or invalid, falls back to Authorization header
//
// Supported Formats for Proxy-Authorization:
//   - "Basic <base64-encoded-credentials>" (RFC 7617 compliant)
//   - "user:password" (direct plaintext format for convenience)
//
// Example Usage:
//
//	# Authenticate with Tinyauth via Proxy-Authorization, pass API key to backend
//	curl -H "Proxy-Authorization: Basic dXNlcjpwYXNz" \
//	     -H "Authorization: Bearer <api-token>" \
//	     https://app.example.com/api/resource
//
// When Proxy-Authorization is used, the original Authorization header is forwarded
// untouched to the backend service (see setHeaders in proxy_controller.go).
func (auth *AuthService) GetBasicAuth(c *gin.Context) *config.User {
	// Check Proxy-Authorization header first
	if proxyAuth := c.Request.Header.Get("Proxy-Authorization"); proxyAuth != "" {
		username, password, ok := auth.parseProxyAuth(proxyAuth)
		if ok {
			return &config.User{
				Username: username,
				Password: password,
			}
		}
	}

	// Fall back to standard Authorization header
	username, password, ok := c.Request.BasicAuth()
	if !ok {
		log.Debug().Msg("No basic auth provided")
		return nil
	}
	return &config.User{
		Username: username,
		Password: password,
	}
}

func (auth *AuthService) CheckIP(acls config.AppIP, ip string) bool {
	for _, blocked := range acls.Block {
		res, err := utils.FilterIP(blocked, ip)
		if err != nil {
			log.Warn().Err(err).Str("item", blocked).Msg("Invalid IP/CIDR in block list")
			continue
		}
		if res {
			log.Debug().Str("ip", ip).Str("item", blocked).Msg("IP is in blocked list, denying access")
			return false
		}
	}

	for _, allowed := range acls.Allow {
		res, err := utils.FilterIP(allowed, ip)
		if err != nil {
			log.Warn().Err(err).Str("item", allowed).Msg("Invalid IP/CIDR in allow list")
			continue
		}
		if res {
			log.Debug().Str("ip", ip).Str("item", allowed).Msg("IP is in allowed list, allowing access")
			return true
		}
	}

	if len(acls.Allow) > 0 {
		log.Debug().Str("ip", ip).Msg("IP not in allow list, denying access")
		return false
	}

	log.Debug().Str("ip", ip).Msg("IP not in allow or block list, allowing by default")
	return true
}

func (auth *AuthService) IsBypassedIP(acls config.AppIP, ip string) bool {
	for _, bypassed := range acls.Bypass {
		res, err := utils.FilterIP(bypassed, ip)
		if err != nil {
			log.Warn().Err(err).Str("item", bypassed).Msg("Invalid IP/CIDR in bypass list")
			continue
		}
		if res {
			log.Debug().Str("ip", ip).Str("item", bypassed).Msg("IP is in bypass list, allowing access")
			return true
		}
	}

	log.Debug().Str("ip", ip).Msg("IP not in bypass list, continuing with authentication")
	return false
}

// parseProxyAuth parses the Proxy-Authorization header value.
//
// Supported formats:
//   - "Basic <base64>" - Standard RFC 7617 Basic authentication
//   - "user:password"  - Direct plaintext credentials (non-standard, for convenience)
//
// Security Note on the "user:password" format:
// The direct plaintext format is NON-STANDARD and exists only for convenience in
// controlled environments (e.g., internal tooling, CI/CD pipelines). It has several
// security implications:
//
//  1. NO OBFUSCATION: Credentials are fully visible in logs, browser dev tools,
//     proxy logs, and network inspection tools. The Base64 encoding in "Basic" auth
//     isn't encryption, but it at least prevents casual shoulder-surfing.
//
//  2. NOT RFC-COMPLIANT: RFC 7235 (HTTP Authentication) and RFC 7617 (Basic Auth)
//     define the "Basic <base64>" format. Proxies, WAFs, and security tools may
//     not recognize or properly handle the raw format, leading to:
//     - Credentials being logged by intermediaries that don't know to redact them
//     - Security scanners flagging it as malformed/suspicious
//
//  3. INJECTION RISK: Without the "Basic " prefix, the header value could be
//     confused with other authentication schemes or manipulated more easily.
//
// RECOMMENDATION: Always use "Basic <base64>" format in production:
//
//	# Generate the base64 value:
//	echo -n "user:password" | base64
//	# Result: dXNlcjpwYXNzd29yZA==
//
//	# Use in header:
//	Proxy-Authorization: Basic dXNlcjpwYXNzd29yZA==
func (auth *AuthService) parseProxyAuth(authHeader string) (username, password string, ok bool) {
	// Handle "Basic <base64>" format (RFC 7617)
	const prefix = "Basic "
	if strings.HasPrefix(authHeader, prefix) {
		decoded, err := base64.StdEncoding.DecodeString(authHeader[len(prefix):])
		if err != nil {
			log.Debug().Err(err).Msg("Failed to decode Proxy-Authorization base64")
			return "", "", false
		}
		username, password, ok = strings.Cut(string(decoded), ":")
		return username, password, ok
	}

	// Handle direct "user:password" format (non-standard, for convenience only)
	if strings.Contains(authHeader, ":") {
		log.Warn().Msg("Proxy-Authorization using non-standard plaintext format; consider using 'Basic <base64>' for better security")
		username, password, ok = strings.Cut(authHeader, ":")
		return username, password, ok
	}

	return "", "", false
}

// IsUsingProxyAuth returns true if the request includes a Proxy-Authorization header.
// This is used by the proxy controller to determine whether to forward the original
// Authorization header untouched (when Proxy-Authorization is used for Tinyauth auth)
// or to potentially override it with configured backend credentials.
func (auth *AuthService) IsUsingProxyAuth(c *gin.Context) bool {
	return c.Request.Header.Get("Proxy-Authorization") != ""
}
