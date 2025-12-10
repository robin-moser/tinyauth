import { languages, SupportedLanguage } from "@/lib/i18n/locales";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
} from "../ui/select";
import { useState } from "react";
import i18n from "@/lib/i18n/i18n";
import { Globe } from "lucide-react";

export const LanguageSelector = () => {
  const [language, setLanguage] = useState<SupportedLanguage>(
    i18n.language as SupportedLanguage,
  );

  const handleSelect = (option: string) => {
    setLanguage(option as SupportedLanguage);
    i18n.changeLanguage(option as SupportedLanguage);
  };

  return (
    <Select onValueChange={handleSelect} value={language}>
      <SelectTrigger className="!size-10 px-0 justify-center" showChevron={false}>
        <Globe className="size-4" />
      </SelectTrigger>
      <SelectContent>
        {Object.entries(languages).map(([key, value]) => (
          <SelectItem key={key} value={key}>
            {value}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
};
