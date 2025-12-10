import { useTranslation } from "react-i18next";
import { Input } from "../ui/input";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormMessage,
} from "../ui/form";
import { Button } from "../ui/button";
import { loginSchema, LoginSchema } from "@/schemas/login-schema";
import { User, Lock, ArrowRight } from "lucide-react";
import z from "zod";

interface Props {
  onSubmit: (data: LoginSchema) => void;
  loading?: boolean;
}

export const LoginForm = (props: Props) => {
  const { onSubmit, loading } = props;
  const { t } = useTranslation();

  z.config({
    customError: (iss) =>
      iss.input === undefined ? t("fieldRequired") : t("invalidInput"),
  });

  const form = useForm<LoginSchema>({
    resolver: zodResolver(loginSchema),
  });

  return (
    <Form {...form}>
      <form onSubmit={form.handleSubmit(onSubmit)}>
        <FormField
          control={form.control}
          name="username"
          render={({ field }) => (
            <FormItem className="mb-4 gap-0">
              <FormControl className="mb-1">
                <Input
                  placeholder={t("loginUsername")}
                  disabled={loading}
                  autoComplete="username"
                  icon={<User className="size-4" />}
                  {...field}
                />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />
        <FormField
          control={form.control}
          name="password"
          render={({ field }) => (
            <FormItem className="mb-4 gap-0">
              <FormControl className="mb-1">
                <Input
                  placeholder={t("loginPassword")}
                  type="password"
                  disabled={loading}
                  autoComplete="current-password"
                  icon={<Lock className="size-4" />}
                  {...field}
                />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />
        <Button className="w-full" type="submit" loading={loading}>
          {t("loginSubmit")}
          <ArrowRight className="size-4" />
        </Button>
      </form>
    </Form>
  );
};
