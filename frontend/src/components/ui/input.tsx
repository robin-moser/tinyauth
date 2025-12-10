import * as React from "react";

import { cn } from "@/lib/utils";

const inputStyles = [
  "file:text-foreground placeholder:text-muted-foreground selection:bg-primary selection:text-primary-foreground dark:bg-input/30 border-input flex h-10 w-full min-w-0 rounded-lg border bg-transparent py-2 text-base shadow-sm transition-all duration-200 outline-none file:inline-flex file:h-7 file:border-0 file:bg-transparent file:text-sm file:font-medium disabled:pointer-events-none disabled:cursor-not-allowed disabled:opacity-50 md:text-sm",
  "focus-visible:border-ring focus-visible:ring-ring/50 focus-visible:ring-[3px]",
  "aria-invalid:ring-destructive/20 dark:aria-invalid:ring-destructive/40 aria-invalid:border-destructive",
];

function Input({
  className,
  type,
  icon,
  ...props
}: React.ComponentProps<"input"> & {
  icon?: React.ReactNode;
}) {
  if (icon) {
    return (
      <div className="relative">
        <span className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground pointer-events-none">
          {icon}
        </span>
        <input
          type={type}
          data-slot="input"
          className={cn(inputStyles, "pl-10 pr-4", className)}
          {...props}
        />
      </div>
    );
  }

  return (
    <input
      type={type}
      data-slot="input"
      className={cn(inputStyles, "px-4", className)}
      {...props}
    />
  );
}

export { Input };
