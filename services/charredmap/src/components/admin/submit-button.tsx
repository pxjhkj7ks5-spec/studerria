"use client";

import { useFormStatus } from "react-dom";
import { cn } from "@/lib/utils";

type SubmitButtonProps = {
  children: React.ReactNode;
  variant?: "primary" | "secondary";
};

export function SubmitButton({
  children,
  variant = "primary",
}: SubmitButtonProps) {
  const status = useFormStatus();

  return (
    <button
      type="submit"
      disabled={status.pending}
      className={cn(
        "rounded-full px-5 py-3 text-sm font-semibold transition disabled:cursor-not-allowed disabled:opacity-55",
        variant === "primary"
          ? "bg-[--paper] text-black hover:bg-white"
          : "border border-white/12 bg-white/[0.04] text-white hover:border-white/30 hover:bg-white/[0.08]",
      )}
    >
      {status.pending ? "Збереження..." : children}
    </button>
  );
}
