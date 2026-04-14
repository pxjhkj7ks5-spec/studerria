"use client";

import { useFormStatus } from "react-dom";
import { cn } from "@/lib/utils";

type SubmitButtonProps = {
  children: React.ReactNode;
  variant?: "primary" | "secondary" | "accent";
  pendingLabel?: string;
};

export function SubmitButton({
  children,
  variant = "primary",
  pendingLabel = "Збереження...",
}: SubmitButtonProps) {
  const status = useFormStatus();

  return (
    <button
      type="submit"
      disabled={status.pending}
      className={cn(
        "rounded-full px-5 py-3 text-sm font-semibold transition disabled:cursor-not-allowed disabled:opacity-55",
        variant === "primary" &&
          "bg-[--paper] text-black hover:bg-white",
        variant === "secondary" &&
          "border border-white/12 bg-white/[0.04] text-white hover:border-white/30 hover:bg-white/[0.08]",
        variant === "accent" &&
          "border border-[rgba(255,255,255,0.16)] bg-[linear-gradient(135deg,rgba(255,193,138,0.98),rgba(255,132,56,0.96))] text-[#140c07] shadow-[0_18px_40px_rgba(255,132,56,0.26)] hover:brightness-[1.04] hover:shadow-[0_22px_48px_rgba(255,132,56,0.34)]",
      )}
    >
      {status.pending ? pendingLabel : children}
    </button>
  );
}
