"use client";

import { useFormStatus } from "react-dom";

type SubmitButtonProps = {
  children: React.ReactNode;
  className?: string;
};

export function SubmitButton({ children, className = "" }: SubmitButtonProps) {
  const { pending } = useFormStatus();

  return (
    <button
      type="submit"
      disabled={pending}
      className={`inline-flex items-center justify-center rounded-full bg-[--accent] px-5 py-3 text-sm font-semibold text-[--ink] transition hover:-translate-y-[1px] hover:bg-[--accent-strong] disabled:cursor-not-allowed disabled:opacity-60 ${className}`}
    >
      {pending ? "Збереження..." : children}
    </button>
  );
}
