"use client";

import { useActionState } from "react";
import { loginAction } from "@/app/actions/admin";
import { SubmitButton } from "@/components/admin/submit-button";

const initialState = {};

export function LoginForm() {
  const [state, formAction] = useActionState(loginAction, initialState);

  return (
    <div className="glass-panel hero-reveal w-full max-w-md rounded-[32px] p-6 md:p-8">
      <div className="space-y-3">
        <p className="text-xs uppercase tracking-[0.3em] text-[--accent-orange]">
          Прихований вхід
        </p>
        <h1 className="font-display text-4xl text-white">Адмінка charredmap</h1>
        <p className="text-sm leading-6 text-[--muted]">
          Ця сторінка не індексується, ізольована окремим префіксом і відкривається лише паролем модератора.
        </p>
      </div>

      <form action={formAction} className="mt-8 space-y-4">
        <label className="space-y-2 text-sm text-[--muted]">
          <span>Пароль модератора</span>
          <input
            name="password"
            type="password"
            autoFocus
            required
            className="w-full rounded-[20px] border border-white/10 bg-black/30 px-4 py-3 text-white outline-none transition focus:border-[--accent-orange]/60"
          />
        </label>

        {state.error ? (
          <p className="rounded-[20px] border border-[--accent-red]/35 bg-[rgba(218,59,59,0.12)] px-4 py-3 text-sm text-[#ffc8c8]">
            {state.error}
          </p>
        ) : null}

        <SubmitButton>Увійти</SubmitButton>
      </form>
    </div>
  );
}
