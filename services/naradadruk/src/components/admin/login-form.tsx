"use client";

import { useActionState } from "react";
import { loginAction, type ActionState } from "@/app/actions/admin";
import { SubmitButton } from "@/components/admin/submit-button";

const initialState: ActionState = {};

export function LoginForm() {
  const [state, formAction] = useActionState(loginAction, initialState);

  return (
    <div className="glass-panel mx-auto w-full max-w-md rounded-[2rem] p-6 md:p-8">
      <div className="space-y-3">
        <p className="text-xs uppercase tracking-[0.35em] text-[--accent]">Закритий вхід</p>
        <h1 className="font-display text-4xl tracking-[-0.05em] text-white">Адмінка Narada Druk</h1>
        <p className="max-w-[40ch] text-sm leading-6 text-[--muted]">
          Окрема адмінка каталогу для керування товарами, категоріями та storefront-текстами.
        </p>
      </div>

      <form action={formAction} className="mt-8 space-y-4">
        <label className="grid gap-2 text-sm text-[--muted]">
          <span>Пароль адміністратора</span>
          <input
            name="password"
            type="password"
            required
            autoFocus
            className="rounded-[1.25rem] border border-white/10 bg-white/5 px-4 py-3 text-white outline-none transition placeholder:text-white/30 focus:border-[--accent]/70"
            placeholder="Введіть пароль"
          />
        </label>

        {state.error ? (
          <div className="rounded-[1.25rem] border border-[rgba(255,109,91,0.35)] bg-[rgba(255,109,91,0.08)] px-4 py-3 text-sm text-[#ffd1ca]">
            {state.error}
          </div>
        ) : null}

        <SubmitButton className="w-full">Увійти</SubmitButton>
      </form>
    </div>
  );
}
