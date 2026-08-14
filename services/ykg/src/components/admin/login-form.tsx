"use client";

import { useActionState } from "react";
import { bootstrapOwnerAction, loginAction, type ActionState } from "@/app/actions/admin";
import { SubmitButton } from "@/components/admin/submit-button";

const initialState: ActionState = {};

export function LoginForm({ bootstrap = false }: { bootstrap?: boolean }) {
  const [state, formAction] = useActionState(bootstrap ? bootstrapOwnerAction : loginAction, initialState);
  return (
    <div className="glass-panel mx-auto w-full max-w-md rounded-[2rem] p-6 md:p-8">
      <div className="space-y-3">
        <p className="text-xs uppercase tracking-[0.35em] text-[--accent]">{bootstrap ? "Перший запуск" : "Закритий вхід"}</p>
        <h1 className="font-display text-4xl tracking-[-0.05em] text-white">YKG Staff</h1>
        <p className="max-w-[42ch] text-sm leading-6 text-[--muted]">
          {bootstrap ? "Створіть перший профіль власника. Після цього bootstrap буде вимкнений." : "Каталог, склад, замовлення та команда в одному робочому просторі."}
        </p>
      </div>
      <form action={formAction} className="mt-8 space-y-4">
        {bootstrap ? <>
          <Field label="Bootstrap token" name="token" type="password" autoFocus />
          <Field label="Імʼя власника" name="displayName" />
        </> : null}
        <Field label="Логін" name="username" autoFocus={!bootstrap} autoComplete="username" />
        <Field label={bootstrap ? "Пароль (від 12 символів)" : "Пароль"} name="password" type="password" autoComplete={bootstrap ? "new-password" : "current-password"} />
        {state.error ? <div className="rounded-[1.25rem] border border-[rgba(208,84,84,.45)] bg-[rgba(208,84,84,.1)] px-4 py-3 text-sm text-[#ffd1ca]">{state.error}</div> : null}
        <SubmitButton className="w-full">{bootstrap ? "Створити owner" : "Увійти"}</SubmitButton>
      </form>
    </div>
  );
}

function Field({ label, name, type = "text", autoFocus, autoComplete }: { label: string; name: string; type?: string; autoFocus?: boolean; autoComplete?: string }) {
  return <label className="grid gap-2 text-sm text-[--muted]"><span>{label}</span><input name={name} type={type} required autoFocus={autoFocus} autoComplete={autoComplete} className="rounded-[1.25rem] border border-white/10 bg-white/5 px-4 py-3 text-white outline-none transition focus:border-[--accent]" /></label>;
}
