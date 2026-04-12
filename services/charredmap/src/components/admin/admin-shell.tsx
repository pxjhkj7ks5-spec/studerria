import Link from "next/link";
import { logoutAction } from "@/app/actions/admin";

type AdminShellProps = {
  adminPath: string;
  children: React.ReactNode;
};

export function AdminShell({ adminPath, children }: AdminShellProps) {
  return (
    <main className="mx-auto flex w-full max-w-7xl flex-col gap-8 px-4 py-8 md:px-6 md:py-10">
      <header className="glass-panel rounded-[32px] p-5 md:p-6">
        <div className="flex flex-col gap-5 lg:flex-row lg:items-end lg:justify-between">
          <div className="space-y-3">
            <p className="text-xs uppercase tracking-[0.3em] text-[--accent-orange]">
              Mod desk
            </p>
            <div className="space-y-2">
              <h1 className="font-display text-3xl text-white md:text-4xl">
                Редакційна адмінка
              </h1>
              <p className="max-w-2xl text-sm leading-6 text-[--muted]">
                Тут модератор додає міста, зберігає чернетки та публікує історії, які відразу виходять на темну карту.
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <Link
              href={`/${adminPath}/stories`}
              className="rounded-full border border-white/12 px-4 py-2 text-sm text-white transition hover:border-white/30"
            >
              Усі історії
            </Link>
            <Link
              href={`/${adminPath}/stories/new`}
              className="rounded-full bg-[--paper] px-4 py-2 text-sm font-semibold text-black transition hover:bg-white"
            >
              Нова історія
            </Link>
            <form action={logoutAction}>
              <button
                type="submit"
                className="rounded-full border border-white/10 px-4 py-2 text-sm text-[--muted] transition hover:border-white/30 hover:text-white"
              >
                Вийти
              </button>
            </form>
          </div>
        </div>
      </header>

      {children}
    </main>
  );
}
