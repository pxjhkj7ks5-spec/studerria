import Link from "next/link";
import { logoutAction } from "@/app/actions/admin";

type AdminShellProps = {
  adminPath: string;
  children: React.ReactNode;
};

export function AdminShell({ adminPath, children }: AdminShellProps) {
  return (
    <main className="mx-auto flex w-full max-w-6xl flex-col gap-6 px-4 py-6 md:px-6 md:py-8">
      <header className="glass-panel rounded-[28px] p-5 md:p-6">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
          <div className="space-y-2">
            <p className="text-xs uppercase tracking-[0.3em] text-[--accent-orange]">Admin</p>
            <h1 className="font-display text-3xl text-white md:text-4xl">Модерація історій</h1>
            <p className="max-w-xl text-sm leading-6 text-[--muted]">
              Черга, базове редагування і публікація без зайвих панелей.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <Link
              href={`/${adminPath}/stories`}
              className="rounded-full bg-[--paper] px-4 py-2 text-sm font-semibold text-black transition hover:bg-white"
            >
              Історії
            </Link>
            <Link
              href={`/${adminPath}/stories/new`}
              className="rounded-full border border-white/12 px-4 py-2 text-sm text-white transition hover:border-white/30"
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
