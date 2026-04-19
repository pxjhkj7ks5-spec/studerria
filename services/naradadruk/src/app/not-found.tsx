import { withBasePath } from "@/lib/base-path";

export default function NotFound() {
  return (
    <main className="mx-auto flex min-h-[70dvh] w-full max-w-[1400px] items-center px-4 py-20 md:px-6">
      <div className="glass-panel max-w-2xl rounded-[2rem] p-8 md:p-10">
        <p className="text-xs uppercase tracking-[0.35em] text-[--accent]">404</p>
        <h1 className="mt-3 font-display text-4xl tracking-[-0.05em] text-white md:text-5xl">
          Сторінку не знайдено.
        </h1>
        <p className="mt-4 max-w-[48ch] text-base leading-7 text-[--muted]">
          Можливо, товар ще не опублікований або посилання вже неактуальне.
        </p>
        <div className="mt-8 flex flex-wrap gap-3">
          <a className="accent-pill" href={withBasePath("/catalog")}>
            До каталогу
          </a>
          <a className="ghost-pill" href={withBasePath("/")}>
            На головну
          </a>
        </div>
      </div>
    </main>
  );
}
