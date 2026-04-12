import Link from "next/link";

export default function NotFound() {
  return (
    <main className="mx-auto flex min-h-[70vh] w-full max-w-4xl items-center px-4 py-10 md:px-6">
      <div className="glass-panel w-full rounded-[32px] p-8 md:p-10">
        <p className="text-xs uppercase tracking-[0.32em] text-[--accent-orange]">404</p>
        <h1 className="mt-4 font-display text-4xl text-white md:text-6xl">
          Сторінку не знайдено
        </h1>
        <p className="mt-4 max-w-2xl text-base leading-7 text-[--muted]">
          Можливо, матеріал ще не опублікований, шлях до адмінки введено неправильно або посилання застаріло.
        </p>
        <Link
          href="/"
          className="mt-8 inline-flex rounded-full bg-[--paper] px-5 py-3 text-sm font-semibold text-black transition hover:bg-white"
        >
          Повернутись на мапу
        </Link>
      </div>
    </main>
  );
}
