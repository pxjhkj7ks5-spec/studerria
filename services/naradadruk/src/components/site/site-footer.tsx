import { withBasePath } from "@/lib/base-path";

export function SiteFooter() {
  return (
    <footer className="reveal-up delay-2 relative z-10 mt-16 border-t border-white/10">
      <div className="mx-auto flex w-full max-w-[1400px] flex-col gap-4 px-4 py-8 text-sm text-[--muted] md:flex-row md:items-center md:justify-between md:px-6">
        <div>
          <div className="font-display text-base text-white">Narada Druk</div>
          <p className="mt-1 max-w-[48ch]">
            Каталог готових рішень і кастомного 3D друку з прямим переходом у Telegram.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-4">
          <a className="footer-link transition hover:text-white" href={withBasePath("/")}>
            Головна
          </a>
          <a className="footer-link transition hover:text-white" href={withBasePath("/catalog")}>
            Каталог
          </a>
          <a
            className="footer-link transition hover:text-white"
            href="https://web.telegram.org/k/#@naradaprint"
            target="_blank"
            rel="noreferrer"
          >
            Telegram
          </a>
        </div>
      </div>
    </footer>
  );
}
