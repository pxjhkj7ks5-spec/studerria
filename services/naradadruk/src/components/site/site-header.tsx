import { PaperPlaneTilt } from "@phosphor-icons/react/ssr";
import { withBasePath } from "@/lib/base-path";
import { buildTelegramLink } from "@/lib/telegram";
import { TrackedLink } from "@/components/site/tracked-link";
import { CartLink } from "@/components/site/cart-link";

type SiteHeaderProps = {
  telegramUrl: string;
};

export function SiteHeader({ telegramUrl }: SiteHeaderProps) {
  const customUrl = buildTelegramLink({
    baseUrl: telegramUrl,
    intent: "custom",
  });

  return (
    <header className="site-header">
      <div className="site-header__inner">
        <a
          className="site-wordmark"
          href={withBasePath("/")}
          aria-label="Narada Druk — головна"
        >
          <span className="site-wordmark__mark" aria-hidden>
            Н
          </span>
          <span className="site-wordmark__text">
            Narada
            <small>druk</small>
          </span>
        </a>

        <nav className="site-nav" aria-label="Головна навігація">
          <a href={withBasePath("/catalog")}>Каталог</a>
          <a href={withBasePath("/#process")}>Як це працює</a>
          <a href={withBasePath("/#delivery")}>Доставка</a>
        </nav>

        <div className="site-header__actions">
          <CartLink />
          <TrackedLink
            className="accent-pill site-header__cta"
            href={customUrl}
            target="_blank"
            rel="noreferrer"
            eventName="Custom Lead"
            eventProps={{ location: "header", intent: "custom" }}
          >
            <PaperPlaneTilt aria-hidden size={18} weight="fill" />
            <span>Індивідуальний виріб</span>
          </TrackedLink>
        </div>
      </div>
    </header>
  );
}
