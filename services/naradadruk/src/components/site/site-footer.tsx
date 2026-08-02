import { withBasePath } from "@/lib/base-path";
import { buildTelegramLink } from "@/lib/telegram";
import { TrackedLink } from "@/components/site/tracked-link";

type SiteFooterProps = {
  telegramUrl: string;
};

export function SiteFooter({ telegramUrl }: SiteFooterProps) {
  const customUrl = buildTelegramLink({
    baseUrl: telegramUrl,
    intent: "custom",
  });

  return (
    <footer className="site-footer">
      <div className="site-footer__inner">
        <div className="site-footer__brand">
          <div className="site-wordmark">
            <span className="site-wordmark__mark" aria-hidden>
              Н
            </span>
            <span className="site-wordmark__text">
              Narada
              <small>druk</small>
            </span>
          </div>
          <p>
            Функціональний 3D-друк від першого ескізу до готової деталі.
          </p>
          <small className="site-footer__location">Київ · доставка по Україні</small>
        </div>

        <nav className="site-footer__nav" aria-label="Навігація у футері">
          <a href={withBasePath("/")}>
            Головна
          </a>
          <a href={withBasePath("/catalog")}>
            Каталог
          </a>
          <a href={withBasePath("/cart")}>Кошик</a>
          <a href={withBasePath("/#process")}>Як замовити</a>
          <a href={withBasePath("/#delivery")}>Доставка й оплата</a>
          <TrackedLink
            href={customUrl}
            target="_blank"
            rel="noreferrer"
            eventName="Custom Lead"
            eventProps={{ location: "footer", intent: "custom" }}
          >
            Telegram
          </TrackedLink>
        </nav>
      </div>
    </footer>
  );
}
