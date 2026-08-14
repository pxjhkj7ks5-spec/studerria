import { withBasePath } from "@/lib/base-path";

export function SiteFooter({ telegramUrl }: { telegramUrl: string }) {
  return <footer className="site-footer"><div className="site-footer__inner"><div className="site-footer__brand"><div className="site-wordmark"><span className="site-wordmark__mark" aria-hidden>Y</span><span className="site-wordmark__text">YKG<small>store</small></span></div><p>Young Killers Group. Короткі серії мерчу й патчів.</p><small className="site-footer__location">Україна · доставка Новою поштою</small></div><nav className="site-footer__nav" aria-label="Навігація у футері"><a href={withBasePath("/")}>Головна</a><a href={withBasePath("/catalog")}>Каталог</a><a href={withBasePath("/reviews")}>Відгуки</a><a href={withBasePath("/cart")}>Кошик</a><a href={withBasePath("/#delivery")}>Доставка й оплата</a><a href={telegramUrl} target="_blank" rel="noreferrer">Instagram</a></nav></div></footer>;
}
