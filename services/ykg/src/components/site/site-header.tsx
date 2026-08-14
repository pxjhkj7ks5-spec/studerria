import { InstagramLogo, SquaresFour } from "@phosphor-icons/react/ssr";
import { withBasePath } from "@/lib/base-path";
import { CartLink } from "@/components/site/cart-link";

export function SiteHeader({ telegramUrl }: { telegramUrl: string }) {
  return <header className="site-header"><div className="site-header__inner">
    <a className="site-wordmark" href={withBasePath("/")} aria-label="YKG — головна"><span className="site-wordmark__mark" aria-hidden>Y</span><span className="site-wordmark__text">YKG<small>store</small></span></a>
    <nav className="site-nav" aria-label="Головна навігація"><a href={withBasePath("/catalog")}>Каталог</a><a href={withBasePath("/reviews")}>Відгуки</a><a href={withBasePath("/#delivery")}>Доставка</a></nav>
    <div className="site-header__actions"><a className="mobile-catalog-link" href={withBasePath("/catalog")}><SquaresFour size={18} /><span>Каталог</span></a><CartLink /><a className="accent-pill site-header__cta" href={telegramUrl} target="_blank" rel="noreferrer"><InstagramLogo size={18} /><span>Instagram</span></a></div>
  </div></header>;
}
