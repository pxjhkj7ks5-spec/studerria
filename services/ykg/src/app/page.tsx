import Image from "next/image";
import type { Metadata } from "next";
import { ArrowDown, ArrowRight, InstagramLogo, Package, ShieldCheck, Truck } from "@phosphor-icons/react/ssr";
import { ProductCard } from "@/components/site/product-card";
import { PublicFrame } from "@/components/site/public-frame";
import { TrackedLink } from "@/components/site/tracked-link";
import { getHomepageProductSections, getSiteSettings } from "@/lib/data";
import { withBasePath } from "@/lib/base-path";
import { siteDescription, siteName, siteShareTitle } from "@/lib/constants";
import { absoluteSiteUrl } from "@/lib/site-url";
import { StructuredData } from "@/components/site/structured-data";

export const dynamic = "force-dynamic";

export async function generateMetadata(): Promise<Metadata> {
  const image = absoluteSiteUrl("/ykg-editorial-hero.png");
  return {
    title: { absolute: siteShareTitle }, description: siteDescription,
    alternates: { canonical: absoluteSiteUrl() },
    openGraph: { type: "website", locale: "uk_UA", url: absoluteSiteUrl(), siteName, title: siteShareTitle, description: siteDescription, images: [{ url: image, alt: "YKG editorial" }] },
    twitter: { card: "summary_large_image", title: siteShareTitle, description: siteDescription, images: [image] },
  };
}

export default async function HomePage() {
  const [settings, sections] = await Promise.all([getSiteSettings(), getHomepageProductSections(4, 4, 4)]);
  const drop = sections.saleProducts.length ? sections.saleProducts : sections.popularProducts;
  const catalog = drop.length ? drop : sections.newProducts;

  return (
    <PublicFrame telegramUrl={settings.telegramUrl}>
      <StructuredData data={{ "@context": "https://schema.org", "@type": "OnlineStore", name: siteName, url: absoluteSiteUrl(), description: siteDescription }} />
      <main className="ykg-home">
        <section className="ykg-hero">
          <Image src={withBasePath("/ykg-editorial-hero.png")} alt="Темний editorial натюрморт із чорним текстилем та оливковими патчами" fill priority sizes="100vw" className="ykg-hero__image" />
          <div className="ykg-hero__veil" />
          <div className="site-container ykg-hero__content">
            <p className="eyebrow">Young Killers Group / Store</p>
            <h1><span>YOUNG</span><span>KILLERS</span><span>GROUP</span></h1>
            <p className="ykg-hero__lead">{settings.heroSubtitle}</p>
            <div className="hero-actions">
              <TrackedLink className="accent-pill accent-pill--large" href={withBasePath("/catalog")} eventName="Catalog Open" eventProps={{ location: "hero", intent: "catalog" }}>Дивитися drop <ArrowRight aria-hidden size={18} /></TrackedLink>
              <TrackedLink className="ghost-pill ghost-pill--large" href={settings.telegramUrl} target="_blank" rel="noreferrer" eventName="Custom Lead" eventProps={{ location: "hero", intent: "custom" }}>Instagram <InstagramLogo aria-hidden size={18} /></TrackedLink>
            </div>
            <a className="ykg-hero__scroll" href="#drop"><ArrowDown aria-hidden size={18} /> Новий drop</a>
          </div>
          <div className="ykg-hero__index" aria-hidden>YKG—01</div>
        </section>

        <section className="site-section ykg-drop" id="drop">
          <div className="site-container">
            <div className="section-heading section-heading--split">
              <div><p className="eyebrow">Current issue / 01</p><h2>Вибраний drop</h2><p>Короткі серії YKG. Реальну назву, ціну й варіанти команда підтверджує перед публікацією.</p></div>
              <TrackedLink className="text-link" href={withBasePath("/catalog")} eventName="Catalog Open" eventProps={{ location: "drop-heading", intent: "catalog" }}>Весь каталог <ArrowRight aria-hidden size={18} /></TrackedLink>
            </div>
            {catalog.length ? <div className="product-grid product-grid--featured">{catalog.map((product, index) => <ProductCard key={product.id} product={product} priority={index < 2} />)}</div> : <div className="ykg-empty-drop"><span>DROP 001</span><h3>Позиції готуються до публікації.</h3><p>Ми не показуємо непідтверджені товари, ціни чи фото. Стежте за анонсами в Instagram.</p><a className="accent-pill" href={settings.telegramUrl} target="_blank" rel="noreferrer">youngkillersgroup_store <ArrowRight size={16} /></a></div>}
          </div>
        </section>

        <section className="site-section ykg-manifesto">
          <div className="site-container ykg-manifesto__grid">
            <p className="eyebrow">About / YKG</p>
            <h2>Речі, що говорять тихо. Присутність, яку помічають.</h2>
            <div><p>{settings.supportBody}</p><p>Чорний текстиль, груба графіка й функціональні деталі без декоративного шуму. Магазин показує лише підтверджені позиції.</p></div>
          </div>
        </section>

        <section className="site-section site-section--compact" id="delivery">
          <div className="site-container trust-grid">
            <article className="trust-item"><ShieldCheck size={25} /><div><h3>Чесна наявність</h3><p>Покупець бачить тільки «В наявності» або «Під замовлення».</p></div></article>
            <article className="trust-item"><Package size={25} /><div><h3>Контроль замовлення</h3><p>Статус та історія доступні за приватним посиланням.</p></div></article>
            <article className="trust-item"><Truck size={25} /><div><h3>Нова пошта</h3><p>{settings.deliveryNote}</p></div></article>
          </div>
        </section>

        <section className="ykg-instagram">
          <div className="site-container ykg-instagram__inner"><div><p className="eyebrow">Field notes / Instagram</p><h2>Дропи, історії, атмосфера.</h2></div><a className="accent-pill accent-pill--large" href={settings.telegramUrl} target="_blank" rel="noreferrer"><InstagramLogo size={19} /> Перейти в Instagram</a></div>
        </section>
      </main>
    </PublicFrame>
  );
}
