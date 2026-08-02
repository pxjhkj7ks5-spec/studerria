import Image from "next/image";
import type { Metadata } from "next";
import {
  ArrowRight,
  ChatText,
  Clock,
  Crosshair,
  Cube,
  DotsThree,
  NotePencil,
  Package,
  PottedPlant,
  ShieldCheck,
  Truck,
} from "@phosphor-icons/react/ssr";
import { ProductCard } from "@/components/site/product-card";
import { PublicFrame } from "@/components/site/public-frame";
import { TrackedLink } from "@/components/site/tracked-link";
import {
  getHomepageProductSections,
  getShowcaseImages,
  getSiteSettings,
  getVisibleCategories,
} from "@/lib/data";
import { withBasePath } from "@/lib/base-path";
import { absoluteSiteUrl, publicPaymentNote, siteName, siteShareTitle } from "@/lib/constants";
import { buildTelegramLink } from "@/lib/telegram";

export const dynamic = "force-dynamic";

export async function generateMetadata(): Promise<Metadata> {
  const settings = await getSiteSettings();
  const cleaned = settings.heroSubtitle.replace(/\s+/g, " ").trim();
  const description = cleaned.length > 165 ? `${cleaned.slice(0, 162).trimEnd()}…` : cleaned;
  return {
    title: { absolute: siteShareTitle },
    description,
    alternates: { canonical: absoluteSiteUrl() },
    openGraph: { type: "website", locale: "uk_UA", url: absoluteSiteUrl(), siteName, title: siteShareTitle, description, images: [{ url: absoluteSiteUrl("/naradadruk-hero.webp"), alt: "3D-друк Narada Druk" }] },
    twitter: { card: "summary_large_image", title: siteShareTitle, description, images: [absoluteSiteUrl("/naradadruk-hero.webp")] },
  };
}

function CategoryIcon({ slug }: { slug: string }) {
  const props = { size: 25, weight: "regular" as const, "aria-hidden": true };

  if (slug.includes("strajk")) {
    return <Crosshair {...props} />;
  }

  if (slug.includes("dekor")) {
    return <PottedPlant {...props} />;
  }

  if (slug.includes("3d")) {
    return <Cube {...props} />;
  }

  return <DotsThree {...props} />;
}

export default async function HomePage() {
  const [settings, categories, productSections, showcaseImages] = await Promise.all([
    getSiteSettings(),
    getVisibleCategories(),
    getHomepageProductSections(),
    getShowcaseImages(),
  ]);
  const { saleProducts, popularProducts, newProducts } = productSections;

  const customUrl = buildTelegramLink({
    baseUrl: settings.telegramUrl,
    intent: "custom",
  });

  const processSteps = [
    {
      icon: ChatText,
      title: "Покажіть задачу",
      body: "Опишіть, що потрібно, або надішліть креслення, фото чи посилання на модель.",
    },
    {
      icon: NotePencil,
      title: "Погодимо матеріал і ціну",
      body: "Підберемо матеріал і технологію під вашу задачу та бюджет. Швидко відповідаємо.",
    },
    {
      icon: Package,
      title: "Надрукуємо та відправимо",
      body: "Друкуємо з контролем якості та доставляємо по Україні або передаємо в Києві.",
    },
  ];

  const trustItems = [
    {
      icon: ShieldCheck,
      title: "Практичні матеріали",
      body: settings.materialsNote,
    },
    {
      icon: Cube,
      title: "Під вашу задачу",
      body: "Серійні вироби та індивідуальні деталі.",
    },
    {
      icon: Clock,
      title: "Зрозумілі терміни",
      body: settings.leadTimeNote,
    },
    {
      icon: Truck,
      title: "Доставка по Україні",
      body: settings.deliveryNote,
    },
  ];

  const faqItems = [
    ["З яких матеріалів ви друкуєте?", settings.materialsNote],
    ["Скільки коштує 3D-друк?", "Ціна залежить від розміру, матеріалу та складності. Надішліть задачу в Telegram — уточнимо вартість до старту."],
    ["Скільки часу займає виготовлення?", settings.leadTimeNote],
    ["Як відбувається доставка?", settings.deliveryNote],
    ["Як оплатити замовлення?", publicPaymentNote],
  ];

  return (
    <PublicFrame telegramUrl={settings.telegramUrl}>
      <main>
        <section className="hero-section">
          <div className="site-container hero-layout">
            <div className="hero-copy">
              <p className="eyebrow">3D-друк під вашу задачу</p>
              <h1>{settings.heroTitle}</h1>
              <p className="hero-copy__body">
                {settings.heroSubtitle}
              </p>

              <div className="hero-actions">
                <TrackedLink
                  className="accent-pill accent-pill--large"
                  href={customUrl}
                  target="_blank"
                  rel="noreferrer"
                  eventName="Custom Lead"
                  eventProps={{ location: "hero", intent: "custom" }}
                >
                  Надрукувати своє
                  <ArrowRight aria-hidden size={18} />
                </TrackedLink>
                <TrackedLink
                  className="ghost-pill ghost-pill--large"
                  href={withBasePath("/catalog")}
                  eventName="Catalog Open"
                  eventProps={{ location: "hero", intent: "catalog" }}
                >
                  Переглянути каталог
                  <ArrowRight aria-hidden size={18} />
                </TrackedLink>
              </div>
            </div>

            <div className="hero-visual">
              <Image
                src={withBasePath("/naradadruk-hero.webp")}
                alt="Ескіз і готова 3D-друкована деталь"
                width={1600}
                height={1000}
                loading="eager"
                fetchPriority="high"
                className="hero-visual__image"
              />
            </div>
          </div>
        </section>

        <section className="site-container category-dock" aria-label="Категорії">
          {categories.map((category) => (
            <TrackedLink
              key={category.id}
              className="category-dock__item"
              href={withBasePath(`/category/${category.slug}`)}
              eventName="Catalog Filter"
              eventProps={{
                location: "home-category",
                category: category.slug,
              }}
            >
              <span className="category-dock__icon">
                {category.representativeImage ? (
                  <Image
                    src={withBasePath(category.representativeImage.urlPath)}
                    alt={category.representativeImage.alt}
                    width={96}
                    height={96}
                    unoptimized
                  />
                ) : (
                  <CategoryIcon slug={category.slug} />
                )}
              </span>
              <span>
                <strong>{category.name}</strong>
                <small>{category.publishedCount} позицій</small>
              </span>
              <ArrowRight
                className="category-dock__arrow"
                aria-hidden
                size={18}
              />
            </TrackedLink>
          ))}
        </section>

        {saleProducts.length > 0 ? (
          <section className="site-section site-section--featured">
            <div className="site-container">
              <div className="section-heading section-heading--split">
                <div><p className="eyebrow">Активні пропозиції</p><h2>Знижки</h2><p>Товари з чинною акційною ціною. Без штучних таймерів або вигаданого дефіциту.</p></div>
                <TrackedLink className="text-link" href={withBasePath("/catalog")} eventName="Catalog Open" eventProps={{ location: "sale-heading", intent: "catalog" }}>До каталогу<ArrowRight aria-hidden size={18} /></TrackedLink>
              </div>
              <div className="product-grid product-grid--featured">{saleProducts.map((product) => <ProductCard key={product.id} product={product} />)}</div>
            </div>
          </section>
        ) : null}

        <section className="site-section site-section--featured">
          <div className="site-container">
            <div className="section-heading section-heading--split">
              <div>
                <p className="eyebrow">Вибір майстерні</p>
                <h2>Популярне</h2>
                <p>Добірка виробів, які команда Narada Druk рекомендує переглянути першими.</p>
              </div>
              <TrackedLink
                className="text-link"
                href={withBasePath("/catalog")}
                eventName="Catalog Open"
                eventProps={{ location: "featured-heading", intent: "catalog" }}
              >
                Переглянути весь каталог
                <ArrowRight aria-hidden size={18} />
              </TrackedLink>
            </div>

            {popularProducts.length > 0 ? (
              <div className="product-grid product-grid--featured">
                {popularProducts.map((product) => (
                  <ProductCard
                    key={product.id}
                    product={product}
                  />
                ))}
              </div>
            ) : (
              <div className="empty-catalog">
                <div>
                  <p className="eyebrow">Поки каталог наповнюється</p>
                  <h3>Потрібна конкретна деталь?</h3>
                  <p>
                    Надішліть опис, розміри або фото прикладу — підкажемо
                    матеріал, термін і вартість до старту.
                  </p>
                </div>
                <TrackedLink
                  className="accent-pill accent-pill--large"
                  href={customUrl}
                  target="_blank"
                  rel="noreferrer"
                  eventName="Custom Lead"
                  eventProps={{ location: "empty-catalog", intent: "custom" }}
                >
                  Обговорити в Telegram
                  <ArrowRight aria-hidden size={18} />
                </TrackedLink>
              </div>
            )}
          </div>
        </section>

        {newProducts.length > 0 ? (
          <section className="site-section">
            <div className="site-container">
              <div className="section-heading section-heading--split">
                <div>
                  <p className="eyebrow">Щойно в каталозі</p>
                  <h2>Новинки</h2>
                  <p>Останні додані позиції без повторів із добірки вище.</p>
                </div>
                <TrackedLink
                  className="text-link"
                  href={withBasePath("/catalog")}
                  eventName="Catalog Open"
                  eventProps={{ location: "new-products-heading", intent: "catalog" }}
                >
                  Переглянути весь каталог
                  <ArrowRight aria-hidden size={18} />
                </TrackedLink>
              </div>

              <div className="product-grid product-grid--featured">
                {newProducts.map((product) => (
                  <ProductCard key={product.id} product={product} />
                ))}
              </div>
            </div>
          </section>
        ) : null}

        <section className="site-section site-section--process" id="process">
          <div className="site-container process-layout">
            <div className="section-heading">
              <p className="eyebrow">Від задачі до деталі</p>
              <h2>Три кроки. Без технічної бюрократії.</h2>
              <p>Пишете як є — ми допомагаємо з матеріалом, моделлю та виробництвом.</p>
            </div>

            <div className="process-grid">
              {processSteps.map((step, index) => {
                const Icon = step.icon;
                return (
                  <article key={step.title} className="process-step">
                    <div className="process-step__topline">
                      <span className="process-step__icon">
                        <Icon aria-hidden size={23} />
                      </span>
                      <p className="process-step__number">0{index + 1}</p>
                    </div>
                    <h3>{step.title}</h3>
                    <p>{step.body}</p>
                    {index === 0 ? (
                      <TrackedLink
                        className="process-step__link"
                        href={customUrl}
                        target="_blank"
                        rel="noreferrer"
                        eventName="Custom Lead"
                        eventProps={{ location: "process", intent: "custom" }}
                        aria-label="Показати задачу в Telegram"
                      >
                        Почати з повідомлення
                        <ArrowRight aria-hidden size={18} />
                      </TrackedLink>
                    ) : null}
                  </article>
                );
              })}
            </div>
          </div>
        </section>

        {showcaseImages.length > 0 ? (
          <section className="site-section site-section--showcase">
            <div className="site-container">
              <div className="section-heading section-heading--split">
                <div>
                  <p className="eyebrow">Надруковано нами</p>
                  <h2>Фактура, форма, результат.</h2>
                </div>
                <p>Живі приклади виробів із каталогу.</p>
              </div>
              <div className="showcase-grid">
                {showcaseImages.map((image) => (
                  <TrackedLink
                    key={image.id}
                    className="showcase-tile"
                    href={withBasePath(`/product/${image.product.slug}`)}
                    eventName="Product Open"
                    eventProps={{
                      location: "showcase",
                      product_slug: image.product.slug,
                      category: image.product.category.name,
                    }}
                  >
                    <Image
                      src={withBasePath(image.urlPath)}
                      alt={image.alt || image.product.title}
                      width={900}
                      height={900}
                      unoptimized
                    />
                    <span>{image.product.title}</span>
                  </TrackedLink>
                ))}
              </div>
            </div>
          </section>
        ) : null}

        <section className="site-section site-section--compact" id="delivery">
          <div className="site-container trust-grid">
            {trustItems.map((item) => {
              const Icon = item.icon;
              return (
                <article key={item.title} className="trust-item">
                  <Icon aria-hidden size={25} />
                  <div>
                    <h3>{item.title}</h3>
                    <p>{item.body}</p>
                  </div>
                </article>
              );
            })}
          </div>
        </section>

        <section className="site-section site-section--compact">
          <div className="site-container faq-layout">
            <div className="section-heading">
              <p className="eyebrow">Без невідомих</p>
              <h2>Поширені запитання</h2>
              <p>
                Коротко про матеріали, вартість, терміни й отримання замовлення.
              </p>
            </div>
            <div className="faq-list">
              {faqItems.map(([question, answer]) => (
                <details key={question}>
                  <summary>{question}</summary>
                  <p>{answer}</p>
                </details>
              ))}
            </div>
          </div>
        </section>

        <section className="site-section site-section--closing">
          <div className="site-container closing-cta">
            <div>
              <p className="eyebrow">Є ідея?</p>
              <h2>Давайте надрукуємо.</h2>
              <p>Опишіть задачу — отримаєте розрахунок і терміни.</p>
            </div>
            <div className="closing-cta__actions">
              <TrackedLink
                className="accent-pill accent-pill--large"
                href={customUrl}
                target="_blank"
                rel="noreferrer"
                eventName="Custom Lead"
                eventProps={{ location: "closing-cta", intent: "custom" }}
              >
                Надрукувати своє
                <ArrowRight aria-hidden size={18} />
              </TrackedLink>
              <TrackedLink
                className="ghost-pill ghost-pill--large ghost-pill--dark"
                href={withBasePath("/catalog")}
                eventName="Catalog Open"
                eventProps={{ location: "closing-cta", intent: "catalog" }}
              >
                Переглянути каталог
              </TrackedLink>
            </div>
          </div>
        </section>
      </main>
    </PublicFrame>
  );
}
