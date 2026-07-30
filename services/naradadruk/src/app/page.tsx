import Image from "next/image";
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
  getFeaturedProducts,
  getShowcaseImages,
  getSiteSettings,
  getVisibleCategories,
} from "@/lib/data";
import { withBasePath } from "@/lib/base-path";
import { buildTelegramLink } from "@/lib/telegram";

export const dynamic = "force-dynamic";

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
  const [settings, categories, featuredProducts, showcaseImages] = await Promise.all([
    getSiteSettings(),
    getVisibleCategories(),
    getFeaturedProducts(),
    getShowcaseImages(),
  ]);

  const customUrl = buildTelegramLink({
    baseUrl: settings.telegramUrl,
    intent: "custom",
  });
  const heroProduct = featuredProducts[0];
  const heroImage = heroProduct?.coverImage?.urlPath ?? "/naradadruk-hero.webp";
  const heroAlt = heroProduct?.coverImage?.alt || heroProduct?.title || "Ескіз і прототип функціонального кріплення";

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
    ["Як оплатити замовлення?", settings.paymentNote],
  ];

  return (
    <PublicFrame telegramUrl={settings.telegramUrl}>
      <main>
        <section className="hero-section">
          <div className="site-container hero-layout">
            <div className="hero-copy">
              <p className="eyebrow">3D-друк під вашу задачу</p>
              <h1>Від ідеї до готової деталі.</h1>
              <p className="hero-copy__body">
                Персональний 3D-друк для дому, хобі та практичних задач.
                Від прототипів до функціональних виробів — точно, швидко й
                без зайвого процесу.
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
                src={withBasePath(heroImage)}
                alt={heroAlt}
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
            </TrackedLink>
          ))}
        </section>

        <section className="site-section" id="process">
          <div className="site-container">
            <div className="section-heading section-heading--center">
              <p className="eyebrow">Простий процес</p>
              <h2>Як ми працюємо</h2>
              <p>Від першого повідомлення до готового виробу — три зрозумілі кроки.</p>
            </div>

            <div className="process-grid">
              {processSteps.map((step, index) => {
                const Icon = step.icon;
                return (
                  <article key={step.title} className="process-step">
                    <span className="process-step__icon">
                      <Icon aria-hidden size={24} />
                    </span>
                    <p className="process-step__number">0{index + 1}</p>
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
                        <ArrowRight aria-hidden size={20} />
                      </TrackedLink>
                    ) : null}
                  </article>
                );
              })}
            </div>
          </div>
        </section>

        <section className="site-section site-section--compact">
          <div className="site-container">
            <div className="section-heading section-heading--split">
              <div>
                <p className="eyebrow">Каталог</p>
                <h2>Готові рішення</h2>
                <p>Популярні вироби, які вже можна замовити або взяти за основу.</p>
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

            {featuredProducts.length > 0 ? (
              <div className="product-grid product-grid--featured">
                {featuredProducts.map((product) => (
                  <ProductCard
                    key={product.id}
                    product={product}
                    telegramUrl={settings.telegramUrl}
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

        {showcaseImages.length > 0 ? (
          <section className="site-section site-section--compact">
            <div className="site-container">
              <div className="section-heading">
                <p className="eyebrow">Реальні роботи</p>
                <h2>Подивіться ближче</h2>
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
