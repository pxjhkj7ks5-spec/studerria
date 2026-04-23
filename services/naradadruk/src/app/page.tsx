import { ProductCard } from "@/components/site/product-card";
import { getFeaturedProducts, getSiteSettings, getVisibleCategories } from "@/lib/data";
import { supportFacts } from "@/lib/constants";
import { withBasePath } from "@/lib/base-path";

export const dynamic = "force-dynamic";

export default async function HomePage() {
  const [settings, categories, featuredProducts] = await Promise.all([
    getSiteSettings(),
    getVisibleCategories(),
    getFeaturedProducts(),
  ]);

  return (
    <main className="pb-12">
      <section className="surface-grid hero-stage border-b border-white/8">
        <div className="mx-auto w-full max-w-[1400px] px-4 pb-12 pt-5 md:px-6 md:pb-16 md:pt-6">
          <div className="flex items-center justify-between gap-4">
            <a href={withBasePath("/")} className="font-display text-[1.95rem] tracking-[-0.055em] text-white">
              Narada Druk
            </a>
            <div className="hidden items-center gap-3 md:flex">
              <a className="ghost-pill" href={withBasePath("/catalog")}>
                Каталог
              </a>
              <a className="accent-pill" href={settings.telegramUrl} target="_blank" rel="noreferrer">
                Замовити
              </a>
            </div>
          </div>

          <div className="hero-grid mt-12 lg:mt-16">
            <div className="hero-copy">
              <p className="hero-kicker">3D друк та практичні аксесуари</p>
              <h1 className="hero-title">{settings.heroTitle}</h1>
              <p className="hero-body">{settings.heroSubtitle}</p>

              <div className="mt-9 flex flex-wrap gap-3">
                <a className="accent-pill" href={withBasePath("/catalog")}>
                  Дивитися каталог
                </a>
                <a className="ghost-pill" href={settings.telegramUrl} target="_blank" rel="noreferrer">
                  Перейти в Telegram
                </a>
              </div>

              <div className="hero-caption">
                <span className="hero-caption-line" />
                <p className="hero-caption-text">Серійні вироби, кастомні деталі, прямий контакт без зайвого процесу.</p>
              </div>
            </div>

            <aside className="hero-rail">
              <p className="hero-rail-label">Асортимент</p>
              <div className="hero-category-list">
                {categories.slice(0, 4).map((category) => (
                  <a key={category.id} href={withBasePath(`/category/${category.slug}`)} className="hero-category-link">
                    <div className="hero-category-head">
                      <span className="hero-category-name">{category.name}</span>
                      <span className="hero-category-count">{category.publishedCount} позицій</span>
                    </div>
                    <p className="hero-category-text">{category.description}</p>
                  </a>
                ))}
              </div>
            </aside>
          </div>

          <div className="hero-band mt-10 lg:mt-12">
            <div className="hero-band-copy">
              <p className="hero-band-label">{settings.supportTitle}</p>
              <p className="hero-band-text">{settings.supportBody}</p>
            </div>

            <div className="hero-facts-grid">
              {supportFacts.slice(0, 3).map((fact) => (
                <p key={fact} className="hero-fact-item">
                  {fact}
                </p>
              ))}
            </div>
          </div>
        </div>
      </section>

      <section className="mx-auto mt-4 w-full max-w-[1400px] px-4 md:px-6">
        <div className="info-strip py-8 md:grid-cols-4">
          {[
            settings.deliveryNote,
            settings.paymentNote,
            settings.materialsNote,
            settings.contactNote,
          ].map((item) => (
            <div key={item} className="info-strip-item">
              {item}
            </div>
          ))}
        </div>
      </section>

      <section className="mx-auto w-full max-w-[1400px] px-4 py-10 md:px-6 md:py-12">
        <div className="flex flex-col gap-4 md:flex-row md:items-end md:justify-between">
          <div className="max-w-[44rem]">
            <p className="text-xs uppercase tracking-[0.32em] text-[--accent]">Featured</p>
            <h2 className="mt-3 font-display text-[clamp(2.2rem,4vw,3.7rem)] leading-[0.95] tracking-[-0.06em] text-white">
              Готові позиції, які вже можна брати за основу.
            </h2>
          </div>
          <a className="ghost-pill" href={withBasePath("/catalog")}>
            Увесь каталог
          </a>
        </div>

        {featuredProducts.length > 0 ? (
          <div className="mt-8 grid gap-5 lg:grid-cols-2 xl:grid-cols-3">
            {featuredProducts.map((product) => (
              <ProductCard key={product.id} product={product} telegramUrl={settings.telegramUrl} />
            ))}
          </div>
        ) : (
          <div className="empty-showcase mt-8">
            <div>
              <p className="empty-showcase-kicker">Наступний крок</p>
              <h3 className="font-display text-[clamp(2rem,3.4vw,3rem)] leading-[0.98] tracking-[-0.05em] text-white">
                Каталог готовий до першого наповнення.
              </h3>
            </div>

            <div className="empty-showcase-copy">
              <p className="text-base leading-8 text-[--muted]">
                Додайте перші товари через адмінку, а поки що клієнтів можна вести напряму в Telegram для індивідуальних замовлень.
              </p>

              <div className="mt-6 flex flex-wrap gap-3">
                <a className="accent-pill" href={settings.telegramUrl} target="_blank" rel="noreferrer">
                  Написати в Telegram
                </a>
                <a className="ghost-pill" href={withBasePath("/catalog")}>
                  Відкрити каталог
                </a>
              </div>
            </div>
          </div>
        )}
      </section>
    </main>
  );
}
