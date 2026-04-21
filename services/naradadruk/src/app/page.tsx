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
    <main className="pb-6">
      <section className="surface-grid hero-stage">
        <div className="mx-auto grid min-h-[calc(100dvh-1.5rem)] w-full max-w-[1400px] content-center gap-10 px-4 pb-10 pt-5 md:px-6 md:pb-12 md:pt-6 lg:grid-cols-[minmax(0,1.08fr)_minmax(24rem,0.92fr)] lg:items-center lg:gap-12 lg:pb-14 lg:pt-8 xl:gap-16">
          <div className="flex min-h-0 flex-col gap-6 md:gap-8 lg:py-8">
            <div className="reveal-up delay-1 flex items-center justify-between gap-4 lg:pb-2">
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

            <div className="hero-reveal delay-2 max-w-[45rem]">
              <p className="text-xs uppercase tracking-[0.35em] text-[--accent]">3D друк та практичні аксесуари</p>
              <h1 className="mt-4 max-w-[10.5ch] font-display text-[clamp(3.1rem,7vw,5.75rem)] leading-[0.9] tracking-[-0.078em] text-white">
                {settings.heroTitle}
              </h1>
              <p className="mt-6 max-w-[48ch] text-base leading-8 text-[--muted] md:text-lg">
                {settings.heroSubtitle}
              </p>

              <div className="mt-9 flex flex-wrap gap-3">
                <a className="accent-pill" href={withBasePath("/catalog")}>
                  Дивитися каталог
                </a>
                <a className="ghost-pill" href={settings.telegramUrl} target="_blank" rel="noreferrer">
                  Перейти в Telegram
                </a>
              </div>
            </div>

            <div className="reveal-up delay-3 grid gap-3 md:grid-cols-[1.08fr_0.92fr] lg:mt-auto">
              <div className="glass-panel hero-support-panel interactive-card rounded-[2rem] p-5">
                <p className="text-xs uppercase tracking-[0.28em] text-[--accent]">{settings.supportTitle}</p>
                <p className="mt-4 max-w-[44ch] text-sm leading-7 text-[--muted]">{settings.supportBody}</p>
              </div>

              <div className="stagger-list grid gap-3">
                {supportFacts.slice(0, 3).map((fact) => (
                  <div key={fact} className="glass-panel hero-fact-card interactive-card rounded-[1.45rem] px-4 py-3.5 text-sm text-[--muted]">
                    {fact}
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div className="reveal-up delay-3 grid gap-4 lg:max-w-[32rem] lg:justify-self-end">
            <div className="glass-panel interactive-card grid gap-5 rounded-[2.5rem] p-5 md:grid-cols-[0.8fr_1.2fr] md:p-7">
              <div className="flex flex-col justify-between gap-6">
                <div>
                  <p className="text-xs uppercase tracking-[0.28em] text-[--muted]">Асортимент</p>
                  <h2 className="mt-4 font-display text-3xl tracking-[-0.05em] text-white">
                    Каталог для готових позицій і кастомних задач.
                  </h2>
                </div>

                <div className="stagger-list grid gap-3 text-sm text-[--muted]">
                  <div className="category-summary-card interactive-card rounded-[1.25rem] px-4 py-3">
                    {settings.materialsNote}
                  </div>
                  <div className="category-summary-card interactive-card rounded-[1.25rem] px-4 py-3">
                    {settings.leadTimeNote}
                  </div>
                </div>
              </div>

              <div className="stagger-list grid gap-3">
                {categories.slice(0, 4).map((category) => (
                  <a
                    key={category.id}
                    href={withBasePath(`/category/${category.slug}`)}
                    className="category-tile interactive-card rounded-[1.4rem] px-4 py-4 transition"
                  >
                    <div className="flex items-center justify-between gap-4">
                      <span className="font-display text-2xl tracking-[-0.04em] text-white">{category.name}</span>
                      <span className="text-xs uppercase tracking-[0.25em] text-[--muted]">
                        {category.publishedCount} позицій
                      </span>
                    </div>
                    <p className="mt-2 text-sm leading-6 text-[--muted]">{category.description}</p>
                  </a>
                ))}
              </div>
            </div>
          </div>
        </div>
      </section>

      <section className="mx-auto mt-4 w-full max-w-[1400px] px-4 pb-10 md:px-6">
        <div className="stagger-grid grid gap-4 border-y border-white/10 py-8 md:grid-cols-4">
          {[
            settings.deliveryNote,
            settings.paymentNote,
            settings.materialsNote,
            settings.contactNote,
          ].map((item) => (
            <div key={item} className="interactive-card rounded-[1.5rem] border border-white/8 bg-white/[0.02] p-4 text-sm leading-7 text-[--muted]">
              {item}
            </div>
          ))}
        </div>
      </section>

      <section className="mx-auto w-full max-w-[1400px] px-4 py-8 md:px-6">
        <div className="reveal-up delay-1 flex flex-col gap-4 md:flex-row md:items-end md:justify-between">
          <div>
            <p className="text-xs uppercase tracking-[0.32em] text-[--accent]">Featured</p>
            <h2 className="mt-3 font-display text-4xl tracking-[-0.05em] text-white">Готові позиції, які вже можна брати за основу.</h2>
          </div>
          <a className="ghost-pill" href={withBasePath("/catalog")}>
            Увесь каталог
          </a>
        </div>

        {featuredProducts.length > 0 ? (
          <div className="stagger-grid mt-8 grid gap-5 lg:grid-cols-2 xl:grid-cols-3">
            {featuredProducts.map((product) => (
              <ProductCard key={product.id} product={product} telegramUrl={settings.telegramUrl} />
            ))}
          </div>
        ) : (
          <div className="glass-panel reveal-up delay-2 mt-8 rounded-[2rem] p-8">
            <h3 className="font-display text-3xl tracking-[-0.05em] text-white">Каталог готовий до наповнення.</h3>
            <p className="mt-3 max-w-[48ch] text-sm leading-7 text-[--muted]">
              Додайте перші товари через адмінку, а поки що клієнтів можна вести напряму в Telegram для індивідуальних замовлень.
            </p>
          </div>
        )}
      </section>
    </main>
  );
}
