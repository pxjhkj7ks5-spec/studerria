import { ProductCard } from "@/components/site/product-card";
import { getCatalogProducts, getSiteSettings, getVisibleCategories } from "@/lib/data";
import { withBasePath } from "@/lib/base-path";

export const dynamic = "force-dynamic";

type CatalogPageProps = {
  searchParams: Promise<{
    q?: string;
    category?: string;
  }>;
};

export default async function CatalogPage({ searchParams }: CatalogPageProps) {
  const params = await searchParams;
  const query = params.q?.trim() ?? "";
  const categorySlug = params.category?.trim() ?? "";

  const [settings, categories, products] = await Promise.all([
    getSiteSettings(),
    getVisibleCategories(),
    getCatalogProducts({
      search: query || undefined,
      categorySlug: categorySlug || undefined,
    }),
  ]);

  return (
    <main className="mx-auto w-full max-w-[1400px] px-4 py-8 md:px-6 md:py-10">
      <div className="reveal-up delay-1 flex flex-wrap items-center justify-between gap-4">
        <div>
          <p className="text-xs uppercase tracking-[0.3em] text-[--accent]">Каталог</p>
          <h1 className="mt-3 font-display text-5xl tracking-[-0.06em] text-white">Готові рішення та практичні деталі.</h1>
          <p className="mt-4 max-w-[60ch] text-base leading-8 text-[--muted]">
            Переглядайте категорії, відбирайте потрібні позиції та переходьте в Telegram для замовлення або уточнення.
          </p>
        </div>

        <a className="accent-pill" href={settings.telegramUrl} target="_blank" rel="noreferrer">
          Замовити через Telegram
        </a>
      </div>

      <div className="mt-8 grid gap-6 lg:grid-cols-[0.34fr_0.66fr]">
        <aside className="glass-panel reveal-up delay-2 h-fit rounded-[2rem] p-5">
          <form action={withBasePath("/catalog")} className="grid gap-4">
            <div className="field-shell">
              <span>Пошук по каталогу</span>
              <input name="q" defaultValue={query} placeholder="Наприклад, кріплення або органайзер" />
            </div>

            <div className="field-shell">
              <span>Категорія</span>
              <select name="category" defaultValue={categorySlug}>
                <option value="">Усі категорії</option>
                {categories.map((category) => (
                  <option key={category.id} value={category.slug}>
                    {category.name}
                  </option>
                ))}
              </select>
            </div>

            <div className="flex flex-wrap gap-3">
              <button className="accent-pill" type="submit">
                Фільтрувати
              </button>
              <a className="ghost-pill" href={withBasePath("/catalog")}>
                Скинути
              </a>
            </div>
          </form>

          <div className="stagger-list mt-6 grid gap-3 border-t border-white/10 pt-6">
            {categories.map((category) => (
              <a
                key={category.id}
                href={withBasePath(`/category/${category.slug}`)}
                className="interactive-card rounded-[1.25rem] border border-white/10 px-4 py-3 transition hover:border-white/20 hover:bg-white/[0.04]"
              >
                <div className="flex items-center justify-between gap-4">
                  <span className="font-medium text-white">{category.name}</span>
                  <span className="text-xs uppercase tracking-[0.2em] text-[--muted]">{category.publishedCount}</span>
                </div>
                <p className="mt-2 text-sm leading-6 text-[--muted]">{category.description}</p>
              </a>
            ))}
          </div>
        </aside>

        <section className="self-start">
          {products.length > 0 ? (
            <div className="stagger-grid grid gap-5 xl:grid-cols-2">
              {products.map((product) => (
                <ProductCard key={product.id} product={product} telegramUrl={settings.telegramUrl} />
              ))}
            </div>
          ) : (
            <div className="glass-panel reveal-up delay-3 rounded-[2rem] p-8">
              <h2 className="font-display text-3xl tracking-[-0.05em] text-white">За цим запитом поки немає товарів.</h2>
              <p className="mt-3 max-w-[44ch] text-sm leading-7 text-[--muted]">
                Спробуйте змінити фільтр або напишіть у Telegram, якщо потрібна індивідуальна деталь чи кастомний виріб.
              </p>
            </div>
          )}
        </section>
      </div>
    </main>
  );
}
