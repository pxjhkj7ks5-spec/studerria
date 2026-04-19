import { notFound } from "next/navigation";
import { ProductCard } from "@/components/site/product-card";
import { getCatalogProducts, getCategoryBySlug, getSiteSettings, getVisibleCategories } from "@/lib/data";
import { withBasePath } from "@/lib/base-path";

export const dynamic = "force-dynamic";

type CategoryPageProps = {
  params: Promise<{
    slug: string;
  }>;
};

export default async function CategoryPage({ params }: CategoryPageProps) {
  const { slug } = await params;
  const [category, settings, categories, products] = await Promise.all([
    getCategoryBySlug(slug),
    getSiteSettings(),
    getVisibleCategories(),
    getCatalogProducts({ categorySlug: slug }),
  ]);

  if (!category) {
    notFound();
  }

  return (
    <main className="mx-auto w-full max-w-[1400px] px-4 py-8 md:px-6 md:py-10">
      <a className="reveal-up delay-1 text-sm text-[--muted] transition hover:text-white" href={withBasePath("/catalog")}>
        Повернутися до каталогу
      </a>

      <div className="mt-4 grid gap-6 lg:grid-cols-[0.34fr_0.66fr]">
        <aside className="glass-panel reveal-up delay-2 h-fit rounded-[2rem] p-5">
          <p className="text-xs uppercase tracking-[0.32em] text-[--accent]">Категорія</p>
          <h1 className="mt-3 font-display text-5xl tracking-[-0.06em] text-white">{category.name}</h1>
          <p className="mt-4 text-sm leading-7 text-[--muted]">{category.description}</p>

          <div className="mt-6 flex flex-wrap gap-3">
            <a className="accent-pill" href={settings.telegramUrl} target="_blank" rel="noreferrer">
              Замовити
            </a>
            <a className="ghost-pill" href={withBasePath("/catalog")}>
              Увесь каталог
            </a>
          </div>

          <div className="stagger-list mt-8 grid gap-3 border-t border-white/10 pt-6">
            {categories.map((item) => (
              <a
                key={item.id}
                href={withBasePath(`/category/${item.slug}`)}
                className={`interactive-card rounded-[1.25rem] border px-4 py-3 transition ${
                  item.slug === category.slug
                    ? "border-[rgba(255,156,74,0.45)] bg-[rgba(255,156,74,0.08)]"
                    : "border-white/10 bg-white/[0.03] hover:border-white/20"
                }`}
              >
                <div className="flex items-center justify-between gap-4">
                  <span className="font-medium text-white">{item.name}</span>
                  <span className="text-xs uppercase tracking-[0.2em] text-[--muted]">{item.publishedCount}</span>
                </div>
              </a>
            ))}
          </div>
        </aside>

        <section className="self-start">
          <div className="stagger-grid grid gap-5 xl:grid-cols-2">
            {products.map((product) => (
              <ProductCard key={product.id} product={product} telegramUrl={settings.telegramUrl} />
            ))}
          </div>
        </section>
      </div>
    </main>
  );
}
