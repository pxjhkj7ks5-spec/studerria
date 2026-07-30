import { ArrowLeft, ArrowRight } from "@phosphor-icons/react/ssr";
import { notFound } from "next/navigation";
import { ProductCard } from "@/components/site/product-card";
import { PublicFrame } from "@/components/site/public-frame";
import { TrackedLink } from "@/components/site/tracked-link";
import {
  getCatalogProducts,
  getCategoryBySlug,
  getSiteSettings,
  getVisibleCategories,
} from "@/lib/data";
import { withBasePath } from "@/lib/base-path";
import { buildTelegramLink } from "@/lib/telegram";

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

  const customUrl = buildTelegramLink({
    baseUrl: settings.telegramUrl,
    intent: "custom",
  });

  return (
    <PublicFrame telegramUrl={settings.telegramUrl}>
      <main className="catalog-page">
        <section className="site-container category-hero">
          <a className="back-link" href={withBasePath("/catalog")}>
            <ArrowLeft aria-hidden size={18} />
            Увесь каталог
          </a>

          <div className="category-hero__body">
            <div>
              <p className="eyebrow">Категорія</p>
              <h1>{category.name}</h1>
              <p>{category.description}</p>
            </div>
            <TrackedLink
              className="accent-pill accent-pill--large"
              href={customUrl}
              target="_blank"
              rel="noreferrer"
              eventName="Custom Lead"
              eventProps={{ location: "category-hero", intent: "custom", category: category.slug }}
            >
              Потрібен свій варіант
              <ArrowRight aria-hidden size={18} />
            </TrackedLink>
          </div>
        </section>

        <section className="site-container catalog-toolbar catalog-toolbar--category">
          <div className="category-chips" aria-label="Інші категорії">
            {categories.map((item) => (
              <TrackedLink
                key={item.id}
                className={
                  item.slug === category.slug
                    ? "category-chip is-active"
                    : "category-chip"
                }
                href={withBasePath(`/category/${item.slug}`)}
                eventName="Catalog Filter"
                eventProps={{
                  location: "category-chip",
                  category: item.slug,
                }}
              >
                {item.name}
                <span>{item.publishedCount}</span>
              </TrackedLink>
            ))}
          </div>
        </section>

        <section className="site-container catalog-results">
          <div className="catalog-results__heading">
            <h2>Товари категорії</h2>
            <p>{products.length} позицій</p>
          </div>

          {products.length > 0 ? (
            <div className="product-grid">
              {products.map((product, index) => (
                <ProductCard
                  key={product.id}
                  product={product}
                  telegramUrl={settings.telegramUrl}
                  priority={index === 0}
                />
              ))}
            </div>
          ) : (
            <div className="empty-catalog empty-catalog--light">
              <div>
                <p className="eyebrow">Категорія наповнюється</p>
                <h3>Можемо зробити потрібне індивідуально.</h3>
                <p>
                  Надішліть опис або приклад — уточнимо матеріал, термін і
                  вартість до початку друку.
                </p>
              </div>
              <TrackedLink
                className="accent-pill"
                href={customUrl}
                target="_blank"
                rel="noreferrer"
                eventName="Custom Lead"
                eventProps={{ location: "category-empty", intent: "custom", category: category.slug }}
              >
                Написати в Telegram
              </TrackedLink>
            </div>
          )}
        </section>
      </main>
    </PublicFrame>
  );
}
