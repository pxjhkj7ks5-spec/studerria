import { ArrowRight } from "@phosphor-icons/react/ssr";
import type { Metadata } from "next";
import { CatalogFilters } from "@/components/site/catalog-filters";
import { BundleCard } from "@/components/site/bundle-card";
import { ProductCard } from "@/components/site/product-card";
import { PublicFrame } from "@/components/site/public-frame";
import { TrackedLink } from "@/components/site/tracked-link";
import { StructuredData } from "@/components/site/structured-data";
import {
  getCatalogProducts,
  getVisibleBundles,
  getSiteSettings,
  getVisibleCategories,
} from "@/lib/data";
import { withBasePath } from "@/lib/base-path";
import { buildTelegramLink } from "@/lib/telegram";
import { siteName } from "@/lib/constants";
import { absoluteSiteUrl } from "@/lib/site-url";
import { collectCatalogTags, hasCatalogTag, sortCatalogProducts, type CatalogSort } from "@/lib/catalog";

export const dynamic = "force-dynamic";

type CatalogPageProps = {
  searchParams: Promise<{
    q?: string;
    category?: string;
    sort?: string;
    purpose?: string;
    compatibility?: string;
  }>;
};

export async function generateMetadata({ searchParams }: CatalogPageProps): Promise<Metadata> {
  const params = await searchParams;
  const filtered = Boolean(params.q?.trim() || params.category?.trim() || params.purpose?.trim() || params.compatibility?.trim() || (params.sort && params.sort !== "recommended"));
  const description = "Каталог готових виробів Narada Druk: декор, практичні аксесуари та товари для страйкболу з доставкою по Україні.";
  return {
    title: "Каталог 3D-друку",
    description,
    alternates: { canonical: absoluteSiteUrl("/catalog") },
    robots: filtered ? { index: false, follow: true } : undefined,
    openGraph: { type: "website", locale: "uk_UA", url: absoluteSiteUrl("/catalog"), siteName, title: `Каталог 3D-друку | ${siteName}`, description, images: [{ url: absoluteSiteUrl("/naradadruk-hero.webp"), alt: "Каталог 3D-друку Narada Druk" }] },
    twitter: { card: "summary_large_image", title: `Каталог 3D-друку | ${siteName}`, description, images: [absoluteSiteUrl("/naradadruk-hero.webp")] },
  };
}

export default async function CatalogPage({ searchParams }: CatalogPageProps) {
  const params = await searchParams;
  const query = params.q?.trim() ?? "";
  const categorySlug = params.category?.trim() ?? "";
  const requestedSort = params.sort?.trim() ?? "recommended";
  const sort: CatalogSort = ["recommended", "newest", "price-asc", "price-desc"].includes(requestedSort) ? requestedSort as CatalogSort : "recommended";
  const purpose = params.purpose?.trim() ?? "";
  const compatibility = params.compatibility?.trim() ?? "";

  const [settings, categories, catalogProducts, bundles] = await Promise.all([
    getSiteSettings(),
    getVisibleCategories(),
    getCatalogProducts({
      search: query || undefined,
      categorySlug: categorySlug || undefined,
    }),
    getVisibleBundles(),
  ]);
  const facets = collectCatalogTags(catalogProducts);
  const products = sortCatalogProducts(catalogProducts.filter((product) =>
    hasCatalogTag(product.purposeTags, purpose) && hasCatalogTag(product.compatibilityTags, compatibility)
  ), sort);
  const customUrl = buildTelegramLink({
    baseUrl: settings.telegramUrl,
    intent: "custom",
  });
  const productList = !query && !categorySlug && !purpose && !compatibility && products.length > 0
    ? {
        "@context": "https://schema.org",
        "@type": "ItemList",
        name: "Каталог Narada Druk",
        itemListElement: products.map((product, index) => ({
          "@type": "ListItem",
          position: index + 1,
          url: absoluteSiteUrl(`/product/${product.slug}`),
          name: product.title,
        })),
      }
    : null;

  return (
    <PublicFrame telegramUrl={settings.telegramUrl}>
      <StructuredData data={[
        {
          "@context": "https://schema.org",
          "@type": "BreadcrumbList",
          itemListElement: [
            { "@type": "ListItem", position: 1, name: siteName, item: absoluteSiteUrl() },
            { "@type": "ListItem", position: 2, name: "Каталог", item: absoluteSiteUrl("/catalog") },
          ],
        },
        ...(productList ? [productList] : []),
      ]} />
      <main className="catalog-page">
        <section className="site-container catalog-hero">
          <div>
            <p className="eyebrow">Готові вироби</p>
            <h1>Каталог практичних рішень.</h1>
            <p>
              Оберіть готову позицію або використайте її як основу для свого
              розміру, кольору чи задачі.
            </p>
          </div>
          <TrackedLink
            className="ghost-pill ghost-pill--large"
            href={customUrl}
            target="_blank"
            rel="noreferrer"
            eventName="Custom Lead"
            eventProps={{ location: "catalog-hero", intent: "custom" }}
          >
            Потрібен свій виріб
            <ArrowRight aria-hidden size={18} />
          </TrackedLink>
        </section>

        <section className="site-container catalog-toolbar">
          <div className="category-chips" aria-label="Категорії каталогу">
            <TrackedLink
              className={!categorySlug ? "category-chip is-active" : "category-chip"}
              href={withBasePath("/catalog")}
              eventName="Catalog Filter"
              eventProps={{ location: "catalog-chip", category: "all" }}
            >
              Усе
              <span>{categories.reduce((total, item) => total + item.publishedCount, 0)}</span>
            </TrackedLink>
            {categories.map((category) => (
              <TrackedLink
                key={category.id}
                className={
                  category.slug === categorySlug
                    ? "category-chip is-active"
                    : "category-chip"
                }
                href={withBasePath(`/category/${category.slug}`)}
                eventName="Catalog Filter"
                eventProps={{
                  location: "catalog-chip",
                  category: category.slug,
                }}
              >
                {category.name}
                <span>{category.publishedCount}</span>
              </TrackedLink>
            ))}
          </div>

          <CatalogFilters
            action={withBasePath("/catalog")}
            categories={categories}
            categorySlug={categorySlug}
            query={query}
            sort={sort}
            purpose={purpose}
            compatibility={compatibility}
            purposes={facets.purposes}
            compatibilities={facets.compatibilities}
          />
        </section>

        {!query && !categorySlug && !purpose && !compatibility && bundles.length > 0 ? (
          <section className="site-container bundle-section">
            <div className="section-heading section-heading--split"><div><p className="eyebrow">Разом зручніше</p><h2>Готові комплекти</h2></div><p>Кілька сумісних виробів для однієї задачі — додаються в кошик одним натисканням.</p></div>
            <div className="bundle-grid">{bundles.map((bundle) => <BundleCard key={bundle.id} bundle={bundle} />)}</div>
          </section>
        ) : null}

        <section className="site-container catalog-results">
          <div className="catalog-results__heading">
            <h2>{query || categorySlug || purpose || compatibility ? "Результати" : "Усі товари"}</h2>
            <p>{products.length} позицій</p>
          </div>

          {products.length > 0 ? (
            <div className="product-grid">
              {products.map((product, index) => (
                <ProductCard
                  key={product.id}
                  product={product}
                  priority={index === 0}
                />
              ))}
            </div>
          ) : (
            <div className="empty-catalog empty-catalog--light">
              <div>
                <p className="eyebrow">Нічого не знайшли</p>
                <h3>Надрукуємо під ваш запит.</h3>
                <p>
                  Змініть фільтри або надішліть у Telegram опис потрібної
                  деталі, фото чи посилання на приклад.
                </p>
              </div>
              <div className="empty-catalog__actions">
                <a className="ghost-pill" href={withBasePath("/catalog")}>
                  Скинути фільтри
                </a>
                <TrackedLink
                  className="accent-pill"
                  href={customUrl}
                  target="_blank"
                  rel="noreferrer"
                  eventName="Custom Lead"
                  eventProps={{ location: "catalog-empty", intent: "custom" }}
                >
                  Обговорити в Telegram
                </TrackedLink>
              </div>
            </div>
          )}
        </section>
      </main>
    </PublicFrame>
  );
}
