import { ArrowLeft, ArrowRight } from "@phosphor-icons/react/ssr";
import type { Metadata } from "next";
import { notFound } from "next/navigation";
import { ProductCard } from "@/components/site/product-card";
import { PublicFrame } from "@/components/site/public-frame";
import { TrackedLink } from "@/components/site/tracked-link";
import { StructuredData } from "@/components/site/structured-data";
import {
  getCatalogProducts,
  getCategoryBySlug,
  getSiteSettings,
  getVisibleCategories,
} from "@/lib/data";
import { withBasePath } from "@/lib/base-path";
import { buildTelegramLink } from "@/lib/telegram";
import { siteName } from "@/lib/constants";
import { absoluteSiteUrl } from "@/lib/site-url";

export const dynamic = "force-dynamic";

type CategoryPageProps = {
  params: Promise<{
    slug: string;
  }>;
};

export async function generateMetadata({ params }: CategoryPageProps): Promise<Metadata> {
  const { slug } = await params;
  const category = await getCategoryBySlug(slug);
  if (!category) return { title: "Категорію не знайдено", robots: { index: false, follow: false } };
  const canonical = absoluteSiteUrl(`/category/${category.slug}`);
  const rawDescription = category.description.trim() || `Товари категорії «${category.name}» від Narada Druk з оформленням замовлення на сайті та доставкою по Україні.`;
  const description = rawDescription.length > 165 ? `${rawDescription.slice(0, 162).trimEnd()}…` : rawDescription;
  const title = `${category.name} — каталог`;
  const categoryImage = category.products[0]?.images[0];
  const images = categoryImage ? [{ url: absoluteSiteUrl(categoryImage.urlPath), alt: categoryImage.alt || category.name }] : [];
  return {
    title,
    description,
    alternates: { canonical },
    openGraph: { type: "website", locale: "uk_UA", url: canonical, siteName, title: `${title} | ${siteName}`, description, images },
    twitter: { card: images.length ? "summary_large_image" : "summary", title: `${title} | ${siteName}`, description, images: images.map((image) => image.url) },
  };
}

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
  const productList = products.length > 0
    ? {
        "@context": "https://schema.org",
        "@type": "ItemList",
        name: `${category.name} — Narada Druk`,
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
            { "@type": "ListItem", position: 3, name: category.name, item: absoluteSiteUrl(`/category/${category.slug}`) },
          ],
        },
        ...(productList ? [productList] : []),
      ]} />
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
