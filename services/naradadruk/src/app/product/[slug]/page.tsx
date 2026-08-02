import {
  ArrowLeft,
  Clock,
  CreditCard,
  Cube,
  Truck,
} from "@phosphor-icons/react/ssr";
import type { Metadata } from "next";
import { notFound } from "next/navigation";
import { ProductCard } from "@/components/site/product-card";
import { ProductGallery } from "@/components/site/product-gallery";
import { ProductPurchasePanel } from "@/components/site/product-purchase-panel";
import { PublicFrame } from "@/components/site/public-frame";
import { StructuredData } from "@/components/site/structured-data";
import {
  getProductBySlug,
  getRelatedProducts,
  getSiteSettings,
} from "@/lib/data";
import { withBasePath } from "@/lib/base-path";
import { publicPaymentNote, siteName } from "@/lib/constants";
import { absoluteSiteUrl } from "@/lib/site-url";

export const dynamic = "force-dynamic";

type ProductPageProps = {
  params: Promise<{
    slug: string;
  }>;
};

function metaDescription(value: string) {
  const cleaned = value.replace(/\s+/g, " ").trim();
  return cleaned.length > 165 ? `${cleaned.slice(0, 162).trimEnd()}…` : cleaned;
}

function contentList(value: string) {
  return value
    .split("\n")
    .map((line) => line.replace(/^\s*[-–—•]\s*/u, "").trim())
    .filter(Boolean);
}

export async function generateMetadata({ params }: ProductPageProps): Promise<Metadata> {
  const { slug } = await params;
  const product = await getProductBySlug(slug);
  if (!product) return { title: "Товар не знайдено", robots: { index: false, follow: false } };
  const canonical = absoluteSiteUrl(`/product/${product.slug}`);
  const description = metaDescription(product.shortDescription || product.fullDescription || `${product.title} від Narada Druk.`);
  const title = product.title;
  const images = product.images.map((image) => ({ url: absoluteSiteUrl(image.urlPath), alt: image.alt || product.title }));
  return {
    title,
    description,
    alternates: { canonical },
    openGraph: { type: "website", locale: "uk_UA", url: canonical, siteName, title: `${title} | ${siteName}`, description, images },
    twitter: { card: images.length ? "summary_large_image" : "summary", title: `${title} | ${siteName}`, description, images: images.map((image) => image.url) },
  };
}

export default async function ProductPage({ params }: ProductPageProps) {
  const { slug } = await params;
  const product = await getProductBySlug(slug);

  if (!product) {
    notFound();
  }

  const [settings, relatedProducts] = await Promise.all([
    getSiteSettings(),
    getRelatedProducts(product.categoryId, product.id),
  ]);
  const detailItems = [
    {
      icon: Cube,
      title: "Матеріали",
      body: product.materialNote || settings.materialsNote,
    },
    {
      icon: Clock,
      title: "Термін",
      body: product.leadTime || settings.leadTimeNote,
    },
    {
      icon: Truck,
      title: "Доставка",
      body: product.deliveryNote || settings.deliveryNote,
    },
    {
      icon: CreditCard,
      title: "Оплата",
      body: publicPaymentNote,
    },
  ];
  const meaningSections = [
    { title: "Для кого", body: product.useCaseNote, list: false },
    { title: "Переваги", body: product.benefitsNote, list: true },
    { title: "Характеристики", body: product.specificationsNote, list: true },
    { title: "Сумісність", body: product.compatibilityNote, list: false },
    { title: "Комплектація", body: product.packageContentsNote, list: false },
  ].filter((section) => section.body.trim());
  const productUrl = absoluteSiteUrl(`/product/${product.slug}`);
  const offers = (product.variants.length > 0
    ? product.variants.map((variant) => ({ name: variant.label, price: variant.price }))
    : typeof product.basePrice === "number" ? [{ name: product.title, price: product.basePrice }] : [])
    .map((offer) => ({
      "@type": "Offer",
      url: productUrl,
      name: offer.name,
      priceCurrency: "UAH",
      price: String(offer.price),
      seller: { "@id": `${absoluteSiteUrl()}#organization` },
    }));
  const structuredProduct: Record<string, unknown> = {
    "@context": "https://schema.org",
    "@type": "Product",
    "@id": `${productUrl}#product`,
    name: product.title,
    ...(product.fullDescription || product.shortDescription ? { description: product.fullDescription || product.shortDescription } : {}),
    category: product.category.name,
    sku: product.slug,
    url: productUrl,
    ...(product.images.length ? { image: product.images.map((image) => absoluteSiteUrl(image.urlPath)) } : {}),
    ...(offers.length ? { offers } : {}),
  };

  return (
    <PublicFrame telegramUrl={settings.telegramUrl}>
      <StructuredData data={[
        {
          "@context": "https://schema.org",
          "@type": "BreadcrumbList",
          itemListElement: [
            { "@type": "ListItem", position: 1, name: siteName, item: absoluteSiteUrl() },
            { "@type": "ListItem", position: 2, name: "Каталог", item: absoluteSiteUrl("/catalog") },
            { "@type": "ListItem", position: 3, name: product.category.name, item: absoluteSiteUrl(`/category/${product.category.slug}`) },
            { "@type": "ListItem", position: 4, name: product.title, item: productUrl },
          ],
        },
        structuredProduct,
      ]} />
      <main className="product-page">
        <section className="site-container">
          <a
            className="back-link"
            href={withBasePath(`/category/${product.category.slug}`)}
          >
            <ArrowLeft aria-hidden size={18} />
            {product.category.name}
          </a>

          <div className="product-layout">
            <ProductGallery images={product.images} title={product.title} />

            <aside className="product-layout__aside">
              <ProductPurchasePanel
                category={product.category.name}
                productId={product.id}
                productSlug={product.slug}
                productTitle={product.title}
                coverImageUrl={product.coverImage?.urlPath ?? ""}
                basePrice={product.basePrice}
                regularBasePrice={product.regularBasePrice}
                priceLabel={product.priceLabel}
                regularPriceLabel={product.regularPriceLabel}
                isOnSale={product.isOnSale}
                saleEndsAt={product.saleEndsAt?.toISOString() ?? null}
                shortDescription={product.shortDescription}
                telegramUrl={settings.telegramUrl}
                variants={product.variants}
              />
            </aside>
          </div>
        </section>

        <section className="site-container product-details">
          <div className="product-details__facts">
            {detailItems.map((item) => {
              const Icon = item.icon;
              return (
                <article key={item.title}>
                  <Icon aria-hidden size={23} />
                  <div>
                    <h2>{item.title}</h2>
                    <p>{item.body}</p>
                  </div>
                </article>
              );
            })}
          </div>

          <article className="product-description">
            <p className="eyebrow">Про виріб</p>
            <h2>Опис і застосування</h2>
            <p className="product-description__body">{product.fullDescription}</p>
          </article>

          {meaningSections.length > 0 ? (
            <section className="product-meaning" aria-labelledby="product-meaning-title">
              <div className="product-meaning__heading">
                <p className="eyebrow">Коротко по суті</p>
                <h2 id="product-meaning-title">Що варто знати про виріб</h2>
              </div>
              <div className="product-meaning__grid">
                {meaningSections.map((section) => (
                  <article className="product-meaning__card" key={section.title}>
                    <h3>{section.title}</h3>
                    {section.list ? (
                      <ul>
                        {contentList(section.body).map((item) => <li key={item}>{item}</li>)}
                      </ul>
                    ) : (
                      <p>{section.body}</p>
                    )}
                  </article>
                ))}
              </div>
            </section>
          ) : null}
        </section>

        {relatedProducts.length > 0 ? (
          <section className="site-container related-products">
            <div className="section-heading">
              <p className="eyebrow">Ще в категорії</p>
              <h2>Схожі вироби</h2>
            </div>
            <div className="product-grid">
              {relatedProducts.map((relatedProduct) => (
                <ProductCard
                  key={relatedProduct.id}
                  product={relatedProduct}
                />
              ))}
            </div>
          </section>
        ) : null}
      </main>
    </PublicFrame>
  );
}
