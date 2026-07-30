import Image from "next/image";
import { withBasePath } from "@/lib/base-path";
import { siteBaseUrl } from "@/lib/constants";
import { buildTelegramLink } from "@/lib/telegram";
import { TrackedLink } from "@/components/site/tracked-link";

type ProductCardProps = {
  product: {
    slug: string;
    title: string;
    shortDescription: string;
    leadTime: string;
    priceLabel: string;
    category: { name: string };
    coverImage: { urlPath: string; alt: string } | null;
  };
  telegramUrl: string;
  priority?: boolean;
};

export function ProductCard({
  product,
  telegramUrl,
  priority = false,
}: ProductCardProps) {
  const productPath = withBasePath(`/product/${product.slug}`);
  const productUrl = new URL(productPath, siteBaseUrl).toString();
  const orderUrl = buildTelegramLink({
    baseUrl: telegramUrl,
    intent: "product",
    productTitle: product.title,
    productUrl,
  });

  return (
    <article className="product-card group">
      <TrackedLink
        className="product-card__media"
        href={productPath}
        eventName="Product Open"
        eventProps={{
          location: "product-card-image",
          product_slug: product.slug,
          category: product.category.name,
        }}
      >
        {product.coverImage ? (
          <Image
            src={withBasePath(product.coverImage.urlPath)}
            alt={product.coverImage.alt || product.title}
            width={1200}
            height={900}
            unoptimized
            priority={priority}
            className="product-card__image"
          />
        ) : (
          <div className="product-placeholder">
            <span>{product.category.name}</span>
          </div>
        )}
      </TrackedLink>

      <div className="product-card__body">
        <div className="product-card__meta">
          <span>{product.category.name}</span>
          {product.leadTime ? <span>{product.leadTime}</span> : null}
        </div>

        <div>
          <TrackedLink
            href={productPath}
            className="product-card__title"
            eventName="Product Open"
            eventProps={{
              location: "product-card-title",
              product_slug: product.slug,
              category: product.category.name,
            }}
          >
            {product.title}
          </TrackedLink>
          <p className="product-card__description">{product.shortDescription}</p>
        </div>

        <div className="product-card__footer">
          <p className="product-card__price">{product.priceLabel}</p>
          <TrackedLink
            className="accent-pill"
            href={orderUrl}
            target="_blank"
            rel="noreferrer"
            eventName="Telegram Lead"
            eventProps={{
              location: "product-card",
              intent: "product",
              product_slug: product.slug,
              category: product.category.name,
            }}
          >
            Замовити
          </TrackedLink>
        </div>
      </div>
    </article>
  );
}
