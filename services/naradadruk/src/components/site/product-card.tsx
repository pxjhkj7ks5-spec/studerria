import Image from "next/image";
import { withBasePath } from "@/lib/base-path";
import { TrackedLink } from "@/components/site/tracked-link";
import { AddToCartButton } from "@/components/site/add-to-cart-button";

type ProductCardProps = {
  product: {
    id: number;
    slug: string;
    title: string;
    shortDescription: string;
    leadTime: string;
    priceLabel: string;
    regularPriceLabel: string;
    isOnSale: boolean;
    saleEndsAt: Date | null;
    basePrice: number | null;
    regularBasePrice: number | null;
    variants: Array<{ id: number; label: string; price: number; regularPrice: number }>;
    category: { name: string };
    coverImage: { urlPath: string; alt: string } | null;
  };
  priority?: boolean;
};

export function ProductCard({
  product,
  priority = false,
}: ProductCardProps) {
  const productPath = withBasePath(`/product/${product.slug}`);
  const defaultVariant = product.variants[0] ?? null;
  const unitPrice = defaultVariant?.price ?? product.basePrice;

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
        {product.isOnSale ? <span className="sale-badge">Знижка</span> : null}
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
          <div className="product-card__price-wrap">
            {product.regularPriceLabel ? <del className="old-price">{product.regularPriceLabel}</del> : null}
            <p className="product-card__price">{product.priceLabel}</p>
            {product.isOnSale ? <small>{product.saleEndsAt ? `Акція до ${new Intl.DateTimeFormat("uk-UA", { dateStyle: "medium", timeStyle: "short", timeZone: "Europe/Kyiv" }).format(product.saleEndsAt)}` : "Акційна ціна діє зараз"}</small> : null}
          </div>
          {product.variants.length > 0 ? (
            <TrackedLink
              className="accent-pill"
              href={productPath}
              eventName="Product Open"
              eventProps={{
                location: "product-card-variant-picker",
                product_slug: product.slug,
                category: product.category.name,
              }}
            >
              Обрати варіант
            </TrackedLink>
          ) : typeof unitPrice === "number" ? (
            <AddToCartButton
              compactLabel
              item={{
                productId: product.id,
                productSlug: product.slug,
                productTitle: product.title,
                variantId: defaultVariant?.id ?? null,
                variantLabel: defaultVariant?.label ?? "",
                unitPrice,
                regularUnitPrice: defaultVariant?.regularPrice ?? product.regularBasePrice ?? unitPrice,
                imageUrl: product.coverImage?.urlPath ?? "",
              }}
            />
          ) : null}
        </div>
      </div>
    </article>
  );
}
