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
    basePrice: number | null;
    variants: Array<{ id: number; label: string; price: number }>;
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
          {typeof unitPrice === "number" ? (
            <AddToCartButton
              compactLabel
              item={{
                productId: product.id,
                productSlug: product.slug,
                productTitle: product.title,
                variantId: defaultVariant?.id ?? null,
                variantLabel: defaultVariant?.label ?? "",
                unitPrice,
                imageUrl: product.coverImage?.urlPath ?? "",
              }}
            />
          ) : null}
        </div>
      </div>
    </article>
  );
}
