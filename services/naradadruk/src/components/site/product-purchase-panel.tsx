"use client";

import { useState } from "react";
import { ArrowRight, CheckCircle } from "@phosphor-icons/react";
import { AddToCartButton } from "@/components/site/add-to-cart-button";
import { TrackedLink } from "@/components/site/tracked-link";
import { buildTelegramLink } from "@/lib/telegram";
import { formatPrice } from "@/lib/utils";

type ProductVariant = {
  id: number;
  label: string;
  price: number;
  regularPrice: number;
  description: string;
};

type ProductPurchasePanelProps = {
  category: string;
  productId: number;
  productSlug: string;
  productTitle: string;
  coverImageUrl: string;
  basePrice: number | null;
  regularBasePrice: number | null;
  priceLabel: string;
  regularPriceLabel: string;
  isOnSale: boolean;
  saleEndsAt: string | null;
  shortDescription: string;
  telegramUrl: string;
  variants: ProductVariant[];
};

export function ProductPurchasePanel({
  category,
  productId,
  productSlug,
  productTitle,
  coverImageUrl,
  basePrice,
  regularBasePrice,
  priceLabel,
  regularPriceLabel,
  isOnSale,
  saleEndsAt,
  shortDescription,
  telegramUrl,
  variants,
}: ProductPurchasePanelProps) {
  const [selectedVariantId, setSelectedVariantId] = useState<number | null>(
    variants[0]?.id ?? null,
  );
  const selectedVariant =
    variants.find((variant) => variant.id === selectedVariantId) ?? null;
  const currentPrice = selectedVariant ? formatPrice(selectedVariant.price) : priceLabel;
  const oldPrice = selectedVariant && selectedVariant.price < selectedVariant.regularPrice
    ? formatPrice(selectedVariant.regularPrice)
    : regularPriceLabel;
  const customUrl = buildTelegramLink({
    baseUrl: telegramUrl,
    intent: "custom",
    productTitle,
  });
  const unitPrice = selectedVariant?.price ?? basePrice;
  const cartItem = typeof unitPrice === "number" ? {
    productId,
    productSlug,
    productTitle,
    variantId: selectedVariant?.id ?? null,
    variantLabel: selectedVariant?.label ?? "",
    unitPrice,
    regularUnitPrice: selectedVariant?.regularPrice ?? regularBasePrice ?? unitPrice,
    imageUrl: coverImageUrl,
  } : null;

  return (
    <>
      <div className="purchase-panel">
        {isOnSale ? <span className="sale-badge">Знижка</span> : null}
        <div className="purchase-panel__meta">
          <span>{category}</span>
          <span>
            <CheckCircle aria-hidden size={17} weight="fill" />
            Готово до замовлення
          </span>
        </div>

        <h1>{productTitle}</h1>
        <p className="purchase-panel__description">{shortDescription}</p>

        {variants.length > 0 ? (
          <div className="variant-picker">
            <p>Оберіть варіант</p>
            <div className="variant-picker__options">
              {variants.map((variant) => (
                <button
                  key={variant.id}
                  type="button"
                  className={variant.id === selectedVariantId ? "is-active" : ""}
                  onClick={() => setSelectedVariantId(variant.id)}
                >
                  <span>{variant.label}</span>
                  <strong>{variant.price < variant.regularPrice ? <><del className="old-price">{formatPrice(variant.regularPrice)}</del> {formatPrice(variant.price)}</> : formatPrice(variant.price)}</strong>
                  {variant.description ? <small>{variant.description}</small> : null}
                </button>
              ))}
            </div>
          </div>
        ) : null}

        <div className="purchase-panel__action">
          <div>
            <span>Орієнтовна ціна</span>
            <span className="sale-price-line">{oldPrice ? <del className="old-price">{oldPrice}</del> : null}<strong>{currentPrice}</strong></span>
            {isOnSale ? <small>{saleEndsAt ? `Акція до ${new Intl.DateTimeFormat("uk-UA", { dateStyle: "medium", timeStyle: "short", timeZone: "Europe/Kyiv" }).format(new Date(saleEndsAt))}` : "Акційна ціна діє зараз"}</small> : null}
          </div>
          {cartItem ? <AddToCartButton className="accent-pill accent-pill--large" item={cartItem} /> : null}
        </div>
        <p className="purchase-panel__custom">
          Потрібні інші розміри, колір або власна модель? Індивідуальні замовлення погоджуємо окремо.
          <TrackedLink
            href={customUrl}
            target="_blank"
            rel="noreferrer"
            eventName="Custom Lead"
            eventProps={{ location: "product-purchase-panel", intent: "custom", product_slug: productSlug, category }}
          >
            Написати в Telegram <ArrowRight aria-hidden size={16} />
          </TrackedLink>
        </p>
      </div>

      <div className="mobile-purchase-bar">
        <div>
          <span>{productTitle}</span>
          <span className="sale-price-line">{oldPrice ? <del className="old-price">{oldPrice}</del> : null}<strong>{currentPrice}</strong></span>
        </div>
        {cartItem ? <AddToCartButton className="accent-pill" compactLabel item={cartItem} /> : null}
      </div>
    </>
  );
}
