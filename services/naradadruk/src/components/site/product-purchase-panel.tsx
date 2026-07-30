"use client";

import { useState } from "react";
import { ArrowRight, CheckCircle } from "@phosphor-icons/react";
import { TrackedLink } from "@/components/site/tracked-link";
import { buildTelegramLink } from "@/lib/telegram";
import { formatPrice } from "@/lib/utils";

type ProductVariant = {
  id: number;
  label: string;
  price: number;
  description: string;
};

type ProductPurchasePanelProps = {
  category: string;
  productSlug: string;
  productTitle: string;
  productUrl: string;
  priceLabel: string;
  shortDescription: string;
  telegramUrl: string;
  variants: ProductVariant[];
};

export function ProductPurchasePanel({
  category,
  productSlug,
  productTitle,
  productUrl,
  priceLabel,
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
  const orderUrl = buildTelegramLink({
    baseUrl: telegramUrl,
    intent: "product",
    productTitle,
    productUrl,
    variantLabel: selectedVariant?.label,
  });

  return (
    <>
      <div className="purchase-panel">
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
                  <strong>{formatPrice(variant.price)}</strong>
                  {variant.description ? <small>{variant.description}</small> : null}
                </button>
              ))}
            </div>
          </div>
        ) : null}

        <div className="purchase-panel__action">
          <div>
            <span>Орієнтовна ціна</span>
            <strong>{currentPrice}</strong>
          </div>
          <TrackedLink
            className="accent-pill accent-pill--large"
            href={orderUrl}
            target="_blank"
            rel="noreferrer"
            eventName="Telegram Lead"
            eventProps={{
              location: "product-purchase-panel",
              intent: "product",
              product_slug: productSlug,
              category,
            }}
          >
            Замовити
            <ArrowRight aria-hidden size={18} />
          </TrackedLink>
        </div>
      </div>

      <div className="mobile-purchase-bar">
        <div>
          <span>{productTitle}</span>
          <strong>{currentPrice}</strong>
        </div>
        <TrackedLink
          className="accent-pill"
          href={orderUrl}
          target="_blank"
          rel="noreferrer"
          eventName="Telegram Lead"
          eventProps={{
            location: "mobile-purchase-bar",
            intent: "product",
            product_slug: productSlug,
            category,
          }}
        >
          Замовити
        </TrackedLink>
      </div>
    </>
  );
}
