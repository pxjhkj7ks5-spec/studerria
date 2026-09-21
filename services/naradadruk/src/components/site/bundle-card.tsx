"use client";

import Image from "next/image";
import { Check, Package } from "@phosphor-icons/react";
import { useState } from "react";
import { useCart } from "@/components/site/cart-provider";
import { trackPlausible } from "@/lib/analytics";
import { withBasePath } from "@/lib/base-path";
import { formatPrice } from "@/lib/utils";

type BundleProduct = {
  id: number;
  slug: string;
  title: string;
  basePrice: number | null;
  regularBasePrice: number | null;
  coverImage: { urlPath: string; alt: string } | null;
  variants: Array<{ id: number; label: string; price: number; regularPrice: number }>;
};

export function BundleCard({ bundle }: { bundle: {
  id: number;
  slug: string;
  title: string;
  shortDescription: string;
  items: Array<{ id: number; quantity: number; variantId: number | null; product: BundleProduct }>;
} }) {
  const { addItems } = useCart();
  const [added, setAdded] = useState(false);
  const additions = bundle.items.map((entry) => {
    const variant = entry.product.variants.find((item) => item.id === entry.variantId) ?? null;
    const unitPrice = variant?.price ?? entry.product.basePrice ?? 0;
    return {
      quantity: entry.quantity,
      item: {
        productId: entry.product.id,
        productSlug: entry.product.slug,
        productTitle: entry.product.title,
        variantId: variant?.id ?? null,
        variantLabel: variant?.label ?? "",
        unitPrice,
        regularUnitPrice: variant?.regularPrice ?? entry.product.regularBasePrice ?? unitPrice,
        imageUrl: entry.product.coverImage?.urlPath ?? "",
      },
    };
  });
  const total = additions.reduce((sum, entry) => sum + entry.item.unitPrice * entry.quantity, 0);

  function addBundle() {
    addItems(additions);
    trackPlausible("Add Bundle to Cart", { location: "catalog-bundle", intent: "bundle", value: total, items: additions.reduce((sum, item) => sum + item.quantity, 0) });
    setAdded(true);
    window.setTimeout(() => setAdded(false), 1800);
  }

  return (
    <article className="bundle-card">
      <div className="bundle-card__media" aria-hidden>
        {bundle.items.slice(0, 3).map((entry) => entry.product.coverImage ? (
          <Image key={entry.id} src={withBasePath(entry.product.coverImage.urlPath)} alt="" width={520} height={520} unoptimized />
        ) : <span key={entry.id}><Package size={28} /></span>)}
      </div>
      <div className="bundle-card__body">
        <div><p className="eyebrow">Готовий набір</p><h3>{bundle.title}</h3></div>
        <p>{bundle.shortDescription}</p>
        <ul>{bundle.items.map((entry) => {
          const variant = entry.product.variants.find((item) => item.id === entry.variantId);
          return <li key={entry.id}><span>{entry.product.title}{variant ? ` · ${variant.label}` : ""}</span><strong>×{entry.quantity}</strong></li>;
        })}</ul>
        <div className="bundle-card__action"><strong>{formatPrice(total)}</strong><button className="accent-pill" type="button" onClick={addBundle}>{added ? <Check aria-hidden size={18} /> : <Package aria-hidden size={18} />} {added ? "Комплект у кошику" : "Додати комплект"}</button></div>
      </div>
    </article>
  );
}
