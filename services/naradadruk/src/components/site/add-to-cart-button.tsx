"use client";

import { useState } from "react";
import { Check, ShoppingBag } from "@phosphor-icons/react";
import { useCart } from "@/components/site/cart-provider";
import { trackPlausible } from "@/lib/analytics";
import type { CartProductInput } from "@/lib/cart";

export function AddToCartButton({
  item,
  className = "accent-pill",
  compactLabel = false,
}: {
  item: CartProductInput;
  className?: string;
  compactLabel?: boolean;
}) {
  const { addItem } = useCart();
  const [added, setAdded] = useState(false);

  function handleClick() {
    addItem(item);
    trackPlausible("Add to Cart", {
      location: compactLabel ? "product-card" : "product-page",
      intent: "product",
      product_slug: item.productSlug,
      value: item.unitPrice,
      items: 1,
    });
    setAdded(true);
    window.setTimeout(() => setAdded(false), 1600);
  }

  return (
    <button className={className} type="button" onClick={handleClick}>
      {added ? <Check aria-hidden size={18} weight="bold" /> : <ShoppingBag aria-hidden size={18} />}
      <span>{added ? "У кошику" : compactLabel ? "Додати" : "Додати в кошик"}</span>
    </button>
  );
}
