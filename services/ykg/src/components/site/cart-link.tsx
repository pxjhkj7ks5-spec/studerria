"use client";

import { ShoppingBag } from "@phosphor-icons/react";
import { useCart } from "@/components/site/cart-provider";
import { withBasePath } from "@/lib/base-path";

export function CartLink() {
  const { itemCount, hydrated } = useCart();

  return (
    <a className="cart-link" href={withBasePath("/cart")} aria-label={`Кошик, товарів: ${itemCount}`}>
      <ShoppingBag aria-hidden size={20} />
      <span>Кошик</span>
      {hydrated && itemCount > 0 ? <strong>{itemCount}</strong> : null}
    </a>
  );
}
