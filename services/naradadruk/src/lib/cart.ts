export type CartItem = {
  key: string;
  productId: number;
  productSlug: string;
  productTitle: string;
  variantId: number | null;
  variantLabel: string;
  unitPrice: number;
  regularUnitPrice: number;
  quantity: number;
  imageUrl: string;
};

export type CartProductInput = Omit<CartItem, "key" | "quantity">;

export function getCartItemKey(productId: number, variantId: number | null) {
  return `${productId}:${variantId ?? "base"}`;
}

export function clampCartQuantity(quantity: number) {
  return Math.max(1, Math.min(20, Math.round(quantity)));
}

export function mergeCartItems(current: CartItem[], additions: Array<{ item: CartProductInput; quantity: number }>) {
  const merged = [...current];
  for (const addition of additions) {
    const key = getCartItemKey(addition.item.productId, addition.item.variantId);
    const index = merged.findIndex((item) => item.key === key);
    if (index >= 0) {
      merged[index] = { ...merged[index], quantity: clampCartQuantity(merged[index].quantity + addition.quantity) };
    } else {
      merged.push({ ...addition.item, key, quantity: clampCartQuantity(addition.quantity) });
    }
  }
  return merged;
}
