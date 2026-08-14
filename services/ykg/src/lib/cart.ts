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
