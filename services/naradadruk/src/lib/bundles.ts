export type BundleItemCandidate = {
  productId: number;
  variantId: number | null;
  quantity: number;
  product: {
    status: "draft" | "published";
    basePrice: number | null;
    variants: Array<{ id: number; price: number }>;
  };
};

export function bundleReadiness(items: BundleItemCandidate[]) {
  if (items.length < 2) return { ready: false, reason: "Додайте щонайменше два товари." };
  for (const item of items) {
    if (item.product.status !== "published") return { ready: false, reason: "Усі товари мають бути опубліковані." };
    if (!Number.isInteger(item.quantity) || item.quantity < 1 || item.quantity > 20) return { ready: false, reason: "Кількість має бути від 1 до 20." };
    if (item.product.variants.length > 0) {
      if (item.variantId === null || !item.product.variants.some((variant) => variant.id === item.variantId)) {
        return { ready: false, reason: "Оберіть чинний варіант для кожного товару з варіантами." };
      }
    } else if (item.variantId !== null || item.product.basePrice === null) {
      return { ready: false, reason: "Кожна позиція повинна мати актуальну ціну." };
    }
  }
  return { ready: true, reason: "Комплект готовий до публікації." };
}
