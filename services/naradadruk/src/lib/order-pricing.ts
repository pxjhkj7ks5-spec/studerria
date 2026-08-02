import { ProductStatus, type PrismaClient } from "@prisma/client";
import { absoluteSiteUrl } from "@/lib/site-url";
import { effectiveUnitPrice, calculatePromoDiscount } from "@/lib/pricing";

type DbClient = Pick<PrismaClient, "product" | "promoCode">;
type RequestedItem = { productId: number; variantId: number | null; quantity: number };

export class OrderPricingError extends Error {}

export function normalizePromoCode(value: string) {
  return value.trim().normalize("NFKC").toLocaleUpperCase("uk-UA").replace(/\s+/g, "");
}

export async function priceRequestedItems(db: DbClient, input: RequestedItem[]) {
  const aggregated = new Map<string, RequestedItem>();
  for (const item of input) {
    const key = `${item.productId}:${item.variantId ?? "base"}`;
    const quantity = (aggregated.get(key)?.quantity ?? 0) + item.quantity;
    if (quantity > 20) throw new OrderPricingError("Максимальна кількість однієї позиції — 20.");
    aggregated.set(key, { ...item, quantity });
  }
  const requested = [...aggregated.values()];
  const products = await db.product.findMany({
    where: { id: { in: [...new Set(requested.map((item) => item.productId))] }, status: ProductStatus.published, category: { isVisible: true } },
    include: { variants: true },
  });
  const productMap = new Map(products.map((product) => [product.id, product]));
  const items = requested.map((item) => {
    const product = productMap.get(item.productId);
    if (!product) throw new OrderPricingError("Один із товарів уже недоступний. Оновіть кошик.");
    const variant = item.variantId ? product.variants.find((entry) => entry.id === item.variantId) : null;
    if (item.variantId && !variant) throw new OrderPricingError(`Варіант «${product.title}» уже недоступний.`);
    if (product.variants.length > 0 && !variant) throw new OrderPricingError(`Оберіть варіант товару «${product.title}».`);
    const regularUnitPrice = variant?.price ?? product.basePrice;
    if (typeof regularUnitPrice !== "number" || regularUnitPrice < 0) throw new OrderPricingError(`Для товару «${product.title}» потрібно уточнити ціну в Telegram.`);
    const unitPrice = effectiveUnitPrice(product, regularUnitPrice, !variant);
    return {
      productId: product.id,
      productSlug: product.slug,
      productTitle: product.title,
      productUrl: absoluteSiteUrl(`/product/${encodeURIComponent(product.slug)}`),
      variantId: variant?.id ?? null,
      variantLabel: variant?.label ?? "",
      quantity: item.quantity,
      unitPrice,
      regularUnitPrice,
      saleDiscountAmount: (regularUnitPrice - unitPrice) * item.quantity,
      totalPrice: unitPrice * item.quantity,
    };
  });
  const subtotal = items.reduce((sum, item) => sum + item.regularUnitPrice * item.quantity, 0);
  const saleDiscountAmount = items.reduce((sum, item) => sum + item.saleDiscountAmount, 0);
  return { items, subtotal, saleDiscountAmount, promoBase: subtotal - saleDiscountAmount };
}

export async function validatePromoCode(db: DbClient, rawCode: string, promoBase: number, now = new Date()) {
  const code = normalizePromoCode(rawCode);
  if (!code) return null;
  if (!/^[A-ZА-ЯІЇЄҐ0-9_-]{3,32}$/u.test(code)) {
    throw new OrderPricingError("Промокод має містити 3–32 українські або латинські літери, цифри, _ чи -.");
  }
  const promo = await db.promoCode.findUnique({ where: { code } });
  if (!promo || !promo.enabled) throw new OrderPricingError("Промокод недійсний або вимкнений.");
  if (promo.expiresAt && promo.expiresAt <= now) throw new OrderPricingError("Термін дії промокоду завершився.");
  if (promo.usageLimit !== null && promo.useCount >= promo.usageLimit) throw new OrderPricingError("Ліміт використань промокоду вичерпано.");
  const discountAmount = calculatePromoDiscount(promoBase, promo.type, promo.value);
  return { promo, discountAmount, total: Math.max(0, promoBase - discountAmount) };
}
