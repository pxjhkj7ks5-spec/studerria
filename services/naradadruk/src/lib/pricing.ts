import { formatPrice } from "@/lib/utils";

export type SaleProduct = {
  basePrice: number | null;
  priceFrom: boolean;
  saleEnabled: boolean;
  salePrice: number | null;
  salePercent: number | null;
  saleStartsAt: Date | null;
  saleEndsAt: Date | null;
  variants: Array<{ price: number }>;
};

export function isSaleActive(product: SaleProduct, now = new Date()) {
  return product.saleEnabled
    && (!product.saleStartsAt || product.saleStartsAt <= now)
    && (!product.saleEndsAt || product.saleEndsAt > now)
    && ((product.salePercent !== null && product.salePercent > 0 && product.salePercent < 100)
      || (product.basePrice !== null && product.salePrice !== null && product.salePrice < product.basePrice));
}

export function effectiveUnitPrice(product: SaleProduct, regularPrice: number, isBasePrice: boolean, now = new Date()) {
  if (!isSaleActive(product, now)) return regularPrice;
  if (product.salePercent !== null && product.salePercent > 0 && product.salePercent < 100) {
    return Math.max(0, Math.round(regularPrice * (100 - product.salePercent) / 100));
  }
  if (product.salePrice !== null && product.basePrice !== null && product.salePrice < product.basePrice) {
    return isBasePrice
      ? product.salePrice
      : Math.max(0, Math.round(regularPrice * product.salePrice / product.basePrice));
  }
  return regularPrice;
}

export function productPricePresentation(product: SaleProduct, now = new Date()) {
  const regularPrices = product.basePrice !== null ? [product.basePrice] : product.variants.map((variant) => variant.price);
  if (regularPrices.length === 0) return { priceLabel: "Ціна за запитом", regularPriceLabel: "", isOnSale: false, saleEndsAt: null };
  const effectivePrices = product.basePrice !== null
    ? [effectiveUnitPrice(product, product.basePrice, true, now)]
    : product.variants.map((variant) => effectiveUnitPrice(product, variant.price, false, now));
  const regularMinimum = Math.min(...regularPrices);
  const effectiveMinimum = Math.min(...effectivePrices);
  const prefix = product.priceFrom || regularPrices.length > 1 ? "від " : "";
  return {
    priceLabel: `${prefix}${formatPrice(effectiveMinimum)}`,
    regularPriceLabel: effectiveMinimum < regularMinimum ? `${prefix}${formatPrice(regularMinimum)}` : "",
    isOnSale: effectiveMinimum < regularMinimum,
    saleEndsAt: effectiveMinimum < regularMinimum ? product.saleEndsAt : null,
  };
}

export function calculatePromoDiscount(subtotal: number, type: "percentage" | "fixed", value: number) {
  const raw = type === "percentage" ? Math.round(subtotal * value / 100) : value;
  return Math.max(0, Math.min(subtotal, raw));
}
