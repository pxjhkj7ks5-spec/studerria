export type CatalogSort = "recommended" | "newest" | "price-asc" | "price-desc";

export function parseCatalogTags(value: string) {
  const seen = new Set<string>();
  return value
    .split("\n")
    .map((item) => item.trim())
    .filter((item) => {
      const key = item.toLocaleLowerCase("uk-UA");
      if (!item || seen.has(key)) return false;
      seen.add(key);
      return true;
    });
}

export function hasCatalogTag(value: string, selected?: string) {
  if (!selected) return true;
  const needle = selected.trim().toLocaleLowerCase("uk-UA");
  return parseCatalogTags(value).some((item) => item.toLocaleLowerCase("uk-UA") === needle);
}

export function minimumProductPrice(product: {
  basePrice: number | null;
  variants: Array<{ price: number }>;
}) {
  const prices = product.basePrice === null
    ? product.variants.map((variant) => variant.price)
    : [product.basePrice];
  return prices.length ? Math.min(...prices) : Number.POSITIVE_INFINITY;
}

export function sortCatalogProducts<T extends {
  createdAt: Date;
  sortOrder: number;
  isFeatured: boolean;
  basePrice: number | null;
  variants: Array<{ price: number }>;
}>(products: T[], sort: CatalogSort) {
  return [...products].sort((left, right) => {
    if (sort === "newest") return right.createdAt.getTime() - left.createdAt.getTime();
    if (sort === "price-asc" || sort === "price-desc") {
      const leftPrice = minimumProductPrice(left);
      const rightPrice = minimumProductPrice(right);
      if (!Number.isFinite(leftPrice) || !Number.isFinite(rightPrice)) {
        if (!Number.isFinite(leftPrice) && !Number.isFinite(rightPrice)) return 0;
        return Number.isFinite(leftPrice) ? -1 : 1;
      }
      const delta = leftPrice - rightPrice;
      return sort === "price-asc" ? delta : -delta;
    }
    return Number(right.isFeatured) - Number(left.isFeatured)
      || left.sortOrder - right.sortOrder
      || right.createdAt.getTime() - left.createdAt.getTime();
  });
}

export function collectCatalogTags(products: Array<{ purposeTags: string; compatibilityTags: string }>) {
  const collect = (field: "purposeTags" | "compatibilityTags") => {
    const values = new Map<string, string>();
    for (const product of products) {
      for (const item of parseCatalogTags(product[field])) {
        const key = item.toLocaleLowerCase("uk-UA");
        if (!values.has(key)) values.set(key, item);
      }
    }
    return [...values.values()].sort((left, right) => left.localeCompare(right, "uk-UA"));
  };
  return { purposes: collect("purposeTags"), compatibilities: collect("compatibilityTags") };
}
