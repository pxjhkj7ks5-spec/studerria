import assert from "node:assert/strict";
import test from "node:test";
import { bundleReadiness } from "../src/lib/bundles";
import { hasCatalogTag, minimumProductPrice, parseCatalogTags, sortCatalogProducts } from "../src/lib/catalog";
import { mergeCartItems, type CartItem } from "../src/lib/cart";
import { resolveReviewProductIds } from "../src/lib/review-products";

test("catalog tags are normalized and matched exactly", () => {
  assert.deepEqual(parseCatalogTags("M-LOK\n Робочий стіл \nm-lok\n"), ["M-LOK", "Робочий стіл"]);
  assert.equal(hasCatalogTag("M-LOK\nPicatinny", "m-lok"), true);
  assert.equal(hasCatalogTag("M-LOK\nPicatinny", "M4"), false);
});

test("catalog sorting uses current presented minimum prices", () => {
  const old = new Date("2025-01-01T00:00:00Z");
  const fresh = new Date("2026-01-01T00:00:00Z");
  const products = [
    { id: 1, createdAt: old, sortOrder: 10, isFeatured: true, basePrice: 300, variants: [] },
    { id: 2, createdAt: fresh, sortOrder: 0, isFeatured: false, basePrice: null, variants: [{ price: 120 }, { price: 180 }] },
  ];
  assert.equal(minimumProductPrice(products[1]), 120);
  assert.deepEqual(sortCatalogProducts(products, "recommended").map((item) => item.id), [1, 2]);
  assert.deepEqual(sortCatalogProducts(products, "newest").map((item) => item.id), [2, 1]);
  assert.deepEqual(sortCatalogProducts(products, "price-asc").map((item) => item.id), [2, 1]);
  const withoutPrice = { id: 3, createdAt: fresh, sortOrder: 0, isFeatured: false, basePrice: null, variants: [] };
  assert.deepEqual(sortCatalogProducts([...products, withoutPrice], "price-desc").map((item) => item.id), [1, 2, 3]);
});

test("bundle readiness requires two purchasable published positions and valid variants", () => {
  const base = { productId: 1, variantId: null, quantity: 1, product: { status: "published" as const, basePrice: 200, variants: [] } };
  assert.equal(bundleReadiness([base]).ready, false);
  assert.equal(bundleReadiness([base, { ...base, productId: 2 }]).ready, true);
  assert.equal(bundleReadiness([base, { ...base, productId: 2, product: { status: "published" as const, basePrice: null, variants: [{ id: 5, price: 250 }] } }]).ready, false);
});

test("adding a bundle merges existing cart lines and clamps quantity", () => {
  const existing: CartItem[] = [{ key: "1:base", productId: 1, productSlug: "one", productTitle: "One", variantId: null, variantLabel: "", unitPrice: 100, regularUnitPrice: 100, quantity: 19, imageUrl: "" }];
  const merged = mergeCartItems(existing, [
    { quantity: 3, item: { productId: 1, productSlug: "one", productTitle: "One", variantId: null, variantLabel: "", unitPrice: 100, regularUnitPrice: 100, imageUrl: "" } },
    { quantity: 2, item: { productId: 2, productSlug: "two", productTitle: "Two", variantId: 7, variantLabel: "Large", unitPrice: 200, regularUnitPrice: 200, imageUrl: "" } },
  ]);
  assert.equal(merged[0].quantity, 20);
  assert.equal(merged[1].quantity, 2);
});

test("review products prefer unique products from an order", () => {
  assert.deepEqual(resolveReviewProductIds([{ productId: 3 }, { productId: 3 }, { productId: 7 }, { productId: null }], 9), [3, 7]);
  assert.deepEqual(resolveReviewProductIds(null, 9), [9]);
  assert.deepEqual(resolveReviewProductIds(null, null), []);
});
