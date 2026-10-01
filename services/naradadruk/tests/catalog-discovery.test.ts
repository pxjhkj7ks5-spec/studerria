import assert from "node:assert/strict";
import test from "node:test";
import { compactLeadTime, minimumProductPrice, parsePriceBound, sortCatalogProducts, withinPriceRange } from "../src/lib/catalog";
import { suggestedCategory } from "../src/lib/catalog-taxonomy";
import { effectiveUnitPrice } from "../src/lib/pricing";

test("price filtering and ordering use the cheapest purchasable variant, including discounts", () => {
  const sale = { priceFrom: false, variants: [], saleEnabled: true, salePercent: 20, salePrice: null, saleStartsAt: null, saleEndsAt: null, basePrice: 500 };
  const product = { createdAt: new Date(), sortOrder: 0, isFeatured: false, basePrice: 400, variants: [{ price: effectiveUnitPrice(sale, 100, false) }, { price: 240 }] };
  assert.equal(minimumProductPrice(product), 80);
  assert.equal(withinPriceRange(product, 80, 80), true);
  assert.equal(withinPriceRange(product, 81, 400), false);
  const fixed = { ...product, basePrice: 120, variants: [] };
  assert.equal(sortCatalogProducts([fixed, product], "price-asc")[0], product);
  assert.equal(sortCatalogProducts([product, fixed], "price-desc")[0], fixed);
  assert.equal(withinPriceRange({ basePrice: null, variants: [] }, 0), false);
  assert.equal(withinPriceRange(product, 200, 100), false);
});

test("invalid URL prices do not turn into bogus filter values", () => {
  for (const value of [undefined, "", "-1", "Infinity", "2.3", "10000001", "abc"]) assert.equal(parsePriceBound(value), undefined);
  assert.equal(parsePriceBound("0"), 0);
});

test("category upgrade preserves unknown categories and classifies known accessories", () => {
  assert.equal(suggestedCategory("Стенд для HyperX QuadCast", "inshe"), "setup");
  assert.equal(suggestedCategory("Глушник Honeycomb Gen2", "inshe"), "strajkbol");
  assert.equal(suggestedCategory("Тримач навушників", "custom-category"), "custom-category");
  assert.equal(compactLeadTime("Від кількох годин до 3 днів залежно від складності."), "До 3 днів");
});
