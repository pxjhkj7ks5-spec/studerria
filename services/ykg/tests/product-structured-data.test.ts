import assert from "node:assert/strict";
import test from "node:test";
import { buildProductOffers } from "../src/lib/product-structured-data";

const productUrl = "https://studerria.com/ykg/product/test";
const sellerId = "https://studerria.com/ykg#organization";

test("buildProductOffers exposes the end date of an active sale", () => {
  const offers = buildProductOffers(
    [{ name: "Варіант", price: 450 }],
    {
      productUrl,
      sellerId,
      isOnSale: true,
      saleEndsAt: new Date("2026-08-31T21:00:00.000Z"),
    },
  );

  assert.deepEqual(offers, [{
    "@type": "Offer",
    url: productUrl,
    name: "Варіант",
    priceCurrency: "UAH",
    price: "450",
    seller: { "@id": sellerId },
    priceValidUntil: "2026-08-31",
  }]);
});

test("buildProductOffers does not claim an expiry date without an active dated sale", () => {
  const inputs = [{ name: "Виріб", price: 700 }];

  for (const options of [
    { isOnSale: false, saleEndsAt: new Date("2026-08-31T21:00:00.000Z") },
    { isOnSale: true, saleEndsAt: null },
  ]) {
    const [offer] = buildProductOffers(inputs, { productUrl, sellerId, ...options });
    assert.equal("priceValidUntil" in offer, false);
  }
});
