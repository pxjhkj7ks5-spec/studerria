import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

type CatalogProduct = {
  slug: string;
  shortDescription: string;
  fullDescription: string;
};

test("legacy catalog products use complete customer-facing descriptions", async () => {
  const catalog = JSON.parse(
    await readFile(new URL("../catalog/products.json", import.meta.url), "utf8"),
  ) as { products: CatalogProduct[] };

  assert.ok(catalog.products.length > 0);

  for (const product of catalog.products) {
    assert.ok(
      product.shortDescription.length >= 40 && product.shortDescription.length <= 220,
      `${product.slug}: short description must be informative and card-sized`,
    );
    assert.ok(
      product.fullDescription.length >= 180,
      `${product.slug}: full description must explain the product and its use`,
    );
    assert.notEqual(
      product.fullDescription,
      product.shortDescription,
      `${product.slug}: full description must add useful detail`,
    );
    assert.doesNotMatch(
      `${product.shortDescription} ${product.fullDescription}`,
      /\b\d[\d\s]*\s*грн\b/iu,
      `${product.slug}: prices belong in structured price fields`,
    );
  }
});
