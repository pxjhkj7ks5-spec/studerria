import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { publicProductSelect } from "../src/lib/data";

const sourceModelUrl =
  "https://makerworld.com/ru/models/759436-red-dot-riser-air-soft?from=search#profileId-693952";

test("catalog keeps the private source for the Riser product", async () => {
  const catalog = JSON.parse(
    await readFile(new URL("../catalog/products.json", import.meta.url), "utf8"),
  ) as {
    products: Array<{ slug: string; sourceModelUrl?: string }>;
  };
  const riser = catalog.products.find(
    (product) => product.slug === "raizer-pid-kolimator",
  );

  assert.ok(riser);
  assert.equal(riser.sourceModelUrl, sourceModelUrl);
});

test("public product queries never select the private model source", () => {
  assert.equal("sourceModelUrl" in publicProductSelect, false);
});
