import assert from "node:assert/strict";
import test from "node:test";
import { assessProductReadiness } from "../src/lib/product-readiness";

const completeProduct = {
  title: "Підставка для навушників",
  shortDescription: "Компактна підставка для робочого столу.",
  fullDescription: "Міцна підставка для навушників, надрукована з практичного PETG для щоденного використання.",
  basePrice: 250,
  leadTime: "1–2 дні",
  materialNote: "PETG",
  deliveryNote: "Нова пошта по Україні",
  paymentNote: "Переказ після підтвердження",
  variants: [],
  images: [{ alt: "Чорна підставка для навушників", isCover: true }],
};

test("marks a complete product as ready", () => {
  const result = assessProductReadiness(completeProduct);
  assert.equal(result.ready, true);
  assert.equal(result.score, 100);
});

test("rejects price-only descriptions and missing media metadata", () => {
  const result = assessProductReadiness({
    ...completeProduct,
    shortDescription: "250 грн",
    images: [{ alt: "", isCover: false }],
  });
  assert.equal(result.ready, false);
  assert.equal(result.checks.find((check) => check.key === "short")?.passed, false);
  assert.equal(result.checks.find((check) => check.key === "cover")?.passed, false);
  assert.equal(result.checks.find((check) => check.key === "alt")?.passed, false);
});
