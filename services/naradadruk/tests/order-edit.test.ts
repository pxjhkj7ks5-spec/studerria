import test from "node:test";
import assert from "node:assert/strict";
import type { Prisma } from "@prisma/client";
import { editOrder, editedOrderTotals, parseOrderEditValue } from "../src/lib/order-edit";

test("order edits reject invalid quantities, prices, contact and delivery input", () => {
  for (const value of ["0", "21", "1.5", "-1", "1e1"]) assert.throws(() => parseOrderEditValue("quantity", value));
  assert.throws(() => parseOrderEditValue("unitPrice", "1000001"));
  assert.throws(() => parseOrderEditValue("phone", "hello"));
  assert.throws(() => parseOrderEditValue("firstName", "-"));
  assert.throws(() => parseOrderEditValue("deliveryMethod", "other"));
  assert.equal(parseOrderEditValue("quantity", "20"), 20);
  assert.equal(parseOrderEditValue("comment", "-"), "");
  assert.equal(parseOrderEditValue("paymentMethod", "Переказ"), "transfer");
  assert.equal(parseOrderEditValue("deliveryMethod", "Кур’єр"), "courier");
});

test("edited totals preserve sale and promo snapshots and cap discounts", () => {
  const items = [{ quantity: 3, regularUnitPrice: 100, unitPrice: 80 }, { quantity: 1, regularUnitPrice: 50, unitPrice: 50 }];
  assert.deepEqual(editedOrderTotals(items, "percentage", 10), { subtotal: 350, saleDiscountAmount: 60, discountAmount: 29, total: 261 });
  assert.equal(editedOrderTotals(items, "fixed", 400).total, 0);
  assert.equal(editedOrderTotals(items, null, null).total, 290);
});

const updatedAt = new Date("2026-10-01T10:00:00Z");
function mockTransaction(order: Record<string, unknown>, count = 1) {
  const writes: string[] = [];
  const transaction = {
    order: { findUnique: async () => order, updateMany: async () => { writes.push("order"); return { count }; } },
    orderItem: { update: async () => { writes.push("item"); } },
    orderEvent: { create: async () => { writes.push("event"); } },
  } as unknown as Prisma.TransactionClient;
  return { transaction, writes };
}

test("stale edits and concurrent saves never write items or history", async () => {
  const stale = mockTransaction({ id: 1, updatedAt: new Date(0), items: [] });
  await assert.rejects(editOrder(stale.transaction, { publicId: "order", updatedAt, field: "firstName", raw: "Іван" }), /змінилося/);
  assert.deepEqual(stale.writes, []);
  const raced = mockTransaction({ id: 1, updatedAt, items: [] }, 0);
  await assert.rejects(editOrder(raced.transaction, { publicId: "order", updatedAt, field: "firstName", raw: "Іван" }), /змінилося/);
  assert.deepEqual(raced.writes, ["order"]);
});

test("catalog price cannot be overridden; manual price updates order, item and audit", async () => {
  const item = { id: 2, productId: 3, productSlug: "catalog", quantity: 2, unitPrice: 100, regularUnitPrice: 100 };
  const catalog = mockTransaction({ id: 1, source: "website", updatedAt, items: [item] });
  await assert.rejects(editOrder(catalog.transaction, { publicId: "order", updatedAt, field: "unitPrice", raw: "50", itemId: 2 }), /каталогом/);
  assert.deepEqual(catalog.writes, []);
  const manual = mockTransaction({ id: 1, source: "manual", updatedAt, items: [{ ...item, productId: null, productSlug: "" }], promoTypeSnapshot: null, promoValueSnapshot: null });
  await editOrder(manual.transaction, { publicId: "order", updatedAt, field: "unitPrice", raw: "50", itemId: 2 });
  assert.deepEqual(manual.writes, ["order", "item", "event"]);
});

test("catalog quantity uses current price and updates all totals with existing promo", async () => {
  let orderData: Record<string, unknown> = {};
  let itemData: Record<string, unknown> = {};
  const transaction = {
    order: {
      findUnique: async () => ({ id: 1, updatedAt, source: "website", promoTypeSnapshot: "percentage", promoValueSnapshot: 10, items: [{ id: 2, productId: 3, productSlug: "catalog", variantId: null, quantity: 1, unitPrice: 100, regularUnitPrice: 100 }] }),
      updateMany: async ({ data }: { data: Record<string, unknown> }) => { orderData = data; return { count: 1 }; },
    },
    product: { findUnique: async () => ({ status: "published", category: { isVisible: true }, variants: [], basePrice: 200, priceFrom: false, saleEnabled: true, salePrice: 150, salePercent: null, saleStartsAt: null, saleEndsAt: null }) },
    orderItem: { update: async ({ data }: { data: Record<string, unknown> }) => { itemData = data; } },
    orderEvent: { create: async () => {} },
  } as unknown as Prisma.TransactionClient;
  await editOrder(transaction, { publicId: "order", updatedAt, field: "quantity", raw: "2", itemId: 2 });
  assert.equal(itemData.unitPrice, 150);
  assert.equal(itemData.totalPrice, 300);
  assert.equal(orderData.subtotal, 400);
  assert.equal(orderData.saleDiscountAmount, 100);
  assert.equal(orderData.discountAmount, 30);
  assert.equal(orderData.total, 270);
});
