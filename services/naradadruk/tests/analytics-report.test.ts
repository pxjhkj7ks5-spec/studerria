import assert from "node:assert/strict";
import test from "node:test";
import {
  buildAnalyticsReport,
  parseAnalyticsRange,
  type AnalyticsEventRecord,
} from "../src/lib/analytics-report";

function event(
  id: number,
  name: string,
  createdAt: string,
  input: Partial<AnalyticsEventRecord> = {},
): AnalyticsEventRecord {
  return {
    id,
    name,
    path: "/naradadruk",
    campaign: "",
    location: "",
    intent: "",
    productSlug: "",
    category: "",
    sessionId: "",
    value: 0,
    itemCount: 0,
    createdAt: new Date(createdAt),
    ...input,
  };
}

test("parseAnalyticsRange accepts supported periods and defaults to 30", () => {
  assert.equal(parseAnalyticsRange("7"), 7);
  assert.equal(parseAnalyticsRange("90"), 90);
  assert.equal(parseAnalyticsRange("14"), 30);
  assert.equal(parseAnalyticsRange(undefined), 30);
});

test("buildAnalyticsReport separates periods and aggregates useful admin metrics", () => {
  const now = new Date("2026-07-30T20:00:00.000Z");
  const report = buildAnalyticsReport(
    [
      event(1, "Page View", "2026-07-30T10:00:00.000Z", {
        sessionId: "session-a",
      }),
      event(2, "Product Open", "2026-07-30T10:01:00.000Z", {
        sessionId: "session-a",
        productSlug: "stand",
      }),
      event(3, "Page View", "2026-07-29T12:00:00.000Z", {
        sessionId: "session-b",
        path: "/naradadruk/product/stand",
      }),
      event(4, "Telegram Lead", "2026-07-29T12:02:00.000Z", {
        sessionId: "session-b",
        productSlug: "stand",
      }),
      event(5, "Page View", "2026-07-23T09:00:00.000Z", {
        sessionId: "previous-session",
      }),
      event(6, "Product Open", "2026-07-23T09:01:00.000Z", {
        sessionId: "previous-session",
        productSlug: "older-product",
      }),
      event(7, "Unknown", "2026-07-30T11:00:00.000Z"),
      event(8, "Add to Cart", "2026-07-30T10:02:00.000Z", {
        sessionId: "session-a",
        productSlug: "stand",
        value: 850,
        itemCount: 1,
      }),
      event(9, "Checkout Open", "2026-07-30T10:03:00.000Z", {
        sessionId: "session-a",
        value: 850,
        itemCount: 1,
      }),
      event(10, "Order Placed", "2026-07-30T10:04:00.000Z", {
        sessionId: "session-a",
        value: 850,
        itemCount: 1,
      }),
    ],
    7,
    now,
  );

  assert.deepEqual(report.current, {
    views: 2,
    clicks: 5,
    leads: 1,
    addToCarts: 1,
    checkouts: 1,
    orders: 1,
    revenue: 850,
    sessions: 2,
  });
  assert.deepEqual(report.previous, {
    views: 1,
    clicks: 1,
    leads: 0,
    addToCarts: 0,
    checkouts: 0,
    orders: 0,
    revenue: 0,
    sessions: 1,
  });
  assert.deepEqual(report.deltas, {
    views: 100,
    clicks: 400,
    leads: null,
    addToCarts: null,
    checkouts: null,
    orders: null,
    revenue: null,
    sessions: 100,
  });
  assert.equal(report.conversionRate, 50);
  assert.deepEqual(report.topProducts, [
    {
      slug: "stand",
      opens: 1,
      carts: 1,
      leads: 1,
      total: 3,
    },
  ]);
  assert.equal(report.topPages[0]?.key, "/naradadruk");
  assert.equal(report.daily.length, 7);
  assert.deepEqual(report.commerce, {
    productOpens: 1,
    addToCarts: 1,
    checkouts: 1,
    orders: 1,
    revenue: 850,
    viewToProductRate: 50,
    productToCartRate: 100,
    cartToCheckoutRate: 100,
    checkoutToOrderRate: 100,
    viewToOrderRate: 50,
  });
  assert.deepEqual(report.funnelInsight, {
    stage: "product",
    title: "Відвідувачі рідко відкривають товари",
    message: "Перевірте перші фото, назви та помітність карток у каталозі.",
    rate: 50,
  });
  assert.equal(report.recentEvents[0]?.id, 10);
});

test("buildAnalyticsReport identifies the weakest measured funnel stage", () => {
  const report = buildAnalyticsReport(
    [
      event(1, "Page View", "2026-07-30T10:00:00.000Z", { sessionId: "session-a" }),
      event(2, "Product Open", "2026-07-30T10:01:00.000Z", {
        sessionId: "session-a",
        productSlug: "stand",
      }),
    ],
    7,
    new Date("2026-07-30T20:00:00.000Z"),
  );

  assert.deepEqual(report.funnelInsight, {
    stage: "cart",
    title: "Найбільше губляться між товаром і кошиком",
    message: "Перевірте фото, опис, ціну та помітність кнопки «У кошик».",
    rate: 0,
  });
});

test("buildAnalyticsReport ranks only labelled campaigns", () => {
  const now = new Date("2026-08-07T09:00:00.000Z");
  const report = buildAnalyticsReport(
    [
      event(1, "Page View", "2026-08-07T06:00:00.000Z", { campaign: "instagram-organic" }),
      event(2, "Product Open", "2026-08-07T06:01:00.000Z", { campaign: "instagram-organic" }),
      event(3, "Page View", "2026-08-07T06:02:00.000Z", { campaign: "telegram-post" }),
      event(4, "Page View", "2026-08-07T06:03:00.000Z"),
    ],
    7,
    now,
  );

  assert.deepEqual(report.topCampaigns, [
    { key: "instagram-organic", count: 2 },
    { key: "telegram-post", count: 1 },
  ]);
});
