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
    location: "",
    intent: "",
    productSlug: "",
    category: "",
    sessionId: "",
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
    ],
    7,
    now,
  );

  assert.deepEqual(report.current, {
    views: 2,
    clicks: 2,
    leads: 1,
    sessions: 2,
  });
  assert.deepEqual(report.previous, {
    views: 1,
    clicks: 1,
    leads: 0,
    sessions: 1,
  });
  assert.deepEqual(report.deltas, {
    views: 100,
    clicks: 100,
    leads: null,
    sessions: 100,
  });
  assert.equal(report.conversionRate, 50);
  assert.deepEqual(report.topProducts, [
    {
      slug: "stand",
      opens: 1,
      leads: 1,
      total: 2,
    },
  ]);
  assert.equal(report.topPages[0]?.key, "/naradadruk");
  assert.equal(report.daily.length, 7);
  assert.equal(report.recentEvents[0]?.id, 2);
});
