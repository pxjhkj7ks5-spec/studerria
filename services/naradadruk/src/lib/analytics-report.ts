import {
  analyticsEventNames,
  type AnalyticsEventName,
} from "@/lib/analytics";

const dayMs = 24 * 60 * 60 * 1000;
const analyticsEventNameSet = new Set<string>(analyticsEventNames);
const kyivDayFormatter = new Intl.DateTimeFormat("en-CA", {
  timeZone: "Europe/Kyiv",
  year: "numeric",
  month: "2-digit",
  day: "2-digit",
});
const shortDayFormatter = new Intl.DateTimeFormat("uk-UA", {
  timeZone: "Europe/Kyiv",
  day: "2-digit",
  month: "short",
});

export const analyticsRanges = [7, 30, 90] as const;
export type AnalyticsRange = (typeof analyticsRanges)[number];

export type AnalyticsEventRecord = {
  id: number;
  name: string;
  path: string;
  location: string;
  intent: string;
  productSlug: string;
  category: string;
  sessionId: string;
  createdAt: Date;
};

type MetricKey = "views" | "clicks" | "leads" | "sessions";

function dayKey(date: Date) {
  return kyivDayFormatter.format(date);
}

function buildDayKeys(now: Date, count: number, offset = 0) {
  const keys: string[] = [];
  let cursor = offset;

  while (keys.length < count) {
    const key = dayKey(new Date(now.getTime() - cursor * dayMs));

    if (!keys.includes(key)) {
      keys.unshift(key);
    }

    cursor += 1;
  }

  return keys;
}

function metricSummary(events: AnalyticsEventRecord[]) {
  const views = events.filter((event) => event.name === "Page View").length;
  const leads = events.filter(
    (event) => event.name === "Telegram Lead" || event.name === "Custom Lead",
  ).length;

  return {
    views,
    clicks: events.length - views,
    leads,
    sessions: new Set(
      events.map((event) => event.sessionId).filter(Boolean),
    ).size,
  };
}

function metricDelta(current: number, previous: number) {
  if (previous === 0) {
    return current === 0 ? 0 : null;
  }

  return Math.round(((current - previous) / previous) * 100);
}

function countBy<T>(
  items: T[],
  getKey: (item: T) => string,
) {
  const counts = new Map<string, number>();

  for (const item of items) {
    const key = getKey(item);

    if (key) {
      counts.set(key, (counts.get(key) ?? 0) + 1);
    }
  }

  return [...counts.entries()]
    .map(([key, count]) => ({ key, count }))
    .sort((left, right) => right.count - left.count || left.key.localeCompare(right.key));
}

export function parseAnalyticsRange(value?: string): AnalyticsRange {
  const parsed = Number(value);
  return analyticsRanges.includes(parsed as AnalyticsRange)
    ? (parsed as AnalyticsRange)
    : 30;
}

export function getAnalyticsQueryStart(range: AnalyticsRange, now = new Date()) {
  return new Date(now.getTime() - (range * 2 + 3) * dayMs);
}

export function buildAnalyticsReport(
  rawEvents: AnalyticsEventRecord[],
  range: AnalyticsRange,
  now = new Date(),
) {
  const events = rawEvents.filter((event) => analyticsEventNameSet.has(event.name));
  const currentDayKeys = buildDayKeys(now, range);
  const previousDayKeys = buildDayKeys(now, range, range);
  const currentKeySet = new Set(currentDayKeys);
  const previousKeySet = new Set(previousDayKeys);
  const currentEvents = events.filter((event) => currentKeySet.has(dayKey(event.createdAt)));
  const previousEvents = events.filter((event) => previousKeySet.has(dayKey(event.createdAt)));
  const current = metricSummary(currentEvents);
  const previous = metricSummary(previousEvents);
  const deltas = Object.fromEntries(
    (Object.keys(current) as MetricKey[]).map((key) => [
      key,
      metricDelta(current[key], previous[key]),
    ]),
  ) as Record<MetricKey, number | null>;

  const daily = currentDayKeys.map((key) => {
    const dayEvents = currentEvents.filter((event) => dayKey(event.createdAt) === key);
    const summary = metricSummary(dayEvents);
    const date = dayEvents[0]?.createdAt ?? new Date(`${key}T12:00:00+03:00`);

    return {
      key,
      label: shortDayFormatter.format(date).replace(".", ""),
      ...summary,
    };
  });

  const actions = countBy(
    currentEvents.filter((event) => event.name !== "Page View"),
    (event) => event.name,
  ).map((item) => ({
    name: item.key as AnalyticsEventName,
    count: item.count,
  }));

  const productStats = new Map<string, { opens: number; leads: number }>();

  for (const event of currentEvents) {
    if (!event.productSlug) {
      continue;
    }

    const currentProduct = productStats.get(event.productSlug) ?? {
      opens: 0,
      leads: 0,
    };

    if (event.name === "Product Open") {
      currentProduct.opens += 1;
    }

    if (event.name === "Telegram Lead" || event.name === "Custom Lead") {
      currentProduct.leads += 1;
    }

    productStats.set(event.productSlug, currentProduct);
  }

  const topProducts = [...productStats.entries()]
    .map(([slug, values]) => ({
      slug,
      ...values,
      total: values.opens + values.leads,
    }))
    .sort(
      (left, right) =>
        right.total - left.total ||
        right.leads - left.leads ||
        left.slug.localeCompare(right.slug),
    )
    .slice(0, 8);

  const topPages = countBy(
    currentEvents.filter((event) => event.name === "Page View"),
    (event) => event.path,
  ).slice(0, 8);

  return {
    range,
    current,
    previous,
    deltas,
    conversionRate:
      current.views > 0
        ? Math.round((current.leads / current.views) * 1000) / 10
        : 0,
    daily,
    actions,
    topProducts,
    topPages,
    recentEvents: [...currentEvents]
      .sort((left, right) => right.createdAt.getTime() - left.createdAt.getTime())
      .slice(0, 10),
    hasData: currentEvents.length > 0,
  };
}

export type AnalyticsReport = ReturnType<typeof buildAnalyticsReport>;
