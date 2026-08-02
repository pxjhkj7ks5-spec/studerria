import { withBasePath } from "@/lib/base-path";

export const analyticsEventNames = [
  "Page View",
  "Catalog Open",
  "Product Open",
  "Catalog Filter",
  "Add to Cart",
  "Checkout Open",
  "Order Placed",
  "Telegram Lead",
  "Custom Lead",
] as const;

export type AnalyticsEventName = (typeof analyticsEventNames)[number];
export type PlausibleEventName = Exclude<AnalyticsEventName, "Page View">;

export type PlausibleEventProps = Partial<{
  location: string;
  intent: "product" | "custom" | "catalog";
  product_slug: string;
  category: string;
  value: number;
  items: number;
}>;

const analyticsSessionStorageKey = "naradadruk-analytics-session-v1";

declare global {
  interface Window {
    plausible?: (
      eventName: PlausibleEventName,
      options?: { props?: PlausibleEventProps },
    ) => void;
  }
}

function getAnalyticsSessionId() {
  try {
    const existing = window.localStorage.getItem(analyticsSessionStorageKey);

    if (existing) {
      return existing;
    }

    const created =
      typeof window.crypto?.randomUUID === "function"
        ? window.crypto.randomUUID()
        : `${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}`;
    window.localStorage.setItem(analyticsSessionStorageKey, created);
    return created;
  } catch {
    return "";
  }
}

function trackInternal(
  eventName: AnalyticsEventName,
  props?: PlausibleEventProps,
) {
  const payload = JSON.stringify({
    name: eventName,
    path: window.location.pathname,
    sessionId: getAnalyticsSessionId(),
    props,
  });
  const endpoint = withBasePath("/api/analytics");

  if (typeof navigator.sendBeacon === "function") {
    const accepted = navigator.sendBeacon(
      endpoint,
      new Blob([payload], { type: "application/json" }),
    );

    if (accepted) {
      return;
    }
  }

  void fetch(endpoint, {
    method: "POST",
    body: payload,
    headers: { "Content-Type": "application/json" },
    credentials: "same-origin",
    keepalive: true,
  }).catch(() => undefined);
}

export function trackAnalytics(
  eventName: AnalyticsEventName,
  props?: PlausibleEventProps,
) {
  if (typeof window === "undefined") {
    return;
  }

  trackInternal(eventName, props);

  if (eventName !== "Page View" && typeof window.plausible === "function") {
    window.plausible(eventName, props ? { props } : undefined);
  }
}

export function trackPlausible(
  eventName: PlausibleEventName,
  props?: PlausibleEventProps,
) {
  trackAnalytics(eventName, props);
}
