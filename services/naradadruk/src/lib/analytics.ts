export type PlausibleEventName =
  | "Catalog Open"
  | "Product Open"
  | "Catalog Filter"
  | "Telegram Lead"
  | "Custom Lead";

export type PlausibleEventProps = Partial<{
  location: string;
  intent: "product" | "custom" | "catalog";
  product_slug: string;
  category: string;
}>;

declare global {
  interface Window {
    plausible?: (
      eventName: PlausibleEventName,
      options?: { props?: PlausibleEventProps },
    ) => void;
  }
}

export function trackPlausible(
  eventName: PlausibleEventName,
  props?: PlausibleEventProps,
) {
  if (typeof window === "undefined" || typeof window.plausible !== "function") {
    return;
  }

  window.plausible(eventName, props ? { props } : undefined);
}
