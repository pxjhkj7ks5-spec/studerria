type AnalyticsEventName = "app.open" | "telegram.authenticated" | "campaign.asset.placed" | "campaign.operation.started" | "campaign.operation.completed" | "campaign.replay.opened" | "campaign.reconnected" | "pwa.offline.queued";
type AnalyticsProperties = Record<string, string | number | boolean | null>;

function sessionId() {
  const key = "shieldline-analytics-session-v1";
  const existing = window.sessionStorage.getItem(key);
  if (existing) return existing;
  const created = crypto.randomUUID();
  window.sessionStorage.setItem(key, created);
  return created;
}

function channel(): "telegram" | "pwa" | "web" {
  if (window.Telegram?.WebApp?.initData) return "telegram";
  if (window.matchMedia("(display-mode: standalone)").matches) return "pwa";
  return "web";
}

export function trackAnalytics(eventName: AnalyticsEventName, properties: AnalyticsProperties = {}) {
  const payload = JSON.stringify({ eventName, channel: channel(), sessionId: sessionId(), occurredAt: new Date().toISOString(), properties });
  void fetch(`${import.meta.env.BASE_URL}api/analytics`, { method: "POST", headers: { "Content-Type": "application/json" }, body: payload, keepalive: true }).catch(() => undefined);
}
