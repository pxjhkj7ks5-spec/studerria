type TelegramWebApp = {
  ready?: () => void;
  expand?: () => void;
  themeParams?: Record<string, string>;
  viewportStableHeight?: number;
  onEvent?: (event: string, callback: () => void) => void;
  HapticFeedback?: { notificationOccurred?: (type: "success" | "error" | "warning") => void };
  initData?: string;
};

declare global { interface Window { Telegram?: { WebApp?: TelegramWebApp } } }

/** Progressive enhancement only: game state never trusts this client shell. */
export function initializeTelegramShell() {
  const app = window.Telegram?.WebApp;
  if (!app) return;
  const sync = () => {
    const root = document.documentElement;
    if (app.viewportStableHeight) root.style.setProperty("--tg-stable-height", `${app.viewportStableHeight}px`);
    Object.entries(app.themeParams || {}).forEach(([name, value]) => root.style.setProperty(`--tg-${name.replace(/_/g, "-")}`, value));
  };
  app.ready?.();
  app.expand?.();
  sync();
  app.onEvent?.("viewportChanged", sync);
  app.onEvent?.("themeChanged", sync);
}

export function telegramCommandFeedback(result: "success" | "error" | "warning" = "success") {
  window.Telegram?.WebApp?.HapticFeedback?.notificationOccurred?.(result);
}

export async function initializeTelegramSession(basePath: string) {
  const initData = window.Telegram?.WebApp?.initData;
  if (!initData) return null;
  const response = await fetch(`${basePath}api/auth/telegram/init`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ initData }) });
  return response.ok ? response.json() : null;
}

export async function setTelegramNotificationPreference(basePath: string, enabled: boolean) {
  const response = await fetch(`${basePath}api/notifications/preferences`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ enabled }) });
  return response.ok;
}
