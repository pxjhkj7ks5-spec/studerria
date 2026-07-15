type TelegramWebApp = {
  ready?: () => void;
  expand?: () => void;
  themeParams?: Record<string, string>;
  viewportStableHeight?: number;
  safeAreaInset?: { top?: number; right?: number; bottom?: number; left?: number };
  contentSafeAreaInset?: { top?: number; right?: number; bottom?: number; left?: number };
  onEvent?: (event: string, callback: () => void) => void;
  offEvent?: (event: string, callback: () => void) => void;
  HapticFeedback?: { notificationOccurred?: (type: "success" | "error" | "warning") => void };
  BackButton?: { show?: () => void; hide?: () => void };
  initData?: string;
};

declare global { interface Window { Telegram?: { WebApp?: TelegramWebApp } } }

const TELEGRAM_SDK_ELEMENT_ID = "telegram-web-app-sdk";

function waitForTelegramWebApp() {
  const current = window.Telegram?.WebApp;
  if (current) return Promise.resolve(current);
  const script = document.getElementById(TELEGRAM_SDK_ELEMENT_ID);
  if (!script) return Promise.resolve(undefined);
  return new Promise<TelegramWebApp | undefined>((resolve) => {
    const finish = () => resolve(window.Telegram?.WebApp);
    script.addEventListener("load", finish, { once: true });
    script.addEventListener("error", () => resolve(undefined), { once: true });
  });
}

export async function getTelegramInitData() {
  return (await waitForTelegramWebApp())?.initData || null;
}

/** Progressive enhancement only: game state never trusts this client shell. */
export function initializeTelegramShell() {
  const connect = (app: TelegramWebApp | undefined) => {
    if (!app) return;
    const sync = () => {
      const root = document.documentElement;
      root.classList.add("telegram-mini-app");
      if (app.viewportStableHeight) root.style.setProperty("--tg-stable-height", `${app.viewportStableHeight}px`);
      for (const [name, value] of Object.entries(app.safeAreaInset || {})) root.style.setProperty(`--tg-safe-area-${name}`, `${value || 0}px`);
      for (const [name, value] of Object.entries(app.contentSafeAreaInset || {})) root.style.setProperty(`--tg-content-safe-area-${name}`, `${value || 0}px`);
      const safeTop = Number(app.safeAreaInset?.top || 0);
      const contentTop = Number(app.contentSafeAreaInset?.top || 0);
      root.style.setProperty("--tg-layout-top", `${Math.max(contentTop, safeTop + 64)}px`);
      Object.entries(app.themeParams || {}).forEach(([name, value]) => root.style.setProperty(`--tg-${name.replace(/_/g, "-")}`, value));
    };
    app.ready?.();
    app.expand?.();
    sync();
    app.onEvent?.("viewportChanged", sync);
    app.onEvent?.("safeAreaChanged", sync);
    app.onEvent?.("contentSafeAreaChanged", sync);
    app.onEvent?.("themeChanged", sync);
  };
  void waitForTelegramWebApp().then(connect);
}

export function bindTelegramBackButton(handler: () => void) {
  const app = window.Telegram?.WebApp;
  if (!app) return () => undefined;
  app.BackButton?.show?.();
  app.onEvent?.("backButtonClicked", handler);
  return () => {
    app.offEvent?.("backButtonClicked", handler);
    app.BackButton?.hide?.();
  };
}

export function telegramCommandFeedback(result: "success" | "error" | "warning" = "success") {
  window.Telegram?.WebApp?.HapticFeedback?.notificationOccurred?.(result);
}

export async function initializeTelegramSession(basePath: string) {
  const initData = await getTelegramInitData();
  if (!initData) return null;
  const response = await fetch(`${basePath}api/auth/telegram/init`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ initData }) });
  return response.ok ? response.json() : null;
}

export async function setTelegramNotificationPreference(basePath: string, enabled: boolean) {
  const response = await fetch(`${basePath}api/notifications/preferences`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ enabled }) });
  return response.ok;
}
