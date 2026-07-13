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
  BottomButton?: { setText?: (text: string) => void; show?: () => void; hide?: () => void; enable?: () => void; disable?: () => void };
  MainButton?: { setText?: (text: string) => void; show?: () => void; hide?: () => void; enable?: () => void; disable?: () => void };
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

/** Progressive enhancement only: game state never trusts this client shell. */
export function initializeTelegramShell() {
  const connect = (app: TelegramWebApp | undefined) => {
    if (!app) return;
    const sync = () => {
      const root = document.documentElement;
      if (app.viewportStableHeight) root.style.setProperty("--tg-stable-height", `${app.viewportStableHeight}px`);
      for (const [name, value] of Object.entries(app.safeAreaInset || {})) root.style.setProperty(`--tg-safe-area-${name}`, `${value || 0}px`);
      for (const [name, value] of Object.entries(app.contentSafeAreaInset || {})) root.style.setProperty(`--tg-content-safe-area-${name}`, `${value || 0}px`);
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

export function bindTelegramBottomButton({ text, enabled, visible, onClick }: { text: string; enabled: boolean; visible: boolean; onClick: () => void }) {
  const app = window.Telegram?.WebApp;
  const button = app?.BottomButton || app?.MainButton;
  if (!app || !button) return () => undefined;
  button.setText?.(text);
  if (enabled) button.enable?.(); else button.disable?.();
  if (visible) button.show?.(); else button.hide?.();
  app.onEvent?.("mainButtonClicked", onClick);
  return () => {
    app.offEvent?.("mainButtonClicked", onClick);
    button.hide?.();
  };
}

export function telegramCommandFeedback(result: "success" | "error" | "warning" = "success") {
  window.Telegram?.WebApp?.HapticFeedback?.notificationOccurred?.(result);
}

export async function initializeTelegramSession(basePath: string) {
  const initData = (await waitForTelegramWebApp())?.initData;
  if (!initData) return null;
  const response = await fetch(`${basePath}api/auth/telegram/init`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ initData }) });
  return response.ok ? response.json() : null;
}

export async function setTelegramNotificationPreference(basePath: string, enabled: boolean) {
  const response = await fetch(`${basePath}api/notifications/preferences`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ enabled }) });
  return response.ok;
}
