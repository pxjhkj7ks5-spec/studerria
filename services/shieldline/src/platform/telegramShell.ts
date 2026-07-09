type TelegramWebApp = {
  ready?: () => void;
  expand?: () => void;
  themeParams?: Record<string, string>;
  viewportStableHeight?: number;
  onEvent?: (event: string, callback: () => void) => void;
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
