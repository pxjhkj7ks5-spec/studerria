import React from "react";
import { createRoot } from "react-dom/client";
import "leaflet/dist/leaflet.css";
import "./styles/app.css";
import App from "./App";
import { AppErrorBoundary } from "./components/AppErrorBoundary";
import { hydrateControlOverlayFromServer } from "./data/controlZones";
import { initializeTelegramSession, initializeTelegramShell } from "./platform/telegramShell";
import { initializeOfflinePersistence } from "./platform/offlineStore";

async function bootstrap() {
  initializeTelegramShell();
  void initializeOfflinePersistence(import.meta.env.BASE_URL);
  void initializeTelegramSession(import.meta.env.BASE_URL);
  if ("serviceWorker" in navigator) {
    const hadController = Boolean(navigator.serviceWorker.controller);
    let refreshingForUpdate = false;
    navigator.serviceWorker.addEventListener("controllerchange", () => {
      if (!hadController || refreshingForUpdate) return;
      refreshingForUpdate = true;
      window.location.reload();
    });
    void navigator.serviceWorker
      .register(`${import.meta.env.BASE_URL}sw.js`, { updateViaCache: "none" })
      .then((registration) => registration.update())
      .catch(() => undefined);
  }
  await hydrateControlOverlayFromServer(import.meta.env.BASE_URL);
  createRoot(document.getElementById("root") as HTMLElement).render(
    <React.StrictMode>
      <AppErrorBoundary><App /></AppErrorBoundary>
    </React.StrictMode>,
  );
}

void bootstrap();
