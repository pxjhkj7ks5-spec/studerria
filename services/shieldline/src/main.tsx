import React from "react";
import { createRoot } from "react-dom/client";
import "leaflet/dist/leaflet.css";
import "./styles/app.css";
import App from "./App";
import { hydrateControlOverlayFromServer } from "./data/controlZones";
import { initializeTelegramSession, initializeTelegramShell } from "./platform/telegramShell";
import { initializeOfflinePersistence } from "./platform/offlineStore";

async function bootstrap() {
  initializeTelegramShell();
  void initializeOfflinePersistence(import.meta.env.BASE_URL);
  void initializeTelegramSession(import.meta.env.BASE_URL);
  if ("serviceWorker" in navigator) {
    void navigator.serviceWorker.register(`${import.meta.env.BASE_URL}sw.js`);
  }
  await hydrateControlOverlayFromServer(import.meta.env.BASE_URL);
  createRoot(document.getElementById("root") as HTMLElement).render(
    <React.StrictMode>
      <App />
    </React.StrictMode>,
  );
}

void bootstrap();
