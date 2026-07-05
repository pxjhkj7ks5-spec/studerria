import React from "react";
import { createRoot } from "react-dom/client";
import "leaflet/dist/leaflet.css";
import "./styles/app.css";
import App from "./App";
import { hydrateControlOverlayFromServer } from "./data/controlZones";

async function bootstrap() {
  await hydrateControlOverlayFromServer(import.meta.env.BASE_URL);
  createRoot(document.getElementById("root") as HTMLElement).render(
    <React.StrictMode>
      <App />
    </React.StrictMode>,
  );
}

void bootstrap();
