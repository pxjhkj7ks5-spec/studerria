import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

function normalizeBasePath(value: string | undefined) {
  const raw = (value || "/shieldline/").trim();
  if (!raw || raw === "/") return "/";
  const withLeading = raw.startsWith("/") ? raw : `/${raw}`;
  return `${withLeading.replace(/\/+$/, "")}/`;
}

export default defineConfig({
  base: normalizeBasePath(process.env.SHIELDLINE_BASE_PATH),
  plugins: [react()],
  server: {
    host: "0.0.0.0",
    port: 5173,
  },
  preview: {
    host: "0.0.0.0",
    port: 8080,
  },
});
