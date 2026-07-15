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
  build: {
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (id.includes("node_modules/lucide-react")) {
            return "icons-vendor";
          }
          if (id.includes("node_modules")) {
            return "vendor";
          }
          return undefined;
        },
      },
    },
  },
  server: {
    host: "0.0.0.0",
    port: 5173,
    proxy: {
      "/shieldline/api": {
        target: process.env.SHIELDLINE_API_PROXY_TARGET || "http://127.0.0.1:4175",
      },
    },
  },
  preview: {
    host: "0.0.0.0",
    port: 8080,
  },
});
