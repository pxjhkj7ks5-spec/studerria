# Shieldline

Shieldline is a fictional strategic map-defense browser game served inside Studerria at `/shieldline`.

It is intentionally isolated as a sidecar service:

- Vite + React + TypeScript
- Zustand persisted state in localStorage
- React-Leaflet map UI
- no Studerria database or account integration in the MVP

## Local development

```bash
cd services/shieldline
npm install
npm run dev
```

The Vite app uses `/shieldline/` as its base path. In production, Studerria proxies `/shieldline` to the sidecar.

## Production sidecar

```bash
npm run build
npm start
```

The production server serves `dist` on port `8080` and falls back to `index.html` for `/shieldline/*` refreshes.
