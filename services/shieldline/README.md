# Shieldline

Shieldline is a fictional strategic map-defense browser game served inside Studerria at `/shieldline`.

It is intentionally isolated as a sidecar service:

- Vite + React + TypeScript
- Telegram-aware React/PWA command shell with an optional tactical map view (`?legacy=1`)
- deterministic, server-resolved Campaign missions with append-only file-backed events and replay
- a server-backed persistent Daily Defense city, daily reports, ranked projection and async co-op shared plans
- a cache-first PWA shell; a server-issued guest cookie supports standalone development while verified Telegram identity is used in production

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

The production server serves `dist` on port `8080`, falls back to `index.html` for `/shieldline/*` refreshes, and stores the game event stream in `SHIELDLINE_GAME_STORE_FILE` (default `/data/game-store.json`). The `shieldline_control_data` Docker volume persists that state.

## Telegram auth and reports

Set `SHIELDLINE_TELEGRAM_BOT_TOKEN` only in the server environment, configure the Shieldline Mini App URL in BotFather, and point it to `https://studerria.com/shieldline/`. The sidecar validates Telegram Mini App `initData` server-side, enforces `SHIELDLINE_TELEGRAM_AUTH_MAX_AGE_SECONDS`, and issues an HttpOnly Shieldline session only after validation. Verified Telegram users can opt in to reports; the worker reads the persistent notification outbox every 30 seconds and retries delivery until Telegram accepts it. `GET /shieldline/api/telegram/status` exposes whether the production token is configured without revealing it.
