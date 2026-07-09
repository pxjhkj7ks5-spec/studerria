# Shieldline

Shieldline is a fictional strategic map-defense browser game served inside Studerria at `/shieldline`.

It is intentionally isolated as a sidecar service:

- Vite + React + TypeScript
- Telegram-aware React/PWA command shell with an optional legacy map view (`?legacy=1`)
- deterministic server-side mission resolution and append-only file-backed event store
- Daily Defense reports, replay, ranked projection and async co-op command-room APIs
- a server-issued guest session cookie is used for local/standalone identity; trusted Telegram identity and bot delivery stay disabled until a server-side `initData` validator and notification worker are connected

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

Set `SHIELDLINE_TELEGRAM_BOT_TOKEN` only in the server environment. The sidecar validates Telegram Mini App `initData` server-side, enforces the configured `SHIELDLINE_TELEGRAM_AUTH_MAX_AGE_SECONDS`, and issues an HttpOnly Shieldline session only after that validation. Verified Telegram users can opt in to reports; the built-in worker reads the persistent notification outbox every 30 seconds and retries delivery until Telegram accepts it.
