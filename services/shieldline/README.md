# Shieldline

Shieldline is a fictional strategic map-defense browser game served inside Studerria at `/shieldline`.

It is intentionally isolated as a sidecar service:

- Vite + React + TypeScript
- Telegram-aware React/PWA command shell with an optional tactical map view (`?legacy=1`)
- deterministic, server-resolved Campaign missions with append-only file-backed events and replay
- a server-backed persistent Daily Defense city, daily reports, ranked projection and async co-op shared plans
- a cache-first PWA shell; a server-issued guest cookie supports standalone development while verified Telegram identity is used in production

## Tactical runtime

The first six modes use the tactical map as their primary gameplay surface. Training starts after the radar + kinetic-defense checklist, Campaign/Rapid/Ranked use an explicit start, Sandbox exposes pause/wave/speed controls, and Co-op uses the HQ-start policy. Daily Defense is deliberately excluded from the client simulation clock and remains a scheduled server mode.

Live operation state follows `planning -> countdown -> running -> paused -> completed`. Random decisions use a persisted deterministic seed/cursor so reloads and automated regression checks can reproduce the same sequence.

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

The versioned operations API is available at `POST /shieldline/api/operations`, with `GET /operations/:id`, `/events?after=<sequence>`, `/snapshots?tick=<tick>` and idempotent revision-checked `/commands`. Existing mission endpoints remain available as compatibility adapters.

## Telegram auth and reports

Set `SHIELDLINE_TELEGRAM_BOT_TOKEN` only in the server environment, configure the Shieldline Mini App URL in BotFather, and point it to `https://studerria.com/shieldline/`. The sidecar validates Telegram Mini App `initData` server-side, enforces `SHIELDLINE_TELEGRAM_AUTH_MAX_AGE_SECONDS`, and issues an HttpOnly Shieldline session only after validation. Verified Telegram users can opt in to reports; the worker reads the persistent notification outbox every 30 seconds and retries delivery until Telegram accepts it. `GET /shieldline/api/telegram/status` exposes whether the production token is configured without revealing it.

Set a unique production `SHIELDLINE_SESSION_SECRET` (minimum 24 characters). Session cookies are signed, expire server-side, use `Secure` in production and can be cleared through `POST /shieldline/api/auth/logout`. `SHIELDLINE_API_RATE_LIMIT_PER_MINUTE` controls the fixed-window API guard.
