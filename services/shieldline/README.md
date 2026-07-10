# Shieldline

Shieldline is a fictional strategic map-defense browser game served inside Studerria at `/shieldline`.

It is intentionally isolated as a sidecar service:

- Vite + React + TypeScript
- Telegram-aware React/PWA command shell with an optional tactical map view (`?legacy=1`)
- deterministic Campaign missions projected from one browser/server simulation core
- PostgreSQL-backed runs, events, snapshots, commands and Campaign progress with Redis read-through caching
- a cache-first PWA shell; a server-issued guest cookie supports standalone development while verified Telegram identity is used in production

## Campaign runtime

Campaign is the active production mode. Other modes remain in the codebase as paused foundations but are hidden from the primary catalog while Campaign reaches production quality.

Campaign state follows `planning -> countdown -> running -> paused -> completed`. The tactical map, reconnect, replay scrubber, snapshots and AAR all project the same `simVersion` event stream. Offline Campaign startup uses the same core and queues the authoritative operation for synchronization.

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

The production server serves `dist` on port `8080` and falls back to `index.html` for `/shieldline/*` refreshes. Docker Compose configures `SHIELDLINE_STORAGE_DRIVER=postgres`; JSON is retained for one compatibility release and as the importer source.

Required production storage settings:

```env
SHIELDLINE_STORAGE_DRIVER=postgres
SHIELDLINE_DB_HOST=db
SHIELDLINE_DB_PORT=5432
SHIELDLINE_DB_USER=studerria
SHIELDLINE_DB_PASSWORD=replace-with-postgres-password
SHIELDLINE_DB_NAME=student_portal
SHIELDLINE_REDIS_URL=redis://redis:6379
```

The same image runs the API, projection worker and notification worker as separate Compose processes. `GET /shieldline/api/health` verifies the API and PostgreSQL connection.

Import the old JSON store with a dry-run first:

```bash
docker compose run --rm shieldline npm run import:json
docker compose run --rm shieldline npm run import:json -- --apply
docker compose run --rm shieldline npm run import:json -- --rollback <import-id>
```

The importer is checksum-idempotent and creates a source backup before its transaction.

## Localization and observability

The active Campaign shell uses key-based Ukrainian, Russian and English dictionaries. Ukrainian is the default, Russian follows Telegram locale, and English is the fallback for English clients. Campaign numbers and timeline values use `Intl` formatting.

`GET /shieldline/api/metrics` exposes Prometheus counters and latency histograms. Set `SHIELDLINE_OTEL_TRACES_ENDPOINT` to enable OTLP/HTTP trace export; request logs always include the OpenTelemetry trace ID. Campaign activation, completion, replay, reconnect and offline-queue events use the validated `/api/analytics` contract and are stored in PostgreSQL. Importable SLO definitions and a Grafana dashboard live in `observability/`.

CI runs unit/contract tests, the production build, a Docker build and the mobile Campaign Playwright flow, including reconnect, critical accessibility checks and layout overlap assertions.

The versioned operations API is available at `POST /shieldline/api/operations`, with `GET /operations/:id`, `/events?after=<sequence>`, `/snapshots?tick=<tick>` and idempotent revision-checked `/commands`. Existing mission endpoints remain available as compatibility adapters.

## Telegram auth and reports

Set `SHIELDLINE_TELEGRAM_BOT_TOKEN` only in the server environment, configure the Shieldline Mini App URL in BotFather, and point it to `https://studerria.com/shieldline/`. The sidecar validates Telegram Mini App `initData` server-side, enforces `SHIELDLINE_TELEGRAM_AUTH_MAX_AGE_SECONDS`, and issues an HttpOnly Shieldline session only after validation. Verified Telegram users can opt in to reports; the worker reads the persistent notification outbox every 30 seconds and retries delivery until Telegram accepts it. `GET /shieldline/api/telegram/status` exposes whether the production token is configured without revealing it.

With PostgreSQL storage enabled, session cookies contain opaque random tokens and only SHA-256 hashes are stored in PostgreSQL/Redis. Sessions expire, rotate according to `SHIELDLINE_SESSION_ROTATION_SECONDS`, use `Secure` in production and are revoked by `POST /shieldline/api/auth/logout`. The signed cookie codec remains only for JSON compatibility mode. `SHIELDLINE_API_RATE_LIMIT_PER_MINUTE` controls the fixed-window API guard; Zod schemas validate Campaign operation and command payloads, and rejected commands are recorded in the audit log.
