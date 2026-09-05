# Обрій / Obriy

Civilian, privacy-first contextual air-threat monitoring. This is a standalone KMA service at `/obriy`, with its own dependency lock and PostgreSQL schema (`obriy`). The supplied 58-page document is a product specification, not permission to change unrelated projects or operate external accounts. v0.1 is server-first Telegram delivery plus a small authenticated web workspace. PWA push/native and unidentified AirSigma are explicitly deferred as in the specification.

## Implementation boundaries

- `src/engine`: pure validation, geodesics, uncertainty, evidence/risk, hysteresis, replay tests.
- `src/ingestion`: one NEPTUN WebSocket, bounded REST resync, independent alerts.in.ua collector.
- `src/store.ts`, `migrations`: encrypted zones/chat IDs, durable tracks, risk state and transactional outbox, leases, deletion and retention.
- `src/server.ts`, `src/telegram.ts`: private web setup, scoped sessions, zone ownership, Telegram linking/commands, retry delivery.
- `public`: Ukrainian status workspace, no third-party assets or map tiles.
- KMA integration: Compose service, `/obriy` proxy, service update selector. Root/shared changes are coordinated by the parent task only.

## Data flow

NEPTUN → singleton collector → normalized tracks → deterministic risk per protected zone → one database transaction (state + outbox) → leased delivery worker → Telegram. alerts.in.ua contributes administrative context only. Neither upstream receives user coordinates or identifiers. The client talks only to this service. No LLM or guessed weapon speed is in the decision path.

Exact zones and Telegram chat identifiers use AES-256-GCM with random 96-bit IVs and field/owner binding as additional authenticated data. Key lives in runtime env, separate from PostgreSQL/backups. No public registration: owner access key bootstraps one owner; one-use pairing code associates an explicitly consenting private Telegram chat. Web access uses an opaque HttpOnly session. Telegram supports private commands after pairing. The service can serve a truthful setup-required workspace without credentials; protected endpoints remain locked.

## Reliability and limits

A PostgreSQL session advisory lock elects one ingestion/dispatch owner; state survives restarts. A bounded outbox uses per-chat rate limiting, expiring notifications, retries/429 handling and deletion cascade. Telegram sendMessage has no idempotency key: a timeout after provider acceptance can cause a duplicate on retry; local dedupe does not promise exactly-once remote delivery. Pending risk notifications are invalidated after source freshness loss, pause, zone edits or deletion. No signal is not proof of safety.

Production deployment uses existing KMA Compose and reverse proxy, not another conflicting TLS server. Standalone TLS/backup procedures are documented separately. The existing PostgreSQL service is reused with a namespaced schema; unrelated schemas are untouched. Do not horizontally scale until multi-process behavior is verified under your expected load.
