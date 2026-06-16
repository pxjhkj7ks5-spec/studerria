# OSIX MVP

OSIX is an isolated sidecar service for public, deterministic monitoring of official open statistics.

## Scope

- Website polling only.
- Official allowlisted sources only:
  - `https://www.zsu.gov.ua/oriientovni-vtraty-protyvnyka`
  - `https://mod.gov.ua/news/tag-vidsich-agresoru`
  - `https://mod.gov.ua/lookup/search?search_type=dfs_query_then_fetch`
  - `https://mod.gov.ua/news/bojovi-vtrati-voroga-na-*`
  - `https://sbs-group.army/`
- No Telegram ingestion in MVP. `TelegramSourceAdapter` is a stub for future work.
- No runtime LLM.
- ClickHouse stores normalized time-series, health, raw snapshot indexes, parser errors, sources, and audit log.
- Raw snapshot bodies are stored on the OSIX filesystem volume with retention cleanup.

## Admin Auth

Admin routes use an OSIX-only signed cookie scoped to `/osix`. Login is disabled unless these environment variables are set:

- `OSIX_ADMIN_USERNAME`
- `OSIX_ADMIN_PASSWORD_HASH`
- `OSIX_JWT_SECRET`

Password hash format:

```text
pbkdf2_sha256$260000$salt$hex_digest
```

## Local URL

When routed through the main Studerria app:

```text
http://localhost:3000/osix
```
