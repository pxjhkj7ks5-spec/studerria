# OSIX MVP

OSIX is an isolated sidecar service for public, deterministic monitoring of attributable open statistics.

## Scope

- Website and JSON API polling only.
- Allowlisted sources only:
  - `https://www.zsu.gov.ua/oriientovni-vtraty-protyvnyka`
  - `https://mod.gov.ua/news/tag-vidsich-agresoru`
  - `https://mod.gov.ua/lookup/search?search_type=dfs_query_then_fetch`
  - `https://mod.gov.ua/news/bojovi-vtrati-voroga-na-*`
  - `https://sbs-group.army/`
  - the MIT-licensed structured mirror of General Staff daily loss reports at `raw.githubusercontent.com/PetroIvaniuk/2022-Ukraine-Russia-War-Dataset/`
  - `https://api.russiafossiltracker.com/v0/counter` from the Centre for Research on Energy and Clean Air (CREA)
- No Telegram ingestion in MVP. `TelegramSourceAdapter` is a stub for future work.
- No runtime LLM.
- ClickHouse stores normalized time-series, health, raw snapshot indexes, parser errors, sources, and audit log.
- Raw snapshot bodies are stored on the OSIX filesystem volume with retention cleanup.
- General loss history starts with a derived zero baseline on `2022-02-24`; the first published daily report is dated `2022-02-25`.
- CREA oil export metrics include daily tonnes, estimated EUR revenue, commodity splits, and destination-region splits. CREA documents Kpler, Eurostat, and customs data as upstream inputs.

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
