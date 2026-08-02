# Local Docker Stack

This stack runs the current KMA app with PostgreSQL, Redis, ClickHouse, and centralized logs through Docker Compose.

## What is included

- `app`: the existing Node.js + Express application from this repository
- `charredmap`: isolated Next.js memorial-map service mounted under `/charredmap`
- `china-map`: isolated static Next.js classroom atlas mounted under `/china-map`
- `naradadruk`: isolated Next.js print/catalog service mounted under `/naradadruk`
- `slashtg`: isolated legacy Telegram mini-app service mounted under `/tg`
- `osix`: isolated official statistics monitoring service mounted under `/osix`
- `db`: PostgreSQL 18 with first-start initialization from `docker/local/db/init/*.sql`
- `redis`: Redis 7 for Studerria session storage
- `clickhouse`: ClickHouse storage for OSIX normalized time-series and service metadata
- `loki`: log storage backend
- `promtail`: Docker log collector that forwards container logs to Loki

The stack includes a compatibility init script that creates `cloudsqlsuperuser` before SQL import, so legacy dumps restore cleanly on plain PostgreSQL.

## Included database backup

The optional SQL dump is expected at:

- `docker/local/db/init/20-backup.sql`

That file is intentionally gitignored. On another machine, place the dump there before first boot if you want imported production data.

## Start

```bash
cd docker/local
docker compose up --build -d
```

App URL:

- [http://localhost:3000](http://localhost:3000)
- [http://localhost:3000/charredmap](http://localhost:3000/charredmap)
- [http://localhost:3000/charredmap/admin](http://localhost:3000/charredmap/admin)
- [http://localhost:3000/china-map](http://localhost:3000/china-map)
- [http://localhost:3000/china-map/print](http://localhost:3000/china-map/print)
- [http://localhost:3000/naradadruk](http://localhost:3000/naradadruk)
- [http://localhost:3000/tg](http://localhost:3000/tg)
- [http://localhost:3000/osix](http://localhost:3000/osix)
- [http://localhost:3000/studerria-tg](http://localhost:3000/studerria-tg)

Observability:

- Loki API: [http://localhost:3100](http://localhost:3100)

Postgres host access:

- host: `localhost`
- port: `5433`
- database: `student_portal`
- user: `studerria`

PostgreSQL 18 stores its versioned data directory under `/var/lib/postgresql/18/docker`, so the Compose named volume is mounted at `/var/lib/postgresql`. Do not remount it to `/var/lib/postgresql/data`, because Docker will create an anonymous volume for the real data directory.

Redis host access:

- host: `localhost`
- port: `6379`

ClickHouse host access:

- host: `localhost`
- port: `8123`
- database: `osix`

## Optional env overrides

If you want custom ports or credentials, copy `.env.example` to `.env` in this folder and adjust the values.

For `charredmap`, set dedicated values for:

- `CHARREDMAP_ADMIN_PASSWORD`
- `CHARREDMAP_SESSION_SECRET`
- `CHARREDMAP_NODE_ENV=production` on the server behind HTTPS

For `osix`, production admin login is disabled until these are set:

- `OSIX_ADMIN_USERNAME`
- `OSIX_ADMIN_PASSWORD_HASH` in `pbkdf2_sha256$iterations$salt$hex_digest` format
- `OSIX_JWT_SECRET`

OSIX only polls explicitly allowlisted public sources configured by `OSIX_SOURCE_*` variables. The military-loss history mirror must remain attributable to General Staff reports, and the oil dataset must remain attributable to CREA. Do not add Telegram, private channels, or anonymous OSINT feeds.

## Update an existing server

For a normal application update, keep the existing PostgreSQL volume and run the helper from the repository root:

```bash
cd ~/studerria
bash scripts/server-update.sh app
```

The helper preserves server-local edits to `docker/local/docker-compose.yml` with `git update-index --skip-worktree`, pulls the latest code, updates only the selected Compose service, and prints that service's latest logs.

Use the service-specific helpers when only one site or service changed:

```bash
cd ~/studerria
bash scripts/server-update-app.sh
bash scripts/server-update-charredmap.sh
bash scripts/server-update-china-map.sh
bash scripts/server-update-naradadruk.sh
bash scripts/server-update-slashtg.sh
bash scripts/server-update-withlforl.sh
bash scripts/server-update-osix.sh
```

Equivalent generic form:

```bash
cd ~/studerria
bash scripts/server-update.sh app
bash scripts/server-update.sh charredmap
bash scripts/server-update.sh china-map
bash scripts/server-update.sh naradadruk
bash scripts/server-update.sh slashtg
bash scripts/server-update.sh withlforl
bash scripts/server-update.sh osix
```

The helper rebuilds only the selected service by default, which is the safe path for code updates because the services run from Docker images. Add `--no-build` for runtime-only Compose/env updates. Use `--pull` when updating a service from a pullable image.

Before updating stateful services, the helper writes a local safety backup under `backups/server-update/`:

- `app` or `db`: full PostgreSQL `pg_dump -Fc`
- `charredmap`, `naradadruk`, `slashtg`, `osix`: compressed `/data` Docker volume archive

Use `--skip-backup` only when you have already made a fresh manual backup.

If this is the first update on a server where `docker/local/docker-compose.yml` is already locally modified and `git pull --rebase` refuses to run, do this once:

```bash
cd ~/studerria
git update-index --skip-worktree docker/local/docker-compose.yml
git pull --rebase
bash scripts/server-update.sh app
```

Manual equivalent:

```bash
cd ~/studerria
git pull --rebase
cd docker/local
docker compose up -d --build app
docker compose ps
docker compose logs --tail=100 app
```

Do not run `docker compose down -v` for a routine update, because that recreates database and cache volumes.

If `docker inspect kma-local-db-1` shows an anonymous volume mounted at `/var/lib/postgresql`, stop and migrate that data into `kma-local_postgres_data` before recreating the database container.

### Recover Telegram data

If Studerria Telegram users disappear after an update, first check whether the current database is empty or just missing Telegram links:

```bash
cd docker/local
docker compose exec db psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "SELECT COUNT(*) AS users, COUNT(*) FILTER (WHERE telegram_id IS NOT NULL AND telegram_id <> '') AS telegram_users FROM users;"
```

Restore from the latest PostgreSQL backup made by the helper:

```bash
cd docker/local
docker compose cp ../../backups/server-update/postgres-YYYYMMDDTHHMMSSZ.dump db:/tmp/studerria.dump
docker compose exec db pg_restore --clean --if-exists --no-owner -U "$POSTGRES_USER" -d "$POSTGRES_DB" /tmp/studerria.dump
```

If the legacy `/tg` sidecar data disappears, restore the `slashtg_data` volume archive:

```bash
cd docker/local
docker compose stop slashtg
docker run --rm -v kma-local_slashtg_data:/target -v "$(pwd)/../../backups/server-update:/backup" alpine:3.20 sh -c "cd /target && tar xzf /backup/slashtg-data-YYYYMMDDTHHMMSSZ.tgz"
docker compose up -d slashtg
```

### Deploy Fast (server routine)

Use this path when there are no Dockerfile/dependency changes and you only need the latest code:

```bash
cd ~/studerria
git pull --rebase
cd docker/local
docker compose pull naradadruk
docker compose up -d naradadruk
docker compose ps
```

### Narada Druk owner bot

The MakerWorld flow reuses the existing Narada Druk order bot and the same configured
owner group that receives new-order notifications. Publishing still uses a separate
Narada Print destination channel:

```env
NARADADRUK_ORDER_TELEGRAM_BOT_TOKEN=bot-token-from-botfather
NARADADRUK_ORDER_TELEGRAM_CHAT_ID=-1001111111111
NARADADRUK_ORDER_TELEGRAM_OWNER_USER_IDS=123456789
NARADADRUK_POSTS_TELEGRAM_CHAT_ID=-1001234567890
```

Create the bot in `@BotFather` with `/newbot`, copy its token into
`NARADADRUK_ORDER_TELEGRAM_BOT_TOKEN`, add it to the owner group and send an explicit
command such as `/help@bot_username`. With the owner worker stopped, call `getUpdates`
once: copy the negative `message.chat.id` to `NARADADRUK_ORDER_TELEGRAM_CHAT_ID` and
the positive `message.from.id` of every manager to the comma-separated owner allowlist.

- `NARADADRUK_ORDER_TELEGRAM_BOT_TOKEN` continues to send order notifications and
  also receives owner-only order, review-moderation, manual-order and MakerWorld commands.
- `NARADADRUK_ORDER_TELEGRAM_CHAT_ID` is the numeric owner group ID (normally `-100…`)
  or, for backward-compatible private operation, a positive private chat ID.
- `NARADADRUK_ORDER_TELEGRAM_OWNER_USER_IDS` contains positive Telegram user IDs,
  separated by commas. Only these actors can run management commands or callbacks in
  the configured group. It is required for groups. In a positive private chat it may
  be omitted, in which case the chat/user ID is the sole owner.
- `NARADADRUK_POSTS_TELEGRAM_CHAT_ID` is the required numeric destination channel ID
  for albums and posts. Do not put the public `@naradaprint` username here.

Telegram Privacy Mode may stay enabled for explicit commands and direct replies to bot
messages. The guided `/manual` and `/makerworld` flows also expect ordinary text such
as a URL, title, description and price. For seamless non-reply input, either make the
bot an owner-group administrator or disable Privacy Mode with `@BotFather` `/setprivacy`
and re-add it to the group. The application allowlist still rejects every unlisted user.

To obtain the numeric channel ID, add the existing bot to the channel and call the
Telegram Bot API `getChat` method with `@naradaprint`; copy the numeric `result.id`
(normally beginning with `-100`) into `NARADADRUK_POSTS_TELEGRAM_CHAT_ID`. The public
channel URL already configured for Narada Druk is reused for post links. If no safe
Telegram link is configured, the secondary Telegram button is omitted. Product buttons
always use `https://studerria.com/naradadruk/product/<slug>`.

```bash
curl -sS -X POST "https://api.telegram.org/bot${NARADADRUK_ORDER_TELEGRAM_BOT_TOKEN}/getChat" \
  --data-urlencode "chat_id=@naradaprint"
```

Send `/makerworld` in the configured owner chat as an allowed user, then provide a public MakerWorld model
URL. The bot creates a non-public product draft, downloads up to six public preview
images (8 MB each, 24 MB total), and exposes buttons and commands for title, full site
description, separate compact Telegram text, selected images, and price. `/publish`
activates the exact product first and then posts the selected album and a styled post
whose primary button links to that product page. `/cancel` removes an unpublished
draft and its downloaded files.

MakerWorld extraction uses only public HTML/Open Graph/JSON-LD data. Private, removed,
access-restricted, or challenge-protected pages are not bypassed, and some pages may
provide fewer metadata fields or images. In-memory Telegram editing sessions do not
survive a service restart; any already-created product remains an unpublished draft
that can be reviewed in the Narada Druk admin area.

Use `/orders` for the refreshable active-order dashboard and `/manual` for the guided
manual-order flow. New website and manual orders start as `Обробляється`; the owner can
move them through `Прийнято в роботу`, `Відправлено`, and confirmed `Закрито`, with
internal comments retained in order history. The dashboard is intentionally not pinned
automatically because chat permissions vary. New public reviews also arrive in this
same owner chat with `Опублікувати` and `Видалити` buttons and remain hidden until
approved. All buttons and commands use the same chat and actor allowlist.

Server `.env` baseline:

```env
NODE_ENV=production
CHARREDMAP_NODE_ENV=production
SHIELDLINE_NODE_ENV=production
STUDERRIA_TG_BOT_TOKEN=your-telegram-bot-token
STUDERRIA_TG_DEV_GREETING_ENABLED=false
STUDERRIA_TG_DEV_GREETING_TARGET_CHAT_ID=
STUDERRIA_TG_DEV_GREETING_TARGET_THREAD_ID=
SLASHTG_BASE_PATH=/tg
OSIX_ADMIN_USERNAME=admin
OSIX_ADMIN_PASSWORD_HASH='pbkdf2_sha256$260000$replace-salt$replace-digest'
OSIX_JWT_SECRET=replace-with-long-random-secret
OSIX_DASHBOARD_AUTH_REQUIRED=true
```

If image build inputs changed (`Dockerfile`, `package.json`, `package-lock.json`, or build tooling), use:

```bash
docker compose up --build -d naradadruk
```

If GHCR package access is private, authenticate once on the server before pulls:

```bash
echo "$GITHUB_TOKEN_WITH_READ_PACKAGES" | docker login ghcr.io -u "$GITHUB_USERNAME" --password-stdin
```

## Re-import the backup from scratch

The PostgreSQL dump is imported only when the database volume is empty. To recreate the database and re-run the import:

```bash
cd docker/local
docker compose down -v
docker compose up --build -d
```

## Notes

- The app uses `NODE_ENV=development` in this stack so local cookies continue to work over plain `http://localhost`.
- Studerria sessions are configured to use Redis by default in this stack (`SESSION_STORE_DRIVER=redis`).
- Container logs are centralized into Loki through Promtail; query them from your preferred Grafana/Loki client.
- The repository `uploads/` directory is mounted into the app container, so uploaded files stay visible in the workspace.
- `charredmap` keeps its own SQLite database and uploads in a dedicated Docker volume, so it stays operationally isolated from the Studerria Postgres app.
- `osix` keeps raw snapshots in its own Docker volume and normalized metrics in ClickHouse, so it stays operationally isolated from the Studerria Postgres app.
- `china-map` is static and keeps no database or upload volume.
- `naradadruk` and `slashtg` also keep their own SQLite data in dedicated Docker volumes.
- The legacy isolated Slash TG service is mounted at `/tg`.
- The Studerria student Telegram mini app is served by the main Express app at `/studerria-tg` and should be configured in a separate Telegram bot.
- If a sidecar service is unhealthy or stopped, the main Studerria app still starts; only that service route returns a temporary `503` or `404`.
- If the backup file is missing, PostgreSQL still starts empty and the app will create schema via its built-in migrations.

## Cleanup audits

Before deleting generated files or legacy compatibility code, run the read-only audit from the repository root:

```bash
npm run cleanup:audit
```

For legacy data, archive first and review the artifact before any destructive migration:

```bash
npm run legacy:archive
node scripts/legacy-archive.js --archive
```
