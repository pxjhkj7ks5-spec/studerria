# Local Docker Stack

This stack runs the current KMA app with PostgreSQL, Redis, and centralized logs through Docker Compose.

## What is included

- `app`: the existing Node.js + Express application from this repository
- `charredmap`: isolated Next.js memorial-map service mounted under `/charredmap`
- `db`: PostgreSQL 18 with first-start initialization from `docker/local/db/init/*.sql`
- `redis`: Redis 7 for Studerria session storage
- `loki`: log storage backend
- `promtail`: Docker log collector that forwards container logs to Loki

The stack includes a compatibility init script that creates the `cloudsqlsuperuser` role before importing Cloud SQL dumps, so Google Cloud exports restore cleanly on plain PostgreSQL.

## Included database backup

The Cloud SQL dump is expected at:

- `docker/local/db/init/20-cloud-run-backup.sql`

That file is intentionally gitignored. On this machine it has already been prepared from the provided backup. On another machine, place the dump there before the first boot if you want the imported production data.

## Start

```bash
cd docker/local
docker compose up --build -d
```

App URL:

- [http://localhost:3000](http://localhost:3000)
- [http://localhost:3000/charredmap](http://localhost:3000/charredmap)
- [http://localhost:3000/charredmap/admin](http://localhost:3000/charredmap/admin)

Observability:

- Loki API: [http://localhost:3100](http://localhost:3100)

Postgres host access:

- host: `localhost`
- port: `5433`
- database: `student_portal`
- user: `studerria`

Redis host access:

- host: `localhost`
- port: `6379`

## Optional env overrides

If you want custom ports or credentials, copy `.env.example` to `.env` in this folder and adjust the values.

For `charredmap`, set dedicated values for:

- `CHARREDMAP_ADMIN_PASSWORD`
- `CHARREDMAP_SESSION_SECRET`
- `CHARREDMAP_NODE_ENV=production` on the server behind HTTPS

## Update an existing server

For a normal application update, keep the existing PostgreSQL volume and run:

```bash
cd ~/studerria
git pull --rebase
cd docker/local
docker compose up --build -d
docker compose ps
docker compose logs --tail=100 app
docker compose logs --tail=100 charredmap
```

Do not run `docker compose down -v` for a routine update, because that recreates database and cache volumes.

### Deploy Fast (server routine)

Use this path when there are no Dockerfile/dependency changes and you only need the latest code:

```bash
cd ~/studerria
git pull --rebase
cd docker/local
docker compose up -d
docker compose ps
```

Server `.env` baseline:

```env
NODE_ENV=production
CHARREDMAP_NODE_ENV=production
```

If image build inputs changed (`Dockerfile`, `package.json`, `package-lock.json`, or build tooling), use:

```bash
docker compose up --build -d
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
- If `charredmap` is unhealthy or stopped, the main Studerria app still starts; only `/charredmap` returns a temporary `503`.
- If the backup file is missing, PostgreSQL still starts empty and the app will create schema via its built-in migrations.
