# Local Docker Stack

This stack runs the current KMA app with PostgreSQL through Docker Compose.

## What is included

- `app`: the existing Node.js + Express application from this repository
- `charredmap`: isolated Next.js memorial-map service mounted under `/charredmap`
- `db`: PostgreSQL 18 with first-start initialization from `docker/local/db/init/*.sql`

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

Postgres host access:

- host: `localhost`
- port: `5433`
- database: `student_portal`
- user: `studerria`

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

Do not run `docker compose down -v` for a routine update, because that recreates the database volume.

## Re-import the backup from scratch

The PostgreSQL dump is imported only when the database volume is empty. To recreate the database and re-run the import:

```bash
cd docker/local
docker compose down -v
docker compose up --build -d
```

## Notes

- The app uses `NODE_ENV=development` in this stack so local cookies continue to work over plain `http://localhost`.
- The repository `uploads/` directory is mounted into the app container, so uploaded files stay visible in the workspace.
- `charredmap` keeps its own SQLite database and uploads in a dedicated Docker volume, so it stays operationally isolated from the Studerria Postgres app.
- If `charredmap` is unhealthy or stopped, the main Studerria app still starts; only `/charredmap` returns a temporary `503`.
- If the backup file is missing, PostgreSQL still starts empty and the app will create schema via its built-in migrations.
