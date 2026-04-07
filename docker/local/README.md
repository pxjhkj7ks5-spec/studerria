# Local Docker Stack

This stack runs the current KMA app with PostgreSQL through Docker Compose.

## What is included

- `app`: the existing Node.js + Express application from this repository
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

Postgres host access:

- host: `localhost`
- port: `5433`
- database: `student_portal`
- user: `studerria`

## Optional env overrides

If you want custom ports or credentials, copy `.env.example` to `.env` in this folder and adjust the values.

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
- If the backup file is missing, PostgreSQL still starts empty and the app will create schema via its built-in migrations.
