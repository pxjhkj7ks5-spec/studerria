# studerria
Student portal (`Node.js + Express + EJS + Postgres`) with Docker Compose as the primary runtime.

The repository also vendors three live sidecar services that are proxied through Studerria:

- `charredmap`: `/charredmap`, `/charredmap/admin`
- `naradadruk`: `/naradadruk`
- `slashtg`: `/tg`

## Primary runtime

The current deployment path is Docker Compose from:

- `docker/local/docker-compose.yml`

Local and server-specific notes live in:

- `docker/local/README.md`

## Fresh start

```bash
cd docker/local
docker compose up --build -d
```

## Update an existing server

Run this on the server from the repository root:

```bash
cd ~/studerria
git pull --rebase
cd docker/local
docker compose up -d
docker compose ps
docker compose logs --tail=100 app
```

Use `docker compose down -v` only when you intentionally want to recreate the PostgreSQL volume or re-import the SQL dump from scratch.

## Cleanup and legacy archive workflow

Use the cleanup audit before deleting repo files or local artifacts:

```bash
npm run cleanup:audit
```

The audit is read-only. It separates safe ignored cleanup candidates from protected local files such as `docker/local/.env` and SQL dumps.

Legacy compatibility must be archived before destructive schema work:

```bash
npm run legacy:archive
node scripts/legacy-archive.js --archive
```

The archive command exports a JSON report under `artifacts/`. It does not drop tables or columns; destructive legacy migrations must be reviewed separately after the archive is verified.
