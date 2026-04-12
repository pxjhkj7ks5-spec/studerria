# studerria
Student portal (`Node.js + Express + EJS + Postgres`) with Docker Compose as the primary runtime.

The repository now also vendors `charredmap` as a separate service proxied through Studerria at:

- `/charredmap`
- `/charredmap/admin`

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
docker compose up --build -d
docker compose ps
docker compose logs --tail=100 app
```

Use `docker compose down -v` only when you intentionally want to recreate the PostgreSQL volume or re-import the SQL dump from scratch.

## Legacy infrastructure

`cloudbuild.yaml` and old Cloud Run-related assets are legacy artifacts and are no longer the active deployment target.
