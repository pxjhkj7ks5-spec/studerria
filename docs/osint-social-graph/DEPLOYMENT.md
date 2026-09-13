# Deployment

## Current supported target: Docker Compose

The repository has no active Cloud Run deployment pipeline. The supported profile adds:

- `osint-db`: PostgreSQL 18, dedicated database/user/volume, internal network only;
- `osint-graph`: read-only filesystem, dropped capabilities, no published port, both app-facing and private DB networks;
- `app`: path-only reverse proxy for `/osint`; it never authenticates OSINT users or connects to the OSINT database.

These additions are also defined in `docker/local/docker-compose.osint.yml`. The update script layers that file over the base Compose configuration for `app` and `osint`, including on servers where the base file is intentionally retained as a local `skip-worktree` configuration.

Generate secrets once:

```bash
bash scripts/setup-osint-env.sh docker/local/.env
```

Deploy only this service boundary:

```bash
bash scripts/server-update.sh osint
```

The service update pulls Git, creates missing OSINT database/login/session secrets, backs up an existing OSINT database, rebuilds `osint-db`, `osint-graph`, and the path-proxying `app`, waits for each health check and prints logs. A first deploy skips backup only when no OSINT Compose volume exists.

## Cloud Run / Cloud SQL future profile

If the platform returns to Google Cloud, deploy `studerria-osint` as a non-public Cloud Run service with its own service account. Grant the Studerria caller only `roles/run.invoker`, send a Google-signed OIDC ID token with the service URL as audience, and combine IAM with internal ingress. Google documents these controls in [Cloud Run service-to-service authentication](https://cloud.google.com/run/docs/authenticating/service-to-service) and [ingress restrictions](https://docs.cloud.google.com/run/docs/securing/ingress).

Create `studerria_osint` plus a dedicated login in Cloud SQL using [Google's database management procedure](https://cloud.google.com/sql/docs/postgres/create-manage-databases). Reusing the same instance minimises cost but shares availability/admin boundaries; a new instance is stronger isolation and a real recurring cost. Do not infer that the legacy `/cloudsql` fallback means this profile is already deployed.

## Cost envelope

The current Compose MVP adds no managed-service bill: it consumes CPU, memory, disk and backups on the existing server. Keep one OSINT worker, no Redis/Neo4j, shallow collectors and a 90-day retention window; GitHub public REST and manual imports have no per-request platform charge.

For a future cloud profile, Cloud Run is pay-per-use and currently advertises a free allocation before usage pricing; see [Cloud Run pricing](https://cloud.google.com/run). A separate database in an existing Cloud SQL instance generally adds storage/backup use but no second compute instance. A separate `db-f1-micro` instance is listed at $0.0105/hour in `us-central1` (about $7.67 for 730 hours) before storage, backups, networking and regional price differences; it has no SLA. Treat this only as a dated planning example and calculate the intended region in the [official Cloud SQL pricing table](https://cloud.google.com/sql/pricing) before provisioning. X and other paid APIs are not enabled in MVP.

## Rollback and recovery

Application rollback is a Git revert plus the same `osint` update command. Database migrations are forward-only; restore the latest `backups/server-update/osint-postgres-*.dump` into an isolated database and validate before a destructive replacement. Never run `docker compose down -v` for a routine rollback.
