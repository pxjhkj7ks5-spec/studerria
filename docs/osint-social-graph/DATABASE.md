# OSINT database

## Isolation

The Compose profile creates a physical PostgreSQL database named `studerria_osint` in the dedicated `osint-db` container and `osint_postgres_data` volume. `osint_owner` owns the database. `studerria_osint` is a separate login with only connect/schema rights needed to create and operate OSINT-owned objects. It is `NOSUPERUSER`, `NOCREATEDB`, `NOCREATEROLE`, and `NOINHERIT`.

The OSINT service receives only `OSINT_DATABASE_URL`. It never receives `DB_HOST`, `DB_PASS`, `POSTGRES_PASSWORD`, the main app session secret, or access to the `student_portal` database. Conversely, the main app does not receive the OSINT database URL.

## Schema

Migrations live only in `services/osint-graph/src/migrations` and are tracked in `osint_schema_migrations`.

- `investigations`: case name, description, opaque creator ID, lifecycle timestamps and optional retention expiry.
- `entities`: investigation-owned typed nodes with canonical/display names and bounded JSONB metadata.
- `social_accounts`: platform-specific public account fields for an entity.
- `observations`: source URL, source type, collector, observation time and bounded raw public payload.
- `relationships`: directed graph edges, weight, confidence and an explicit `FACT` or `INFERENCE` status.
- `relationship_evidence`: one or more source records supporting a relationship.
- `relationship_inference_inputs`: facts used by an inference; inference and evidence cannot be silently merged.
- `interactions`: timestamped public interactions with provenance.
- `analysis_runs`: durable `queued`, `running`, `completed`, or `failed` collector/analysis jobs.
- `findings`: deterministic structural findings derived from one analysis run.
- `audit_logs`: actor, action, resource and bounded metadata without a cross-database user foreign key.

All graph children are scoped by `investigation_id`, with composite foreign keys preventing cross-investigation references. Unique constraints deduplicate canonical entities, platform usernames and equivalent relationship facts. Indexes cover investigation ownership, entity type, JSONB metadata, graph endpoints/types, observations, run status and audit time.

## Deletion and retention

Deleting an investigation cascades to its entities, accounts, relationships, evidence, observations, interactions, runs and findings. `OSINT_RETENTION_DAYS` defaults to 90; an internal daily task deletes expired investigations. Shared global entity records are deliberately absent in the MVP, so deletion has deterministic semantics.

The server update script takes a custom-format `pg_dump` before an existing OSINT deployment. On the first deployment it skips backup only if no Compose OSINT volume exists; an existing volume without a running database blocks the update.

## Production database options

The current target is the separate Compose PostgreSQL container. If deployed to Cloud SQL later, create a distinct database and login in the existing instance for the lowest incremental cost, or a distinct instance for stronger resource/network isolation. A separate database is a security boundary for credentials and privileges, but not for instance availability or the Cloud SQL administrator.
