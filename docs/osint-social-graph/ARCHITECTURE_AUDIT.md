# Studerria architecture audit for Social Graph

Audit date: 2026-09-12. This document describes the checked-in `main` worktree before the OSINT service was added. Runtime secrets and the live server were not inspected.

## Current Studerria architecture

### Application stack

- The Studerria portal is a Node.js 20 application built on Express 5, EJS server-rendered views, plain browser JavaScript and CSS. The main process is `app.js`.
- PostgreSQL is accessed through `pg`. The application has a small compatibility wrapper that converts SQLite-style `?` placeholders to PostgreSQL placeholders.
- Authentication is local username/password authentication with `bcryptjs`. The authenticated user and their current role set are stored in an `express-session` session.
- Sessions use Redis in the current Compose profile and can fall back to a PostgreSQL `connect-pg-simple` store. The cookie is HTTP-only, `SameSite=Lax`, secure in production, rolling, and subject to idle and absolute expiry.
- Authorization uses `access_roles`, `access_permissions`, `access_role_permissions` and `user_roles`. Existing permissions are split between `admin_section` and `feature` categories. The legacy `users.role` value remains as a compatibility field.
- Security middleware includes Helmet/CSP, same-origin checks for authenticated mutating requests, request size limits, upload allowlists and session rotation when roles change.
- A `ws` WebSocket server shares the HTTP server. Upgrades require a valid session, a same-host Origin and an authorized channel. Existing channels cover messages and admin updates.
- Logs are structured only in selected areas; most application logs use stdout/stderr. Compose sends Docker logs through Promtail to Loki. Runtime health and session-store errors have structured JSON payloads.

### Data and migrations

- The primary database is the Compose `db` service (PostgreSQL 18) with the configured `POSTGRES_DB`, normally `student_portal`.
- Main-app migrations are JavaScript modules in `migrations/`, loaded lexically by `migrations/index.js` and applied by the startup migration runner.
- The main database contains academic, account, RBAC, session, audit and portal operational data. It is not an acceptable store for OSINT investigation data.
- Existing service-separation work for Obriy and Shieldline demonstrates the repository's direction toward isolated service data, but their current checked-in Compose environment still points at the shared `db` service. That configuration must not be copied for Social Graph.

### Deployment and networking

- The authoritative deployment target is Docker Compose under `docker/local`. The base stack is in `docker-compose.yml`; isolated OSINT services also have an additive `docker-compose.osint.yml` overlay so server-local base Compose customizations can remain untouched. A changed service is rebuilt independently with `scripts/server-update.sh <service>`.
- The main `app` container is the public entry point and reverse-proxies sidecars with `http-proxy-middleware`. The checked-in Compose file currently uses the default Compose network and exposes only selected ports.
- The production notes describe a trusted reverse-proxy/Cloudflare Tunnel hop and configure Express `TRUST_PROXY` accordingly. The exact external proxy configuration is not stored in this repository.
- No current Cloud Run deployment manifest, Cloud Build deployment pipeline or active Cloud SQL provisioning configuration exists in the repository. `app.js` retains a legacy `/cloudsql/<INSTANCE_CONNECTION_NAME>` host fallback, but project rules explicitly identify Docker Compose as the active target.
- There is no repository-defined staging environment. CI is GitHub Actions and is service-specific (currently NaradaDruk image publishing, YKG image publishing, and Obriy/Shieldline verification); there is no whole-Studerria deploy workflow.
- Secrets are expected in untracked `docker/local/.env` or the server environment. Tracked `.env.example` files contain placeholders. Service tokens must remain server-side.

## What can be reused

- Studerria's login, session expiry, secure cookie and role-assignment flows.
- The existing PostgreSQL RBAC model and Role Studio UI by adding one explicit `osint-access` permission. No email allowlist is needed.
- The public app as a narrow authenticated reverse-proxy/gateway at `/osint` and `/api/osint`.
- Helmet/security-header principles, same-origin CSRF gate, request IDs, service health checks, read-only containers, dropped Linux capabilities and Compose service health dependencies.
- PostgreSQL, JavaScript migrations and application-side deterministic graph algorithms. Neo4j and Redis are unnecessary for the MVP.
- Polling for persisted collector/analysis run statuses. The existing WebSocket server should not be coupled to the new service in the first version.
- Existing Apple Liquid Glass visual language, spacing and theme conventions, adapted to a dense graph workspace rather than an admin page.

## What must not be reused

- The primary Studerria database, its database user or its connection string for OSINT entities, relationships, observations, uploads, runs or audit events.
- Browser-only route hiding as authorization. Both the Studerria gateway and OSINT service boundary must reject unauthorized/direct requests.
- Main-app controllers for collectors or graph analysis. Collection, normalization, storage and analysis belong entirely to the isolated service.
- Main Studerria sessions inside the sidecar. Sharing the session secret or session store would widen the blast radius.
- Generic public sidecar proxy registration, because it runs before Studerria session middleware and is intentionally unauthenticated.
- Existing general-purpose upload storage. OSINT imports are parsed in memory under separate size/record limits and are never executed or publicly served.
- The legacy Cloud Run/Cloud SQL fallback as evidence of an active cloud deployment.

## Integration risks

1. **Authorization bypass:** a public or generic proxy route could bypass the RBAC check. The OSINT routes must be registered after session/RBAC middleware and the sidecar must require a signed gateway assertion.
2. **Credential crossover:** reusing `POSTGRES_*` would expose the portal database. Compose must use distinct `OSINT_DB_*` values and a dedicated database container/volume/user.
3. **IDOR:** every investigation, entity, path, import and run query must be scoped to a caller-visible investigation. MVP access is shared among OSINT-authorized operators, with actor IDs preserved in the audit log.
4. **SSRF:** the website collector can reach internal services unless scheme, port, hostname, DNS result and every redirect are validated and the connection is pinned to an approved public address.
5. **Unbounded graph/API use:** collectors and imports require hard node, edge, page, byte, depth, duration and per-user request limits.
6. **Evidence confusion:** inferred clusters and scores can be mistaken for facts. Facts, inferences and their input evidence require separate fields/tables and distinct UI labels.
7. **Sensitive logging:** tokens, raw import bodies and full collector payloads must not appear in stdout or audit metadata.
8. **Long-running work:** an in-process MVP worker can lose a running task during restart. Runs must be persisted as `queued/running/completed/failed`; restart recovery must mark abandoned runs failed. A durable external queue remains a later option.
9. **External API drift:** Instagram, X, LinkedIn, TikTok and Telegram access changes frequently. Unsupported collectors must remain manual/disabled rather than fall back to brittle scraping.

## Proposed MVP architecture

```text
browser
  | Studerria secure session + same-origin CSRF policy
  v
Studerria app
  | lookup role permissions in primary Studerria DB
  | short-lived HMAC gateway assertion (user id, timestamp, nonce)
  v
osint-graph service (no Studerria DB credentials)
  | REST + graph UI + collectors + in-process job abstraction
  v
osint-db PostgreSQL
  dedicated database, role, password, migrations and volume
```

- UI URL: `/osint`; API prefix: `/api/osint`.
- Permission: `osint-access` in the main RBAC catalog. It is granted through Role Studio (for example to a custom `osint_admin` role), never by email.
- Trust boundary: the sidecar accepts all product requests only with a valid `OSINT_GATEWAY_SECRET` HMAC assertion and enforces replay/age limits. The secret is not sent to the browser.
- Storage: investigation-owned entities make deletion deterministic: deleting an investigation cascades through entities, accounts, facts, evidence, observations, interactions, runs and findings. Actor IDs are opaque references to Studerria users and have no foreign key to the primary database.
- Jobs: collector and analysis runs are persisted and executed by a bounded in-process worker in the MVP. The UI polls their status. No Redis dependency is introduced.
- Collectors: manual JSON/CSV, official GitHub REST and a bounded SSRF-safe website collector are supported. Instagram remains a manual-import adapter unless official platform capabilities materially change.
- Graph: PostgreSQL adjacency data is analyzed application-side for degree, mutual/common neighbors, paths, connected components, articulation/bridge nodes and deterministic communities. Cytoscape.js is used for the interactive graph rather than custom SVG.
- Deployment: add `osint-db` on an internal-only Compose network and `osint-graph` on both that network and the app-facing Compose network. Do not publish either service port in production.

## Cloud option assessment

If Studerria later returns to Google Cloud, the equivalent design is a private `studerria-osint` Cloud Run service invoked only by the Studerria service account with `roles/run.invoker` and a Google-signed ID token. OSINT should use a dedicated Cloud SQL database and user (or, for stronger isolation, a dedicated instance). This is documented as a future deployment profile only; it is not the current deployment target.
