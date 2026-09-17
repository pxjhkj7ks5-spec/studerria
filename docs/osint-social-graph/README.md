> Current product: [OSINT Investigation Graph](../../services/osint-graph/README.md). The manual workspace supersedes the collector-oriented behavior described below; collection is disabled and investigations no longer expire automatically.

# Social Graph / OSINT Graph MVP

Social Graph is an isolated, direct-link service beside Studerria for analysing relationships that are explicitly present in public or manually supplied data. It does not use the Studerria account/session, identify people, claim personal acquaintance, or turn structural inferences into facts.

## MVP capabilities

- create and delete investigations;
- add entities manually or import bounded JSON/CSV files and official Instagram Data Export ZIP archives;
- automatically attempt bounded public Instagram followers/following collection through an explicitly configured third-party provider;
- collect public GitHub data through the official REST API;
- inspect a small number of public web pages with SSRF protection;
- preserve a source URL, collector, observation time and confidence for facts;
- calculate degrees, mutual links, common neighbours, connected components, bridges, communities, shortest paths and transparent connection scores;
- explore the graph with filters, focus/hide/expand controls and a provenance inspector;
- persist collector/analysis runs and audit operator actions.

Instagram collection is best-effort and disabled until an Apify provider token is configured. It does not use an Instagram password or session cookie, never bypasses private profiles, and labels third-party observations with explicit provenance. Meta's official API still does not expose arbitrary follower/following identity lists. See [SOURCE_RESEARCH.md](./SOURCE_RESEARCH.md).

A free fallback requires no provider account: request the account owner's Instagram export with only **Followers and following**, select **JSON**, then upload the resulting ZIP and enter its owner username. The archive parser finds the connection files, creates directional `FOLLOWS` facts and discards unrelated archive content. This covers the operator's own/consensually supplied account export, not arbitrary third-party profiles.

## Local start

From the repository root:

```bash
bash scripts/setup-osint-env.sh docker/local/.env
docker compose -f docker/local/docker-compose.yml -f docker/local/docker-compose.osint.yml up -d --build osint-db osint-graph app
```

Open `http://localhost:3000/osint` directly and sign in with the separate Social Graph username/password. No link is added to the Studerria navigation.

The first `osint-db` start creates database `studerria_osint`, owner `osint_owner`, and a minimally privileged application login. `osint-graph` then applies only its own migrations. It receives no primary Studerria database credentials.

## Access

Access is configured only through `OSINT_ADMIN_USERNAME`, `OSINT_ADMIN_PASSWORD`, and `OSINT_SESSION_SECRET`. The service issues its own HTTP-only, Secure, SameSite=Strict cookie and requires a session-bound CSRF token for mutations. Studerria roles and credentials do not grant access.

## Demo and imports

Use **Demo graph** in the UI to load the 24-entity fictitious dataset at `services/osint-graph/fixtures/demo-social-graph.json`.

JSON must contain `entities` and `relationships` arrays. CSV can be one entity file (`id,type,name,platform,username,url`) and one relationship file (`source,target,type,weight,source_url`). Two files may be uploaded together. An Instagram ZIP must be uploaded alone and requires the owner's username. Imported cells that begin with spreadsheet formulas are neutralised before storage, ZIP entry count/decompressed size are capped, uploads remain in memory, and files are never executed or served.

## Environment

Copy only fake examples from `services/osint-graph/.env.example` and `docker/local/.env.example`. Required production values are:

- `OSINT_DATABASE_URL` — connection string for the separate OSINT database;
- `OSINT_ADMIN_USERNAME` and `OSINT_ADMIN_PASSWORD` — separate operator credentials;
- `OSINT_SESSION_SECRET` — at least 32 random characters for the service-owned signed session;
- `OSINT_DB_OWNER_PASSWORD` and `OSINT_DB_PASSWORD` — distinct generated database secrets.

To enable automatic Instagram attempts, set `OSINT_INSTAGRAM_APIFY_TOKEN`. The default community Actor is configurable through `OSINT_INSTAGRAM_APIFY_ACTOR_ID`; review its current terms, output and price before enabling it. `OSINT_INSTAGRAM_MAX_CONNECTIONS` and `OSINT_INSTAGRAM_MAX_COST_USD` cap each run.

Optional controls include `OSINT_GITHUB_TOKEN`, graph/import/page limits, collector timeout, rate limit, retention days and run concurrency. Secrets must remain in untracked environment files or a secret manager.

## Verification

```bash
cd services/osint-graph
npm ci
npm test
npm audit --omit=dev
```

Set `OSINT_TEST_DATABASE_URL` to an expendable PostgreSQL database to enable the migration/deduplication integration test. The GitHub workflow provisions PostgreSQL for this test.

The supporting documents describe the [architecture](./ARCHITECTURE.md), [database](./DATABASE.md), [security model](./SECURITY.md), [API](./API.md), [deployment](./DEPLOYMENT.md), and [roadmap](./ROADMAP.md).
