# OSINT API

All product endpoints are under `/osint/api` and require the separate Social Graph session. Mutating endpoints additionally require the session CSRF token in `X-OSINT-CSRF`. JSON errors use `{ "ok": false, "error": "stable_code" }`. Collector and analysis work returns `202` and is polled by run ID.

| Method | Endpoint | Purpose |
| --- | --- | --- |
| `GET` | `/health` | Database-aware service health (no credentials returned) |
| `POST` | `/auth/login` | Create a standalone Social Graph session |
| `GET` | `/auth/session` | Read the current operator label and CSRF token |
| `POST` | `/auth/logout` | End the standalone session |
| `GET` | `/collectors` | Supported collector capabilities |
| `GET` | `/investigations` | List authorized workspace investigations |
| `POST` | `/investigations` | Create investigation |
| `GET` | `/investigations/:id` | Investigation and latest findings |
| `DELETE` | `/investigations/:id` | Cascade-delete investigation data |
| `POST` | `/investigations/:id/entities` | Add one normalised entity |
| `POST` | `/investigations/:id/import` | Import up to two multipart CSV/JSON files |
| `POST` | `/investigations/:id/collect` | Queue bounded `github`, `instagram` or `web` collection |
| `POST` | `/investigations/:id/analyze` | Queue deterministic analysis |
| `GET` | `/investigations/:id/runs/:runId` | Poll persisted job status/result |
| `GET` | `/investigations/:id/graph` | Entities, relationships, interactions and metrics |
| `GET` | `/investigations/:id/entities/:entityId` | Entity card, evidence and connection scores |
| `GET` | `/investigations/:id/entities/:entityId/neighbors?depth=1` | Bounded one/two-hop neighbourhood |
| `GET` | `/investigations/:id/path?from=&to=` | Shortest observed path with entity details |
| `POST` | `/demo` | Create a safe fictitious investigation |

## Import JSON

```json
{
  "entities": [
    { "id": "ada", "type": "SOCIAL_ACCOUNT", "name": "Ada Code", "platform": "github", "username": "ada-code", "url": "https://github.com/ada-code" }
  ],
  "relationships": [
    { "source": "ada", "target": "team", "type": "MEMBER_OF", "weight": 1, "confidence": 1, "source_url": "https://github.com/orgs/example/people" }
  ]
}
```

Relationship provenance is required by collectors and demo/import data should provide `source_url`. A relationship may have multiple evidence records. `INFERENCE` rows additionally reference their input facts; collectors do not fabricate them.

## Collector requests

```json
{ "collector": "github", "username": "octocat", "depth": 1 }
```

```json
{ "collector": "web", "url": "https://example.org" }
```

```json
{ "collector": "instagram", "username": "public.account", "direction": "both", "limit": 100 }
```

Instagram queues a best-effort third-party provider run. The configured service maximum overrides the requested limit. Missing provider configuration and provider failures are saved as stable run errors rather than silently producing an empty graph.

The GitHub depth is clamped to 1–2. Website page, redirect, response-size and duration limits are server configuration. The graph rejects growth above the configured node/relationship caps.
