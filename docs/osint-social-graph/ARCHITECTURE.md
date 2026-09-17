> Current product: [OSINT Investigation Graph](../../services/osint-graph/README.md). The manual workspace supersedes the collector-oriented behavior described below; collection is disabled and investigations no longer expire automatically.

# Social Graph architecture

## Product boundary

Social Graph is an internal investigation workspace beside Studerria, not an academic portal module. The isolated service owns authentication, sessions, every investigation, observation, fact, inference, collector run and graph calculation.

Studerria acts only as a path reverse proxy. No Studerria identity, session, role, permission, cookie secret, database credential or account data crosses into Social Graph.

## Runtime components

- **Path proxy:** the existing app forwards `/osint` as it does for other isolated services; it performs no portal authentication for this route.
- **OSINT API/UI:** Express sidecar at `services/osint-graph`, externally reachable only through `/osint`, with its API under `/osint/api`.
- **Standalone auth:** dedicated environment credentials, a service-owned signed HttpOnly/Secure/SameSite=Strict cookie, login throttling and CSRF token checks.
- **OSINT database:** dedicated PostgreSQL service, database, user, password and volume. Its network is internal to Compose.
- **Run executor:** bounded in-process queue. State is persisted before work begins and terminal status is persisted after work ends. Startup recovery fails stale `queued/running` runs explicitly.
- **Collectors:** adapters implementing a common metadata, `collect()` and `normalize()` contract. Automated adapters are GitHub REST, safe bounded web collection and an optional third-party Instagram provider; manual import is always available.
- **Analysis:** deterministic application-side graph algorithms and transparent scoring. The summarizer interface consumes structured metrics and currently produces templates, not LLM output.

## Authentication boundary

The login endpoint compares the dedicated operator credentials in constant time and is independently rate-limited. A successful login creates an HMAC-signed, expiring session containing only the operator label, isolated actor ID and random CSRF token. Product APIs reject missing/invalid sessions; mutating requests additionally require the matching `X-OSINT-CSRF` header. Logout clears the service cookie. The cookie path is `/osint`, so it is not sent to ordinary Studerria routes.

## Data ownership and deletion

Every entity belongs to exactly one investigation in the MVP. This deliberately trades cross-case entity resolution for predictable privacy deletion and simple IDOR scoping. Investigation deletion cascades through graph data and analysis output. Audit records retain only the action, actor ID and minimal resource metadata; the deleted subject or imported raw body is not copied into audit logs.

## Provenance model

- An `observation` is a captured public-source statement or normalized import record.
- A `FACT` relationship can have one or more `relationship_evidence` rows with collector, source type, source URL, observation time and confidence.
- An `INFERENCE` relationship has an explanation and `inference_inputs` that point only to fact relationships.
- Analysis findings are structural descriptions, not identity or intent claims.

## Graph limits

The defaults are 500 nodes, 2,000 relationships, one-hop expansion, 300-node warning, 5 MB imports, five web pages and a collector timeout. All limits are server-side. Two-hop expansion is allowed only when it remains under the same hard limits.

## Frontend design brief

- **Visual thesis:** a calm, high-contrast intelligence canvas with translucent Tahoe-style controls, one cyan accent and the graph as the dominant material.
- **Content plan:** investigation rail; full-canvas graph; compact action bar; evidence inspector; findings/path drawer. There is no dashboard-card mosaic or marketing hero.
- **Interaction thesis:** staged graph entrance, spatial focus/dimming on selection, and a quick inspector/drawer transition. Reduced-motion users receive immediate state changes.

Nodes use both type-specific shapes/icons and color. Confidence, provenance and fact/inference status remain readable without relying on color alone.

## Deliberate MVP constraints

- No Neo4j, Redis queue or LLM dependency.
- No browser access to collector tokens.
- No Instagram passwords, cookies or direct in-service browser scraping. The optional Instagram adapter calls a separately reviewed provider and labels its evidence as non-official.
- No shared entities across investigations.
- No raw evidence archive or screenshot capture.
- No collector concurrency above the configured worker limit.
