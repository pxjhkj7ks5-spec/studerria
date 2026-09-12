# Social Graph architecture

## Product boundary

Social Graph is an internal investigation workspace beside Studerria, not an academic portal module. Studerria owns identity and permission assignment. The isolated service owns every investigation, observation, fact, inference, collector run and graph calculation.

The only cross-boundary user data is an opaque numeric Studerria user ID and a display label in a short-lived signed request assertion. The OSINT service has no main-database credentials and does not call main-database APIs.

## Runtime components

- **Studerria gateway:** checks the `osint-access` permission on every UI/API request, applies the existing CSRF/session controls, strips spoofable identity headers and signs a fresh internal assertion.
- **OSINT API/UI:** Express sidecar at `services/osint-graph`, mounted externally only through Studerria at `/osint` and `/api/osint`.
- **OSINT database:** dedicated PostgreSQL service, database, user, password and volume. Its network is internal to Compose.
- **Run executor:** bounded in-process queue. State is persisted before work begins and terminal status is persisted after work ends. Startup recovery fails stale `queued/running` runs explicitly.
- **Collectors:** adapters implementing a common metadata, `collect()` and `normalize()` contract. The first automated adapters are GitHub REST and safe bounded web collection; manual import is always available.
- **Analysis:** deterministic application-side graph algorithms and transparent scoring. The summarizer interface consumes structured metrics and currently produces templates, not LLM output.

## Gateway assertion

The gateway adds `X-Studerria-OSINT-*` headers containing actor ID, display label, timestamp, nonce and an HMAC-SHA256 signature. The signature covers version, actor, timestamp and nonce. The service:

1. requires all fields;
2. validates the timestamp window;
3. compares the signature in constant time;
4. rejects replayed nonces;
5. removes expired nonce entries.

The Compose network boundary is primary; the HMAC is defense in depth and protects a mistakenly exposed service from anonymous product API access.

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
- No Instagram/X/LinkedIn/TikTok/Telegram scraping.
- No shared entities across investigations.
- No raw evidence archive or screenshot capture.
- No collector concurrency above the configured worker limit.
