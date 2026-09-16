# Security and privacy review

## Trust boundaries

The browser authenticates directly to Social Graph with credentials dedicated to this service. Studerria only forwards the `/osint` path and does not authorize it. The sidecar issues and verifies its own signed, expiring session cookie before serving product APIs; requests without the session return 401.

The session secret and operator password are server-only. The sidecar has no Studerria session secret/store and no primary database credentials. Its cookie is HTTP-only, Secure in production, SameSite=Strict and scoped to `/osint`. The `osint-db` port is not published and is attached to an internal Compose network.

## Control review

| Risk | MVP control | Remaining limitation |
| --- | --- | --- |
| Authentication bypass | Dedicated credentials, throttled login, HMAC-signed expiring service session | MVP has one environment-configured operator account |
| IDOR | Every entity/run/path query is constrained by investigation ID | The single standalone operator sees the whole OSINT workspace in MVP |
| CSRF | SameSite=Strict cookie plus a random session-bound `X-OSINT-CSRF` token on every mutation | Cookie remains same-host because `/osint` is path-proxied |
| XSS | EJS escaped output, DOM escaping, safe URL protocols, CSP, no remote scripts | Public text still requires safe rendering in future export formats |
| SQL injection | Parameterised `pg` queries and strict enum/input validation | Migration SQL is trusted application code |
| SSRF | HTTP(S) only, default ports only, hostname/IP denylist, DNS validation, connection pinned to an approved public IP, redirects revalidated, byte/page/time limits | DNS rebinding defence depends on the pinned Node lookup remaining in use |
| Upload abuse | In-memory parsing, two-file/5 MiB defaults, record and row-size limits, extension/type allowlist, no execution or public persistence | Large but valid imports still consume bounded process memory |
| CSV injection | Formula-leading values are prefixed before storage | Exports added later must repeat this defence |
| Malicious JSON | depth/key/size/prototype validation and graph limits | Arbitrary metadata is retained only within configured bounds |
| Rate abuse | Separate login throttle, per-session API rate limit, bounded collector depth/concurrency, graph and Instagram cost/result caps | Rate state is per process in MVP |
| Secret leakage | Server-only environment, redacted structured logs, no request bodies/passwords/session tokens | Operator must keep `.env` untracked and rotate leaked credentials |
| Evidence confusion | `FACT`/`INFERENCE` status, evidence tables, confidence and “Why” UI | Imported source truth still depends on operator diligence |

## Collector safety

GitHub uses official public REST endpoints. The optional token never enters browser responses or logs. Website collection is intentionally shallow and does not bypass authentication, robots controls or access restrictions.

Instagram follower identities are not available from Meta's official general-purpose APIs. The optional collector therefore sends only the requested public username, direction and bounded result count to the configured third-party provider. The provider token stays in the server environment and is sent in an Authorization header, never a URL or browser response. Instagram passwords, cookies and sessions are not accepted. Provider output is allowlisted to graph fields; contact enrichment is discarded. Enabling the provider requires a separate legal, privacy, retention and vendor review.

## Privacy and audit

Only data necessary for the selected investigation is stored. Operators can delete an investigation and all owned analysis data; automatic retention is configurable. Audit entries record the isolated operator ID, time, action, resource, collector and run status, but not credentials or full uploaded/remote payloads. OSINT does not copy Studerria user data.

## Deployment checklist

- generate independent database passwords, operator password and session secret and keep them outside Git;
- verify `osint-graph`/`osint-db` have no host ports;
- verify Studerria login alone cannot authorize `/osint` and the standalone login is shown;
- confirm the OSINT application role cannot connect to the Studerria database;
- keep production at one worker/replica until session/rate-limit state needs multi-replica support;
- back up and test restore of `studerria_osint`;
- review collector API terms and tokens periodically;
- verify logs contain request/run IDs but no tokens, cookies, import bodies or raw credentials.
