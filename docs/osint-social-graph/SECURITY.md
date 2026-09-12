# Security and privacy review

## Trust boundaries

The browser authenticates only to Studerria. Studerria checks the live `osint-access` permission on every request, strips caller-supplied identity/auth headers, and adds a short-lived HMAC assertion containing the opaque actor ID, timestamp and nonce. The sidecar verifies signature, age and nonce before serving UI or API routes. Direct calls without the assertion return 401; users without permission receive 403 at the gateway.

The HMAC secret is server-only and at least 32 characters in production. The sidecar has no Studerria session secret/store and no primary database credentials. The `osint-db` port is not published and is attached to an internal Compose network.

## Control review

| Risk | MVP control | Remaining limitation |
| --- | --- | --- |
| Authentication bypass | Session plus permission at gateway; independently signed assertion at sidecar | Nonce cache is per process; keep one replica in Compose MVP |
| IDOR | Every entity/run/path query is constrained by investigation ID | All holders of `osint-access` share investigations in MVP |
| CSRF | Studerria same-origin policy runs before the protected proxy; cookies are HTTP-only, secure in production, SameSite=Lax | No separate synchronizer token is added because same-origin enforcement is already authoritative |
| XSS | EJS escaped output, DOM escaping, safe URL protocols, CSP, no remote scripts | Public text still requires safe rendering in future export formats |
| SQL injection | Parameterised `pg` queries and strict enum/input validation | Migration SQL is trusted application code |
| SSRF | HTTP(S) only, default ports only, hostname/IP denylist, DNS validation, connection pinned to an approved public IP, redirects revalidated, byte/page/time limits | DNS rebinding defence depends on the pinned Node lookup remaining in use |
| Upload abuse | In-memory parsing, two-file/5 MiB defaults, record and row-size limits, extension/type allowlist, no execution or public persistence | Large but valid imports still consume bounded process memory |
| CSV injection | Formula-leading values are prefixed before storage | Exports added later must repeat this defence |
| Malicious JSON | depth/key/size/prototype validation and graph limits | Arbitrary metadata is retained only within configured bounds |
| Rate abuse | Per-actor API rate limit, bounded collector depth/concurrency, graph caps | Rate state is per process in MVP |
| Secret leakage | server-only environment, stripped proxy headers, redacted structured logs, no request bodies/tokens | Operator must keep `.env` untracked and rotate leaked credentials |
| Evidence confusion | `FACT`/`INFERENCE` status, evidence tables, confidence and “Why” UI | Imported source truth still depends on operator diligence |

## Collector safety

GitHub uses official public REST endpoints. The optional token never enters browser responses or logs. Website collection is intentionally shallow and does not bypass authentication, robots controls or access restrictions. Instagram and constrained networks do not use brittle scraping.

## Privacy and audit

Only data necessary for the selected investigation is stored. Operators can delete an investigation and all owned analysis data; automatic retention is configurable. Audit entries record actor, time, action, resource, collector and run status, but not credentials or full uploaded/remote payloads. Actor IDs are opaque references; OSINT does not copy user email/profile data.

## Deployment checklist

- generate three independent OSINT secrets and keep them outside Git;
- verify `osint-graph`/`osint-db` have no host ports;
- grant `osint-access` only to a dedicated role;
- confirm the OSINT application role cannot connect to the Studerria database;
- keep production at one worker/replica until replay and rate-limit state is externalised;
- back up and test restore of `studerria_osint`;
- review collector API terms and tokens periodically;
- verify logs contain request/run IDs but no tokens, cookies, import bodies or raw credentials.
