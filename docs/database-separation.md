# PostgreSQL service separation

Status: preflight only. No production connections or data have been changed.

Target: retain the existing Studerria PostgreSQL; move Obriy and Shieldline to
separate PostgreSQL 18 instances, named volumes and dedicated credentials.
No new database host ports. Preserve Obriy's encryption key and all service secrets.
SQLite services and OSIX ClickHouse are outside this migration.
Separate containers still share host CPU and disk; select resource budgets from
live usage rather than treating this as a guaranteed schedule-latency fix.

Run `bash scripts/audit-database-separation.sh` on the server first. It is read-only
and reports object ownership, cross-boundary foreign keys, view/trigger dependencies,
connections, free disk and RAM. No passwords or application row contents are printed.
Catalog dependency checks cannot detect every dynamic SQL reference; also review code.

Required cutover sequence, one service at a time:

1. Resolve live dependencies and produce an exact table/sequence/function manifest.
2. Create an isolated target with fresh credentials and sufficient disk headroom.
3. Rehearse a custom-format dump/restore with `--no-owner --no-acl` and
   `--exit-on-error`; verify constraints, sequence values and exact per-table counts.
4. Pause ALL service writers (including every Shieldline worker), drain connections,
   and take a final backup. Studerria remains online.
5. Restore into a fresh empty target; compare counts and stable content hashes while
   writers remain paused. Preserve source tables and encrypted backup off-server.
6. Switch only that service's connection configuration and start with outbound workers
   paused. Check health, authentication, reads and writes before enabling workers.
7. Back up the dedicated database independently and document restore verification.

Rollback before target writes: restore old connection configuration and restart writers.
Rollback after target writes: stop writers and reconcile/migrate new writes back first;
blindly switching to the stale source would lose data or repeat notifications.
Never run two active writer sets concurrently. Never drop source tables during cutover.
Source cleanup is a separate later step after a verified recovery window.

Deployment prerequisites: the existing update script backs up shared PostgreSQL for
Obriy/Shieldline. It must be changed to select their actual database before cutover;
all four Shieldline service definitions must move together. Server-local Compose
changes must be inspected and preserved, not replaced wholesale.
