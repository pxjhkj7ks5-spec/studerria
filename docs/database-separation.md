# PostgreSQL service separation

Status: audit, isolated rehearsal and operator-run Obriy cutover available.
Shieldline has a separate operator-run cutover after Obriy is healthy.

## Shieldline cutover

After its rehearsal succeeds and Obriy's state is `complete`, run
`python3 scripts/separate-shieldline-database.py --execute` during a Shieldline
maintenance window. The main service and all three workers are stopped before
the final dump. A non-graceful writer shutdown aborts the operation. Only
`public.shieldline_*` tables/sequences are copied; cross-boundary foreign keys
block migration. Row digests, counts and sequence states must match the stopped
source before any target application starts.

The existing JSON Compose override from the Obriy migration is backed up privately
and merged, never replaced wholesale. Effective configurations of ALL unrelated
services must remain identical. If the override changes concurrently, activation
is refused. Shieldline gets `shieldline-db`, its own internal network, volume,
administrator and restricted application role. Passwords remain local and gitignored.

The main service starts first and must pass the PostgreSQL health endpoint. Workers
then start and must publish fresh heartbeats into the target. An intentionally
disabled admin bot is exempt from heartbeat checks. Its drop-pending-updates option
is set to false so restarting does not discard pending Telegram updates.

Success: `SHIELDLINE_DATABASE_SEPARATED_OK`. State:
`.local/shieldline-database-cutover.json`. Before activation, failure resumes the
original writers and retains the original override. After activation, failure pauses
ALL Shieldline writers and never resumes the stale source automatically. Source
tables and dump remain intact. Do not rerun, remove state, or start old containers
after an error without inspecting the migration phase. Subsequent service updates
back up the dedicated Shieldline database and refuse to proceed if that backup fails.

## Obriy cutover

Only after a successful rehearsal and within an Obriy maintenance window, run
`python3 scripts/separate-obriy-database.py --execute` from the server checkout.
This stops Obriy while dumping and verifying its complete data. Allow several minutes
for the large history table. Studerria and Shieldline remain running.

The command refuses existing targets, existing Compose overrides, unexpected connections,
Compose/live environment drift, less than 10 GiB free space, or cross-schema foreign keys.
It creates a dedicated PostgreSQL with no published ports on an internal network,
1 GiB memory limit, one CPU, separate volume and fresh credentials. The application
role has no superuser, role-management or database-creation privilege; it owns only
its dedicated database/schema for migrations. The administrator password is in a
private file under `.local/obriy-database-secrets/`; never rotate/delete that file during cleanup.
The active Compose override also contains a credential and is mode 600/gitignored.
Do not remove these paths in generic backup rotation.

All source/target table row counts and sorted row-digest fingerprints, plus sequence
state, must match before activation. The source is checked twice to detect continued
writes. Existing Obriy encryption keys are preserved. Server update backups then
select `obriy-db` and fail closed if its backup fails.

State lives in `.local/obriy-database-cutover.json`. A state other than `complete`
blocks further Obriy updates. Failure before activation restarts the original container;
failure after activation pauses Obriy and requires explicit reconciliation of target
writes, not an automatic switch to stale data. All databases/dumps remain intact.
Do not erase state to retry or run whole-stack Compose during migration.
The final success marker is `OBRIY_DATABASE_SEPARATED_OK`.

Existing source tables are deliberately retained. Shared PostgreSQL backups therefore
still contain the old Obriy snapshot until a later approved source cleanup.

## Restore rehearsal

Run `bash scripts/rehearse-database-separation.sh obriy`, then separately run
`bash scripts/rehearse-database-separation.sh shieldline` on the server.
The script takes a consistent service-scoped dump, uses the exact source PostgreSQL
image, restores with errors fatal into a fresh volume, lists exact restored row counts
and sequence values, and stops the rehearsal container. It refuses to overwrite
existing targets. CPU is limited to one core and RAM to 1 GiB. `--network none`
and no published ports prevent application or external access. The administrator
credential is unique to rehearsal, not a production application credential.

Backups and inventories are retained under `backups/db-rehearsal/` with private
permissions. Treat dumps and the generated credential file as sensitive.
Failure retains artifacts for diagnosis; an unsuccessful target may still be running.
This stage creates only rehearsal resources; it neither changes production connections
nor runs application workers. Compare live counts only during the final paused-writer
cutover: the source continues changing while this rehearsal runs.
Do not start applications against these targets or treat their copies as current.
Report `RESTORE_REHEARSAL_OK` and the inventory before preparing cutover.

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
# Retrying an interrupted Shieldline preparation

After fixing the source shutdown issue, an operator may run
`python3 scripts/separate-shieldline-database.py --execute --retry-failed`.
This is a real maintenance-window cutover, not a dry run. It is allowed only for
`failed-before-activation-source-retained`, with unchanged source and override,
an isolated empty target and no other database clients. Existing credentials and
target volume are retained; previous state is archived in the new backup directory.
Current writer container IDs are rediscovered. A fresh dump and full comparison
are required. Failures after activation still prohibit automatic rollback.
