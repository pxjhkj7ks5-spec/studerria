#!/usr/bin/env bash
# Read-only inventory. Never prints credentials, queries or application rows.
set -Eeuo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR/docker/local"
docker compose exec -T db sh -c 'exec psql -X -v ON_ERROR_STOP=1 -P pager=off -U "$POSTGRES_USER" -d "$POSTGRES_DB"' <<'SQL'
BEGIN READ ONLY;
SET LOCAL statement_timeout = '30s';
SELECT current_database() AS database, version();
SELECT n.nspname AS schema, c.relname AS object, c.relkind AS kind,
       pg_get_userbyid(c.relowner) AS owner,
       pg_size_pretty(pg_total_relation_size(c.oid)) AS size
FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
WHERE (n.nspname='obriy' OR (n.nspname='public' AND c.relname LIKE 'shieldline\_%'))
  AND c.relkind IN ('r','p','S','v','m')
ORDER BY n.nspname,c.relname;

-- Every foreign key crossing a proposed service boundary is a migration blocker.
WITH boundaries AS (
  SELECT c.oid, n.nspname, c.relname,
    CASE WHEN n.nspname='obriy' THEN 'obriy'
         WHEN n.nspname='public' AND c.relname LIKE 'shieldline\_%' THEN 'shieldline'
         ELSE 'other' END AS service
  FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
)
SELECT k.conname, a.nspname||'.'||a.relname AS source,
       b.nspname||'.'||b.relname AS target
FROM pg_constraint k
JOIN boundaries a ON a.oid=k.conrelid JOIN boundaries b ON b.oid=k.confrelid
WHERE k.contype='f' AND a.service<>b.service
  AND (a.service<>'other' OR b.service<>'other');

-- Review views/triggers/functions and extension dependencies before selecting dump objects.
SELECT DISTINCT pg_describe_object(d.classid,d.objid,d.objsubid) AS dependent,
       pg_describe_object(d.refclassid,d.refobjid,d.refobjsubid) AS referenced,
       d.deptype
FROM pg_depend d JOIN pg_class c ON d.refclassid='pg_class'::regclass AND d.refobjid=c.oid
JOIN pg_namespace n ON n.oid=c.relnamespace
WHERE (n.nspname='obriy' OR (n.nspname='public' AND c.relname LIKE 'shieldline\_%'))
  AND d.classid IN ('pg_rewrite'::regclass,'pg_trigger'::regclass,'pg_proc'::regclass)
ORDER BY 1,2;
SELECT extname,extversion FROM pg_extension;
SELECT datname,usename,application_name,state,count(*) AS connections
FROM pg_stat_activity WHERE backend_type='client backend'
GROUP BY datname,usename,application_name,state ORDER BY datname,usename;
COMMIT;
SQL
df -h "$ROOT_DIR"
free -h
docker stats --no-stream --format 'table {{.Name}}\t{{.MemUsage}}\t{{.CPUPerc}}'
