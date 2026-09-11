#!/usr/bin/env bash
# Restore a consistent source dump into an isolated, disposable PostgreSQL.
# Never stops applications, edits connection settings, or deletes source data.
set -Eeuo pipefail
umask 077
service="${1:-}"
case "$service" in
  obriy) selection=(--schema=obriy) ;;
  shieldline) selection=('--table=public.shieldline_*') ;;
  *) echo 'Usage: bash scripts/rehearse-database-separation.sh obriy|shieldline' >&2; exit 2 ;;
esac
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR/docker/local"
command -v openssl >/dev/null
source_id="$(docker compose ps -q db)"
[ -n "$source_id" ] || { echo 'Source database is not running.' >&2; exit 1; }
image_id="$(docker inspect --format '{{.Image}}' "$source_id")"
target="kma-db-rehearsal-$service"
volume="kma-db-rehearsal-$service-data"
if docker container inspect "$target" >/dev/null 2>&1 || docker volume inspect "$volume" >/dev/null 2>&1; then
  echo "Refusing to overwrite existing rehearsal: $target / $volume" >&2
  exit 1
fi
docker_root="$(docker info --format '{{.DockerRootDir}}')"
for location in "$ROOT_DIR" "$docker_root" /var/lib/containerd; do
  [ -d "$location" ] || continue
  available="$(df -Pk "$location" | awk 'END {print $4}')"
  [ "$available" -ge 10485760 ] || { echo "Need at least 10 GiB free at $location" >&2; exit 1; }
done
mkdir -p "$ROOT_DIR/backups/db-rehearsal"
run_dir="$(mktemp -d "$ROOT_DIR/backups/db-rehearsal/$service.XXXXXXXX")"
trap 'echo "Rehearsal files retained at $run_dir; no source data or application settings were changed."' EXIT
echo 'Creating a consistent backup. Source services remain online.'
docker exec "$source_id" sh -c 'exec pg_dump -Fc --lock-wait-timeout=10s --no-owner --no-acl -U "$POSTGRES_USER" -d "$POSTGRES_DB" "$@"' sh "${selection[@]}" > "$run_dir/source.dump"
test -s "$run_dir/source.dump"
docker exec -i "$source_id" pg_restore --list < "$run_dir/source.dump" > "$run_dir/archive-list.txt"
if ! grep -q 'TABLE DATA' "$run_dir/archive-list.txt"; then
  echo 'Backup contains no table data entries; refusing to continue.' >&2
  exit 1
fi
# The generated administrator exists ONLY in this network-isolated rehearsal.
# Production cutover requires a separate restricted application role.
printf 'POSTGRES_USER=rehearsal_admin\nPOSTGRES_DB=%s\nPOSTGRES_PASSWORD=%s\n' "$service" "$(openssl rand -hex 32)" > "$run_dir/.env"
docker volume create --label kma.purpose=db-rehearsal "$volume" >/dev/null
docker run -d --name "$target" --label kma.purpose=db-rehearsal \
  --network none --memory 1g --cpus 1 --shm-size 128m \
  --env-file "$run_dir/.env" -v "$volume:/var/lib/postgresql" "$image_id" >/dev/null
ready=0
for ((attempt=0; attempt<60; attempt++)); do
  # The image's temporary initialization server accepts Unix sockets only.
  # Wait for TCP so restore cannot race the initialization server shutdown.
  if docker exec "$target" pg_isready -h 127.0.0.1 -U rehearsal_admin -d "$service" >/dev/null 2>&1; then
    ready=1; break
  fi
  sleep 2
done
[ "$ready" = 1 ] || { echo 'Target database did not become ready.' >&2; exit 1; }
echo 'Restoring into the empty isolated target; no application can connect to it.'
docker exec -i "$target" pg_restore --exit-on-error --single-transaction \
  --no-owner --no-acl -U rehearsal_admin -d "$service" < "$run_dir/source.dump"
docker exec -i "$target" psql -X -v ON_ERROR_STOP=1 -P pager=off -U rehearsal_admin -d "$service" <<'SQL' > "$run_dir/restored-inventory.txt"
BEGIN READ ONLY;
SET LOCAL statement_timeout='120s';
SELECT format('SELECT %L AS table_name, count(*) AS rows FROM %I.%I;', schemaname||'.'||tablename,schemaname,tablename)
FROM pg_tables WHERE schemaname='obriy' OR (schemaname='public' AND tablename LIKE 'shieldline\_%') ORDER BY schemaname,tablename
\gexec
SELECT schemaname,sequencename,last_value FROM pg_sequences
WHERE schemaname='obriy' OR (schemaname='public' AND sequencename LIKE 'shieldline\_%');
SELECT pg_size_pretty(pg_database_size(current_database())) AS restored_database_size;
COMMIT;
SQL
cat "$run_dir/restored-inventory.txt"
docker stop "$target" >/dev/null
echo "RESTORE_REHEARSAL_OK service=$service target=$target (stopped) volume=$volume"
echo 'This verifies restoration only. It is NOT a production cutover or live-source equality check.'
