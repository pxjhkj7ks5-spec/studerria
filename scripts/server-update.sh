#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="docker/local/docker-compose.yml"
LOG_TAIL="${LOG_TAIL:-80}"
HEALTH_WAIT_SECONDS="${HEALTH_WAIT_SECONDS:-120}"
HEALTH_POLL_INTERVAL_SECONDS="${HEALTH_POLL_INTERVAL_SECONDS:-2}"
BACKUP_DIR="${BACKUP_DIR:-$ROOT_DIR/backups/server-update}"
SERVICE="app"
BUILD=1
PULL=0
SHOW_LOGS=1
BACKUP_DATA=1

usage() {
  cat <<'USAGE'
Usage:
  bash scripts/server-update.sh [service] [--build|--no-build] [--pull] [--skip-backup] [--no-logs] [--logs N]

Services:
  app          Main Studerria app
  charredmap   /charredmap sidecar
  china-map    /china-map sidecar
  naradadruk   /naradadruk sidecar
  slashtg      /tg sidecar
  withlforl    /withlforl sidecar
  osix         /osix sidecar
  shieldline   /shieldline sidecar
  db           PostgreSQL
  redis        Redis
  loki         Loki
  promtail     Promtail

Examples:
  bash scripts/server-update.sh app
  bash scripts/server-update.sh charredmap
  bash scripts/server-update.sh naradadruk --pull
  bash scripts/server-update.sh withlforl
  bash scripts/server-update.sh osix
  bash scripts/server-update.sh shieldline
USAGE
}

normalize_service() {
  case "$1" in
    app|studerria|main) echo "app" ;;
    charredmap|charred-map) echo "charredmap" ;;
    china-map|chinamap|china) echo "china-map" ;;
    naradadruk|narada-druk) echo "naradadruk" ;;
    slashtg|slash-tg|tg) echo "slashtg" ;;
    withlforl|with-l-for-l) echo "withlforl" ;;
    osix) echo "osix" ;;
    shieldline|shield-line) echo "shieldline" ;;
    db|postgres|postgresql) echo "db" ;;
    redis) echo "redis" ;;
    loki) echo "loki" ;;
    promtail) echo "promtail" ;;
    *)
      echo "Unknown service: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
}

service_set=0

while [ "$#" -gt 0 ]; do
  case "$1" in
    --build)
      BUILD=1
      ;;
    --no-build)
      BUILD=0
      ;;
    --pull)
      PULL=1
      BUILD=0
      ;;
    --skip-backup)
      BACKUP_DATA=0
      ;;
    --no-logs)
      SHOW_LOGS=0
      ;;
    --logs)
      if [ "$#" -lt 2 ]; then
        echo "--logs requires a number" >&2
        exit 2
      fi
      LOG_TAIL="$2"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    -*)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
    *)
      if [ "$service_set" -eq 1 ]; then
        echo "Only one service can be updated per run: got '$SERVICE' and '$1'" >&2
        exit 2
      fi
      SERVICE="$(normalize_service "$1")"
      service_set=1
      ;;
  esac
  shift
done

timestamp() {
  date -u +"%Y%m%dT%H%M%SZ"
}

ensure_backup_dir() {
  mkdir -p "$BACKUP_DIR"
}

backup_compose_volume_mount() {
  service_name="$1"
  mount_destination="$2"
  backup_label="$3"

  container_id="$(docker compose ps -q "$service_name" 2>/dev/null || true)"
  if [ -z "$container_id" ]; then
    echo "Backup skipped for $service_name: container is not running."
    return 0
  fi

  volume_name="$(
    docker inspect "$container_id" \
      --format "{{range .Mounts}}{{if eq .Destination \"$mount_destination\"}}{{.Name}}{{end}}{{end}}" \
      2>/dev/null || true
  )"
  if [ -z "$volume_name" ]; then
    echo "Backup skipped for $service_name: no named volume mounted at $mount_destination."
    return 0
  fi

  ensure_backup_dir
  backup_file="$BACKUP_DIR/${backup_label}-$(timestamp).tgz"
  echo "Backing up Docker volume $volume_name to $backup_file"
  if ! docker run --rm \
    -v "$volume_name:/source:ro" \
    -v "$BACKUP_DIR:/backup" \
    alpine:3.20 \
    sh -c "cd /source && tar czf /backup/$(basename "$backup_file") ."; then
    echo "Warning: volume backup failed for $service_name; update will continue." >&2
    return 0
  fi
}

backup_postgres_database() {
  container_id="$(docker compose ps -q db 2>/dev/null || true)"
  if [ -z "$container_id" ]; then
    echo "Postgres backup skipped: db container is not running."
    return 0
  fi

  ensure_backup_dir
  backup_file="$BACKUP_DIR/postgres-$(timestamp).dump"
  echo "Backing up PostgreSQL database to $backup_file"
  if ! docker compose exec -T db sh -c 'pg_dump -Fc -U "$POSTGRES_USER" -d "$POSTGRES_DB"' > "$backup_file"; then
    rm -f "$backup_file"
    echo "Warning: PostgreSQL backup failed; update will continue." >&2
    return 0
  fi
}

backup_stateful_data() {
  if [ "$BACKUP_DATA" -ne 1 ]; then
    echo "Pre-update data backup skipped by --skip-backup."
    return 0
  fi

  case "$SERVICE" in
    app|db)
      backup_postgres_database
      ;;
    charredmap)
      backup_compose_volume_mount charredmap /data charredmap-data
      ;;
    naradadruk)
      backup_compose_volume_mount naradadruk /data naradadruk-data
      ;;
    slashtg)
      backup_compose_volume_mount slashtg /data slashtg-data
      ;;
    osix)
      backup_compose_volume_mount osix /data osix-data
      ;;
    shieldline)
      backup_postgres_database
      backup_compose_volume_mount shieldline /data shieldline-legacy-data
      ;;
    *)
      ;;
  esac
}

wait_for_service_ready() {
  service_name="$1"
  elapsed_seconds=0
  previous_state=""

  echo "Waiting for $service_name to become healthy (timeout: ${HEALTH_WAIT_SECONDS}s)..."

  while [ "$elapsed_seconds" -lt "$HEALTH_WAIT_SECONDS" ]; do
    container_id="$(docker compose ps -a -q "$service_name" 2>/dev/null || true)"
    current_state="missing"

    if [ -n "$container_id" ]; then
      inspected_state="$(
        docker inspect "$container_id" \
          --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' \
          2>/dev/null || true
      )"
      if [ -n "$inspected_state" ]; then
        current_state="$inspected_state"
      fi
    fi

    if [ "$current_state" != "$previous_state" ]; then
      echo "$service_name state: $current_state"
      previous_state="$current_state"
    fi

    case "$current_state" in
      healthy|running)
        echo "$service_name is ready."
        return 0
        ;;
      unhealthy|exited|dead)
        echo "$service_name failed to become ready (state: $current_state)." >&2
        docker compose logs --tail="$LOG_TAIL" "$service_name" >&2 || true
        return 1
        ;;
    esac

    sleep "$HEALTH_POLL_INTERVAL_SECONDS"
    elapsed_seconds=$((elapsed_seconds + HEALTH_POLL_INTERVAL_SECONDS))
  done

  echo "$service_name did not become ready within ${HEALTH_WAIT_SECONDS}s (last state: $previous_state)." >&2
  docker compose logs --tail="$LOG_TAIL" "$service_name" >&2 || true
  return 1
}

if ! [[ "$HEALTH_WAIT_SECONDS" =~ ^[1-9][0-9]*$ ]] ||
  ! [[ "$HEALTH_POLL_INTERVAL_SECONDS" =~ ^[1-9][0-9]*$ ]]; then
  echo "HEALTH_WAIT_SECONDS and HEALTH_POLL_INTERVAL_SECONDS must be positive integers." >&2
  exit 2
fi

cd "$ROOT_DIR"

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "Not a git repository: $ROOT_DIR" >&2
  exit 1
fi

if ! git diff --quiet -- "$COMPOSE_FILE" || ! git diff --cached --quiet -- "$COMPOSE_FILE"; then
  echo "Keeping server-local $COMPOSE_FILE changes out of git pulls."
  git update-index --skip-worktree "$COMPOSE_FILE"
fi

dirty_blocking="$(
  git status --porcelain --untracked-files=no |
    grep -vE '^[ MARCUD?!]{2} docker/local/docker-compose\.yml$' || true
)"

if [ -n "$dirty_blocking" ]; then
  echo "Cannot update because tracked files have local changes:" >&2
  echo "$dirty_blocking" >&2
  echo "Commit, stash, or discard those changes before running this script." >&2
  exit 1
fi

git pull --rebase

cd "$ROOT_DIR/docker/local"

update_targets=("$SERVICE")
if [ "$SERVICE" = "shieldline" ]; then
  update_targets=(shieldline shieldline-projection-worker shieldline-notification-worker shieldline-admin-bot-worker)
fi

if [ "$PULL" -eq 1 ]; then
  docker compose pull "${update_targets[@]}" || echo "No pullable image for $SERVICE; continuing with local Compose update."
fi

backup_stateful_data

compose_up=(docker compose up -d)
if [ "$BUILD" -eq 1 ]; then
  compose_up+=(--build)
fi
compose_up+=("${update_targets[@]}")

echo "Updating Docker Compose service set: ${update_targets[*]}"
"${compose_up[@]}"

for updated_service in "${update_targets[@]}"; do
  wait_for_service_ready "$updated_service"
done

docker compose ps "${update_targets[@]}"

if [ "$SHOW_LOGS" -eq 1 ]; then
  docker compose logs --tail="$LOG_TAIL" "${update_targets[@]}"
fi
