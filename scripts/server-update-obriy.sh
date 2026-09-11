#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [ "${1:-}" = "--live" ]; then
  shift
  cd "$ROOT_DIR"
  git pull --rebase
  env_path="$ROOT_DIR/docker/local/.env"
  bash "$ROOT_DIR/scripts/setup-obriy-env.sh" "$env_path"
  umask 077
  env_tmp="$(mktemp "$env_path.obriy.XXXXXX")"
  trap 'rm -f "$env_tmp"' EXIT
  awk '!/^[[:space:]]*(export[[:space:]]+)?OBRIY_BULLETIN_(MODE|APPROVED|COOLDOWN_MS)=/' "$env_path" > "$env_tmp"
  printf '\nOBRIY_BULLETIN_MODE=live\nOBRIY_BULLETIN_APPROVED=true\nOBRIY_BULLETIN_COOLDOWN_MS=15000\n' >> "$env_tmp"
  chmod 600 "$env_tmp"
  mv "$env_tmp" "$env_path"
  trap - EXIT
  echo 'Obriy civil bulletin delivery enabled; duplicate window: 15 seconds.'
fi
exec bash "$ROOT_DIR/scripts/server-update.sh" obriy "$@"
