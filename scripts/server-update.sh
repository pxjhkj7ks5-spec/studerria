#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="docker/local/docker-compose.yml"
LOG_TAIL="${LOG_TAIL:-80}"

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
docker compose up -d --build app
docker compose logs --tail="$LOG_TAIL" app
