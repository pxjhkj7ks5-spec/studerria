#!/bin/sh
set -eu

SCHEMA_FILE="prisma/schema.prisma"
SCHEMA_HASH_FILE="/data/.schema-prisma.sha256"
SEED_MARKER_FILE="/data/.seeded-v1"

if [ "${NODE_ENV:-production}" = "production" ]; then
  case "${YKG_SESSION_SECRET:-}" in
    ""|change-me*|replace-with*|ykg-local*)
      echo "[entrypoint] YKG_SESSION_SECRET must be a non-placeholder secret in production" >&2
      exit 78
      ;;
  esac
  if [ "${#YKG_SESSION_SECRET}" -lt 32 ]; then
    echo "[entrypoint] YKG_SESSION_SECRET must contain at least 32 characters" >&2
    exit 78
  fi
fi

current_schema_hash="$(sha256sum "$SCHEMA_FILE" | awk '{print $1}')"
previous_schema_hash=""
[ -f "$SCHEMA_HASH_FILE" ] && previous_schema_hash="$(cat "$SCHEMA_HASH_FILE" 2>/dev/null || true)"
if [ "$current_schema_hash" != "$previous_schema_hash" ]; then
  echo "[entrypoint] applying YKG schema"
  ./node_modules/.bin/prisma db push
  printf '%s\n' "$current_schema_hash" > "$SCHEMA_HASH_FILE"
fi

if [ ! -f "$SEED_MARKER_FILE" ]; then
  echo "[entrypoint] creating settings and private draft references"
  ./node_modules/.bin/tsx prisma/seed.ts
  : > "$SEED_MARKER_FILE"
fi

if [ -n "${YKG_TELEGRAM_BOT_TOKEN:-}" ] && [ -n "${YKG_TELEGRAM_CHAT_ID:-}" ]; then
  echo "[entrypoint] starting YKG staff bot"
  ./node_modules/.bin/tsx scripts/ykg-bot-worker.ts &
else
  echo "[entrypoint] YKG staff bot disabled"
fi

exec node server.js
