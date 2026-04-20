#!/bin/sh
set -eu

SCHEMA_FILE="prisma/schema.prisma"
SCHEMA_HASH_FILE="/data/.schema-prisma.sha256"
SEED_MARKER_FILE="/data/.seeded-v1"

if [ -f "$SCHEMA_FILE" ]; then
  current_schema_hash="$(sha256sum "$SCHEMA_FILE" | awk '{print $1}')"
  previous_schema_hash=""
  if [ -f "$SCHEMA_HASH_FILE" ]; then
    previous_schema_hash="$(cat "$SCHEMA_HASH_FILE" 2>/dev/null || true)"
  fi

  if [ "$current_schema_hash" != "$previous_schema_hash" ]; then
    echo "[entrypoint] schema changed; running prisma db push"
    ./node_modules/.bin/prisma db push
    printf '%s\n' "$current_schema_hash" > "$SCHEMA_HASH_FILE"
  else
    echo "[entrypoint] schema unchanged; skipping prisma db push"
  fi
fi

if [ ! -f "$SEED_MARKER_FILE" ]; then
  echo "[entrypoint] running one-time seed"
  ./node_modules/.bin/tsx prisma/seed.ts
  : > "$SEED_MARKER_FILE"
else
  echo "[entrypoint] seed marker found; skipping seed"
fi

exec node server.js
