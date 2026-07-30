#!/bin/sh
set -eu

SCHEMA_FILE="prisma/schema.prisma"
SCHEMA_HASH_FILE="/data/.schema-prisma.sha256"
SEED_MARKER_FILE="/data/.seeded-v1"
CATALOG_FILE="${CATALOG_FILE:-catalog/products.json}"
CATALOG_HASH_FILE="/data/.catalog-products.sha256"

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

if [ -f "$CATALOG_FILE" ]; then
  current_catalog_hash="$(sha256sum "$CATALOG_FILE" | awk '{print $1}')"
  previous_catalog_hash=""
  if [ -f "$CATALOG_HASH_FILE" ]; then
    previous_catalog_hash="$(cat "$CATALOG_HASH_FILE" 2>/dev/null || true)"
  fi

  if [ "$current_catalog_hash" != "$previous_catalog_hash" ]; then
    echo "[entrypoint] catalog changed; importing products"
    ./node_modules/.bin/tsx prisma/import-catalog.ts
    printf '%s\n' "$current_catalog_hash" > "$CATALOG_HASH_FILE"
  else
    echo "[entrypoint] catalog unchanged; skipping import"
  fi
fi

case "${TELEGRAM_AUTO_IMPORT_ENABLED:-true}" in
  0|false|FALSE|no|NO|off|OFF)
    echo "[entrypoint] Telegram catalog sync disabled"
    ;;
  *)
    echo "[entrypoint] starting Telegram catalog sync"
    ./node_modules/.bin/tsx scripts/telegram-catalog-worker.ts &
    ;;
esac

exec node server.js
