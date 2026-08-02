#!/bin/sh
set -eu

SCHEMA_FILE="prisma/schema.prisma"
SCHEMA_HASH_FILE="/data/.schema-prisma.sha256"
SEED_MARKER_FILE="/data/.seeded-v1"
CATALOG_FILE="${CATALOG_FILE:-catalog/products.json}"
CATALOG_HASH_FILE="/data/.catalog-products.sha256"

owner_bot_token_state="MISSING"
if [ -n "${NARADADRUK_ORDER_TELEGRAM_BOT_TOKEN:-}" ]; then
  owner_bot_token_state="SET"
fi

owner_bot_chat_state="MISSING"
owner_bot_chat_id="${NARADADRUK_ORDER_TELEGRAM_CHAT_ID:-}"
case "$owner_bot_chat_id" in
  -[1-9]*)
    case "${owner_bot_chat_id#-}" in
      *[!0-9]*) owner_bot_chat_state="SET_INVALID_SHAPE" ;;
      *) owner_bot_chat_state="SET_GROUP_SHAPE" ;;
    esac
    ;;
  [1-9]*)
    case "$owner_bot_chat_id" in
      *[!0-9]*) owner_bot_chat_state="SET_INVALID_SHAPE" ;;
      *) owner_bot_chat_state="SET_PRIVATE_SHAPE" ;;
    esac
    ;;
  ?*) owner_bot_chat_state="SET_INVALID_SHAPE" ;;
esac

owner_bot_allowlist_state="MISSING"
if [ -n "${NARADADRUK_ORDER_TELEGRAM_OWNER_USER_IDS:-}" ]; then
  if printf '%s' "$NARADADRUK_ORDER_TELEGRAM_OWNER_USER_IDS" | awk -F, '
    {
      for (index = 1; index <= NF; index += 1) {
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", $index)
        if ($index == "") continue
        found = 1
        if ($index !~ /^[1-9][0-9]*$/) exit 1
      }
    }
    END { if (!found) exit 1 }
  '; then
    owner_bot_allowlist_state="SET_VALID_SHAPE"
  else
    owner_bot_allowlist_state="SET_INVALID_SHAPE"
  fi
elif [ "$owner_bot_chat_state" = "SET_PRIVATE_SHAPE" ]; then
  owner_bot_allowlist_state="PRIVATE_CHAT_FALLBACK"
fi

echo "[entrypoint] owner bot preflight: token=$owner_bot_token_state chat=$owner_bot_chat_state owner_allowlist=$owner_bot_allowlist_state"

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

echo "[entrypoint] normalizing persisted order data"
./node_modules/.bin/tsx prisma/migrate-runtime-data.ts

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

if [ -n "${NARADADRUK_ORDER_TELEGRAM_BOT_TOKEN:-}" ] && [ -n "${NARADADRUK_ORDER_TELEGRAM_CHAT_ID:-}" ]; then
  echo "[entrypoint] starting Narada Druk owner bot"
  ./node_modules/.bin/tsx scripts/makerworld-bot-worker.ts &
else
  echo "[entrypoint] Narada Druk owner bot disabled"
fi

exec node server.js
