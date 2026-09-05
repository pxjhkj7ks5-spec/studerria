#!/usr/bin/env bash
# Add missing Obriy-owned secrets only; never print values or rotate existing keys.
set -Eeuo pipefail
umask 077
env_path="${1:-docker/local/.env}"
if [ ! -f "$env_path" ]; then
  echo "Missing Compose .env: $env_path" >&2
  exit 1
fi
command -v openssl >/dev/null || { echo "OpenSSL is required to generate Obriy secrets." >&2; exit 1; }
for key in OBRIY_ENCRYPTION_KEY OBRIY_ADMIN_TOKEN OBRIY_METRICS_TOKEN OBRIY_TELEGRAM_WEBHOOK_SECRET; do
  if ! awk -v key="$key" 'index($0,key "=")==1 {value=substr($0,length(key)+2); if (length(value)>0 && value!="\"\"" && value!="\047\047") found=1} END {exit !found}' "$env_path"; then
    value="$(openssl rand -hex 32)"
    # A trailing value wins in dotenv/Compose. Preserve all unrelated content.
    printf '\n%s=%s\n' "$key" "$value" >> "$env_path"
    unset value
    echo "Initialized $key in Compose .env (value hidden)."
  fi
done
chmod 600 "$env_path"
echo 'Obriy secrets are ready. Telegram and alerts.in.ua tokens are configured separately.'
