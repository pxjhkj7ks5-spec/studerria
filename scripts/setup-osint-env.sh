#!/usr/bin/env bash
# Add missing OSINT-owned secrets only; never print values or rotate existing keys.
set -Eeuo pipefail
umask 077
env_path="${1:-docker/local/.env}"
if [ ! -f "$env_path" ]; then
  echo "Missing Compose .env: $env_path" >&2
  exit 1
fi
command -v openssl >/dev/null || { echo "OpenSSL is required to generate OSINT secrets." >&2; exit 1; }
for key in OSINT_DB_OWNER_PASSWORD OSINT_DB_PASSWORD OSINT_ADMIN_PASSWORD OSINT_SESSION_SECRET; do
  if ! awk -v key="$key" 'index($0,key "=")==1 {value=substr($0,length(key)+2); if (length(value)>0 && value!="\"\"" && value!="\047\047") found=1} END {exit !found}' "$env_path"; then
    value="$(openssl rand -hex 32)"
    printf '\n%s=%s\n' "$key" "$value" >> "$env_path"
    unset value
    echo "Initialized $key in Compose .env (value hidden)."
  fi
done
chmod 600 "$env_path"
echo 'OSINT database and standalone login secrets are ready. GitHub token is configured separately.'
