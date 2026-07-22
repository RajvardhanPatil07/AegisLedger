#!/usr/bin/env bash
set -euo pipefail

KCADM=/opt/keycloak/bin/kcadm.sh
KCADM_CONFIG=/tmp/kcadm.config
trap 'rm -f "$KCADM_CONFIG"' EXIT

case "${AEGIS_WEB_PORT:-}" in
  "" | *[!0-9]*)
    echo "AEGIS_WEB_PORT must be an integer" >&2
    exit 1
    ;;
esac
if ((AEGIS_WEB_PORT < 1 || AEGIS_WEB_PORT > 65535)); then
  echo "AEGIS_WEB_PORT must be between 1 and 65535" >&2
  exit 1
fi

authenticated=false
for _attempt in {1..40}; do
  if "$KCADM" config credentials \
    --server http://keycloak:8080 \
    --realm master \
    --user "$KEYCLOAK_BOOTSTRAP_ADMIN_USERNAME" \
    --password "$KEYCLOAK_BOOTSTRAP_ADMIN_PASSWORD" \
    --config "$KCADM_CONFIG" >/dev/null 2>&1; then
    authenticated=true
    break
  fi
  sleep 2
done
if [[ "$authenticated" != true ]]; then
  echo "Keycloak did not become ready for client configuration" >&2
  exit 1
fi

client_id="$($KCADM get clients \
  --target-realm aegisledger \
  --query clientId=aegisledger-console \
  --fields id \
  --format csv \
  --noquotes \
  --config "$KCADM_CONFIG" | tr -d '\r' | head -n 1)"
if [[ ! "$client_id" =~ ^[a-zA-Z0-9-]+$ ]]; then
  echo "Unable to resolve the AegisLedger console client" >&2
  exit 1
fi

redirect_uris="[\"http://localhost:${AEGIS_WEB_PORT}/*\",\"http://127.0.0.1:${AEGIS_WEB_PORT}/*\",\"http://localhost:5173/*\",\"http://127.0.0.1:5173/*\"]"
web_origins="[\"http://localhost:${AEGIS_WEB_PORT}\",\"http://127.0.0.1:${AEGIS_WEB_PORT}\",\"http://localhost:5173\",\"http://127.0.0.1:5173\"]"

"$KCADM" update "clients/$client_id" \
  --target-realm aegisledger \
  --set "redirectUris=$redirect_uris" \
  --set "webOrigins=$web_origins" \
  --config "$KCADM_CONFIG"

echo "Keycloak console redirects are configured for port $AEGIS_WEB_PORT."
