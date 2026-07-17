#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ENV_FILE=${AEGIS_ENV_FILE:-"$ROOT/.env.local"}
BACKUP_DIR=${AEGIS_BACKUP_DIR:-"$ROOT/artifacts/backups"}

if [ ! -f "$ENV_FILE" ]; then
  echo "missing environment file: $ENV_FILE" >&2
  exit 1
fi

set -a
. "$ENV_FILE"
set +a

umask 077
mkdir -p "$BACKUP_DIR"
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
BACKUP_FILE="$BACKUP_DIR/aegisledger-$STAMP.dump"

docker compose --env-file "$ENV_FILE" --project-directory "$ROOT" \
  exec -T postgres pg_dump \
  --username "$POSTGRES_USER" \
  --dbname "$POSTGRES_DB" \
  --format custom \
  --no-owner \
  --no-privileges >"$BACKUP_FILE"

test -s "$BACKUP_FILE"
echo "$BACKUP_FILE"
