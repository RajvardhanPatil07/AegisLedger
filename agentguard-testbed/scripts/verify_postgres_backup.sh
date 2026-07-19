#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
  echo "usage: $0 BACKUP_FILE" >&2
  exit 2
fi

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ENV_FILE=${AEGIS_ENV_FILE:-"$ROOT/.env.local"}
BACKUP_FILE=$1

if [ ! -s "$BACKUP_FILE" ]; then
  echo "backup is missing or empty: $BACKUP_FILE" >&2
  exit 1
fi
if [ ! -f "$ENV_FILE" ]; then
  echo "missing environment file: $ENV_FILE" >&2
  exit 1
fi

set -a
. "$ENV_FILE"
set +a

VERIFY_DATABASE="aegis_restore_check_$$"
cleanup() {
  docker compose --env-file "$ENV_FILE" --project-directory "$ROOT" \
    exec -T postgres dropdb \
    --username "$POSTGRES_USER" \
    --if-exists "$VERIFY_DATABASE" >/dev/null 2>&1 || true
}
trap cleanup EXIT HUP INT TERM

docker compose --env-file "$ENV_FILE" --project-directory "$ROOT" \
  exec -T postgres createdb \
  --username "$POSTGRES_USER" "$VERIFY_DATABASE"

docker compose --env-file "$ENV_FILE" --project-directory "$ROOT" \
  exec -T postgres pg_restore \
  --username "$POSTGRES_USER" \
  --dbname "$VERIFY_DATABASE" \
  --exit-on-error <"$BACKUP_FILE"

TABLE_COUNT=$(docker compose --env-file "$ENV_FILE" --project-directory "$ROOT" \
  exec -T postgres psql \
  --username "$POSTGRES_USER" \
  --dbname "$VERIFY_DATABASE" \
  --tuples-only \
  --no-align \
  --command "select count(*) from pg_tables where schemaname = 'public';")

if [ "$TABLE_COUNT" -lt 10 ]; then
  echo "restore verification found only $TABLE_COUNT application tables" >&2
  exit 1
fi

echo "restore verification succeeded with $TABLE_COUNT application tables"
