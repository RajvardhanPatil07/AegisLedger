#!/bin/sh
set -eu

if [ "${AEGIS_RUN_MIGRATIONS:-true}" = "true" ]; then
  aegisledger migrate
fi

exec "$@"
