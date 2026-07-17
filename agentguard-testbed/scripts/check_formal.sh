#!/bin/sh
set -eu

VERSION=1.7.4
SHA256=936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88
CACHE_DIR="${AEGIS_TOOL_CACHE:-artifacts/tools}"
JAR="$CACHE_DIR/tla2tools-$VERSION.jar"
mkdir -p "$CACHE_DIR"

if [ ! -f "$JAR" ]; then
  curl -fsSL "https://github.com/tlaplus/tlaplus/releases/download/v$VERSION/tla2tools.jar" -o "$JAR"
fi

if command -v sha256sum >/dev/null 2>&1; then
  ACTUAL=$(sha256sum "$JAR" | cut -d ' ' -f 1)
else
  ACTUAL=$(shasum -a 256 "$JAR" | cut -d ' ' -f 1)
fi
test "$ACTUAL" = "$SHA256"

if java -version >/dev/null 2>&1; then
  TLC_META_DIR=$(mktemp -d "${TMPDIR:-/tmp}/aegis-tlc.XXXXXX")
  trap 'rm -rf "$TLC_META_DIR"' EXIT
  java -XX:+UseParallelGC -jar "$JAR" \
    -metadir "$TLC_META_DIR" \
    -config formal/Authorization.cfg formal/Authorization.tla
elif command -v docker >/dev/null 2>&1; then
  PROJECT_DIR=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
  docker run --rm \
    --volume "$PROJECT_DIR:/workspace:ro" \
    --workdir /workspace \
    eclipse-temurin:21-jre-jammy@sha256:d63bd8d9b171999cbed8576f2c76e874dd4856791a358536e5c4d407e77edc13 \
    java -XX:+UseParallelGC -jar "$JAR" \
      -metadir /tmp/aegis-tlc \
      -config formal/Authorization.cfg formal/Authorization.tla
else
  echo "Java 21 or Docker is required to run the TLA+ model checker." >&2
  exit 1
fi
