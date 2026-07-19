#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
PROJECT=${AEGIS_REVIEW_PROJECT:-"aegisledger-review-$$"}
EVIDENCE_DIR=${AEGIS_REVIEW_EVIDENCE_DIR:-"$ROOT/artifacts/reviewer"}
ENV_FILE=${AEGIS_ENV_FILE:-"$ROOT/.env.local"}

compose() {
  docker compose --project-name "$PROJECT" --env-file "$ENV_FILE" --project-directory "$ROOT" "$@"
}

cleanup() {
  status=$?
  if [ "$status" -ne 0 ]; then
    compose logs --no-color --tail=300 >"$EVIDENCE_DIR/compose-failure.log" 2>&1 || true
  fi
  compose down --volumes >/dev/null 2>&1 || true
  exit "$status"
}
trap cleanup EXIT HUP INT TERM

run_with_log() {
  log=$1
  shift
  if "$@" >"$log" 2>&1; then
    cat "$log"
  else
    status=$?
    cat "$log" >&2
    return "$status"
  fi
}

for command in uv cargo forge npm docker curl; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "required command is unavailable: $command" >&2
    exit 1
  }
done
cargo audit --version >/dev/null 2>&1 || {
  echo "install cargo-audit 0.22.2 before running the reviewer flow" >&2
  exit 1
}
cargo deny --version >/dev/null 2>&1 || {
  echo "install cargo-deny 0.20.2 before running the reviewer flow" >&2
  exit 1
}

if [ -e "$EVIDENCE_DIR" ]; then
  echo "evidence directory already exists; choose a new AEGIS_REVIEW_EVIDENCE_DIR" >&2
  exit 1
fi
umask 077
mkdir -p "$EVIDENCE_DIR"
cd "$ROOT"

git rev-parse HEAD | tee "$EVIDENCE_DIR/commit.txt"
test -z "$(git status --porcelain)"

run_with_log "$EVIDENCE_DIR/bootstrap.log" make bootstrap
run_with_log "$EVIDENCE_DIR/verify.log" make verify
run_with_log "$EVIDENCE_DIR/cargo-audit.log" \
  cargo audit --file signer/Cargo.lock
run_with_log "$EVIDENCE_DIR/cargo-deny.log" \
  cargo deny --manifest-path signer/Cargo.toml check
run_with_log "$EVIDENCE_DIR/slither.log" \
  uvx --from slither-analyzer==0.11.5 slither . \
  --filter-paths "contracts/test|contracts/cache|lib" \
  --exclude-low --exclude-informational --exclude-optimization

if (cd web && npm run test:e2e) >"$EVIDENCE_DIR/playwright.log" 2>&1; then
  cat "$EVIDENCE_DIR/playwright.log"
else
  cat "$EVIDENCE_DIR/playwright.log" >&2
  exit 1
fi

compose config --quiet
compose config --images >"$EVIDENCE_DIR/compose-images.txt"
run_with_log "$EVIDENCE_DIR/compose-up.log" compose up --build --detach

attempt=0
until curl -fsS http://127.0.0.1:8000/health/ready >/dev/null; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 80 ]; then
    echo "API did not become ready" >&2
    exit 1
  fi
  sleep 3
done

if compose exec --no-TTY api python /app/scripts/runtime_smoke.py \
  >"$EVIDENCE_DIR/runtime-smoke.json" \
  2>"$EVIDENCE_DIR/runtime-smoke.stderr"; then
  cat "$EVIDENCE_DIR/runtime-smoke.json"
else
  cat "$EVIDENCE_DIR/runtime-smoke.stderr" >&2
  exit 1
fi

uv run python scripts/release_evidence.py build \
  --output "$EVIDENCE_DIR/evidence-manifest.json" \
  --artifact "$EVIDENCE_DIR"

echo "reviewer reproduction passed for $(git rev-parse HEAD)"
