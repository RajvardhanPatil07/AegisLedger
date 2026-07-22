UV ?= $(shell command -v uv 2>/dev/null || printf '%s' 'python3 -m uv')
AEGIS_API_PORT ?= $(shell sed -n 's/^AEGIS_API_PORT=//p' .env.local 2>/dev/null | tail -n 1)
AEGIS_API_PORT := $(if $(strip $(AEGIS_API_PORT)),$(AEGIS_API_PORT),8000)
AEGIS_WEB_PORT ?= $(shell sed -n 's/^AEGIS_WEB_PORT=//p' .env.local 2>/dev/null | tail -n 1)
AEGIS_WEB_PORT := $(if $(strip $(AEGIS_WEB_PORT)),$(AEGIS_WEB_PORT),4173)
COMPOSE ?= docker compose --env-file .env.local
export AEGIS_API_PORT AEGIS_WEB_PORT

.PHONY: bootstrap up down logs demo test test-web lint security formal \
	release-metadata release-metadata-final assurance-scorecard assurance-public \
	provenance provenance-public public-release-ready verify-evidence evaluate \
	backup verify-backup runtime-smoke reproduce verify

bootstrap:
	$(UV) sync --all-extras --frozen
	$(UV) run python scripts/bootstrap_dev.py

up: bootstrap
	$(COMPOSE) up --build --detach

down:
	$(COMPOSE) down

logs:
	$(COMPOSE) logs --follow --tail=200

demo: up
	@attempt=0; until curl -fsS http://127.0.0.1:$(AEGIS_API_PORT)/health/ready >/dev/null; do \
		attempt=$$((attempt + 1)); \
		if [ "$$attempt" -ge 80 ]; then \
			$(COMPOSE) logs --no-color --tail=200; \
			echo "AegisLedger API did not become ready" >&2; \
			exit 1; \
		fi; \
		sleep 3; \
	done
	$(MAKE) runtime-smoke
	@echo "AegisLedger demo passed. Console: http://localhost:$(AEGIS_WEB_PORT)"

test:
	$(UV) run pytest -q
	cargo test --manifest-path signer/Cargo.toml --locked
	forge test
	$(MAKE) test-web

test-web:
	cd web && npm ci && npm run typecheck && npm test && npm run build

lint:
	$(UV) run ruff check src tests migrations scripts
	$(UV) run mypy
	cargo fmt --manifest-path signer/Cargo.toml --check
	cargo clippy --manifest-path signer/Cargo.toml --locked -- -D warnings
	forge fmt --check

security:
	$(UV) run bandit -q -r src -ll
	$(UV) run pip-audit --skip-editable

formal:
	scripts/check_formal.sh

release-metadata:
	$(UV) run python scripts/check_release_metadata.py --mode auto

release-metadata-final:
	$(UV) run python scripts/check_release_metadata.py --mode release

assurance-scorecard:
	$(UV) run python scripts/check_assurance_scorecard.py

assurance-public:
	$(UV) run python scripts/check_assurance_scorecard.py --require-track public_release

provenance:
	$(UV) run python scripts/check_provenance_inventory.py

provenance-public:
	$(UV) run python scripts/check_provenance_inventory.py --require-release-ready

public-release-ready: release-metadata-final assurance-public provenance-public

verify-evidence:
	test -n "$(MANIFEST)"
	$(UV) run python scripts/release_evidence.py verify "$(MANIFEST)" $(if $(ARTIFACT_ROOT),--artifact-root "$(ARTIFACT_ROOT)")

evaluate:
	$(UV) run aegisledger-experiment --seed research-baseline --runs 12

backup:
	scripts/backup_postgres.sh

verify-backup:
	test -n "$(BACKUP)"
	scripts/verify_postgres_backup.sh "$(BACKUP)"

runtime-smoke:
	$(COMPOSE) exec --no-TTY api python /app/scripts/runtime_smoke.py

reproduce:
	scripts/reproduce_release.sh

verify: release-metadata assurance-scorecard provenance lint test security formal
