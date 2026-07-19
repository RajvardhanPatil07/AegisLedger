UV ?= uv
COMPOSE ?= docker compose --env-file .env.local

.PHONY: bootstrap up down logs test test-web lint security formal release-metadata assurance-scorecard provenance verify-evidence evaluate backup verify-backup runtime-smoke reproduce verify

bootstrap:
	$(UV) sync --all-extras --frozen
	$(UV) run python scripts/bootstrap_dev.py

up: bootstrap
	$(COMPOSE) up --build --detach

down:
	$(COMPOSE) down

logs:
	$(COMPOSE) logs --follow --tail=200

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
	$(UV) run python scripts/check_release_metadata.py --mode candidate

assurance-scorecard:
	$(UV) run python scripts/check_assurance_scorecard.py

provenance:
	$(UV) run python scripts/check_provenance_inventory.py

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
