UV ?= uv
COMPOSE ?= docker compose --env-file .env.local

.PHONY: bootstrap up down logs test test-web lint security formal evaluate backup verify-backup verify

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

evaluate:
	$(UV) run aegisledger-experiment --seed research-baseline --runs 12

backup:
	scripts/backup_postgres.sh

verify-backup:
	test -n "$(BACKUP)"
	scripts/verify_postgres_backup.sh "$(BACKUP)"

verify: lint test security formal
