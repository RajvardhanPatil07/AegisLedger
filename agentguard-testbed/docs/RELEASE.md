# Release gates

A release candidate is acceptable only when all of these checks pass for the
same commit:

1. Python 3.11 and 3.13 tests, Ruff, mypy, and package build.
2. Rust format, Clippy with warnings denied, and signer tests.
3. Solidity format, build, unit, fuzz, and invariant tests.
4. The pinned TLA+ model checker and reproducible evaluation artifact.
5. Console TypeScript checks, component tests, production build, Chromium
   workflow tests, and automated Axe accessibility checks at desktop and mobile
   breakpoints.
6. Bandit high/medium scan, pip-audit, full-history Gitleaks scan, and Trivy
   scans of the API, isolated signer, and console runtime images.
7. Clean-runner Compose smoke test with PostgreSQL migrations, API readiness,
   an accepted OIDC authorization request, console, Prometheus, Grafana, and
   Anvil verification.
8. A recent verified backup/restore drill and an identified rollback image.

GitHub Actions and third-party actions are pinned to full commit SHAs.
Dependabot maintains Python, Cargo, Docker, npm, and workflow dependencies.
Repository administrators should also enable secret scanning, push protection,
required status checks, signed releases, and review for deployment-environment
changes.
