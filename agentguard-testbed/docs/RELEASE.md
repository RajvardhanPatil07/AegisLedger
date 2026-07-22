# Release gates

A release candidate is acceptable only when all technical gates pass for the
same commit. Passing them does not authorize public visibility or production
custody.

The machine-readable [assurance scorecard](assurance-scorecard.json) assigns an
owner, status, review date, and evidence reference to every research,
public-release, and production-custody gate. Validate its structure and evidence
paths with `make assurance-scorecard`. A track is ready only when every gate is
current and `passed`, verified evidence is recorded, and the scorecard is bound
to an exact candidate commit. Pending or blocked gates are intentionally valid
scorecard states; they are not release approval.

`make assurance-public` additionally requires every public-release gate to be
current and passed, and rejects a `candidate_commit` that differs from the
checked-out Git commit. This prevents evidence from a previously reviewed SHA
from approving different code.

The [source and asset provenance inventory](PROVENANCE.md) must cover every
tracked file and relevant historical object. `make provenance` validates the
inventory without overstating clearance. A public release must additionally
pass `python scripts/check_provenance_inventory.py --require-release-ready`;
that command fails until all distributable material has durable ownership,
license, and source evidence.

## Release metadata lifecycle

Release metadata is validated in three fail-closed states:

1. **Candidate:** versions agree, the changelog remains unreleased, no release
   date is recorded, and no matching tag exists.
2. **Prepared:** versions agree and the citation, roadmap, and changelog contain
   one matching release version and date, but the tag does not exist yet.
3. **Released:** the prepared metadata is committed and the matching `v*` tag
   exists.

`make release-metadata` detects and validates the current state. After the
prepared release commit is reviewed, create the signed tag and run
`make public-release-ready`. The latter requires final tagged metadata, the
exact-commit public assurance track, and release-cleared current and historical
provenance. It must be green before changing repository visibility.

## Automated gates

1. Python 3.11 and 3.13: Ruff, mypy, tests, package build, a 75% whole-repository
   coverage floor, Bandit high/medium gate, and `pip-audit`.
2. Rust 1.97.1: format, Clippy with warnings denied, signer tests,
   `cargo-audit`, and `cargo-deny` advisory/license/source policy.
3. Solidity/Foundry 1.7.1: format, size build, unit/fuzz/invariant tests, formal
   checks, and Slither medium/high gate.
4. Console/Node 24: TypeScript, component tests, production build, Chromium
   Playwright flows, responsive layouts, and Axe checks.
5. CodeQL security-extended analysis for Python and JavaScript/TypeScript when
   the repository is public, or when GitHub Code Security is enabled for the
   private repository and the `CODEQL_ENABLED` repository variable is `true`.
6. Full-history Gitleaks plus Trivy HIGH/CRITICAL scans for API, signer, and
   console images.
7. CycloneDX SBOMs for all three shipped images and BuildKit provenance metadata.
8. Deterministic evaluation artifact and scheduled signer-authorization mutation
   testing with a score of at least 95% and no unresolved mutants.
9. Clean Compose startup, database migrations, OIDC page, console/metrics/RPC
   health, actual signed Anvil settlement, configured finality, persisted
   attestation, and offline verification.
10. A recent backup/restore drill and an identified rollback release.

Third-party actions use full commit SHAs. Runtime image tags are retained for
human readability and paired with immutable digests. Dependabot should maintain
Cargo, Docker, GitHub Actions, npm, and Python dependencies; an update cannot
merge solely because it is newer.

Every `v*` tag triggers CI, CodeQL, dependency/source/image security, mutation,
and full runtime-smoke workflows at the tagged commit. Do not create the GitHub
release until all tag-triggered jobs are green and their evidence has been
retained.

## Candidate evidence bundle

Retain these together for the candidate commit:

- exact Git commit, clean-tree status, and an
  `aegisledger.release_evidence.v1` checksum manifest;
- workflow run URLs and job conclusions;
- Python coverage XML and test reports;
- reproducible evaluation output;
- Rust/Solidity/web test output and formal result;
- CodeQL, dependency, secret, Slither, and image-scan results;
- CycloneDX SBOMs and container provenance attestations;
- Compose-rendered image list with digests;
- runtime-smoke JSON containing proposal, signer, signing hash, transaction hash,
  settlement state, confirmations, and attestation result;
- verified backup path/checksum and rollback candidate;
- current [security claim matrix](SECURITY_CLAIMS.md) and unresolved exceptions.

The CI test, evaluation, image, and runtime bundles each include a manifest
created by `scripts/release_evidence.py`. Verify a downloaded bundle from the
same checked-out candidate with
`make verify-evidence MANIFEST=<path> ARTIFACT_ROOT=<download-directory>`. The
verification fails on a different commit, a missing artifact, an unsafe path,
or any size/checksum change. `ARTIFACT_ROOT` is optional while files remain at
the repository-relative bundle location recorded during generation.

For a local independent review, set `AEGIS_REVIEW_EVIDENCE_DIR` to a new ignored
directory and run `scripts/reproduce_release.sh`. The flow refuses an existing
evidence directory, retains logs for each major gate, and writes the final
checksum manifest only after the runtime proof succeeds.

## Repository administration gates

Before any shared or public release, the owner should enable protected `main`,
required status checks, review for workflow/deployment changes, secret scanning,
push protection, signed tags/releases, least-privilege environments, and a
documented incident contact. These are hosting-administration actions and are
not asserted by repository files alone.

## External blocking gates

- **Patent/publication decision:** the owner must record a decision with
  qualified counsel if protection may be desired. Until then, keep the
  repository private.
- **Independent security assessment:** a party independent of implementation
  must review the exact candidate and report/remediate findings.
- **Production custody:** managed key custody/attestation, production identity
  and database topology, live-chain controls, measured load/chaos SLOs, and
  operational ownership must be approved separately.

None of these gates may be checked off based on self-review, automated tools, or
the wording “industry-grade.”
