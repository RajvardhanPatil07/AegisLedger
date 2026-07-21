# Changelog

All notable changes to AegisLedger are documented here. The project follows
Semantic Versioning while its public contracts stabilize.

## [Unreleased]

### Security

- Grant the private-repository CodeQL job the minimum `actions: read`
  permission required to upload and report analysis results.
- Bind public-release assurance to the exact checked-out commit and run every
  required remote gate automatically for `v*` tags.
- Stage file-backed Compose secrets into service-owned, mode-`0400` volumes so
  non-root API and signer processes can start without weakening host key permissions.
- Enable the containerd image store in security CI so local image scans retain
  maximum-mode provenance attestations without requiring a registry push.
- Write action-generated image SBOMs to the repository-relative artifact path
  used by the evidence binder and artifact uploader.
- Keep the container scanner cache in the runner's temporary directory so
  exact-commit evidence generation sees an otherwise clean checkout.
- Bound serialized EIP-1559 bytes exactly to authorized transaction fields in
  the deployed Rust signer, with stable identity and replay state.
- Added smart-account reentrancy protection and a malicious-target regression.
- Added CodeQL, Rust dependency/license policy, Slither, coverage, mutation,
  digest-pinned runtime images, SBOM, provenance, and real settlement smoke gates.

### Added

- Add a one-command local signed-settlement demo and a fail-closed
  `make public-release-ready` gate.
- Validate candidate, prepared-release, and tagged-release metadata as distinct
  lifecycle states.
- Durable signed-transaction, settlement, attestation, audit, experiment, and
  rate-limit state with restart recovery.
- Evidence-backed security claim matrix, architecture decisions, independent
  reviewer checklist, and disposable reproduction workflow.

### Changed

- Prepare the repository for independent review and a publication decision.
- Prevent non-auditors from issuing an audit-journal request that can only be
  rejected, and explain the required role before the action.

### Fixed

- Reconcile Keycloak callback origins on every Compose startup so authentication
  works with custom console ports and both loopback hostnames.

## [0.2.0] - 2026-07-18

### Added

- Production-oriented API, PostgreSQL state adapters, isolated Rust signer,
  smart-account enforcement, formal authorization model, observability stack,
  and OIDC-gated research console.
- Reproducible attack/defense evaluation and complete-attestation verification.
