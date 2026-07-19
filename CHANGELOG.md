# Changelog

All notable changes to AegisLedger are documented here. The project follows
Semantic Versioning while its public contracts stabilize.

## [Unreleased]

### Security

- Bound serialized EIP-1559 bytes exactly to authorized transaction fields in
  the deployed Rust signer, with stable identity and replay state.
- Added smart-account reentrancy protection and a malicious-target regression.
- Added CodeQL, Rust dependency/license policy, Slither, coverage, mutation,
  digest-pinned runtime images, SBOM, provenance, and real settlement smoke gates.

### Added

- Durable signed-transaction, settlement, attestation, audit, experiment, and
  rate-limit state with restart recovery.
- Evidence-backed security claim matrix, architecture decisions, independent
  reviewer checklist, and disposable reproduction workflow.

### Changed

- Prepare the repository for independent review and a publication decision.

## [0.2.0] - 2026-07-18

### Added

- Production-oriented API, PostgreSQL state adapters, isolated Rust signer,
  smart-account enforcement, formal authorization model, observability stack,
  and OIDC-gated research console.
- Reproducible attack/defense evaluation and complete-attestation verification.
