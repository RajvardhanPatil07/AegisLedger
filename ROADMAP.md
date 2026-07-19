# AegisLedger roadmap

AegisLedger is evolving from a deterministic security testbed into an
end-to-end reference platform for authorization, signing, settlement, and
evidence generation for agent-controlled wallets. This roadmap distinguishes
implemented behavior from release gates and longer-term research.

## Current candidate: 0.3.0

Implemented today:

- deterministic x402-style and delegated-mandate simulations;
- composed prompt-injection, malicious-tool, permission-abuse, and MEV attack
  scenarios using simulated assets;
- strict policy contracts, atomic reservations, signed decisions, and
  settlement-time smart-account rules;
- a local Rust signing service with mandatory mTLS and a transaction-bound
  authorization interface;
- PostgreSQL schemas, OIDC, metrics, traces, alerts, backups, formal modeling,
  reproducible evaluation, and a research console.

The reference Compose deployment is for local research and pre-production
validation. It is not approved for internet exposure, mainnet custody, or real
funds.

## Completed hardening milestones

### Exact signer boundary

- Decoded serialized EIP-1559 transactions inside the signer and bound every
  signed field to the policy-authorized proposal.
- Added native Rust substitution, replay, concurrency, property, and mTLS integration
  tests.
- Required explicit durable key and replay-state configuration in the Compose
  signer; hardware sealing remains a production gate.

### Durable end-to-end lifecycle

- Connected proposal reservation, decision issuance, isolated signing, Anvil
  submission, finality reconciliation, complete attestation, and console
  verification in one tested vertical flow.
- Persisted decisions, audit events, signed transactions, settlements,
  attestations, and jobs across restarts.
- Proved normal-path retry safety, worker recovery, signer identity/replay
  persistence, and audit continuity across restarts.

### Release assurance

- Added object-level authorization, quotas, SBOMs, build provenance metadata,
  coverage, mutation, CodeQL, dependency, Solidity, secret, and image gates.
- Added a claim-to-test evidence matrix and clean-room reproduction bundle.
- Require an independent security assessment before any real-fund or
  production-custody claim.

## Remaining engineering gates

- Automate a measured load/chaos SLO suite and migration compatibility matrix.
- Add signed-image publication/verification when a target registry and release
  identity are selected.
- Add optional replayable live-LLM adapters without making CI depend on secrets.
- Expand statistical confidence intervals, latency, gas, and availability-cost
  reporting over larger retained runs.

## Research track

- Add optional replayable integrations with multiple LLM runtimes while
  keeping the deterministic scripted suite as the required CI baseline.
- Report confidence intervals, latency, gas, availability cost, and utility
  trade-offs over larger seeded evaluations.
- Compare against documented prompt-, tool-, signer-, and smart-account-level
  baselines without claiming novelty beyond the available evidence.

## Publication gate

Repository visibility is an owner decision. If patent protection is desired,
the filing strategy must be resolved before public disclosure. A public release
also requires green release gates for the same commit and an independently
authored security assessment.

The detailed implementation sequence and acceptance criteria live in
`tasks/plan.md`.
