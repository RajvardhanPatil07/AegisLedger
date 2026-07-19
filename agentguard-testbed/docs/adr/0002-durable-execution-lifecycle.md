# ADR 0002: Durable idempotent execution lifecycle

- Status: Accepted
- Date: 2026-07-18

## Context

Signing and chain submission cross PostgreSQL, an isolated signer, and an EVM
RPC endpoint. None supports one distributed transaction. Retrying an ambiguous
failure can otherwise duplicate signatures, consume the wrong nonce, or lose
settlement evidence.

## Decision

PostgreSQL is the reference source of truth for proposals, policy versions,
reservations, decisions, executions, submissions, settlements, attestations,
audit events, jobs, and rate windows. In-memory adapters are test doubles.

The API persists authorization intent before signing, permits one execution per
proposal, records unique decision/wallet nonces and transaction hashes, submits
the retained raw bytes idempotently, and reconciles chain receipts in a
restart-safe worker. Terminal settlement closes the reservation. Complete
attestation creation is idempotent and only occurs after canonical terminal
evidence exists.

## Consequences

- API and worker restarts recover without duplicate normal-path signing or lost
  audit continuity.
- A signer-consumed authorization is never replayed merely to repair the
  database.
- An interruption between external signing and database persistence remains an
  explicit reconciliation case; safety is preferred over automatic liveness.
- Production deployments need database HA, backup/PITR, migration compatibility
  drills, and an operator workflow for ambiguous in-flight operations.
