# ADR 0001: Exact transaction as the signer boundary

- Status: Accepted
- Date: 2026-07-18

## Context

A policy decision over a high-level proposal is insufficient if an API can ask
the signer to sign a different transaction with the same proposal or digest
metadata. Trusting a caller-supplied hash creates a substitution boundary at the
most sensitive component.

## Decision

The signer accepts a versioned authorization containing the proposal, signed
decision, reservation, normalized transaction binding, and unsigned EIP-1559
bytes. It independently verifies the decision and every cross-object binding,
decodes the type-2 transaction, compares every security-relevant field,
requires canonical encoding, derives the signing hash, and returns the complete
signed raw transaction.

Unknown authorization fields fail deserialization. Decision IDs and wallet
nonces are durably consumed by the signer. The API recomputes the network
transaction hash from returned bytes and rejects any response mismatch.

## Consequences

- API compromise cannot silently substitute destination, value, calldata, gas,
  fees, chain, or nonce inside an otherwise valid authorization.
- Adding a transaction field requires an explicit schema and signer update;
  older signers fail closed.
- The signer is more complex than an opaque `sign(hash)` service, but that
  complexity is directly tested in its native implementation.
- Application-specific contract semantics still require policy adapters or
  on-chain rules; byte binding alone cannot infer user intent.
