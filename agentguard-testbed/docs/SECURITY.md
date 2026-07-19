# Security posture

This document describes the implemented reference deployment. It is not an
independent audit report and must not be presented as one. The authoritative
claim inventory is [SECURITY_CLAIMS.md](SECURITY_CLAIMS.md).

## Trust boundaries

The agent, model output, tools, peer messages, counterparties, and public chain
data are untrusted. They can propose an operation but never receive signing
material or a signer-capable object. The API constructs the transaction from
the retained proposal and fee/nonce inputs; the Rust signer treats the API
request as untrusted and independently validates the complete authorization.

The local reference separates these authorities:

1. Keycloak authenticates the human/API principal and supplies roles.
2. PostgreSQL owns proposal, policy, reservation, decision, transaction,
   settlement, attestation, audit, experiment, and rate-limit state.
3. The Python API evaluates policy and orchestrates lifecycle transitions.
4. The Rust signer owns the secp256k1 key and its replay state, reachable only
   over mutual TLS.
5. The EVM verifies the signed raw transaction and produces settlement evidence.
6. Offline verification recomputes hashes and validates signatures without
   consulting mutable service state.

## Signer authorization boundary

The signer accepts only an `aegisledger.sign_request.v1` object. Unknown fields
are denied. It verifies the policy decision signature, signer identity, active
reservation, proposal hash, policy hash allowlist, decision and request expiry,
chain allowlist, wallet binding, replay state, and monotonic wallet nonce.

For EIP-1559, it decodes the supplied unsigned typed transaction and compares
every security-relevant field with the authorized transaction binding. It
rejects non-canonical RLP and derives the signing hash internally. A successful
response contains the complete signed raw transaction; the API recomputes the
network transaction hash before accepting the response.

## Durable lifecycle

Proposal states are monotonic. An ALLOW result creates a reservation and signed
decision. Signing persists a single execution per proposal; `(wallet, chain,
nonce)`, decision nonce, EIP-712 hash, signing hash, and transaction hash are
unique. Submission is idempotent. Reconciliation retains canonical receipt
observations, marks pre-finality reorgs non-canonical, and closes the reservation
only after the configured confirmation threshold.

The signer and PostgreSQL are separate durability domains. The workflow
persists intent before signing and makes retries idempotent, but it is not a
distributed transaction. An interruption after the signer consumes a decision
and before PostgreSQL stores the signed result requires operator reconciliation;
the signer remains fail-closed rather than re-signing.

## Complete attestation

The retained attestation binds the original proposal, policy decision, exact
transaction fields, signing hash, raw signed bytes, network transaction hash,
signer identity, software measurement, signature, and canonical settlement
receipt. The verifier checks the policy signature, signer evidence signature,
transaction hashes, all cross-object bindings, measurement allowlist, chain,
and final lifecycle consistency.

Local `local-compose-v1` evidence is software evidence. It does not establish
hardware isolation or remote-attestation trust.

## Service controls

- OIDC audience/issuer/JWKS verification, role checks, and proposal ownership.
- ASGI-layer streaming body cap even when `Content-Length` is absent or false.
- Durable per-principal fixed-window rate limits and active experiment quotas.
- Append-only, PostgreSQL-trigger-protected hash-chained audit events.
- Loopback-only published ports, read-only containers, non-root UIDs,
  `no-new-privileges`, bounded tmpfs, and mTLS signer traffic.
- Readiness checks cover database-backed stores, active policy, and signer
  identity; graceful shutdown closes signer and RPC clients.

## Supply-chain controls

GitHub Actions and third-party actions are pinned to full commit SHAs. All
third-party Compose images and Dockerfile bases are pinned by digest. CI runs
CodeQL, Bandit, `pip-audit`, `cargo-audit`, `cargo-deny`, Slither, Gitleaks, and
Trivy, and uploads image SBOM and Python coverage artifacts. BuildKit-generated
container provenance is retained by the release process.

Two RustSec entries are explicitly acknowledged in `deny.toml`: both describe
unmaintained transitive crates with no reported vulnerability and no safe
upgrade. They remain visible by ID and must be revisited on dependency updates.

## Residual risks

- Development keys and certificates are local files, not managed custody.
- Keycloak uses development mode and PostgreSQL is a single node without TLS.
- A compromised host can deny service or withhold transactions and evidence.
- Policy controls money movement, not arbitrary data exfiltration through tool
  arguments.
- MEV protection in the deterministic research track does not prove safety on a
  live chain.
- Audit chaining detects mutation but external root anchoring is not automatic
  in the Compose profile.
- The project has not completed an independent security assessment.

Report vulnerabilities using the private process in the repository-level
`.github/SECURITY.md`; do not open a public issue for a suspected vulnerability.
