# Security claim matrix

Status meanings:

- **Implemented:** enforced by shipped code and automated tests.
- **Reference-only:** implemented for the local profile but requires a different
  production control or topology.
- **Research result:** supported by deterministic experiments, not a deployment
  guarantee.
- **External gate:** cannot be completed by the implementing repository.
- **Not claimed:** intentionally outside the assurance boundary.

| Claim | Status | Executable evidence | Limitation |
|---|---|---|---|
| The signer authorizes one exact canonical EIP-1559 transaction and derives its digest internally. | Implemented | `signer/src/main.rs`; 11 native signer tests; `tests/test_signer_authorization.py`; runtime smoke | Native transfer and allowlisted contract-call bindings are implemented; this does not validate arbitrary application semantics. |
| Mutation of chain, nonce, wallet, destination, value, calldata, gas, or fees is denied. | Implemented | Rust substitution/property tests; Python reference-gate tests | Correctness depends on maintaining the versioned contract when fields are added. Unknown fields deny by default. |
| Signer identity and replay state survive restart and fail closed on corrupt/missing durable configuration. | Implemented | Rust persistence/replay tests; Compose restart proof; signer volume configuration | Local file-backed key/replay state is not HSM, TEE, or MPC custody. |
| API-to-signer traffic is mutually authenticated and signer responses are treated as untrusted. | Reference-only | `src/aegisledger/signer_client.py`; contract tests; generated local CA/client certificates | Development CA material is generated on disk. Production needs managed issuance, rotation, revocation, and workload identity. |
| Decisions, executions, settlements, attestations, audit events, jobs, and rate windows survive API restart. | Implemented | PostgreSQL adapters and migrations `0001`–`0005`; restart/recovery tests; live Compose restart proofs | Single-node PostgreSQL is a reference topology; HA, TLS, PITR, and regional recovery are deployment work. |
| A proposal cannot be signed/submitted twice under a different execution request. | Implemented | Unique database constraints, idempotent artifact store, execution API tests, signer replay denial | Signer and PostgreSQL are separate commit domains; interrupted in-flight operations may require reconciliation and remain fail closed. |
| Submitted transactions reconcile finality and pre-finality reorg observations durably. | Implemented | `src/aegisledger/reconciler.py`; restart/reorg tests; runtime smoke reaches two confirmations | Confirmation count is a configured local threshold, not a universal finality guarantee. |
| A complete attestation is independently verifiable from retained bytes. | Implemented | `src/aegisledger/attestations.py`; tamper tests; persisted attestation API; runtime smoke offline verification | `local-compose-v1` is software build evidence, not hardware remote attestation. |
| Audit mutation is detectable and database clients cannot rewrite journal history. | Implemented | `src/aegisledger/audit.py`; database append-only trigger; chain verification tests | External root anchoring and third-party transparency logging are not automatic. |
| Human/API access is authenticated, role-scoped, ownership-safe, rate-limited, and body-bounded. | Reference-only | OIDC/API tests; streamed-body 413 proof; durable rate-limit test | Compose uses Keycloak `start-dev`; production identity, WAF, abuse controls, and session policy remain deployment responsibilities. |
| Experiment jobs have durable ownership, active quotas, restart recovery, and atomic result publication. | Implemented | `src/aegisledger/experiment_store.py`; migration `0004`; recovery tests and live restart proof | Workers share the API image/volume in Compose; large-scale scheduling and resource isolation are not claimed. |
| The smart account blocks direct unsigned/incorrectly signed bypass, replay, policy violations, and reentrancy. | Implemented | 8 Solidity unit tests, 2 invariant suites, Slither medium/high gate | Contract is testnet/reference code and has not been externally audited or deployed with real funds. |
| Deterministic AgentGuard evaluations show zero monetary loss for the scoped strict-guard attack variants. | Research result | `docs/RESULTS.md`, `docs/results.json`, reproducible evaluation workflow | Scripted agents and simulated economics do not establish live-model or live-market effectiveness. Tool-argument exfiltration remains out of money-policy scope. |
| The system is safe for production custody or direct internet exposure. | Not claimed | N/A | Requires managed custody, HA services, live-chain risk work, load/chaos SLOs, and independent audit. |
| Novelty, patentability, freedom to operate, or safe public disclosure is established. | External gate | Owner/counsel decision record | Repository implementation cannot provide legal advice or preserve rights after publication. |
| An independent security audit is complete. | External gate | Signed report from a reviewer independent of implementation | Self-review, automated scanning, and agent review do not satisfy this gate. |

## Release interpretation

The repository can be described as an **industry-grade security research
reference with a real local transaction lifecycle** once its automated gates
pass. It must not be described as an audited production wallet, custody system,
or hardware-attested signer. Public release remains blocked by the two external
gates above.

Current gate ownership, freshness, blockers, and evidence references are tracked
in the machine-readable [assurance scorecard](assurance-scorecard.json). Its
validation proves that the gate record is complete and internally consistent;
it does not convert pending or blocked gates into passed claims.
