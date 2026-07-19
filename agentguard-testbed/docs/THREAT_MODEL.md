# Threat model

## Protected assets

1. Wallet signing keys and authorized wallet balances.
2. Proposal intent, active policy, reservations, budgets, mandates, and nonces.
3. Exact transaction integrity from proposal through settlement.
4. Decision, signer, settlement, attestation, and audit evidence.
5. Availability of legitimate proposal, execution, and reconciliation work.

## Adversaries

| Adversary | In-scope capabilities | Out-of-scope assumption |
|---|---|---|
| Content injector | Controls text/tool output read by an agent, including encoded instructions | Cannot directly access the signer network/key |
| Malicious tool or counterparty | Controls tool metadata/results, payment request, recipient, quote, or inbound asset | Cannot forge policy/signer signatures |
| Compromised peer/model | Emits arbitrary proposals and tries forbidden API operations | Receives proposal-only capability, no raw signing primitive |
| Authenticated malicious principal | Sends malformed/large/replayed requests and probes another owner's objects | Cannot forge a valid OIDC token for a stronger role |
| Compromised API host | Sends arbitrary signer requests, reorders lifecycle operations, withholds evidence | Cannot read signer key or rewrite signer replay state |
| RPC/searcher adversary | Delays, replaces, reorders, reorgs, or returns malformed chain data | Cannot forge a transaction signed by the managed key |
| Direct smart-account caller | Bypasses off-chain policy and attempts replay, underbound calldata, or reentrancy | Cannot forge owner/session signature or owner rule update |
| Database client compromise | Attempts to mutate/delete audit history and lifecycle state | Database superuser/host takeover is a deployment incident, not cryptographically prevented |

## Trust boundaries

```text
untrusted content/tools/models
        -> authenticated proposal API
        -> deterministic policy + durable reservation/decision
        -> mTLS isolated signer (independent validation + replay state)
        -> EVM RPC / mempool / chain
        -> durable reconciliation + complete attestation
        -> offline verifier / reviewer
```

Keycloak, PostgreSQL, the API, the signer, and the chain are separate failure
domains. Development Compose places them on one Docker host for reproduction;
that does not make the host a production isolation boundary.

## Security objectives

- Only an active policy ALLOW decision for the same proposal/reservation can
  authorize signing.
- The signer, not the API, derives the digest of the exact canonical transaction.
- A decision or wallet nonce cannot produce a second signature.
- Ownership and roles prevent cross-principal lifecycle/evidence operations.
- A submitted transaction reaches one durable terminal state from canonical
  receipt evidence after configured confirmations.
- Retained evidence verifies without mutable service state and audit mutation is
  detectable.
- Direct smart-account calls cannot bypass signature, nonce, cap, allowlist,
  deadline, calldata, emergency-stop, or reentrancy controls.

## Availability and ambiguity

Fail-closed behavior can sacrifice liveness. Signer/database interruption may
consume an authorization without persisting a signed execution; identity/RPC
unavailability blocks new execution; MEV-aware cancellation can defer a valid
swap. These outcomes are preferred to duplicate or underbound signing and must
be handled by runbook, not replay-state deletion.

## Explicit non-goals

- Preventing arbitrary data exfiltration through model/tool arguments.
- Defending a fully compromised production database superuser, signer runtime,
  hypervisor, or hardware root of trust.
- Proving economic safety across live chains, bridges, tokens, protocols, MEV,
  oracle failures, or governance changes.
- Establishing hardware attestation from `local-compose-v1` software evidence.
- Claiming independent audit or production custody readiness.

Map each objective to current evidence in [SECURITY_CLAIMS.md](SECURITY_CLAIMS.md).
