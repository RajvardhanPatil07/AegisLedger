# Independent reviewer checklist

Review the exact candidate commit; record tool versions, commands, output, and
all deviations. Do not rely on screenshots or the implementer's summary.

## Scope and claims

- [ ] Confirm the commit SHA and a clean working tree.
- [ ] Read the threat model, claim matrix, three ADRs, operations runbook, and
  external release gates.
- [ ] Mark every claim as supported, overstated, underspecified, or out of scope.
- [ ] Confirm the review is independent of implementation and disclose conflicts.

## Signer and transaction path

- [ ] Trace proposal fields into decision, reservation, transaction binding,
  unsigned RLP, signer validation, raw signed bytes, and submission.
- [ ] Mutate chain, wallet, nonce, target, value, calldata, gas, priority fee,
  maximum fee, decision ID, policy hash, expiry, and unknown JSON fields.
- [ ] Prove replay and concurrent duplicate requests deny across signer restart.
- [ ] Corrupt/miss key and replay files and confirm startup fails closed.
- [ ] Verify API response validation recomputes the raw-transaction network hash.

## Lifecycle and evidence

- [ ] Interrupt before signing, after signer consumption, after persistence,
  after RPC acceptance, and during reconciliation; classify each recovered state.
- [ ] Verify unique constraints and idempotency under concurrent requests.
- [ ] Exercise receipt disappearance/reorg before finality and canonical recovery.
- [ ] Recompute all complete-attestation hashes/signatures with a separate tool.
- [ ] Attempt attestation/audit mutation and unauthorized cross-owner reads.
- [ ] Restart API, signer, PostgreSQL client workers, and experiment workers.

## API, identity, and abuse

- [ ] Test token issuer/audience/signature/expiry failures and every role matrix edge.
- [ ] Stream an oversized body without `Content-Length`; test invalid lengths,
  rate-window concurrency, quota races, and object-ID enumeration.
- [ ] Review error bodies/logs/metrics for secrets and authorization artifacts.
- [ ] Validate read-only/non-root/no-new-privileges/container network assumptions.

## Smart account

- [ ] Review EIP-712 domain/signature malleability, nonce/caps/session arithmetic,
  calldata decoding, call/value binding, emergency stop, and owner governance.
- [ ] Reproduce direct bypass, replay, underbound calldata, reentrancy, and
  invariant suites using an independent Foundry environment.
- [ ] Treat the contract as unaudited testnet code until this review is complete.

## Supply chain and operations

- [ ] Re-run CodeQL, dependency/advisory/license/source scans, Slither, Gitleaks,
  Trivy, coverage, mutation tests, formal checks, and browser accessibility flows.
- [ ] Verify every action/base/runtime image pin against its upstream release.
- [ ] Inspect CycloneDX SBOMs and BuildKit provenance for every shipped image.
- [ ] Run `scripts/reproduce_release.sh` from a fresh clone/runner.
- [ ] Perform backup/restore, rollback, ambiguous-signing, load, and chaos drills.

## Report

- [ ] Assign severity, exploit preconditions, affected claim, reproduction, and
  remediation to every finding.
- [ ] Re-test fixes on the final candidate SHA.
- [ ] State residual risks and whether public research release is acceptable.
- [ ] Separately state whether production custody is in scope; default is no.
