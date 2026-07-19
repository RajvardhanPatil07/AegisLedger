# AegisLedger maximum-assurance checklist

This is the executable index for `tasks/plan.md`. A checked box requires linked,
exact-version evidence. Prose, screenshots, ancestor CI runs, and self-review alone
do not count.

## Implementation ledger — 2026-07-19

The following local controls are implemented on the current hardening branch.
They reduce ambiguity and automate evidence collection, but do not satisfy the
external acceptance criteria of their parent tasks by themselves:

- `0689f8e` adds a fail-closed, owner/evidence/freshness-aware scorecard. Task 1
  remains open until the owner and an independent reviewer approve the matrix.
- `01a7914` makes 0.3.0 consistently an unreleased candidate. Task 4 remains open
  until an approved release is signed, tagged, and revalidated in release mode.
- `3a246b1` inventories every tracked provenance group and relevant deleted Git
  material. Task 5 remains open while owner confirmation and independent license/
  source review are unresolved.
- `757e286` binds retained test, evaluation, image, runtime, and reviewer evidence
  to one Git SHA with file checksums. Task 8 remains open until the exact pushed
  candidate passes every remote workflow and the complete manifest contains the
  resulting workflow URLs, conclusions, tool versions, and missing gate outputs.

No public-visibility or production-custody approval is implied by this ledger.

## Gate 0: Decisions and scorecards

- [ ] 1. Assign owners, evidence URIs, expiry dates, and status to every research,
      public-release, and production-custody scorecard item.
- [ ] 2. Record the patent/publication decision before changing visibility.
- [ ] 3. Approve the exact production custody scope and explicit non-goals.
- [ ] Checkpoint 0: visibility and production implementation gates are enforced.

## Gate 1: Public research release

- [ ] 4. Reconcile 0.3.0 package, changelog, citation, tag, and release metadata.
- [ ] 5. Complete code/text/figure/data/prompt copyright and provenance inventory.
- [ ] 6. Push and review the hardening work through focused pull requests.
- [ ] 7. Protect `main`; require checks/reviews; enable secret/code/dependency
      security, vulnerability reporting, and least-privilege environments.
- [ ] 8. Produce complete same-SHA CI, security, runtime, mutation, evaluation,
      backup/restore, SBOM, and provenance evidence.
- [ ] 9. Sign images, SBOMs, provenance, source archive, checksums, and release
      manifest; verify them on a clean runner.
- [ ] 10. Complete independent assessment and re-test all remediations on the final
      candidate SHA.
- [ ] 11. Merge, sign, tag, release, reproduce from two clean accounts, then change
      visibility only with explicit owner authorization.
- [ ] Checkpoint 1: public-release scorecard has no failing or expired gate.

## Gate 2: Research excellence

- [ ] 12. Audit every material claim, citation, date, figure, and novelty statement.
- [ ] 13. Freeze hypotheses, endpoints, baselines, sample sizes, statistics, and
      failure taxonomy before large runs.
- [ ] 14. Add replayable, secret-safe live-model transcripts and at least two
      optional adapters.
- [ ] 15. Retain latency, token/model cost, gas, availability, RPC, denial, and
      recovery observations with confidence intervals.
- [ ] 16. Reproduce at least two external/literature baselines and all internal
      ablations under the same harness.
- [ ] 17. Obtain independent replication and publish an immutable archival bundle.
- [ ] Checkpoint 2: claims and results reproduce from raw artifacts without manual
      correction.

## Gate 3: Core implementation assurance

- [ ] 18. Split API transport, authorization, orchestration, policy, experiments,
      and evidence into focused modules with stable contracts.
- [ ] 19. Split Rust schemas, decision verification, Ethereum binding, replay,
      evidence, transport, and startup into focused security layers.
- [ ] 20. Enforce critical-path branch/condition coverage and >=98% signer
      authorization mutation score.
- [ ] 21. Expand formal models and cross-language differential vectors for replay,
      ambiguity, policy, finality, canonicalization, and transaction codecs.
- [ ] 22. Automate migration, backup/restore, rollback, load, soak, race, chaos, and
      ambiguous-signing matrices.
- [ ] Checkpoint 3: critical paths are modular, adversarially tested, and reviewed.

## Gate 4: Production custody boundary

- [ ] 23. Approve HSM/MPC/TEE custody ADR and residual-risk analysis.
- [ ] 24. Define provider-neutral exact-transaction custody contract and
      conformance suite with no arbitrary-signing capability.
- [ ] 25. Implement and certify one selected managed custody adapter.
- [ ] 26. Pass witnessed key creation, dual approval, activation, rotation,
      recovery, suspension, compromise, and destruction exercises.
- [ ] 27. Verify production attestation roots and ambiguous-signing recovery across
      every interruption boundary.
- [ ] Checkpoint 4: no exportable local production key path or single-person key/
      policy control remains.

## Gate 5: Production platform

- [ ] 28. Deploy reviewed IaC for isolated environments, private networks,
      workload identity, secrets, ingress/egress, WAF/rate/DDoS controls, and
      least privilege.
- [ ] 29. Deploy production identity and HA PostgreSQL with MFA/admin controls,
      TLS, encryption, PITR, immutable audit export, and tenant isolation.
- [ ] 30. Prove approved SLOs, capacity, failover, RTO/RPO, and regional disaster
      recovery under measured load and chaos.
- [ ] 31. Staff on-call and pass deployment, rollback, access-review, dependency,
      vulnerability, compromise, and incident-communication exercises.
- [ ] Checkpoint 5: platform claims are supported by production-like drill data.

## Gate 6: Chain and economic safety

- [ ] 32. Implement semantic, version-aware adapters for every supported protocol
      operation; deny all other contract calls.
- [ ] 33. Require independent simulation, oracle/risk checks, expected balance
      deltas, bounded slippage, and measured MEV routing policy.
- [ ] 34. Enforce chain-specific finality, reorg behavior, velocity/exposure/loss
      caps, emergency stop, and dual-controlled governance.
- [ ] Checkpoint 6: every supported action stays inside an approved maximum-loss
      envelope under adversarial tests.

## Gate 7: Audit, compliance, and launch

- [ ] 35. Complete independent smart-contract audit, platform/custody audit, and
      scoped penetration test; close and re-test critical/high findings.
- [ ] 36. Obtain applicable legal, privacy, financial/custody, sanctions/AML,
      reporting, customer-disclosure, and insurance approvals.
- [ ] 37. Complete at least 30 consecutive days of capped production-topology
      testnet operation inside SLO/error budgets.
- [ ] 38. Obtain separate go-live approval and complete a tiny, allowlisted,
      strictly loss-capped real-fund pilot.
- [ ] 39. Hold a cross-functional scale review before increasing any balance,
      user, chain, protocol, or operation limit.
- [ ] Checkpoint 7: audited deployed artifacts, pilots, operations, and approvals
      satisfy the production-custody scorecard.

## Gate 8: Continuous assurance

- [ ] 40. Automate evidence-age expiry; run continuous security gates, monthly
      risk review, quarterly access/key/restore/incident exercises, annual external
      audit/threat-model refresh, patch SLAs, advisories, and public bug bounty.
- [ ] Continuous gate: any stale evidence, severe incident, failed drill, or
      unresolved critical/high finding automatically lowers readiness and blocks
      scope expansion.

## Next execution queue

1. [ ] Task 1 — adopt the measurable scorecards.
2. [ ] Task 2 — complete the private publication decision.
3. [ ] Task 4 — reconcile 0.3.0 release metadata.
4. [ ] Task 5 — complete provenance inventory.
5. [ ] Task 6 — push the hardening work and open focused review.
6. [ ] Task 7 — configure repository governance.
7. [ ] Task 8 — obtain complete same-commit release evidence.
8. [ ] Task 10 — commission independent candidate review.

Production Tasks 23-40 remain blocked until the production scope (Task 3) and
core assurance checkpoint (Tasks 18-22) are approved.
