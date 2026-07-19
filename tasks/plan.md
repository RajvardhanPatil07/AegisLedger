# Maximum-Assurance Plan: AegisLedger 10/10 Program

## Objective

Move AegisLedger from a strong private research candidate to:

1. a publication-ready open research repository;
2. a reproducible, externally credible research artifact; and
3. a separately approved production-custody platform for narrowly defined assets,
   chains, protocols, and transaction types.

“10/10” is an evidence target, not a permanent security claim. The production
score is earned only while the exact deployed release has green controls, no
unresolved critical/high findings, approved residual risk, and demonstrated
operations. A public research release must never be described as production
custody merely because its repository checks pass.

## Baseline at commit `8e8d6ce`

Already present:

- exact EIP-1559 transaction binding in the Rust signer;
- mTLS, durable replay state, policy signatures, and fail-closed parsing;
- PostgreSQL-backed lifecycle, audit, attestation, rate, and experiment state;
- Solidity policy controls with unit and invariant tests;
- OIDC roles, ownership checks, request bounds, quotas, and observability;
- reproducible deterministic attack evaluations;
- Python, Rust, Solidity, web, dependency, browser, mutation, formal, secret,
  container, SBOM, provenance, and runtime workflow definitions;
- Apache-2.0 licensing, contribution metadata, threat model, ADRs, security
  claims, release gates, and reviewer guidance.

Verified locally during the readiness review:

- 194 Python tests passed with 78.9% whole-package coverage;
- Ruff, mypy, Bandit, `pip-audit`, Rust format/Clippy/tests, `cargo-audit`,
  `cargo-deny`, Solidity unit/invariant tests, web tests/build, `npm audit`, and
  Playwright/Axe checks passed;
- Gitleaks 8.30.1 scanned 31 commits and found no leaks.

Current blockers:

- the exact candidate is local-only and has no same-commit CI evidence;
- remote `main` is 29 commits behind and has no protection or rulesets;
- patent/publication and independent-review gates are unresolved;
- release metadata says 0.3.0 while the changelog remains Unreleased and no tag
  exists;
- load/chaos, migration compatibility, image signing, stronger research
  statistics, source cleanup, production custody, HA, and operational proof are
  incomplete.

## Target scorecards

### Research and portfolio: maximum-assurance exit gate

- Every material claim maps to code, a retained artifact, a primary source, or
  an explicitly labeled hypothesis.
- Deterministic and live-model experiments publish seeds, versions, transcripts,
  failure classifications, confidence intervals, latency, gas, availability,
  and cost.
- At least two relevant baselines are reproduced under the same harness.
- A clean-room reviewer reproduces the release from the public instructions.
- The paper/source inventory has no unresolved fabricated, weak, or
  mischaracterized citation and no unqualified novelty claim.
- The archived release has a stable identifier, signed tag, immutable artifacts,
  and a claim-to-evidence matrix.

### Public-release readiness: maximum-assurance exit gate

- The owner records a patent/publication decision before disclosure.
- The complete history passes secret, license, dependency, and provenance review.
- The exact release SHA passes every required workflow with no allowed failure.
- Protected `main`, required reviews/checks, push protection, CodeQL, Dependabot,
  private vulnerability reporting, and least-privilege environments are enabled.
- Version, changelog, citation, tag, release notes, SBOMs, provenance, checksums,
  and container signatures agree.
- An independent reviewer approves the exact public candidate for research use;
  all critical/high findings are fixed and re-tested.
- The README and release clearly state that real funds and direct internet
  exposure remain prohibited unless the production scorecard is separately met.

### Production custody: maximum-assurance exit gate

- Scope is narrow and explicit: supported jurisdictions, chains, assets,
  protocols, transaction types, customer types, and custody model.
- Keys are held by an approved managed HSM/MPC/TEE design with attested workload
  identity, separation of duties, dual control, rotation, recovery, and tested
  destruction procedures.
- Identity, secrets, database, network, workloads, logs, and backups use a
  production topology with encryption, least privilege, HA, PITR, and disaster
  recovery.
- Transaction simulation, oracle checks, protocol adapters, caps, allowlists,
  MEV controls, reorg/finality rules, and circuit breakers cover every supported
  action.
- SLOs are measured under load and chaos; incident, rollback, restore, key
  compromise, and ambiguous-signing exercises pass.
- Independent smart-contract and platform/custody audits are complete; critical
  and high findings are closed and medium residuals are owner-approved.
- Applicable legal, privacy, financial, custody, sanctions/AML, reporting, and
  insurance requirements are decided by qualified specialists and implemented
  where applicable.
- A capped testnet and then capped real-fund pilot operate successfully before
  limits increase. A bug bounty and continuous assurance program are active.

## Architecture decisions

- Keep research and production profiles separate. Research may use Compose,
  Anvil, local keys, and deterministic agents; production may not.
- Keep the proposal -> policy -> exact transaction -> isolated signer -> chain ->
  finality -> attestation path as the only money-moving path.
- Use provider-neutral custody interfaces, but certify each provider adapter and
  configuration independently. “Portable” must not mean lowest-common-denominator
  security.
- Treat signer state and database state as separate commit domains. Fail closed,
  retain evidence, and reconcile ambiguity through a reviewed recovery protocol.
- Support only explicitly modeled chain/protocol operations. Arbitrary contract
  calls are outside production scope until a dedicated semantic adapter exists.
- Make release evidence immutable and machine-verifiable. Screenshots and prose
  summaries are supporting material, never the gate itself.
- Require two-person approval for production policy, custody, deployment, and
  emergency-governance changes.
- Prefer deleting unsupported scope over adding generic abstractions.

## Dependency graph

```text
Publication decision + scorecards
  -> release metadata and repository governance
  -> exact-SHA CI/reproduction
  -> independent public-release review
  -> public research release

Research schema + retained transcript format
  -> deterministic/live-model evaluations
  -> statistics + baselines + cost/latency/gas
  -> external reproduction
  -> archival research release

Production scope + custody threat model
  -> custody interface and provider test harness
  -> managed custody adapter + attestation roots
  -> key lifecycle + dual control
  -> production infrastructure + chain risk controls
  -> audits and remediation
  -> testnet pilot -> capped real-fund pilot -> scale review
  -> continuous assurance
```

## Phase 0: Freeze the meaning of success

### Task 1: Adopt measurable scorecards

**Description:** Convert the three target scorecards above into release-blocking
requirements with named evidence owners.

**Acceptance criteria:** Each item has an owner, evidence URI, expiry/review date,
and pass/fail state; production gates cannot be waived by a research release.

**Verification:** Review the matrix with the owner and one independent reviewer;
validate that every “pass” links to immutable evidence.

**Dependencies:** None.

**Likely files:** `agentguard-testbed/docs/SECURITY_CLAIMS.md`,
`agentguard-testbed/docs/RELEASE.md`, `tasks/todo.md`.
**Scope:** Medium.

### Task 2: Record the patent and publication decision

**Description:** Decide whether protection is desired before any visibility change
and record the permitted publication path.

**Acceptance criteria:** A dated owner decision exists; qualified counsel is used
if protection may be desired; the decision names the exact material that may be
published.

**Verification:** Owner signs the decision record and confirms that changing
GitHub visibility is authorized.

**Dependencies:** Task 1.

**Likely files:** Private decision record; public summary in
`agentguard-testbed/docs/RELEASE.md` only if approved. **Scope:** External.

### Task 3: Define the production custody scope

**Description:** Specify what “production” means before choosing vendors or adding
code.

**Acceptance criteria:** The scope names custody model, jurisdictions, users,
chains, assets, protocols, operations, maximum balances, and explicit non-goals;
regulatory questions have assigned specialist owners.

**Verification:** Architecture, security, operations, product, and legal owners
approve the scope and abuse cases.

**Dependencies:** Task 1. May run in parallel with Task 2.

**Likely files:** New `agentguard-testbed/docs/PRODUCTION_SCOPE.md`, update
`agentguard-testbed/docs/THREAT_MODEL.md`. **Scope:** Medium plus external review.

### Checkpoint 0

- No repository visibility change is allowed before Task 2 passes.
- No production implementation is allowed before Task 3 passes.
- Every future task maps to at least one scorecard item.

## Phase 1: Earn a defensible public release

### Task 4: Reconcile version and release metadata

**Description:** Make package versions, changelog, citation, release notes, and tag
policy describe one release truth.

**Acceptance criteria:** `0.3.0` is either consistently released or consistently
unreleased; dates agree; a release checklist validates all version-bearing files.

**Verification:** Automated metadata test passes and `git tag --verify` succeeds
for a test tag.

**Dependencies:** Task 2.

**Likely files:** `CHANGELOG.md`, `CITATION.cff`,
`agentguard-testbed/pyproject.toml`, package manifests, new metadata test.
**Scope:** Medium.

### Task 5: Complete copyright and third-party provenance inventory

**Description:** Establish authorship/license provenance for code, research text,
figures, datasets, prompts, templates, and generated assets.

**Acceptance criteria:** Every non-trivial third-party or generated item has a
source, license/permission, and attribution decision; NOTICE and SBOM policy agree.

**Verification:** Independent license review reports no unresolved incompatible or
unknown material.

**Dependencies:** Task 2.

**Likely files:** `NOTICE`, new `agentguard-testbed/docs/PROVENANCE.md`, research
document, asset manifest. **Scope:** Medium.

### Task 6: Publish the hardening change as reviewable pull requests

**Description:** Push the current work and, where practical, split foundation,
signer/lifecycle, service hardening, console, and release-assurance changes into
reviewable stacks without rewriting evidence-bearing history after review begins.

**Acceptance criteria:** Every PR has standalone intent, risk, tests, and evidence;
the final integration commit is reproducible from reviewed commits.

**Verification:** All PR checks pass and reviewers can trace each security claim to
its implementing PR.

**Dependencies:** Tasks 4-5.

**Likely files:** Git history and PR metadata; no behavioral change required.
**Scope:** Medium.

### Task 7: Enforce repository governance

**Description:** Protect `main` and all release/deployment paths.

**Acceptance criteria:** Required status checks, two-person review for security and
workflow changes, signed commits/tags policy, push protection, secret scanning,
CodeQL, Dependabot, vulnerability reporting, and least-privilege environments are
enabled.

**Verification:** A disposable PR proves direct push, missing review, unsigned
release, and failed required check are blocked.

**Dependencies:** Task 6.

**Likely files:** GitHub rules/settings evidence,
`agentguard-testbed/docs/RELEASE.md`. **Scope:** Medium plus hosting administration.

### Task 8: Produce same-commit automated evidence

**Description:** Run every declared gate for the exact candidate SHA.

**Acceptance criteria:** Python 3.11/3.13, Rust, Solidity, formal, web, browser,
CodeQL, dependencies, Slither, Gitleaks history, Trivy images, SBOM/provenance,
mutation, deterministic evaluation, Compose runtime, and backup/restore all pass;
no job relies on an ancestor result.

**Verification:** A machine-readable release manifest binds each workflow URL,
artifact digest, tool version, and conclusion to the candidate SHA.

**Dependencies:** Tasks 6-7.

**Likely files:** Workflows, `agentguard-testbed/scripts/reproduce_release.sh`,
release manifest generator, `agentguard-testbed/docs/RELEASE.md`. **Scope:** Medium.

### Task 9: Sign and verify release artifacts

**Description:** Add registry-backed image signing and signed release metadata.

**Acceptance criteria:** Images, SBOMs, provenance, source archive, checksums, and
release manifest are signed through an approved identity; verification is
documented and enforced before deployment.

**Verification:** Clean runner verifies every signature and rejects one tampered
artifact and one artifact from an unapproved identity.

**Dependencies:** Task 8.

**Likely files:** Release workflow, verification script,
`agentguard-testbed/docs/RELEASE.md`, `agentguard-testbed/docs/OPERATIONS.md`.
**Scope:** Medium.

### Task 10: Obtain an independent public-release assessment

**Description:** Have a reviewer who did not implement the candidate execute the
reviewer checklist and issue a signed report.

**Acceptance criteria:** All critical/high findings are fixed; medium findings are
fixed or explicitly accepted with owner, reason, expiry, and compensating control;
the exact final SHA is re-tested.

**Verification:** Signed report, remediation commits, and re-test evidence are in
the private release dossier; an approved summary is prepared for publication.

**Dependencies:** Tasks 8-9.

**Likely files:** Reviewer report, `agentguard-testbed/docs/SECURITY_CLAIMS.md`,
release manifest. **Scope:** External.

### Task 11: Publish the research release

**Description:** Merge the approved candidate, create the signed tag/release, then
change visibility only after a final history and settings check.

**Acceptance criteria:** Default branch points to the approved SHA; tag, release,
artifacts, docs, install/reproduction flow, contact routes, and non-production
warning are correct; no private artifact or Actions log leaks secrets.

**Verification:** Two clean external accounts can clone, verify signatures, run the
documented research flow, and report a vulnerability privately.

**Dependencies:** Tasks 2 and 4-10.

**Likely files:** Release notes and public documentation. **Scope:** Medium plus
owner-controlled visibility change.

### Checkpoint 1: Public-release 10/10 target

- All Tasks 2 and 4-11 pass for one SHA.
- Zero unresolved critical/high security, secret, license, or provenance findings.
- Public description says “audited research reference,” not “production custody.”
- Rollback to private is not treated as a confidentiality recovery mechanism.

## Phase 2: Raise research quality to maximum assurance

### Task 12: Audit every research claim and source

**Description:** Replace weak secondary sources where primary sources exist and
label estimates, vendor claims, reported incidents, and hypotheses distinctly.

**Acceptance criteria:** Every quantitative/material claim has a traceable citation;
venue dates and market figures carry retrieval dates; novelty language is qualified;
asset inputs are reproducible.

**Verification:** Independent literature reviewer classifies every citation as
supported, overstated, or unresolved; unresolved claims are removed or rewritten.

**Dependencies:** Task 5.

**Likely files:** Research document, new citation/source manifest, figure scripts
or data. **Scope:** Medium per section; execute as multiple focused PRs.

### Task 13: Predefine the evaluation protocol

**Description:** Specify hypotheses, baselines, seeds, sample sizes, metrics,
exclusions, statistical tests, and failure taxonomy before the larger run.

**Acceptance criteria:** Primary/secondary endpoints and confidence methods are
frozen; money loss, task utility, false denial, latency, gas, availability, and cost
have exact definitions.

**Verification:** Statistical reviewer approves the protocol; the harness validates
all required metadata before accepting a run.

**Dependencies:** Task 1.

**Likely files:** New `agentguard-testbed/docs/EVALUATION_PROTOCOL.md`, evaluation
schemas/tests. **Scope:** Medium.

### Task 14: Add replayable live-model adapters

**Description:** Add provider-neutral transcript recording and at least two optional
model adapters without placing secrets or network dependence in required CI.

**Acceptance criteria:** Inputs, tool calls, outputs, model/version, sampling
parameters, timestamps, and content hashes replay deterministically; secrets and
PII are redacted before persistence.

**Verification:** Recorded runs replay offline; malicious transcript content cannot
escape the sandbox or invoke unapproved tools.

**Dependencies:** Task 13.

**Likely files:** New adapter module, transcript schema/store, focused tests,
documentation. **Scope:** Medium per adapter.

### Task 15: Measure operational and economic cost

**Description:** Retain latency distributions, token/model cost, gas, RPC calls,
availability loss, signer denials, and recovery events for every experiment.

**Acceptance criteria:** Metrics have units and confidence intervals; retained
artifacts link raw observations to summaries; missing data fails the release run.

**Verification:** Golden-data tests recompute published tables/figures from raw
artifacts with no manual edits.

**Dependencies:** Tasks 13-14.

**Likely files:** Evaluation schema/harness, results renderer, tests, result docs.
**Scope:** Medium.

### Task 16: Reproduce meaningful baselines

**Description:** Compare strict guard, prompt-only defense, tool allowlisting,
custody-only rules, smart-account controls, and private-routing variants under the
same attacks and utility tasks.

**Acceptance criteria:** At least two external or literature baselines and all
internal ablations use identical workloads; limitations and negative results are
published.

**Verification:** Baseline configurations and output hashes reproduce on a clean
runner; statistical comparisons follow Task 13.

**Dependencies:** Tasks 13 and 15.

**Likely files:** Baseline configurations, evaluation harness, tests, results docs.
**Scope:** Medium per baseline.

### Task 17: Obtain independent replication and archival release

**Description:** Have a second party reproduce the main results and archive the
paper, code, data, configs, and environment manifest.

**Acceptance criteria:** Replicator records deviations and independently reaches
the stated conclusions; the archival package has a stable identifier and immutable
checksums.

**Verification:** Public replication report and archive verification script pass.

**Dependencies:** Tasks 12-16.

**Likely files:** Replication report, archive manifest, citation metadata.
**Scope:** External plus Medium packaging.

### Checkpoint 2: Research 10/10 target

- Claims, sources, results, figures, and artifacts are mutually reproducible.
- Live-model results are separated from deterministic CI results.
- Confidence intervals, baselines, utility trade-offs, costs, and limitations are
  visible in the abstract/executive summary, not buried in an appendix.
- Independent replication is complete.

## Phase 3: Reduce core implementation risk

### Task 18: Split API orchestration from domain logic

**Description:** Break the 1,011-line API module into transport, authorization,
execution orchestration, policy, experiment, and evidence modules without changing
public contracts.

**Acceptance criteria:** No new module exceeds the agreed size threshold; route
handlers contain validation/translation only; lifecycle logic has direct tests.

**Verification:** Contract snapshots, all tests, mypy, coverage, and runtime smoke
remain green; complexity decreases rather than moving branches.

**Dependencies:** Task 8.

**Likely files:** API module plus 3-5 extracted modules per focused PR and tests.
**Scope:** Several Medium PRs.

### Task 19: Split the signer into explicit security layers

**Description:** Separate schemas/canonicalization, decision verification, Ethereum
transaction validation, replay persistence, evidence, transport, and startup from
the 1,140-line signer file.

**Acceptance criteria:** Security boundaries have narrow typed interfaces; no
arbitrary-message signing path exists; unknown fields and unsupported operations
remain fail closed.

**Verification:** Native, mutation, property, malformed corpus, restart, and mTLS
tests pass against the refactored binary with unchanged vectors.

**Dependencies:** Task 8.

**Likely files:** Rust modules and focused tests, 3-5 files per PR.
**Scope:** Several Medium PRs.

### Task 20: Raise assurance on critical paths

**Description:** Set targeted branch/condition and mutation gates for authorization,
signing, lifecycle transitions, ownership, attestation, reorg, and recovery code.

**Acceptance criteria:** Critical modules meet >=90% branch coverage where tooling
supports it; signer authorization mutation score is >=98%; every previously
surviving meaningful mutant has a regression test or documented equivalent-proof
rationale.

**Verification:** CI fails on deliberately removed authorization, ownership, replay,
and attestation checks.

**Dependencies:** Tasks 18-19.

**Likely files:** Tests, coverage config, mutation workflow, critical modules only
when a defect is found. **Scope:** Medium per subsystem.

### Task 21: Expand formal and differential verification

**Description:** Model nonce/reservation ambiguity, policy approval, signer replay,
settlement finality, and emergency governance; add cross-language canonicalization
and transaction-codec differential vectors.

**Acceptance criteria:** Safety invariants and explicit liveness trade-offs are
documented; Python/Rust/Solidity agree on shared vectors; bounded model checks and
fuzz corpora run in CI.

**Verification:** Seeded faulty implementations violate the intended invariant and
are caught by formal or differential gates.

**Dependencies:** Tasks 18-20.

**Likely files:** Formal specs/configs, shared vectors, language-specific tests.
**Scope:** Medium per invariant.

### Task 22: Automate migration, backup, load, and chaos matrices

**Description:** Test every supported upgrade/rollback path and failure boundary,
including API/signer/database/RPC interruption.

**Acceptance criteria:** N-1 -> N migration, restore, reconciliation, ambiguous
signing, quota races, degraded dependencies, and rollback scenarios have automated
results; no test deletes evidence to recover.

**Verification:** Scheduled clean-environment matrix produces retained RTO/RPO,
integrity, latency, and recovery evidence.

**Dependencies:** Tasks 18-21.

**Likely files:** Migration/chaos scripts, workflows, fixtures, operations docs.
**Scope:** Medium per scenario family.

### Checkpoint 3

- Security-critical modules have explicit interfaces, adversarial tests, and
  independent review.
- Formal/differential tests cover cross-service assumptions.
- Upgrade, restore, rollback, and ambiguity evidence pass before custody work.

## Phase 4: Replace local signing with approved custody

### Task 23: Select the custody architecture

**Description:** Evaluate managed HSM, MPC, and TEE-assisted options against the
production scope and threat model.

**Acceptance criteria:** ADR records trust roots, operator powers, certification,
attestation, quorum, latency, availability, recovery, geography, cost model, vendor
exit, and residual risks; an accountable owner approves one option.

**Verification:** Independent security architect challenges compromise and outage
scenarios and signs the decision.

**Dependencies:** Tasks 3 and 21-22.

**Likely files:** New custody ADR, updated threat model and production scope.
**Scope:** External plus Medium documentation.

### Task 24: Define a provider-neutral custody contract and conformance suite

**Description:** Specify exact-transaction signing, identity/attestation, replay,
idempotency, timeouts, errors, health, rotation, and audit behavior independent of a
specific vendor.

**Acceptance criteria:** Contract cannot express arbitrary signing; every provider
must pass the same mutation, replay, failover, and evidence tests.

**Verification:** A fake permissive provider fails conformance; local signer passes
as a non-production reference implementation.

**Dependencies:** Task 23.

**Likely files:** Custody protocol/types, conformance tests, ADR.
**Scope:** Medium.

### Task 25: Implement and certify the selected custody adapter

**Description:** Integrate one approved provider using workload identity and exact
transaction authorization.

**Acceptance criteria:** No exportable production key reaches application memory or
disk; provider policy binds tenant/wallet/chain/action; responses and attestations
are validated; retries cannot duplicate signatures.

**Verification:** Provider sandbox tests cover substitution, replay, stale policy,
identity spoofing, quota, outage, partial success, and key-disabled states.

**Dependencies:** Task 24.

**Likely files:** One adapter, configuration, conformance tests, runbook.
**Scope:** Several Medium PRs.

### Task 26: Implement the key lifecycle and dual-control runbooks

**Description:** Define creation, approval, activation, rotation, backup/recovery,
suspension, compromise response, and destruction.

**Acceptance criteria:** No single human or workload can create and activate a
production key/policy alone; break-glass use is time-bound, alerted, and reviewed;
recovery never bypasses transaction policy.

**Verification:** Witnessed key ceremony, rotation, lost-operator, provider outage,
and compromise drills produce signed evidence.

**Dependencies:** Task 25.

**Likely files:** Key-management runbook, policy-as-code, drill scripts/evidence.
**Scope:** Medium plus operations.

### Task 27: Harden attestation trust and ambiguous-signing recovery

**Description:** Replace software build labels with approved roots of trust and a
reviewed repair/reconciliation workflow for uncertain signer outcomes.

**Acceptance criteria:** Attestation chain, freshness, revocation, measurement
policy, and rotation are verified; ambiguous outcomes cannot be retried until chain,
custody, and durable state are reconciled.

**Verification:** Expired/revoked/wrong-workload attestations and every interruption
boundary fail safely; recovery preserves evidence and never reuses an authorization.

**Dependencies:** Tasks 25-26.

**Likely files:** Attestation verifier/policy, reconciler, tests, runbook.
**Scope:** Several Medium PRs.

### Checkpoint 4

- No local file-backed production key path remains enabled.
- Custody provider, workload identity, key policy, and application authorization
  are independently enforced.
- Key and ambiguous-signing drills pass under dual control.

## Phase 5: Build a production platform

### Task 28: Implement production infrastructure and identity boundaries

**Description:** Create reviewed infrastructure-as-code for separate environments,
private networks, workload identity, secrets, ingress, egress, and least privilege.

**Acceptance criteria:** Production has no public database/signer endpoint, no static
cloud credential, controlled egress, encrypted transport/storage, isolated admin
plane, WAF/rate/DDoS controls, and policy-checked deployments.

**Verification:** IaC scan, permission tests, network reachability tests, and a cloud
security review pass from a clean account.

**Dependencies:** Tasks 3 and 23-27.

**Likely files:** New `agentguard-testbed/infra/` modules and policy tests, split by
resource family. **Scope:** Several Medium PRs.

### Task 29: Deploy production-grade identity and durable data services

**Description:** Replace development Keycloak/PostgreSQL topology with managed or
hardened HA services.

**Acceptance criteria:** OIDC/MFA/admin policy, tenant isolation, database TLS,
encryption, HA, PITR, immutable audit export, retention, and schema ownership meet
the production scope.

**Verification:** Cross-tenant, token, failover, replica, PITR, credential rotation,
and privileged-database incident tests pass.

**Dependencies:** Task 28.

**Likely files:** Identity/data IaC modules, migrations, policy tests, runbooks.
**Scope:** Several Medium PRs.

### Task 30: Define and prove SLOs, capacity, and disaster recovery

**Description:** Establish authorization, signing, settlement, evidence, and support
SLOs plus resource and recovery budgets.

**Acceptance criteria:** Approved SLI formulas, alert thresholds, capacity model,
RTO/RPO, dependency budgets, and degraded modes exist; dashboards use production
signals.

**Verification:** Load, soak, zone loss, database failover, custody outage, RPC
degradation, queue backlog, and regional recovery drills meet the agreed objectives.

**Dependencies:** Tasks 28-29 and 22.

**Likely files:** Load/chaos suites, alerts/dashboards, SLO and DR runbooks.
**Scope:** Medium per scenario family.

### Task 31: Establish secure operations and change management

**Description:** Define on-call, access reviews, deployment approvals, audit review,
vulnerability SLAs, dependency updates, rollback, and evidence retention.

**Acceptance criteria:** Named 24x7 escalation for money-moving incidents, quarterly
access review, two-person production changes, tested rollback, and expiring risk
exceptions are operational.

**Verification:** Tabletop and live drills prove alert receipt, escalation,
containment, evidence preservation, communication, and recovery.

**Dependencies:** Tasks 28-30.

**Likely files:** Operations/security runbooks, policy-as-code, drill records.
**Scope:** Medium plus organization process.

### Checkpoint 5

- Production infrastructure is reproducible, least-privilege, private, observable,
  recoverable, and independently reviewed.
- Capacity and DR claims are measured, not estimated.
- No launch occurs without staffed operational ownership.

## Phase 6: Constrain chain and economic risk

### Task 32: Build semantic adapters for every supported operation

**Description:** Replace generic contract-call permission with protocol/version-
specific decoding, invariants, and allowlists.

**Acceptance criteria:** Every supported selector binds recipient, asset, amount,
slippage, deadline, destination chain, and protocol-specific constraints; unknown
proxy/implementation/version changes fail closed.

**Verification:** Malicious calldata, proxy upgrade, token quirks, approval abuse,
callback/reentrancy, fee-on-transfer, and decimal edge cases are denied.

**Dependencies:** Tasks 3 and 21.

**Likely files:** One adapter, policy schema, tests, threat update per protocol.
**Scope:** Medium per operation.

### Task 33: Add independent simulation, oracle, and MEV controls

**Description:** Require preflight simulation and independent price/risk evidence,
then choose protected routing or bounded public execution.

**Acceptance criteria:** Stale/manipulated oracle, state drift, excessive price
impact, sandwich risk, unexpected balance delta, and simulation divergence trigger
deny/cancel; private routing has fallback and censorship policy.

**Verification:** Forked-chain and adversarial relay tests quantify loss, false
denials, latency, and availability cost.

**Dependencies:** Task 32.

**Likely files:** Simulation/risk clients, policy rules, tests, economic results.
**Scope:** Several Medium PRs.

### Task 34: Make finality, limits, and circuit breakers chain-specific

**Description:** Define reorg/finality rules, exposure caps, velocity limits, daily
loss limits, emergency stop, and governance per chain/asset.

**Acceptance criteria:** Limits are enforced off-chain and where feasible on-chain;
configuration changes require dual control; chain halt/reorg/oracle/custody incidents
automatically reduce or stop exposure.

**Verification:** Historical and synthetic deep reorg, congestion, chain halt,
depeg, and oracle failure scenarios preserve the approved maximum loss envelope.

**Dependencies:** Tasks 32-33.

**Likely files:** Chain risk profiles, policy/on-chain controls, tests, runbooks.
**Scope:** Medium per chain.

### Checkpoint 6

- Production supports no arbitrary protocol or chain action.
- Maximum-loss envelopes and false-denial trade-offs are measured.
- Emergency controls are dual-controlled, monitored, and rehearsed.

## Phase 7: Independent assurance and staged launch

### Task 35: Complete external audits and remediation

**Description:** Commission separate smart-contract and platform/custody reviews,
plus a scoped penetration test of identity, API, infrastructure, and operations.

**Acceptance criteria:** Exact commit/image/IaC revisions are in scope; critical/high
findings are fixed and re-tested; medium residual risk is time-bound and approved;
public summaries describe scope and exclusions.

**Verification:** Auditors issue final re-test letters and deployed digests match
audited artifacts.

**Dependencies:** Checkpoints 4-6.

**Likely files:** Audit reports, remediation PRs, claim matrix, release manifest.
**Scope:** External plus remediation tasks sized per finding.

### Task 36: Complete legal, privacy, compliance, and insurance decisions

**Description:** Determine and implement obligations created by the exact custody,
jurisdiction, customer, and data model.

**Acceptance criteria:** Qualified owners decide licensing/registration, custody,
AML/sanctions, privacy, retention, incident reporting, terms, insurance, and
customer disclosures as applicable; product behavior matches those decisions.

**Verification:** Legal/compliance launch approval exists and control owners provide
evidence for every applicable obligation.

**Dependencies:** Tasks 3 and 28-34. May run alongside Task 35.

**Likely files:** Private control records; approved public policies and product
changes. **Scope:** External plus separate implementation tasks.

### Task 37: Run a capped testnet production pilot

**Description:** Operate the real production topology and custody path on testnet
with representative users, workloads, attacks, and incidents.

**Acceptance criteria:** At least 30 consecutive days meet SLO/error-budget targets;
all drills pass; no unresolved critical/high issue; every signed transaction has a
complete verifiable attestation.

**Verification:** Independent readiness review checks operational data, not a demo.

**Dependencies:** Tasks 35-36.

**Likely files:** Pilot configuration, dashboards, evidence dossier, findings.
**Scope:** Operations period.

### Task 38: Run a capped real-fund pilot

**Description:** After explicit human authorization, launch a tiny allowlisted
production cohort with strict per-transaction, per-user, daily, and total-system
loss caps.

**Acceptance criteria:** Caps are below the owner-approved loss budget; manual kill
switch and rollback are staffed; no scope expansion occurs automatically; customer
support and incident communication are live.

**Verification:** Pre-launch ceremony verifies deployed digests and controls; pilot
completes the approved observation period with reconciled funds/evidence and no
unresolved severe incident.

**Dependencies:** Task 37 and a separate owner go-live approval.

**Likely files:** Pilot policies/configuration and signed launch record.
**Scope:** High-stakes operational gate.

### Task 39: Hold the scale readiness review

**Description:** Decide whether to increase users, balances, chains, or operations
using pilot evidence.

**Acceptance criteria:** Security, SRE, custody, chain risk, product, support, legal,
and executive owners approve; each scope increase has new caps and rollback criteria;
no approval relies solely on the absence of incidents.

**Verification:** Signed decision cites SLOs, near misses, audit status, bug bounty,
loss envelope, capacity, and unresolved risks.

**Dependencies:** Task 38.

**Likely files:** Readiness dossier and updated production scope.
**Scope:** External governance.

### Task 40: Operate continuous assurance

**Description:** Keep the maximum-assurance score current after launch.

**Acceptance criteria:** Continuous CI/scanning and runtime controls; monthly risk
review; quarterly access/key/restore/incident exercises; annual external audit and
threat-model refresh; defined patch SLAs; public security advisories and bug bounty;
automatic score expiry when evidence ages out.

**Verification:** Dashboard shows scorecard status, evidence age, exceptions,
incidents, SLOs, audit actions, and next drill; expired evidence changes the score to
failing automatically.

**Dependencies:** Task 39.

**Likely files:** Governance automation, dashboards, runbooks, public security docs.
**Scope:** Continuous.

### Checkpoint 7: Production-custody maximum-assurance target

- Audited artifacts equal deployed artifacts.
- Zero unresolved critical/high findings; every accepted residual risk is explicit,
  owned, expiring, and monitored.
- Custody, platform, chain, economic, compliance, support, and incident controls are
  all operationally proven.
- Testnet and capped real-fund pilots pass before scale.
- The score expires when audits, drills, scans, or evidence become stale.

## Delivery sequence and indicative duration

These are planning ranges, not promises; external counsel, custody vendors, cloud
accounts, auditors, and pilot observation periods control the critical path.

| Wave | Outcome | Tasks | Indicative duration |
|---|---|---|---|
| 0 | Decisions and scorecards | 1-3 | 1-3 weeks |
| 1 | Defensible public research release | 4-11 | 3-8 weeks plus reviewer availability |
| 2 | Maximum-assurance research artifact | 12-17 | 8-16 weeks |
| 3 | Core refactor and stronger proofs | 18-22 | 8-16 weeks |
| 4 | Managed custody boundary | 23-27 | 12-24 weeks |
| 5 | Production platform and chain controls | 28-34 | 16-32 weeks |
| 6 | Audits and staged launch | 35-39 | 16-36 weeks including observation periods |
| 7 | Continuous assurance | 40 | Ongoing |

With a coordinated 4-6 person engineering/security team plus external specialists,
public release and research excellence can run partly in parallel, while a credible
production pilot is roughly a 9-18 month program. A solo implementation should
expect substantially longer and still cannot self-issue the independent approvals.

## Parallelization

Safe after the relevant contract/decision is frozen:

- Tasks 4 and 5;
- repository administration in Task 7 while CI evidence work starts;
- source audit, statistical protocol, and API/signer refactor work;
- production infrastructure, semantic protocol adapters, and compliance analysis;
- separate smart-contract and platform audits.

Must remain sequential:

- publication decision before visibility change;
- production scope before custody/vendor implementation;
- custody contract before provider adapter;
- provider adapter before key ceremonies and attestation trust;
- production controls before audits;
- testnet pilot before real-fund pilot;
- real-fund evidence before scale.

## Program risks and mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| “10/10” becomes a marketing claim | Critical | Use expiring evidence-based scorecards and publish scope/non-claims. |
| Public disclosure harms rights | High | Complete Task 2 before any visibility change. |
| Self-review is mistaken for audit | Critical | Require independent reports and exact-artifact re-tests. |
| Custody vendor becomes a new single point of failure | Critical | Provider policy, quorum/dual control, attestation, exit plan, and outage drills. |
| Generic contract support creates unbounded risk | Critical | Support only semantic adapters and fail closed on unknown versions. |
| Signer/database ambiguity causes duplicate or stuck funds | Critical | Durable pre-commit, non-reusable authorization, chain/provider reconciliation. |
| Research claims overfit scripted attacks | High | Live replayable adapters, baselines, confidence intervals, external replication. |
| Compliance scope changes late | High | Freeze production scope and begin specialist analysis before infrastructure build. |
| Large refactors hide security regression | High | Small PRs, unchanged vectors, mutation/differential gates, independent review. |
| Passing pre-launch tests creates complacency | High | Capped pilots, continuous assurance, evidence expiry, drills, and bug bounty. |

## Definition of done for every task

A task is done only when:

- acceptance criteria are evidenced, not merely asserted;
- focused and project-wide relevant tests pass;
- security, operations, threat model, claims, and public docs are updated when the
  boundary changes;
- no critical/high finding remains and every lower residual risk has an owner and
  expiry;
- artifacts identify the exact commit, build, configuration, tool versions, and
  environment;
- an appropriate independent reviewer approves security-sensitive work;
- rollback/recovery behavior is tested when the task changes persistent or
  money-moving state.

## Immediate next milestone

Do not start production custody work first. Complete Tasks 1-11 to earn a clean,
well-governed, independently reviewed public research release. In parallel, begin
Task 3 privately so production scope and regulatory questions do not surprise the
engineering program later.
