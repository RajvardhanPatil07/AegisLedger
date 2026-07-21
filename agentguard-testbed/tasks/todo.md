# AegisLedger Productization Task List

This is the execution checklist for `tasks/plan.md`. Each task is intended to be
small enough for one focused implementation or business session. Do not begin a
later production phase merely because code exists; satisfy the checkpoint.

## Phase 0: Product and Risk Foundation

### Task 1: Freeze the initial customer and job-to-be-done

**Description:** Write a one-page product brief for AI-agent developers who need
policy-controlled onchain execution and verifiable evidence without giving
AegisLedger custody.

**Acceptance criteria:**
- [ ] Names one buyer, one daily user, one protected workflow, and one measurable pain.
- [ ] Lists v1 non-goals and the alternative products customers use today.
- [ ] Defines the promise without “production-grade,” “unhackable,” or unsupported claims.

**Verification:**
- [ ] Five target users can explain the product after reading only the brief.

**Dependencies:** None

**Files likely touched:** `docs/product/PRODUCT_BRIEF.md`

**Estimated scope:** S

### Task 2: Complete ten qualified discovery interviews

**Description:** Interview builders currently operating or planning agents that
can transfer funds, trade, or pay for APIs.

**Acceptance criteria:**
- [ ] Ten interview records capture current workflow, incidents, budget, buyer, and urgency.
- [ ] At least five interviewees have a live or funded-testnet agent.
- [ ] Findings distinguish evidence from founder interpretation.

**Verification:**
- [ ] A synthesis ranks the top three repeated pains and rejected assumptions.

**Dependencies:** Task 1

**Files likely touched:** `docs/product/DISCOVERY_SYNTHESIS.md`

**Estimated scope:** M

### Task 3: Secure three design partners

**Description:** Convert discovery interest into scoped pilot commitments with
testnet workflows, success criteria, named owners, and feedback dates.

**Acceptance criteria:**
- [ ] Three partners provide a real integration workflow and technical owner.
- [ ] Each partner agrees to a pilot timeline and measurable success condition.
- [ ] At least one partner agrees to discuss paid production use if the pilot passes.

**Verification:**
- [ ] Redacted partner matrix records status without storing confidential terms in Git.

**Dependencies:** Task 2

**Files likely touched:** `docs/product/DESIGN_PARTNERS.md`

**Estimated scope:** S

### Task 4: Define security requirements and SLOs

**Description:** Turn the threat model into production requirements for tenancy,
custody, signing ambiguity, availability, recovery, privacy, and incident response.

**Acceptance criteria:**
- [ ] Every protected asset and trust boundary maps to a requirement and owner.
- [ ] Availability, latency, RPO, RTO, webhook, and incident targets are numerical.
- [ ] Real-fund launch blockers are explicit and fail closed.

**Verification:**
- [ ] Independent reviewer can trace each requirement to a planned test or exercise.

**Dependencies:** Task 1

**Files likely touched:** `docs/PRODUCT_SECURITY_REQUIREMENTS.md`, `docs/SLOS.md`

**Estimated scope:** M

## Checkpoint A: Product Validation

- [ ] Ten interviews completed.
- [ ] Three design partners committed.
- [ ] One supported workflow and network selected.
- [ ] Security requirements and SLOs approved.

## Phase 1: Stable Developer Surface

### Task 5: Freeze the canonical v1 transaction contract

**Description:** Define the immutable intent, policy decision, exact transaction,
operation state, error, and evidence schemas independently of internal models.

**Acceptance criteria:**
- [ ] OpenAPI schemas reject unknown fields and define compatibility rules.
- [ ] One idempotency key maps to one organization/environment/operation.
- [ ] Security-relevant fields are covered by golden canonicalization vectors.

**Verification:**
- [ ] Consumer contract tests pass against the Python API.
- [ ] Backward-compatibility check fails on an unversioned breaking change.

**Dependencies:** Task 4

**Files likely touched:** `docs/api/openapi-v1.yaml`, `src/aegisledger/contracts.py`, `tests/test_contract_v1.py`

**Estimated scope:** M

### Task 6: Add durable organization and environment ownership

**Description:** Make organization, environment, wallet, and principal ownership
first-class database constraints for every policy and lifecycle object.

**Acceptance criteria:**
- [ ] Migration backfills ownership and adds non-null/foreign-key constraints.
- [ ] Repository methods always require tenant context.
- [ ] Cross-tenant reads and mutations fail under ID enumeration and concurrency.

**Verification:**
- [ ] Migration upgrade/downgrade policy passes on a production-like snapshot.
- [ ] Tenant-isolation integration suite passes.

**Dependencies:** Task 5

**Files likely touched:** `migrations/versions/*tenant*.py`, `src/aegisledger/postgres.py`, `src/aegisledger/auth.py`, `tests/test_tenant_isolation.py`

**Estimated scope:** M

### Task 7: Add scoped service accounts and API-key rotation

**Description:** Support machine-to-machine agent authentication separately from
human OIDC sessions, with hashed credentials and least-privilege scopes.

**Acceptance criteria:**
- [ ] Keys are shown once, stored hashed, scoped, expiring, and revocable.
- [ ] Rotation permits overlap without widening access.
- [ ] Authentication, authorization, and audit events never contain raw keys.

**Verification:**
- [ ] Expired, revoked, wrong-environment, and scope-escalation tests pass.
- [ ] Log/trace redaction test finds no credential material.

**Dependencies:** Task 6

**Files likely touched:** `src/aegisledger/auth.py`, `src/aegisledger/api.py`, `migrations/versions/*service_accounts*.py`, `tests/test_service_accounts.py`

**Estimated scope:** M

### Task 8: Add asynchronous operations and durable webhooks

**Description:** Expose execution as a durable state machine with an outbox so
customers can recover from timeouts without retrying money movement blindly.

**Acceptance criteria:**
- [ ] Mutation returns an operation ID and supports safe status polling.
- [ ] Webhooks are signed, ordered per operation, retryable, and replayable.
- [ ] Duplicate API requests and webhook deliveries do not duplicate signing.

**Verification:**
- [ ] Kill tests at every state transition recover to one terminal outcome.
- [ ] Webhook consumer contract test tolerates duplicates and reordering.

**Dependencies:** Tasks 5-7

**Files likely touched:** `src/aegisledger/api.py`, `src/aegisledger/state.py`, `src/aegisledger/webhooks.py`, `tests/test_webhook_outbox.py`

**Estimated scope:** M

### Task 9: Publish TypeScript and Python SDKs

**Description:** Generate or hand-maintain thin, typed clients with retries only
where idempotency makes them safe.

**Acceptance criteria:**
- [ ] Both SDKs cover evaluate, execute, status, cancel, and evidence retrieval.
- [ ] SDKs expose typed errors and never retry unsafe operations without an idempotency key.
- [ ] Version compatibility is tested against the public OpenAPI document.

**Verification:**
- [ ] Fresh sample projects install released packages and pass contract tests.

**Dependencies:** Task 8

**Files likely touched:** `sdk/typescript/`, `sdk/python/`, `tests/contract/`

**Estimated scope:** M per SDK; implement as two sessions

### Task 10: Build the Coinbase AgentKit adapter

**Description:** Implement an action provider that converts value-moving AgentKit
actions into AegisLedger intents and returns structured operation/evidence IDs.

**Acceptance criteria:**
- [ ] Transfer action cannot bypass policy or directly receive a signing primitive.
- [ ] Action schema distinguishes proposal, approval-needed, denied, submitted, and settled.
- [ ] Adapter works with one documented AgentKit wallet provider on Base Sepolia.

**Verification:**
- [ ] Real agent integration test proves allowed, denied, replay, and timeout flows.

**Dependencies:** Task 9

**Files likely touched:** `integrations/agentkit/`, `examples/agentkit/`, `tests/integrations/test_agentkit.py`

**Estimated scope:** M

### Task 11: Ship the 15-minute testnet example

**Description:** Provide one minimal agent that requests a Base Sepolia transfer,
receives policy authorization, settles, and verifies evidence.

**Acceptance criteria:**
- [ ] Clean-machine instructions require no repository archaeology.
- [ ] Setup validates environment and reports actionable failures.
- [ ] Example displays the exact policy decision and verification result.

**Verification:**
- [ ] Three external developers complete it; median completion is under 15 minutes.

**Dependencies:** Tasks 9-10

**Files likely touched:** `examples/base-sepolia-agent/`, `docs/QUICKSTART.md`

**Estimated scope:** M

## Checkpoint B: Developer Preview

- [ ] Clean Base Sepolia flow completes in under 15 minutes.
- [ ] Python/TypeScript contract tests pass against one API version.
- [ ] AgentKit cannot bypass the gateway for the protected action.
- [ ] Design partners can integrate without direct founder intervention.

## Phase 2: Production Signing Boundary

### Task 12: Define the provider-neutral CustodySigner interface

**Description:** Separate authorization from key custody using a narrow interface
for sign, status, provider transaction ID, identity evidence, and reconciliation.

**Acceptance criteria:**
- [ ] Interface represents accepted, rejected, pending, signed, and ambiguous outcomes.
- [ ] Provider idempotency and identity are bound into retained evidence.
- [ ] Local Rust signer implements the same conformance suite.

**Verification:**
- [ ] Fake-provider conformance tests cover every outcome and timeout boundary.

**Dependencies:** Task 5

**Files likely touched:** `src/aegisledger/custody.py`, `src/aegisledger/signer_client.py`, `tests/test_custody_conformance.py`

**Estimated scope:** M

### Task 13: Integrate one managed wallet/custody provider

**Description:** Implement exactly one production candidate selected through a
security and operational spike; do not add multiple superficial adapters.

**Acceptance criteria:**
- [ ] No private key or reusable signing secret enters application logs or persistence.
- [ ] Exact transaction fields and provider operation IDs are retained and verified.
- [ ] Provider authentication rotates without downtime.

**Verification:**
- [ ] Base Sepolia allow/deny/replay/restart flow passes using the real provider sandbox.

**Dependencies:** Task 12

**Files likely touched:** `src/aegisledger/custody_providers/<provider>.py`, `tests/integration/test_<provider>.py`, `docs/runbooks/<provider>.md`

**Estimated scope:** M

### Task 14: Prove provider failure and ambiguity handling

**Description:** Exercise timeouts before and after provider acceptance, stale
status, duplicate callbacks, inconsistent hashes, and provider outage.

**Acceptance criteria:**
- [ ] No tested failure produces a second signature or false settlement.
- [ ] Ambiguous operations stop new signing and enter operator-visible reconciliation.
- [ ] Recovery never deletes replay state.

**Verification:**
- [ ] Fault-injection matrix is automated and retained per release.

**Dependencies:** Task 13

**Files likely touched:** `tests/integration/test_custody_failures.py`, `src/aegisledger/reconciler.py`, `docs/runbooks/ambiguous-custody.md`

**Estimated scope:** M

### Task 15: Add mainnet safety controls

**Description:** Enforce per-transaction, daily, token, contract, method, and
wallet limits plus emergency stop and human approval escalation.

**Acceptance criteria:**
- [ ] Limits reserve atomically and remain correct under concurrent requests.
- [ ] Emergency stop blocks signing while preserving status/reconciliation.
- [ ] Policy changes above configured risk require independent approval.

**Verification:**
- [ ] Property tests cover arithmetic, races, expiry, bypass, and rollback.

**Dependencies:** Tasks 6 and 12

**Files likely touched:** `src/aegisledger/policy.py`, `src/aegisledger/policies.py`, `src/aegisledger/mandates.py`, `tests/test_mainnet_controls.py`

**Estimated scope:** M

### Task 16: Decide Safe/ERC-7579 interoperability

**Description:** Prototype one adapter and decide whether onchain enforcement adds
material defense without unacceptable lockout/recovery risk.

**Acceptance criteria:**
- [ ] Spike measures compatibility, gas, recovery, upgrade, and denial-of-service risk.
- [ ] Decision records whether to ship, defer, or reject the adapter.
- [ ] No production claim relies on unaudited contract code.

**Verification:**
- [ ] ADR is reviewed by an external smart-account engineer.

**Dependencies:** Tasks 13 and 15

**Files likely touched:** `docs/adr/0004-smart-account-interoperability.md`, `contracts/spikes/`

**Estimated scope:** M

## Checkpoint C: Signing Boundary

- [ ] Managed-provider testnet settlement and offline evidence pass.
- [ ] Ambiguous signing is observable and fail closed.
- [ ] No production private key is held by the AegisLedger API.
- [ ] Mainnet safety controls pass concurrency/property tests.

## Phase 3: Managed Operations

### Task 17: Create isolated staging and production infrastructure

**Description:** Define repeatable infrastructure with separate accounts/projects,
private service networking, immutable images, and least-privilege runtime identity.

**Acceptance criteria:**
- [ ] Infrastructure is reproducible from reviewed code.
- [ ] Staging cannot reach production data, secrets, wallets, or signing authority.
- [ ] Public ingress reaches only the documented API/console edge.

**Verification:**
- [ ] Policy-as-code and network reachability tests pass in CI.

**Dependencies:** Task 4

**Files likely touched:** `infra/modules/`, `infra/staging/`, `infra/production/`

**Estimated scope:** M per module; split by service

### Task 18: Prove managed PostgreSQL recovery

**Description:** Deploy encrypted managed PostgreSQL with point-in-time recovery,
replicas appropriate to the SLO, migration controls, and tenant-safe backups.

**Acceptance criteria:**
- [ ] Backup encryption and restore permissions are separated from app runtime.
- [ ] Restore reaches the declared RPO/RTO and preserves audit/lifecycle continuity.
- [ ] Migration rollback/roll-forward policy is exercised on a snapshot.

**Verification:**
- [ ] Quarterly automated restore drill produces a signed report.

**Dependencies:** Tasks 6 and 17

**Files likely touched:** `infra/modules/database/`, `scripts/production_restore_drill.py`, `docs/runbooks/database.md`

**Estimated scope:** M

### Task 19: Harden secrets, runtime identity, and telemetry

**Description:** Replace environment-file production secrets with workload
identity and a managed secret system; prevent sensitive data from entering traces.

**Acceptance criteria:**
- [ ] Services use short-lived identity where supported and rotate remaining secrets.
- [ ] Telemetry schema excludes tokens, raw transactions when sensitive, prompts, and PII.
- [ ] Collector/export paths are authenticated, encrypted, and rate bounded.

**Verification:**
- [ ] Secret-canary and telemetry-redaction integration tests pass.

**Dependencies:** Task 17

**Files likely touched:** `src/aegisledger/observability.py`, `deploy/otel-collector.yaml`, `infra/modules/identity/`, `tests/test_telemetry_redaction.py`

**Estimated scope:** M

### Task 20: Implement SLO dashboards and alerts

**Description:** Measure user-visible availability, policy latency, signing
latency, stuck operations, reconciliation lag, webhook delivery, and error budgets.

**Acceptance criteria:**
- [ ] Every SLO has a query, dashboard, alert threshold, and named responder.
- [ ] Alerts link to a tested runbook and avoid wallet/customer cardinality leaks.
- [ ] Synthetic protected transactions continuously test the full path.

**Verification:**
- [ ] Game day proves alerts fire and responders can diagnose within target time.

**Dependencies:** Tasks 18-19

**Files likely touched:** `deploy/prometheus/alerts.yml`, `deploy/grafana/`, `docs/runbooks/alerts.md`

**Estimated scope:** M

### Task 21: Add load, isolation, chaos, restore, and rollback gates

**Description:** Turn operational assumptions into repeatable release evidence.

**Acceptance criteria:**
- [ ] Load test meets p95/availability targets at 2x projected six-month traffic.
- [ ] Chaos tests cover database, identity, custody provider, RPC, and webhook outage.
- [ ] Tenant-isolation, restore, and rollback tests are release blockers.

**Verification:**
- [ ] Exact-commit report contains thresholds, results, environment, and artifacts.

**Dependencies:** Tasks 18-20

**Files likely touched:** `tests/load/`, `tests/chaos/`, `scripts/release_operational_evidence.py`

**Estimated scope:** M per failure domain; split into sessions

### Task 22: Add commercial metering and entitlements

**Description:** Meter protected wallets, policy evaluations, executions, evidence
retention, and support tier without placing billing in the signing critical path.

**Acceptance criteria:**
- [ ] Entitlements fail predictably without allowing unauthorized value movement.
- [ ] Usage events are idempotent, reconcilable, and tenant-owned.
- [ ] Support bundle exposes diagnostics without secrets or cross-tenant data.

**Verification:**
- [ ] Billing-provider outage does not duplicate or under-authorize transactions.

**Dependencies:** Tasks 6 and 8

**Files likely touched:** `src/aegisledger/metering.py`, `src/aegisledger/entitlements.py`, `tests/test_metering.py`

**Estimated scope:** M

## Checkpoint D: Managed Beta

- [ ] SLOs pass at 2x projected load.
- [ ] Restore/rollback/chaos exercises pass.
- [ ] Telemetry and support exports contain no sampled secrets.
- [ ] Staging and production isolation is independently reviewed.

## Phase 4: Credible Research

### Task 23: Pre-register the real-model benchmark

**Description:** Define hypotheses, attack corpus, defense variants, model/version
selection, power analysis, exclusion rules, metrics, and stopping conditions
before collecting primary results.

**Acceptance criteria:**
- [ ] Deterministic simulator results are labeled regression tests, not model evidence.
- [ ] Primary and exploratory outcomes are separated.
- [ ] Protocol includes privacy/redaction and cost controls.

**Verification:**
- [ ] External researcher reviews and timestamps the protocol.

**Dependencies:** Task 4

**Files likely touched:** `research/protocol.md`, `research/power_analysis.ipynb`

**Estimated scope:** M

### Task 24: Build provider-neutral real-model runners

**Description:** Execute the same tool/action environment against version-pinned
models from at least three independent model families.

**Acceptance criteria:**
- [ ] Runner records exact model/version, parameters, prompts, tools, outputs, and timing.
- [ ] Provider adapters produce a common raw-run schema.
- [ ] Secrets and personal data are excluded or irreversibly redacted.

**Verification:**
- [ ] Golden scenarios reproduce from retained manifests within provider variability.

**Dependencies:** Task 23

**Files likely touched:** `research/runner/`, `research/providers/`, `tests/research/test_runner.py`

**Estimated scope:** M per provider

### Task 25: Execute the powered experiment matrix

**Description:** Run the pre-registered model/attack/defense comparisons with
sample sizes justified by the power analysis.

**Acceptance criteria:**
- [ ] Every run maps to an immutable protocol and exact code commit.
- [ ] Failures, refusals, timeouts, and exclusions are retained, not discarded silently.
- [ ] Confidence intervals and multiple-comparison treatment are reported.

**Verification:**
- [ ] Independent analysis script recomputes every published table from raw runs.

**Dependencies:** Task 24

**Files likely touched:** `research/results/`, `research/analyze.py`, `docs/RESEARCH_RESULTS.md`

**Estimated scope:** M

### Task 26: Publish a reproducibility bundle

**Description:** Package protocol, manifests, redacted raw data, analysis,
limitations, artifact hashes, and environment instructions.

**Acceptance criteria:**
- [ ] Clean account reproduces all aggregate tables from published artifacts.
- [ ] Bundle distinguishes statistical evidence from architecture assertions.
- [ ] Artifact receives a durable archival identifier when publication is approved.

**Verification:**
- [ ] Reproduction command passes from a clean clone.

**Dependencies:** Task 25

**Files likely touched:** `research/README.md`, `scripts/reproduce_research.sh`, `docs/RESEARCH_LIMITATIONS.md`

**Estimated scope:** M

### Task 27: Obtain independent replication

**Description:** Have an unaffiliated researcher execute the primary protocol and
publish differences, failures, and residual risks.

**Acceptance criteria:**
- [ ] Replicator controls its own accounts and execution environment.
- [ ] Report identifies exact commit, model versions, deviations, and raw evidence.
- [ ] Claims are narrowed when replication disagrees.

**Verification:**
- [ ] Independent report and response are linked from the claim matrix.

**Dependencies:** Task 26

**Files likely touched:** `docs/INDEPENDENT_REPLICATION.md`, `docs/SECURITY_CLAIMS.md`

**Estimated scope:** External

## Phase 5: Independent Security and Pilots

### Task 28: Complete independent security assessments

**Description:** Commission separate reviews for application/custody/lifecycle,
cloud configuration, and any production smart-account code.

**Acceptance criteria:**
- [ ] Reviewers receive source, architecture, threat model, deployment, and test evidence.
- [ ] Reports cover authorization bypass, ambiguity, tenancy, key compromise, and recovery.
- [ ] Findings have severity, owner, deadline, and disclosure status.

**Verification:**
- [ ] Signed reports identify the exact candidate commit and environment.

**Dependencies:** Checkpoints C and D

**Files likely touched:** `docs/audits/README.md`, private finding tracker

**Estimated scope:** External

### Task 29: Remediate and re-test audit findings

**Description:** Fix findings in isolated changes and require the original
reviewer to verify critical/high remediation.

**Acceptance criteria:**
- [ ] No critical/high item is waived solely for schedule reasons.
- [ ] Regression tests reproduce each finding before its fix.
- [ ] Residual accepted risks name owner, expiry, and compensating control.

**Verification:**
- [ ] Independent re-test letter covers the final candidate commit.

**Dependencies:** Task 28

**Files likely touched:** Finding-specific; `docs/SECURITY_CLAIMS.md`

**Estimated scope:** Split one task per finding

### Task 30: Establish signed releases and vulnerability response

**Description:** Protect the release path and provide a tested private security
reporting and coordinated disclosure process.

**Acceptance criteria:**
- [ ] Protected main, two-person release approval, signed tags/images, SBOM, and provenance are enforced.
- [ ] Security contact, severity policy, response targets, and supported versions are public.
- [ ] Critical revocation/rollback path is exercised.

**Verification:**
- [ ] Release gate rejects unsigned, unreviewed, stale-evidence, or wrong-commit artifacts.

**Dependencies:** Task 29

**Files likely touched:** `.github/workflows/`, `.github/SECURITY.md`, `docs/RELEASE.md`

**Estimated scope:** M

### Task 31: Run capped real-fund pilots

**Description:** Start with allowlisted wallets, assets, contracts, and tiny
limits; require human approval and a staffed kill switch.

**Acceptance criteria:**
- [ ] Legal/security approval records exact limits and participants.
- [ ] Every transaction has canonical intent, decision, provider ID, settlement, and evidence.
- [ ] Automatic stop triggers on anomaly, SLO breach, ambiguity, or audit-chain failure.

**Verification:**
- [ ] Pilot report accounts for every attempted operation and incident.

**Dependencies:** Tasks 29-30 and Task 34

**Files likely touched:** `docs/pilots/PILOT_PLAN.md`, private participant records

**Estimated scope:** External/operational

### Task 32: Exercise incident and disaster recovery

**Description:** Run tabletop and live exercises for key/custody compromise,
database loss, cross-tenant exposure, malicious policy change, and RPC reorg.

**Acceptance criteria:**
- [ ] Named responders execute containment, evidence preservation, communication, and recovery.
- [ ] Measured acknowledgement/RPO/RTO meet targets.
- [ ] Every gap becomes a tracked remediation with owner and deadline.

**Verification:**
- [ ] Independent observer signs the exercise report.

**Dependencies:** Tasks 21 and 30

**Files likely touched:** `docs/runbooks/incidents/`, `docs/exercises/`

**Estimated scope:** M per exercise

## Checkpoint E: Production Candidate

- [ ] Exact release independently assessed and re-tested.
- [ ] Zero unresolved critical/high findings.
- [ ] Signed release, rollback, incident, and DR exercises pass.
- [ ] Capped pilot meets security and reliability limits.

## Phase 6: General Availability and Revenue

### Task 33: Finish production onboarding and lifecycle documentation

**Description:** Document evaluation, rollout, migration, SDK upgrades, policy
changes, incidents, offboarding, and evidence export for customers.

**Acceptance criteria:**
- [ ] New customer reaches testnet without founder assistance.
- [ ] Breaking-change and deprecation windows are explicit.
- [ ] Offboarding exports evidence and revokes access predictably.

**Verification:**
- [ ] External documentation usability test passes.

**Dependencies:** Checkpoint E

**Files likely touched:** `docs/guides/`, `docs/api/`, `CHANGELOG.md`

**Estimated scope:** M

### Task 34: Approve legal and compliance boundaries

**Description:** Obtain qualified advice for entity, terms, privacy, DPA,
licensing, sanctions, custody, money transmission, supported jurisdictions,
assets, and incident duties.

**Acceptance criteria:**
- [ ] Counsel documents why the launch model is or is not custodial in each supported jurisdiction.
- [ ] Terms, privacy, DPA, retention, subprocessors, and acceptable-use rules are approved.
- [ ] Public/open-core IP, trademark, patent, and contribution decisions are recorded.

**Verification:**
- [ ] Product configuration and sales claims match the approved scope.

**Dependencies:** Tasks 1, 3, and 13

**Files likely touched:** Public policy documents plus private legal records

**Estimated scope:** External

### Task 35: Convert two design partners to paid production contracts

**Description:** Price the measured value of protected workflows and support,
then sell bounded pilots rather than free indefinite experiments.

**Acceptance criteria:**
- [ ] Two customers pay for defined wallet/volume/support scope.
- [ ] Contract success measures include active protected volume and retention.
- [ ] Discounts have an expiry and documented learning objective.

**Verification:**
- [ ] Revenue is collected and customers use the product after onboarding.

**Dependencies:** Tasks 31, 33, and 34

**Files likely touched:** Private CRM/contracts; `docs/product/PRICING_HYPOTHESES.md`

**Estimated scope:** External

### Task 36: Publish support and SLA tiers

**Description:** Match promised response and availability to actual staffing,
monitoring, escalation, maintenance, and compensation capacity.

**Acceptance criteria:**
- [ ] Every tier defines hours, severity, response, availability, exclusions, and escalation.
- [ ] On-call has at least two trained responders before 24/7 claims.
- [ ] Status and incident communication channels are operational.

**Verification:**
- [ ] Support game day meets the advertised response targets.

**Dependencies:** Tasks 20, 32, and 34

**Files likely touched:** `docs/SUPPORT.md`, `docs/SLA.md`, status-page configuration

**Estimated scope:** S

### Task 37: Make the general-availability decision

**Description:** Review security, SLO, customer retention, protected volume,
gross margin, support cost, legal scope, and team capacity together.

**Acceptance criteria:**
- [ ] All production-candidate gates are current for the exact release.
- [ ] At least two paying pilots demonstrate repeat protected usage.
- [ ] Owner records launch, delay, or narrow-scope decision with evidence.

**Verification:**
- [ ] Assurance scorecard and public claims match the decision.

**Dependencies:** Tasks 33-36

**Files likely touched:** `docs/GA_DECISION.md`, `docs/assurance-scorecard.json`

**Estimated scope:** S

## Final Definition of Done

- [ ] Product solves a repeated, paid customer problem.
- [ ] Real users can integrate without founder assistance.
- [ ] Production signing does not rely on local file keys.
- [ ] Multi-tenant authorization and idempotency are independently tested.
- [ ] Research claims come from real models and independent replication.
- [ ] Exact production release has no unresolved critical/high audit findings.
- [ ] Load, chaos, restore, rollback, incident, and key-compromise exercises pass.
- [ ] Legal, licensing, privacy, custody, and jurisdiction boundaries are approved.
- [ ] Two paying production pilots show repeat protected transaction volume.
- [ ] Public wording stays inside the evidence.
