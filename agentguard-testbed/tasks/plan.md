# Implementation Plan: AegisLedger Industry-Grade Productization

## Overview

AegisLedger should become a non-custodial transaction-policy gateway for AI
agents, not a consumer wallet and not a production custodian. An agent submits
an intended onchain action; AegisLedger evaluates an organization-owned policy,
binds authorization to the exact transaction, delegates signing to an approved
wallet/custody provider, reconciles settlement, and exports independently
verifiable evidence. The first commercial wedge is teams building autonomous
payment or onchain agents on EVM networks.

The repository already proves a local proposal -> policy -> isolated signer ->
Anvil -> finality -> offline-attestation path. Productization must now prove
external usefulness, real-model behavior, managed-wallet interoperability,
multi-tenant operations, and independent security. More local features do not
substitute for those proofs.

## Product Decision

### Recommended product

**AegisLedger Gateway**: an API and SDK that protects every value-moving action
an AI agent attempts.

- The customer keeps custody through an approved wallet provider, Safe, or its
  own signing infrastructure.
- AegisLedger owns policy evaluation, approvals, exact-transaction binding,
  lifecycle evidence, alerts, and audit export.
- The first supported production chain is one EVM network; use Base Sepolia for
  integration and capped Base mainnet pilots only after the security gate.
- The first agent integration is a Coinbase AgentKit action provider because
  AgentKit explicitly supports custom action and wallet providers and framework
  adapters. Add generic REST, Python, and TypeScript SDKs so the core product is
  not vendor-locked.
- Safe/ERC-7579 interoperability is a later adapter, not a launch dependency.

### Explicit non-goals for v1

- Consumer seed phrase or private-key custody.
- Broad DeFi protocol coverage.
- Multiple chains before one chain is operationally proven.
- Claims that deterministic simulations measure frontier-model security.
- Mainnet autonomy without per-wallet caps, allowlists, emergency stop, and
  human escalation.

## Business Model

Use an open-core/managed-service model:

- **Community:** local/testnet policy engine, verifier, SDKs, AgentKit adapter,
  example application, and reproducible benchmark.
- **Managed:** hosted high-availability control plane, managed upgrades,
  webhooks, retention, monitoring, and support.
- **Enterprise:** SSO/SCIM, approval workflows, customer-managed keys/custody
  integrations, private networking, compliance exports, SLAs, and audit support.

Do not finalize pricing from intuition. Test these as starting hypotheses:

- Developer cloud: free testnet tier, then USD 99-299/month.
- Team production: USD 1,000-3,000/month plus protected-transaction usage.
- Enterprise: annual contract priced from wallet count, volume, support, and
  deployment model.

Commercial validation requires at least three design partners, two paid pilots,
and evidence that customers continue routing transactions through the gateway.
Downloads, stars, and demo traffic are not commercial validation.

## Definition of "Industry Grade"

No security product is permanently 10/10. The useful replacement is a set of
objective release gates.

| Track | Gate for a 9+/10 assessment |
|---|---|
| Engineering | Stable v1 contract; two supported SDKs; idempotent lifecycle; managed deployment; p95 and availability SLOs met under load; restore and rollback proven |
| Portfolio/demo | New user reaches a real testnet settlement in under 15 minutes; five-minute demo; clear architecture; examples; public roadmap; no undocumented bootstrap steps |
| Research | Pre-registered protocol; real version-pinned models from at least three model families; powered sample sizes; raw/redacted data; confidence intervals; independent replication |
| Production security | Managed custody adapter; independent application and contract audits; no open critical/high findings; incident/DR/chaos exercises; signed releases; vulnerability response |
| Commercial | Three design partners; two paid pilots; measurable protected volume; repeat use; support process; approved legal/compliance scope; sustainable unit economics |

## Architecture Decisions

- **Non-custodial first:** replace the local file key as the production path with
  a provider-neutral `CustodySigner` boundary. The local Rust signer remains a
  research/self-hosted implementation.
- **Single authoritative transaction object:** policy, approval, signing,
  submission, webhook, and attestation must refer to one canonical transaction
  envelope and one immutable intent ID.
- **Multi-tenancy is foundational:** organization, environment, principal,
  wallet, policy, and evidence ownership must be part of database keys and
  authorization checks, not added as controller filters later.
- **Asynchronous execution:** return an operation ID, make every mutation
  idempotent, and deliver signed lifecycle events through authenticated,
  retryable webhooks.
- **Cloud-neutral core:** keep policy and verification portable. Put provider,
  wallet, and deployment integrations behind narrow adapters.
- **Fail closed for money, degrade gracefully for observation:** signing stops
  when authority is ambiguous; status and reconciliation remain available.
- **Evidence before claims:** security and research claims are generated from
  retained artifacts tied to an exact commit and environment.

## Dependency Graph

```text
Product wedge and security requirements
        |
        v
Public v1 contract and tenant ownership model
        |
        +--> Service accounts/API keys --> SDKs --> AgentKit adapter --> sample agent
        |
        +--> CustodySigner interface --> managed-wallet adapter --> testnet proof
        |
        +--> Async lifecycle/webhooks --> managed control plane --> paid pilots
        |
        +--> SLOs/threat model --> production infrastructure --> audit/chaos/DR

Benchmark protocol --> real-model runner --> public data --> external replication

All production tracks --> capped pilot --> independent re-test --> general availability
```

## Roadmap

### Phase 0: Validate the Product Wedge (Weeks 1-3)

- [ ] Task 1: Freeze the initial customer and job-to-be-done.
- [ ] Task 2: Interview ten qualified agent/wallet teams.
- [ ] Task 3: Convert three teams into design partners.
- [ ] Task 4: Define production security requirements and SLOs.

**Checkpoint: continue only if at least three teams confirm that transaction
policy/evidence is painful enough to pilot.** If not, reposition before adding
infrastructure.

### Phase 1: Deliver a Real Developer Product (Weeks 4-10)

- [ ] Task 5: Freeze the public API v1 and canonical transaction envelope.
- [ ] Task 6: Add organization/environment/wallet ownership.
- [ ] Task 7: Add scoped service accounts and API-key rotation.
- [ ] Task 8: Add idempotent asynchronous operations and webhooks.
- [ ] Task 9: Publish Python and TypeScript SDKs.
- [ ] Task 10: Build the AgentKit action-provider adapter.
- [ ] Task 11: Ship a 15-minute Base Sepolia example.

**Checkpoint:** a developer with a clean machine can protect and verify a real
testnet transfer without reading repository internals.

### Phase 2: Remove the Local-Custody Blocker (Weeks 8-14)

- [ ] Task 12: Define the production `CustodySigner` interface.
- [ ] Task 13: Integrate one managed wallet/custody provider.
- [ ] Task 14: Add provider failure, replay, and reconciliation tests.
- [ ] Task 15: Add wallet-level caps, emergency stop, and approval escalation.
- [ ] Task 16: Evaluate Safe/ERC-7579 interoperability after the primary path works.

**Checkpoint:** no production key is stored in the API container, repository,
database plaintext, or local signer file; provider outage and ambiguous signing
remain fail closed.

### Phase 3: Build the Managed Control Plane (Weeks 12-22)

- [ ] Task 17: Create infrastructure-as-code for isolated staging and production.
- [ ] Task 18: Use managed PostgreSQL with tested point-in-time recovery.
- [ ] Task 19: Harden secrets, networking, runtime identity, and telemetry.
- [ ] Task 20: Implement SLO dashboards and actionable alerts.
- [ ] Task 21: Prove load, rate-limit, tenant-isolation, chaos, restore, and rollback behavior.
- [ ] Task 22: Add metering, entitlements, invoices, and support diagnostics.

**Checkpoint:** staging survives dependency failure and restore drills without
cross-tenant access, duplicate signing, or loss of settlement evidence.

### Phase 4: Replace Simulated Research with Credible Evidence (Weeks 10-22, Parallel)

- [ ] Task 23: Pre-register the benchmark protocol and primary hypotheses.
- [ ] Task 24: Build provider-neutral real-model runners.
- [ ] Task 25: Run the powered model/attack/defense matrix.
- [ ] Task 26: Publish reproducible redacted raw data and analysis.
- [ ] Task 27: Obtain independent replication.

**Checkpoint:** marketing uses only externally reproducible results and clearly
separates deterministic regression tests from real-model findings.

### Phase 5: Independent Security and Capped Pilots (Weeks 22-34)

- [ ] Task 28: Complete application, infrastructure, and smart-contract review.
- [ ] Task 29: Remediate and independently re-test every critical/high finding.
- [ ] Task 30: Establish signed releases and vulnerability response.
- [ ] Task 31: Run capped mainnet pilots with kill switches and human approval.
- [ ] Task 32: Complete incident, disaster-recovery, and key-compromise exercises.

**Checkpoint:** no real-fund expansion until the exact release has independent
approval, proven recovery, and zero unresolved critical/high findings.

### Phase 6: General Availability and Revenue (Weeks 30-40)

- [ ] Task 33: Finish onboarding, documentation, examples, and migration policy.
- [ ] Task 34: Approve terms, privacy, DPA, custody boundaries, and jurisdiction.
- [ ] Task 35: Convert at least two design partners to paid production contracts.
- [ ] Task 36: Publish support/SLA tiers and operational ownership.
- [ ] Task 37: Review retention, protected volume, margin, and support cost before scaling.

**Checkpoint:** general availability is a business and operational decision, not
a successful CI build.

## First 90 Days

### Days 1-30

1. Pick the non-custodial gateway wedge and one EVM chain.
2. Conduct ten interviews and secure three design-partner agreements.
3. Freeze API v1, canonical intent/transaction schema, tenant model, and SLOs.
4. Select one managed wallet/custody integration using a written security spike.

### Days 31-60

1. Implement tenancy/service accounts and async webhooks.
2. Publish one SDK first, then the second after contract tests stabilize.
3. Implement the custody adapter and Base Sepolia end-to-end flow.
4. Build the AgentKit adapter and a minimal sample agent.

### Days 61-90

1. Put the full flow in the hands of design partners.
2. Measure time-to-first-protected-transaction and failed integrations.
3. Begin the real-model benchmark using a frozen protocol.
4. Prepare the external audit scope; do not pay for an audit while architecture
   and contracts are still changing weekly.

## Metrics

### Product

- Median time to first protected testnet transaction: under 15 minutes.
- Proposal-to-terminal-state success rate: at least 99.9% excluding customer or
  chain rejection.
- Duplicate signatures caused by the platform: zero.
- Cross-tenant authorization failures: zero.
- Webhook delivery: 99.9% within five minutes with replay available.

### Security and reliability

- Zero unresolved critical/high independent findings at a release gate.
- Recovery point and recovery time objectives are defined, measured, and met.
- Every release has signed artifacts, SBOMs, provenance, rollback instructions,
  and an exact-commit runtime proof.
- Incident acknowledgement and customer-notification targets are tested.

### Commercial

- Three active design partners and two paid pilots before GA.
- At least 80% of pilot wallets remain active after 90 days.
- Protected transaction volume and active wallets grow for three consecutive
  months.
- Gross margin and support time are measured per customer before pricing scales.

### Research

- Model/version, prompts, tools, seed, environment, and stopping rules retained.
- Sample size justified by power analysis; primary comparisons report confidence
  intervals and multiple-comparison handling.
- At least one independent team reproduces the primary result.

## Publication Strategy

Do not make the repository public merely because the code runs. First:

1. Complete the owner/patent/publication decision.
2. Validate current and historical provenance and licensing.
3. Remove local artifacts and re-run full-history secret scanning.
4. Enable protected main, required checks, signed releases, security reporting,
   and an incident contact.
5. Publish a narrow, honest claim: research/reference gateway, not audited
   custody software.

If open-core is chosen, keep the portable policy/verifier/SDK/reference path in
the Apache-2.0 repository. Keep managed operations, enterprise identity,
private-network deployment, premium policy packs, and support automation in a
separately governed commercial product. Have counsel review licensing and
trademark decisions before accepting outside contributions.

## Team and Effort

A realistic path is 6-10 months with a focused 4-5 person team:

- Product/security lead.
- Backend/distributed-systems engineer.
- Wallet/smart-contract engineer.
- Frontend/developer-experience engineer.
- Part-time SRE plus independent security reviewers and qualified counsel.

A solo founder can build the developer preview, but cannot independently supply
the audit, operational coverage, legal review, customer discovery, and external
research replication required for an industry-grade claim.

## Risks and Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| No painful customer problem | Fatal | Discovery and paid-design-partner gate before cloud build-out |
| Competing with wallet providers | High | Integrate as their policy/evidence layer; do not become another generic wallet SDK |
| Custody or money-transmission obligations | High | Non-custodial architecture and qualified jurisdiction-specific counsel before real funds |
| Ambiguous signing across distributed systems | Critical | Single immutable intent, idempotency, provider transaction IDs, durable outbox, reconciliation, fail-closed runbook |
| Overstated research claims | High | Real models, frozen protocol, powered trials, raw evidence, independent replication |
| Smart-contract lockout or bypass | Critical | Minimal contract surface, recovery path, formal properties, independent audit, capped rollout |
| Solo-maintainer operational failure | High | On-call ownership, runbooks, support limits, automation, and at least two release approvers |
| Open-source cloning without revenue | Medium | Hosted reliability, integrations, enterprise controls, support, brand, and execution speed as the moat |

## Open Questions Requiring Owner Decisions

- Which customer comes first: agent-framework developers, treasury teams, or
  wallet infrastructure vendors? Recommendation: agent-framework developers.
- Which single production EVM network and wallet provider will be supported?
- Open-source managed-control-plane code or keep it commercial?
- Which jurisdictions and customer asset classes are allowed in the first pilot?
- What maximum value can a pilot wallet and transaction expose?
- Is patent protection relevant? Resolve before public visibility.

## Standards Baseline

Map the production program to NIST SSDF 1.1 and OWASP ASVS 5.0, but treat them as
risk frameworks rather than checkbox certification. The repository's existing
SBOM, provenance, scanning, and exact-commit evidence are good inputs; independent
verification and real operating evidence remain mandatory.
