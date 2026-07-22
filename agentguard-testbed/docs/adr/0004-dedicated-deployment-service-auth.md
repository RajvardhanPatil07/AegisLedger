# ADR 0004: Scope agent credentials to one organization and environment per deployment

## Status

Accepted

## Date

2026-07-21

## Context

OIDC roles are suitable for the human research console, but an agent integration
needs a non-interactive credential with narrowly defined capabilities. The
long-term product plan includes shared multi-tenancy. The current ledger schema,
however, does not carry an organization and environment key through every policy,
proposal, reservation, decision, execution, attestation, experiment, rate limit,
and audit query.

Adding tenant filters only at HTTP handlers would create a false isolation claim:
one missed query could expose or authorize another tenant's object. Retrofitting
all tables in the same change would also enlarge the signing-path change beyond
what can be reviewed and rolled back safely.

## Decision

The first agent-facing product slice uses one configured organization and
environment per deployment.

- OIDC principals inherit the deployment scope after issuer, audience, signature,
  and expiry validation.
- Agent service credentials are high-entropy bearer tokens with explicit
  permissions. Only a SHA-256 digest is stored; the raw token is returned once.
- Credentials expire, can be revoked, and are rejected if their retained scope
  differs from the deployment scope.
- Service credentials can submit/read/execute proposals or invoke specifically
  granted simulation/verification operations. They receive no human
  policy-administrator or auditor role.
- Rate limiting includes organization and environment in its subject key.
- The local Compose profile enables this authentication path after the durable
  credential migration, while existing OIDC console access remains unchanged.

This is dedicated-deployment isolation, not shared-database multi-tenancy.

## Alternatives considered

### Add optional tenant fields only to API requests

Rejected. Client-controlled tenant identifiers are not an authorization boundary,
and optional fields would preserve unsafe unscoped paths.

### Add API-layer filters without migrating every durable object

Rejected. This is easy to demonstrate but too easy to bypass through a forgotten
store, background worker, reconciliation path, or administrative endpoint.

### Migrate the entire ledger to shared multi-tenancy immediately

Deferred. It remains a product-plan task, but requires a contract-first schema,
backfill policy, composite uniqueness constraints, store conformance tests,
background-worker isolation, and independent review.

## Consequences

- A customer or environment that requires stronger isolation receives a separate
  deployment and database.
- Operators must provision and rotate service credentials through the CLI; raw
  credentials cannot be recovered from storage.
- Shared managed hosting is not yet supported and must not be claimed.
- A future shared-tenant ADR must supersede this decision and prove tenant keys at
  every persistence, cache, rate-limit, audit, webhook, and worker boundary before
  multiple customers share a deployment.
