# ADR 0003: Private release status and external gates

- Status: Accepted
- Date: 2026-07-18

## Context

The implementation has strong automated and runtime evidence, but repository
visibility can affect intellectual-property options and self-review cannot be
called an independent audit. Local software evidence also cannot substitute for
managed production key custody.

## Decision

Keep the repository private and describe it as a production-oriented research
reference. A public release requires all automated gates for the same commit,
an owner-recorded patent/publication decision, and a completed assessment by a
reviewer independent of implementation. Production-custody language is
forbidden until managed keys, production service topology, live-chain risk
controls, operational SLO evidence, and audit remediation are complete.

## Consequences

- Passing CI does not authorize changing GitHub visibility.
- Legal and independent-review gates remain visibly incomplete in checklists
  and release notes.
- Review artifacts distinguish implemented, reference-only, research, external,
  and not-claimed properties.
- The owner controls any future public release, branch protection, signing
  identity, and production deployment decision.
