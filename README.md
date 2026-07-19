# AegisLedger

AegisLedger is a reproducible security and economics research project for
autonomous AI agents that hold and spend money. It combines a deterministic
local-chain testbed, adversarial payment scenarios, durable policy decisions, an
mTLS-isolated Rust signer that validates exact EIP-1559 transactions, Anvil
settlement/finality, offline-verifiable complete attestations, contract-wallet
controls, and measured evaluations of financial loss and task utility.

All experiments run locally with simulated assets. The project does not use
real funds, live networks, or third-party targets.

## What is included

- A runnable Python testbed for x402-style payments and delegated purchase mandates
- Four attack classes covering composed prompt injection, malicious tools,
  permission abuse, and MEV extraction
- A real proposal → policy → isolated signer → Anvil → finality → complete
  attestation reference path
- PostgreSQL-backed lifecycle, audit, evidence, rate-limit, and experiment state
- Contract-wallet and private-relay defense comparisons
- Python, Rust, Solidity, console, browser, formal, static-analysis, SBOM,
  provenance, image-scan, and end-to-end runtime gates
- Reproducible evaluation results and supporting research material

## Run the testbed

```bash
cd agentguard-testbed
make bootstrap
make verify
make evaluate
make up
make runtime-smoke
```

The evaluation writes its report to `agentguard-testbed/docs/RESULTS.md` and
machine-readable data to `agentguard-testbed/docs/results.json`.

## Repository map

- `agentguard-testbed/` — runnable implementation, tests, policies, and results
- `Security-and-Economics-of-Money-Holding-AI-Agents.md` — research assessment
- `ROADMAP.md` — implementation status, hardening milestones, and release gates
- `assets/` — research figures

## Release status

AegisLedger is a production-oriented research reference, not a production
custody service. The Compose deployment is loopback-only and uses simulated
assets. Do not expose it directly to the internet or use it with real funds.

See `agentguard-testbed/docs/SECURITY_CLAIMS.md` for the claim/evidence matrix,
`agentguard-testbed/docs/THREAT_MODEL.md` for scope,
`agentguard-testbed/docs/OPERATIONS.md` for deployment limitations, and
`agentguard-testbed/docs/REVIEWER_CHECKLIST.md` for independent review.

Keep the repository private until the owner completes the patent/publication
decision and an independent security assessment. Passing repository checks does
not make the reference deployment suitable for production custody.
