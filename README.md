# AegisLedger

AegisLedger is a reproducible security and economics research project for
autonomous AI agents that hold and spend money. It combines a deterministic
local-chain testbed, adversarial payment scenarios, policy-enforced signing,
contract-wallet controls, and measured evaluations of financial loss and task
utility.

All experiments run locally with simulated assets. The project does not use
real funds, live networks, or third-party targets.

## What is included

- A runnable Python testbed for x402-style payments and delegated purchase mandates
- Four attack classes covering composed prompt injection, malicious tools,
  permission abuse, and MEV extraction
- A policy guard with signed attestations and isolated-key handling
- Contract-wallet and private-relay defense comparisons
- A 67-test unit, end-to-end, and security suite
- Reproducible evaluation results and supporting research material

## Run the testbed

```bash
cd agentguard-testbed
python3 -m pip install pyyaml pytest cryptography
python3 -m pytest tests/ -q
python3 scripts/run_evaluation.py
```

The evaluation writes its report to `agentguard-testbed/docs/RESULTS.md` and
machine-readable data to `agentguard-testbed/docs/results.json`.

## Repository map

- `agentguard-testbed/` — runnable implementation, tests, policies, and results
- `Security-and-Economics-of-Money-Holding-AI-Agents.md` — research assessment
- `Agent-Wallet-Security-Project-Master-Prompt.md` — project brief and roadmap
- `assets/` — research figures
