# AgentGuard Testbed — Security & Economics of Money-Holding AI Agents

An open, reproducible testbed for studying **autonomous AI agents that hold and
spend money**: machine-native payment rails (x402-style), delegated-purchase
mandates (AP2-style), MCP tool poisoning, composed agent chains, and MEV
extraction — plus **AgentGuard**, a policy-enforcement layer with enclave-style
attestations and on-chain contract-wallet enforcement.

Built for the research program *"When Agents Hold Money"* (see the companion
deep-research report). All experiments run on a fully local, deterministic
simulated chain. **No real funds, no live networks, no third-party targets.**

## What this demonstrates

| # | Attack class | Undefended | Model-level defense | AgentGuard | Contract wallet |
|---|---|---|---|---|---|
| I | Composed injection → unauthorized payment (plaintext / Morse / base64) | 100% success, $250/run lost | 67% success (encoded payloads bypass) | **0% success, $0 lost** | 50% success (under-cap variants pass) |
| II | Malicious MCP tool (recipient substitution, oracle distortion, exfil) | 100% success | 67% success | $0 lost; only tool-arg exfil remains (documented blind spot) | 100% success |
| III | Permission-via-inbound-asset + public Morse command (Grok/Bankrbot pattern) | 100% success, $157.5/run | 100% success | **0% success** | 100% success |
| IV | MEV sandwich vs. predictable treasury flow ($2,000 swap) | $72.96 extracted/run (≈3.6%) | — | **$0** (guard cancels: pool moved >100bps) / **$0** via private relay | — |

Task utility under the guard: **100%** on all four financial tasks
(pay-per-call data, mandate-bound procurement, subscriptions, treasury
rebalancing) — the defense blocks attacks without breaking legitimate flows.

## Quick start

```bash
pip install pyyaml pytest cryptography
cd agentguard-testbed
python3 -m pytest tests/ -q          # 67 tests: unit + E2E + security
python3 scripts/run_evaluation.py    # full matrix -> docs/RESULTS.md
```

## Architecture

```
            untrusted content / tools / peers
                          │
                ┌─────────▼─────────┐     no keys, no authority
                │  LanguageAgent    │ ──(instructions)──┐
                └───────────────────┘                   ▼
                                        ┌──────────────────────────┐
                                        │  ExecutorAgent           │  holds a
                                        │  (GuardClient only)      │  submit-only handle
                                        └───────────┬──────────────┘
                                                    │ Proposal
                                        ┌───────────▼──────────────┐
                                        │  AgentGuard              │
                                        │  1. PolicyEngine (YAML   │
                                        │     DSL: caps, velocity, │
                                        │     allowlists, mandate  │
                                        │     requirement, risk)   │
                                        │  2. EnclaveAttestor ─────┼──► attestation
                                        │     (signs verdict +     │    (policy hash,
                                        │      policy/tx hashes)   │    tx hash, verdict)
                                        │  3. IsolatedSigner ──────┼──► signature
                                        │     (keys never leave)   │
                                        │  4. hash-chained audit   │
                                        └───────────┬──────────────┘
                                                    │ Tx
                ┌───────────────────────────────────▼──────────────────┐
                │  LocalChain: mempool → blocks; AMM; contract-wallet  │
                │  rule hooks re-check rules AT SETTLEMENT (on-chain)  │
                └──────────────────────────────────────────────────────┘
```

The model **proposes**; the guard **disposes**. Attestations let anyone verify,
offline, that a named policy (hash) evaluated a specific transaction (hash) and
reached a specific verdict — the assurance artifact missing from production
policy engines today.

## Layout

```
src/agentwallet/
  chain/       crypto (Ed25519), deterministic ledger, AMM, mempool, blocks
  payments/    x402 facilitator flow; AP2-style Intent/Cart mandates + verifier
  guard/       policy DSL (fail-closed YAML), PolicyEngine, EnclaveAttestor, pipeline
  wallet/      IsolatedSigner; contract-wallet on-chain rules
  agents/      scripted language/executor agents (configurable susceptibility)
  tools/       benign + adversarial MCP-style servers (TPA, rug pull, oracle poison)
  attacks/     classes I–IV, each returning measured metrics
  mev/         searcher bot; private relay
  tasks/       financial task suite (utility measurement)
  eval/        matrix harness -> docs/RESULTS.md + results.json
configs/policies/    strict.yaml, mev-aware.yaml
tests/               67 tests: unit, E2E attack assertions, security/tamper
docs/                RESULTS.md, THREAT_MODEL.md, SECURITY.md
```

## Honest limitations (read before citing)

- **Scripted agents, not live LLMs.** The testbed measures *system-layer*
  defenses. Agent susceptibility is explicit and configurable; a sanitizer
  models model-level defense (blocks plaintext, misses encoded channels).
  Swapping in a real LLM runtime requires only implementing the agent
  interface — the harness, attacks, and metrics are unchanged.
- **Simulated chain.** Balances, mempool observability, irreversible settlement,
  AMM impact, and settlement-time rule hooks are modeled with on-chain
  arithmetic; a `ChainBackend` interface point exists for a real EVM fork.
- **Attestor is a software enclave stand-in.** It enforces non-exportability of
  the attestation key by object design; a production deployment would use a
  TEE (Nitro/SGX) or MPC with identical attestation semantics.
- **Documented blind spot:** tool-argument exfiltration (class II-c) is not a
  money-movement event, so the policy engine does not see it. It is reported
  as a residual success under guard modes rather than hidden.
