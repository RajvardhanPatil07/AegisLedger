# Security Notes — Self-Check Results

## Static analysis

`bandit -r src/` — **0 high, 0 medium** severity findings. 8 low findings, all
false positives or accepted design:

| Finding | Verdict |
|---|---|
| `hardcoded_password: 'TUSDC'/'DRB'` (x6) | False positive — token ticker symbols, not secrets. |
| `assert_used` (x2, `ConstantProductAMM.__init__`) | Accepted — constructor invariant checks in a testbed; not reachable with attacker-controlled input. |

## Trust-boundary review (manual)

- **Key custody:** wallet key material exists only inside `IsolatedSigner`; the
  attestation key only inside `EnclaveAttestor`. Neither is reachable from the
  agent-facing `GuardClient` (submit-only; verified by
  `test_agent_handle_is_submit_only`).
- **Fail-closed parsing:** unknown keys, negative amounts, booleans-as-integers,
  and malformed YAML all raise `PolicyError` at load — a broken policy can
  never silently become permissive (tested).
- **Deny means no settlement:** engine deny → no mempool submission (tested).
- **Bypass attempt:** direct-to-mempool submission in contract-wallet config is
  reverted by settlement-time rules for over-cap transfers (tested).
- **Replay:** facilitator nonces are single-use (tested).
- **Tamper evidence:** attestation field mutation invalidates verification;
  audit-log mutation breaks the hash chain (both tested).
- **Determinism:** all keys derived from seeds; all clocks injectable; the
  evaluation matrix is exactly reproducible.

## Ethical posture

- Entirely local, simulated assets; no live networks, platforms, or third-party
  agents are touched at any point.
- Adversarial tools and payloads exist to measure defenses and are documented
  as such; they target only the testbed's own agents.
- Where this work models real incidents (Morse-encoded injection, inbound-asset
  privilege grants, tool poisoning), it reimplements the *mechanics* against
  synthetic wallets — no victim infrastructure is involved.

## Known blind spots (disclosed, not hidden)

1. **Tool-argument exfiltration** (class II-c): policy engines govern money
   movement, not data flow inside tool calls. Mitigation requires a separate
   information-flow control layer (e.g., CaMeL-style provenance) — noted as
   future work.
2. **Availability cost of MEV-aware cancellation:** when the guard cancels a
   sandwiched swap, the legitimate swap does not execute in that block; the
   private-relay configuration avoids this cost by removing the information
   leak instead.
3. **Per-tx caps bound, not prevent:** under-cap theft passes cap-only
   configurations (contract-wallet results) — caps must be composed with
   recipient allowlists and mandate requirements.
