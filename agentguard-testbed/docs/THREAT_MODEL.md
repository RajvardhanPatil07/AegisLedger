# Threat Model

## Assets

1. Wallet balances (TUSDC, DRB) controlled by the agent's signer.
2. Wallet configuration and API credentials readable by the agent host.
3. Execution integrity: the agent trades at intended prices, at intended times.
4. Availability: legitimate financial tasks must still complete under defense.

## Adversary classes

| Adversary | Capabilities | Non-goals |
|---|---|---|
| **A1 Content injector** | Plants instructions in web pages, emails, tool outputs the language agent reads; may encode them (Morse, base64) | Cannot sign, cannot touch the guard host |
| **A2 Malicious tool server** | Controls tool descriptions and outputs; can redefine tools after approval (rug pull); sees tool-call arguments | Cannot call other tools directly |
| **A3 Malicious counterparty / resource server** | Inflates payment requirements, swaps recipients, manipulates prices, sends unsolicited inbound assets | Cannot forge signatures |
| **A4 Compromised peer agent** | A language agent fully following injected instructions; its output is trusted by the executor | Holds no keys by architecture |
| **A5 Extractive searcher** | Observes the public mempool; can insert/reorder own transactions; ms-latency | Cannot see private-relay flow |
| **A6 Compromised agent host** (contract-wallet config) | Can bypass the off-chain guard and submit raw transactions | Cannot bypass settlement-time on-chain rules |

## Trust boundaries

```
untrusted:  content, tools, peers, counterparties, mempool observers
boundary 1: LanguageAgent        (sanitizer — probabilistic, bypassable)
boundary 2: GuardClient          (submit-only object capability)
boundary 3: PolicyEngine         (deterministic, fail-closed, outside model reach)
boundary 4: EnclaveAttestor      (key non-exportable; binds verdict to policy+tx)
boundary 5: IsolatedSigner       (signs only after ALLOW)
boundary 6: contract-wallet hook (rules re-checked at settlement; survives 1–5 compromise)
```

## Security claims tested

- **C1** A1–A4 cannot produce a settled unauthorized transfer when the strict
  guard is active (classes I–III residual success = 0; II-c exfil is out of
  money scope and disclosed).
- **C2** A5 cannot extract value when flow is private, and is detected/cancelled
  when the mev-aware guard observes >100bps pool movement.
- **C3** A6 cannot exceed on-chain per-tx caps (contract-wallet config).
- **C4** Every verdict is accompanied by an attestation that verifies offline;
  any tampering with policy hash, tx hash, or verdict invalidates it.
- **C5** Audit-log tampering is detectable (hash chain).
- **C6** Utility: defenses do not degrade legitimate task completion.
