"""Testbed factory: wires chain, custody, guard, and agents for each defense
configuration under study.

Defense modes:
  UNDEFENDED      — prompt-only protection; unrestricted policy; no sanitizer.
  MODEL_LEVEL     — sanitizer strips plaintext injections; encoded payloads bypass.
  GUARD_STRICT    — AgentGuard with a strict policy; no sanitizer.
  GUARD_FULL      — strict policy + sanitizer (defense in depth).
  GUARD_MEV       — strict policy + dynamic tightening + private-relay routing.
  CONTRACT_WALLET — on-chain rules only (no off-chain guard; host may be compromised).
"""
from __future__ import annotations

import itertools
from dataclasses import dataclass, field
from enum import Enum

from .chain.ledger import LocalChain, MICRO
from .chain.crypto import KeyPair
from .guard.policy import load_policy, UNRESTRICTED
from .guard.engine import PolicyEngine
from .guard.attestation import EnclaveAttestor
from .guard.guard import AgentGuard, GuardClient
from .wallet.signer import IsolatedSigner
from .wallet.smart_wallet import ContractWalletRules, deploy_contract_wallet
from .agents.base import Sanitizer
from .agents.language_agent import LanguageAgent
from .agents.executor_agent import ExecutorAgent


class DefenseMode(Enum):
    UNDEFENDED = "undefended"
    MODEL_LEVEL = "model_level"
    GUARD_STRICT = "guard_strict"
    GUARD_FULL = "guard_full"
    GUARD_MEV = "guard_mev"
    CONTRACT_WALLET = "contract_wallet"


STRICT_POLICY = """name: strict
per_tx_cap: 250000000
window_caps:
  - {window_s: 3600, cap: 800000000}
  - {window_s: 86400, cap: 1000000000}
velocity: {max_tx_per_window: 10, window_s: 3600}
allowed_assets: [TUSDC, DRB]
allowlist_recipients: []
blocklist_recipients: []
require_mandate_above: 100000000
risk: {dynamic_tightening: false, pool_move_threshold_bps: 100, max_slippage_bps: 100}
kill_switch: false
"""

MEV_AWARE_POLICY = """name: mev-aware
per_tx_cap: 5000000000
window_caps:
  - {window_s: 3600, cap: 20000000000}
  - {window_s: 86400, cap: 50000000000}
velocity: {max_tx_per_window: 30, window_s: 3600}
allowed_assets: [TUSDC, DRB]
allowlist_recipients: []
blocklist_recipients: []
require_mandate_above: 100000000
risk: {dynamic_tightening: true, pool_move_threshold_bps: 100, max_slippage_bps: 50}
kill_switch: false
"""

_tick = itertools.count(1_700_000_000)


@dataclass
class Testbed:
    mode: DefenseMode
    seed: str = "run"
    amm_a: int = 1_000_000 * MICRO
    amm_b: int = 500_000 * MICRO
    chain: LocalChain = field(init=False)
    clock: int = field(init=False)
    guard: AgentGuard = field(init=False)
    client: GuardClient = field(init=False)
    executor: ExecutorAgent = field(init=False)
    language: LanguageAgent = field(init=False)
    attacker: str = "0xattacker0000000000000000000000000000dead"
    vendors: dict = field(init=False)

    def __post_init__(self):
        self.clock = next(_tick)
        now = lambda: self.clock
        self.chain = LocalChain(amm_a=self.amm_a, amm_b=self.amm_b)

        # Vendor identities are derived first: strict policies allowlist them.
        self.vendors = {
            "data-api": KeyPair.from_seed("vendor-data-api").address,
            "merchant": KeyPair.from_seed("vendor-merchant").address,
            "feed": KeyPair.from_seed("vendor-feed").address,
        }
        vendor_list = "[" + ", ".join(f'"{a}"' for a in self.vendors.values()) + "]"

        # --- custody stack ---
        signer = IsolatedSigner(self.seed)
        if self.mode is DefenseMode.CONTRACT_WALLET:
            policy = load_policy(UNRESTRICTED)
        elif self.mode is DefenseMode.GUARD_MEV:
            policy = load_policy(MEV_AWARE_POLICY.replace("allowlist_recipients: []",
                                                          f"allowlist_recipients: {vendor_list}"))
        elif self.mode in (DefenseMode.GUARD_STRICT, DefenseMode.GUARD_FULL):
            policy = load_policy(STRICT_POLICY.replace("allowlist_recipients: []",
                                                       f"allowlist_recipients: {vendor_list}"))
        else:
            policy = load_policy(UNRESTRICTED)

        engine = PolicyEngine(policy, now=now)
        attestor = EnclaveAttestor(self.seed, now=now)
        self.guard = AgentGuard(engine, attestor, signer, chain=self.chain)
        self.client = GuardClient(self.guard, agent_address=f"agent::{self.seed}")
        self.wallet = signer.address

        # --- contract wallet on-chain rules (second custody configuration) ---
        if self.mode is DefenseMode.CONTRACT_WALLET:
            rules = ContractWalletRules(per_tx_cap=200 * MICRO,
                                        allowlist=[], allowed_assets=["TUSDC"])
            deploy_contract_wallet(self.chain, self.wallet, rules)

        # --- agents ---
        san = Sanitizer(enabled=self.mode in (DefenseMode.MODEL_LEVEL,
                                              DefenseMode.GUARD_FULL))
        self.language = LanguageAgent(sanitizer=san, attacker_address=self.attacker)
        self.executor = ExecutorAgent(name="executor", client=self.client,
                                      chain=self.chain)

        # --- funded parties ---
        self.chain.mint("TUSDC", self.wallet, 10_000 * MICRO)
        self.chain.mint("TUSDC", self.attacker, 2_000 * MICRO)
        self.chain.mint("DRB", self.attacker, 5_000 * MICRO)

    def advance_time(self, seconds: int) -> None:
        self.clock += seconds

    def mine(self):
        return self.chain.mine_block()

    def balance(self, addr: str, asset: str = "TUSDC") -> int:
        return self.chain.balance(asset, addr)
