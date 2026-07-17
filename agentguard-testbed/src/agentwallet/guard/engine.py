"""PolicyEngine: evaluates payment/swap proposals against a Policy plus
spending history. Deterministic, injectable clock, fail-closed on malformed
input.

This is the component the model can never reach: agents submit *proposals*;
the engine returns verdicts; only the guard pipeline can turn an approval into
a signature.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field

from ..payments.mandates import CartMandate, IntentMandate, MandateVerifier
from .policy import Policy


@dataclass
class Proposal:
    kind: str  # "transfer" | "swap"
    amount: int  # micro-USDC (transfer) or amount_in (swap)
    asset: str = "TUSDC"
    to: str = ""  # transfer recipient
    token_in: str = "TUSDC"  # swap fields
    token_out: str = "DRB"
    min_out: int = 0
    quoted_out: int = 0  # quote observed at decision time (for slippage check)
    purpose: str = ""
    meta: dict = field(default_factory=dict)

    def canonical(self) -> bytes:
        return json.dumps(asdict(self), sort_keys=True, separators=(",", ":")).encode()


@dataclass
class Verdict:
    allow: bool
    reasons: list[str] = field(default_factory=list)

    def __str__(self) -> str:
        verdict = "ALLOW" if self.allow else "DENY"
        return verdict + (": " + "; ".join(self.reasons) if self.reasons else "")


@dataclass
class SpendRecord:
    ts: int
    amount: int
    asset: str
    to: str


class MalformedProposal(Exception):
    pass


class PolicyEngine:
    def __init__(self, policy: Policy, now=None):
        self.policy = policy
        self.history: list[SpendRecord] = []
        self._now = now or (lambda: int(time.time()))
        self.mandate_verifier = MandateVerifier(now=self._now)
        # Optional market-state observer for dynamic tightening (set by harness).
        self.pool_move_bps: int = 0

    # ---- validation ----
    @staticmethod
    def _validate(p: Proposal) -> None:
        if p.kind not in ("transfer", "swap"):
            raise MalformedProposal(f"unknown kind {p.kind!r}")
        if not isinstance(p.amount, int) or isinstance(p.amount, bool) or p.amount <= 0:
            raise MalformedProposal("amount must be a positive integer")
        if p.kind == "transfer" and not p.to:
            raise MalformedProposal("transfer requires recipient")

    # ---- history ----
    def record(self, p: Proposal) -> None:
        self.history.append(SpendRecord(ts=self._now(), amount=p.amount, asset=p.asset, to=p.to))

    def _spent_in_window(self, window_s: int) -> int:
        now = self._now()
        return sum(r.amount for r in self.history if now - r.ts < window_s)

    def _count_in_window(self, window_s: int) -> int:
        now = self._now()
        return sum(1 for r in self.history if now - r.ts < window_s)

    def spent_under_intent(self) -> int:
        return sum(r.amount for r in self.history)

    # ---- evaluation ----
    def evaluate(
        self,
        p: Proposal,
        mandate_chain: tuple[IntentMandate, CartMandate, dict] | None = None,
    ) -> Verdict:
        try:
            self._validate(p)
        except MalformedProposal as e:
            return Verdict(False, [f"malformed proposal: {e}"])

        pol = self.policy
        reasons: list[str] = []

        if pol.kill_switch:
            return Verdict(False, ["kill switch engaged"])

        if p.asset not in pol.allowed_assets:
            reasons.append(f"asset {p.asset} not in allowed_assets")

        if pol.per_tx_cap and p.amount > pol.per_tx_cap:
            reasons.append(f"amount {p.amount} > per-tx cap {pol.per_tx_cap}")

        for wc in pol.window_caps:
            spent = self._spent_in_window(wc.window_s)
            if spent + p.amount > wc.cap:
                reasons.append(
                    f"window cap exceeded: {spent}+{p.amount} > {wc.cap} over {wc.window_s}s"
                )

        if (
            pol.max_tx_per_window
            and self._count_in_window(pol.velocity_window_s) + 1 > pol.max_tx_per_window
        ):
            reasons.append("velocity limit exceeded")

        if p.kind == "transfer":
            if p.to in pol.blocklist_recipients:
                reasons.append(f"recipient {p.to} blocklisted")
            if pol.allowlist_recipients and p.to not in pol.allowlist_recipients:
                reasons.append(f"recipient {p.to} not on allowlist")

        # AP2 mandate requirement above threshold (payments to counterparties only;
        # swaps are self-trades and governed by the risk controls instead)
        if p.kind == "transfer" and p.amount > pol.require_mandate_above:
            if mandate_chain is None:
                reasons.append(f"amount {p.amount} requires an AP2 mandate chain")
            else:
                intent, cart, pubs = mandate_chain
                ok, why = self.mandate_verifier.check_payment_against_chain(
                    intent,
                    cart,
                    user_pub=pubs["user"],
                    merchant_pub=pubs["merchant"],
                    agent=p.meta.get("agent", ""),
                    merchant=p.to,
                    amount=p.amount,
                    already_spent=self.spent_under_intent(),
                )
                if not ok:
                    reasons.append(f"mandate chain invalid: {why}")

        # Dynamic tightening on swaps: if the pool moved adversely beyond the
        # threshold between quote and submission, refuse to execute at stale terms.
        if p.kind == "swap" and pol.risk.dynamic_tightening:
            if self.pool_move_bps > pol.risk.pool_move_threshold_bps:
                reasons.append(
                    f"pool moved {self.pool_move_bps}bps > threshold "
                    f"{pol.risk.pool_move_threshold_bps}bps (possible sandwich)"
                )
            if p.quoted_out and p.min_out:
                slip_bps = (p.quoted_out - p.min_out) * 10_000 // max(p.quoted_out, 1)
                if slip_bps > pol.risk.max_slippage_bps:
                    reasons.append(
                        f"slippage tolerance {slip_bps}bps > policy max "
                        f"{pol.risk.max_slippage_bps}bps"
                    )

        return Verdict(allow=not reasons, reasons=reasons)
