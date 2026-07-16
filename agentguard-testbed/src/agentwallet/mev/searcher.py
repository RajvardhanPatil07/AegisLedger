"""Adversarial searcher: watches the public mempool and sandwiches agent swaps.

Strategy (classic sandwich):
  1. Observe a victim swap (TUSDC -> DRB) of size S with slippage tolerance.
  2. Front-run: buy DRB with fraction `front_frac` of S, moving the price up.
  3. Victim executes at a worse price (still >= min_out, else victim reverts).
  4. Back-run: sell the acquired DRB, pocketing the difference.

Extracted value is measured exactly from ledger state, not estimated.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..chain.ledger import LocalChain, Tx, TxKind


@dataclass
class SearcherBot:
    address: str
    front_frac: float = 0.5
    log: list[str] = field(default_factory=list)

    def plan_sandwich(self, chain: LocalChain) -> tuple[Tx | None, Tx | None]:
        """Inspect the visible mempool; if an agent swap is present, return
        (front_run_tx, back_run_placeholder). The back-run size is computed
        after the victim executes, so here we return the front-run only."""
        for tx in chain.visible_mempool():
            if tx.kind is TxKind.SWAP and tx.token_in == "TUSDC" and tx.sender != self.address:
                front_amt = int(tx.amount_in * self.front_frac)
                if front_amt <= 0 or chain.balance("TUSDC", self.address) < front_amt:
                    return None, None
                self.log.append(f"sandwich planned vs {tx.sender}: front {front_amt}")
                return (Tx(kind=TxKind.SWAP, sender=self.address, amount_in=front_amt,
                           token_in="TUSDC", token_out="DRB", min_out=0), tx)
        return None, None
