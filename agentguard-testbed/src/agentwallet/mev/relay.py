"""Private relay: submits transactions directly to the block executor, invisible
to mempool watchers — the standard MEV-visibility mitigation."""

from __future__ import annotations

from ..chain.ledger import LocalChain, Tx


class PrivateRelay:
    name = "private-relay"

    def submit(self, chain: LocalChain, tx: Tx) -> None:
        tx.private = True
        chain.submit(tx)
