"""ExecutorAgent: holds wallet authority (via a GuardClient) and executes
payment instructions. Trusts peer-agent output by default — the composed-chain
vulnerability under study. Optional legacy flaw: treats inbound assets
(e.g., a "membership NFT") as privilege grants, replicating the Grok/Bankrbot
permission-chain abuse primitive.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..guard.engine import Proposal
from ..guard.guard import GuardClient, GuardReceipt
from .base import PaymentInstruction


@dataclass
class ExecutorAgent:
    name: str
    client: GuardClient
    trust_peer_instructions: bool = True
    inbound_asset_grants: bool = False  # the legacy flaw toggle
    accepts_public_commands: bool = False  # trust "public reply" as authorized
    _privilege_unlocked: bool = False
    log: list[str] = field(default_factory=list)

    def on_inbound_asset(self, asset: str, frm: str) -> None:
        """Inbound assets are conventionally passive. With the legacy flaw on,
        receiving a 'membership' token unlocks executive transfer privileges."""
        if self.inbound_asset_grants and asset == "BANKR_CLUB_NFT":
            self._privilege_unlocked = True
            self.log.append(
                f"PRIVILEGE ESCALATION: inbound {asset} from {frm} interpreted as permission grant"
            )

    def execute(self, instr: PaymentInstruction, source: str = "user") -> GuardReceipt | None:
        if source == "peer" and not self.trust_peer_instructions:
            self.log.append("refused peer instruction (peer trust disabled)")
            return None
        if source == "public" and not (self.accepts_public_commands and self._privilege_unlocked):
            self.log.append("refused public instruction (no privilege)")
            return None
        p = Proposal(
            kind="transfer",
            amount=instr.amount,
            asset=instr.asset,
            to=instr.to,
            purpose=instr.purpose,
        )
        self.log.append(
            f"submitting proposal from {source}: {instr.amount} -> {instr.to} ({instr.purpose})"
        )
        return self.client.submit(p)

    def execute_swap(
        self,
        amount_in: int,
        min_out: int,
        quoted_out: int,
        private: bool = False,
        token_in: str = "TUSDC",
        token_out: str = "DRB",
    ) -> GuardReceipt:
        p = Proposal(
            kind="swap",
            amount=amount_in,
            token_in=token_in,
            token_out=token_out,
            min_out=min_out,
            quoted_out=quoted_out,
            purpose="treasury-rebalance",
            meta={"private": private},
        )
        return self.client.submit(p)
