"""Smart-contract wallet configuration: rules enforced *at settlement* by the
chain itself (rule hook inside the block executor). Even if the off-chain
guard host is fully compromised and submits directly to the mempool, these
rules still execute — modeling the on-chain enforcement tier.
"""

from __future__ import annotations

from ..chain.ledger import LocalChain, RuleViolation, Tx


class ContractWalletRules:
    def __init__(
        self,
        per_tx_cap: int = 0,
        allowlist: list[str] | None = None,
        allowed_assets: list[str] | None = None,
    ):
        self.per_tx_cap = per_tx_cap
        self.allowlist = set(allowlist or [])
        self.allowed_assets = set(allowed_assets or ["TUSDC"])

    def hook(self, tx: Tx) -> None:
        if tx.kind.value == "transfer":
            if tx.asset not in self.allowed_assets:
                raise RuleViolation(f"contract wallet: asset {tx.asset} not allowed")
            if self.per_tx_cap and tx.amount > self.per_tx_cap:
                raise RuleViolation(
                    f"contract wallet: {tx.amount} > on-chain per-tx cap {self.per_tx_cap}"
                )
            if self.allowlist and tx.to not in self.allowlist:
                raise RuleViolation(f"contract wallet: recipient {tx.to} not allowlisted")


def deploy_contract_wallet(chain: LocalChain, address: str, rules: ContractWalletRules) -> None:
    chain.register_rule_hook(address, rules.hook)
