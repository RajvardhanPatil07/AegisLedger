"""Benign MCP-style tool servers."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..payments.x402 import PaymentRequirements, ResourceServer


@dataclass
class PriceOracleTool:
    name: str = "price-oracle"
    description: str = "Returns the current USD price of a crypto asset."
    prices: dict = field(default_factory=lambda: {"DRB": 0.00005, "ETH": 3200.0})
    manipulated_discount: float = 0.0  # >0 means the oracle is lying (poisoned)

    def get_price(self, symbol: str) -> float:
        p = self.prices.get(symbol, 1.0)
        return p * (1.0 - self.manipulated_discount)


@dataclass
class DataAPITool:
    """x402-gated data API: first response is 402; after payment, delivers data."""

    name: str = "data-api"
    description: str = "Premium market data. Pay per call."
    server: ResourceServer | None = None

    def _server(self) -> ResourceServer:
        if self.server is None:
            raise RuntimeError("data API resource server is not configured")
        return self.server

    def request(self) -> tuple[int, PaymentRequirements | None, dict | None]:
        """Returns (status, requirements, data). 402 until paid."""
        return 402, self._server().respond_402(), None

    def fulfill(self) -> dict:
        return self._server().deliver()


@dataclass
class MerchantTool:
    name: str = "merchant"
    description: str = "Creates carts and accepts mandate-bound payments."
    address: str = "0xmerchant"
    catalog: dict = field(
        default_factory=lambda: {
            "api-credits-100": 25_000_000,  # 25 USDC
            "dataset-q3": 120_000_000,  # 120 USDC
            "premium-feed-monthly": 60_000_000,  # 60 USDC
        }
    )

    def price_of(self, item: str) -> int:
        return self.catalog[item]

    def create_cart(self, items: list[str], intent_hash: str, merchant_keys, expires_at: int):
        from ..payments.mandates import CartMandate

        total = sum(self.price_of(i) for i in items)
        return CartMandate(
            merchant=self.address,
            intent_hash=intent_hash,
            items=items,
            total=total,
            expires_at=expires_at,
        ).sign(merchant_keys)
