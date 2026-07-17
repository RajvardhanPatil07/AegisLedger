"""AP2-style authorization mandates (Intent Mandate + Cart Mandate).

An Intent Mandate is the user's signed grant to an agent: what it may buy, for
how much, from whom, until when. A Cart Mandate is the merchant's signed
commitment to exact goods and price, bound to the intent hash. Verification
replays the chain: signature validity, hash linkage, and constraint compliance.

The guard uses this to answer: "is *this* payment inside the user's grant?"
"""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ..chain.crypto import KeyPair, sha256_hex, verify
from .x402 import canonical


@dataclass
class IntentMandate:
    user: str
    agent: str
    max_total: int  # micro-USDC cumulative cap for this grant
    allowed_merchants: list[str]  # empty = any
    expires_at: int
    nonce: str
    signature_hex: str = ""

    def digest(self) -> bytes:
        d = asdict(self).copy()
        d.pop("signature_hex")
        return canonical(d)

    def sign(self, keys: KeyPair) -> IntentMandate:
        self.signature_hex = keys.sign(self.digest()).hex()
        return self

    def hash(self) -> str:
        return sha256_hex(self.digest())

    def verify_signature(self, pub: Ed25519PublicKey) -> bool:
        return verify(pub, self.digest(), bytes.fromhex(self.signature_hex))


@dataclass
class CartMandate:
    merchant: str
    intent_hash: str
    items: list[str]
    total: int
    expires_at: int
    signature_hex: str = ""

    def digest(self) -> bytes:
        d = asdict(self).copy()
        d.pop("signature_hex")
        return canonical(d)

    def sign(self, keys: KeyPair) -> CartMandate:
        self.signature_hex = keys.sign(self.digest()).hex()
        return self

    def verify_signature(self, pub: Ed25519PublicKey) -> bool:
        return verify(pub, self.digest(), bytes.fromhex(self.signature_hex))


class MandateVerifier:
    """Checks that a proposed payment is consistent with the mandate chain."""

    def __init__(self, now=None):
        self._now = now or (lambda: int(time.time()))

    def check_payment_against_chain(
        self,
        intent: IntentMandate,
        cart: CartMandate,
        *,
        user_pub: Ed25519PublicKey,
        merchant_pub: Ed25519PublicKey,
        agent: str,
        merchant: str,
        amount: int,
        already_spent: int,
    ) -> tuple[bool, str]:
        if not intent.verify_signature(user_pub):
            return False, "bad intent signature"
        if not cart.verify_signature(merchant_pub):
            return False, "bad cart signature"
        if cart.intent_hash != intent.hash():
            return False, "cart not bound to intent"
        if intent.expires_at < self._now() or cart.expires_at < self._now():
            return False, "mandate expired"
        if intent.agent != agent:
            return False, "agent mismatch"
        if cart.merchant != merchant:
            return False, "merchant mismatch"
        if intent.allowed_merchants and merchant not in intent.allowed_merchants:
            return False, "merchant not allowed by intent"
        if cart.total != amount:
            return False, "payment amount != cart total"
        if already_spent + amount > intent.max_total:
            return False, "intent budget exceeded"
        return True, "ok"
