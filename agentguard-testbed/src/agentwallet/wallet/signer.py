"""Isolated signer: the only object that holds wallet key material.

Agents and tools never receive an IsolatedSigner reference — the guard owns it
and calls it only after an ALLOW verdict. This models TEE/MPC custody: the
model proposes, the signer disposes.
"""

from __future__ import annotations

from ..chain.crypto import KeyPair
from ..chain.ledger import RuleViolation, Tx


class IsolatedSigner:
    def __init__(self, seed: str):
        self._keys = KeyPair.from_seed(f"wallet::{seed}")

    @property
    def address(self) -> str:
        return self._keys.address

    @property
    def public_key(self):
        return self._keys.pub

    def sign(self, digest: bytes) -> tuple[str, str]:
        """Returns (pub_hex, sig_hex). Only the guard pipeline may call this."""
        return self._keys.public_key_bytes().hex(), self._keys.sign(digest).hex()

    def authorize_transaction(self, tx: Tx) -> Tx:
        """Bind this signer to the exact transaction envelope."""
        if tx.sender.lower() != self.address.lower():
            raise RuleViolation("isolated signer does not control transaction sender")
        tx.public_key_hex, tx.signature_hex = self.sign(tx.digest())
        return tx
