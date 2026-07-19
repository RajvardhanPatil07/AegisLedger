"""Deterministic Ed25519 key management and signatures.

Keys are derived from seeds so every experiment is reproducible. Addresses are
20-byte hex strings derived from the public key (Ethereum-style truncation of
a hash, but over Ed25519 public keys for dependency-light signing).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)


def _seed_bytes(seed: str) -> bytes:
    return hashlib.sha256(f"agentwallet-seed::{seed}".encode()).digest()


def address_of(pub: Ed25519PublicKey) -> str:
    raw = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return "0x" + hashlib.sha256(raw).hexdigest()[-40:]


@dataclass(frozen=True)
class KeyPair:
    """An Ed25519 keypair. The private key never leaves the object that owns it."""

    _priv: Ed25519PrivateKey
    pub: Ed25519PublicKey
    address: str

    @staticmethod
    def from_seed(seed: str) -> KeyPair:
        priv = Ed25519PrivateKey.from_private_bytes(_seed_bytes(seed))
        pub = priv.public_key()
        return KeyPair(_priv=priv, pub=pub, address=address_of(pub))

    def sign(self, msg: bytes) -> bytes:
        return self._priv.sign(msg)

    def public_key_bytes(self) -> bytes:
        return self.pub.public_bytes(Encoding.Raw, PublicFormat.Raw)


def verify(pub: Ed25519PublicKey, msg: bytes, sig: bytes) -> bool:
    try:
        pub.verify(sig, msg)
        return True
    except Exception:
        return False


def verify_with_address(address: str, msg: bytes, sig: bytes, pub: Ed25519PublicKey) -> bool:
    """Verify a signature *and* that the supplied public key maps to the address."""
    if address_of(pub) != address.lower() and address_of(pub) != address:
        return False
    return verify(pub, msg, sig)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
