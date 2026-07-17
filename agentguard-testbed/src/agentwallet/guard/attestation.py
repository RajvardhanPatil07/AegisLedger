"""Enclave-style attestation service.

Stands in for a TEE: the attestation keypair is generated inside this object
and *never exported* — only the public key is published. Every guard verdict
produces an Attestation binding (policy hash, proposal hash, verdict, time)
signed by the enclave key. Any verifier can check, offline, that a named
policy binary evaluated a specific transaction and reached a specific verdict.

Tamper-evidence property: mutating any attested field invalidates the
signature (covered by tests).
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ..chain.crypto import KeyPair, sha256_hex, verify


@dataclass
class Attestation:
    policy_hash: str
    proposal_hash: str
    verdict: str  # "ALLOW" | "DENY"
    reasons: list[str]
    timestamp: int
    enclave_pub_hex: str
    signature_hex: str

    def payload(self) -> bytes:
        d = asdict(self).copy()
        d.pop("signature_hex")
        return json.dumps(d, sort_keys=True, separators=(",", ":")).encode()


class EnclaveAttestor:
    """Simulated secure enclave. Private key is not exportable by design."""

    def __init__(self, seed: str, now=None):
        self._keys = KeyPair.from_seed(f"enclave::{seed}")
        self._now = now or (lambda: int(time.time()))

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self._keys.pub

    @property
    def public_hex(self) -> str:
        return self._keys.public_key_bytes().hex()

    def attest(
        self, policy_hash: str, proposal_canonical: bytes, verdict: str, reasons: list[str]
    ) -> Attestation:
        att = Attestation(
            policy_hash=policy_hash,
            proposal_hash=sha256_hex(proposal_canonical),
            verdict=verdict,
            reasons=list(reasons),
            timestamp=self._now(),
            enclave_pub_hex=self.public_hex,
            signature_hex="",
        )
        att.signature_hex = self._keys.sign(att.payload()).hex()
        return att


def verify_attestation(att: Attestation, expected_pub: Ed25519PublicKey) -> bool:
    """Offline verification: signature validity + enclave identity binding."""
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    if expected_pub.public_bytes(Encoding.Raw, PublicFormat.Raw).hex() != att.enclave_pub_hex:
        return False
    return verify(expected_pub, att.payload(), bytes.fromhex(att.signature_hex))
