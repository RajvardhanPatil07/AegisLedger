"""Policy-service decision issuance and independent signature verification."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from agentwallet.chain.crypto import KeyPair, verify

from .canonical import canonical_json, uuid7
from .contracts import DecisionTokenV1, DecisionVerdict, LifecycleState
from .policies import PolicyVersion
from .state import ProposalRecord


def decision_signature_payload(token: DecisionTokenV1) -> bytes:
    return canonical_json(token.model_dump(mode="json", exclude={"signature"}))


class DecisionIssuer:
    """Non-exportable policy signing identity for transaction-bound decisions."""

    def __init__(self, keys: KeyPair, *, lifetime_seconds: int = 30) -> None:
        self._keys = keys
        self._lifetime_seconds = lifetime_seconds

    @classmethod
    def from_seed(cls, seed: str, *, lifetime_seconds: int = 30) -> DecisionIssuer:
        return cls(KeyPair.from_seed(f"policy-service::{seed}"), lifetime_seconds=lifetime_seconds)

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self._keys.pub

    @property
    def identity(self) -> str:
        return self._keys.address

    def issue(self, record: ProposalRecord, policy_version: PolicyVersion) -> DecisionTokenV1:
        if record.state not in {LifecycleState.RESERVED, LifecycleState.DENIED}:
            raise ValueError(f"cannot issue a decision for lifecycle state {record.state.value}")
        verdict = (
            DecisionVerdict.ALLOW
            if record.state is LifecycleState.RESERVED
            else DecisionVerdict.DENY
        )
        expires_at = min(
            record.proposal.deadline,
            datetime.now(UTC) + timedelta(seconds=self._lifetime_seconds),
        )
        placeholder = DecisionTokenV1(
            schema_version="aegisledger.decision.v1",
            decision_id=uuid7(),
            proposal_hash=record.proposal.proposal_hash(),
            policy_version_id=policy_version.version_id,
            policy_hash=policy_version.policy_hash,
            state_version=record.state_version,
            reservation_id=record.reservation_id,
            verdict=verdict,
            reason_codes=record.reason_codes,
            expires_at=expires_at,
            decision_nonce=uuid7(),
            policy_signer=self.identity,
            signature="0" * 128,
        )
        signature = self._keys.sign(decision_signature_payload(placeholder)).hex()
        return DecisionTokenV1.model_validate(
            {**placeholder.model_dump(mode="python"), "signature": signature}
        )


def verify_decision_token(
    token: DecisionTokenV1,
    public_key: Ed25519PublicKey,
    *,
    now: datetime | None = None,
) -> bool:
    current_time = now or datetime.now(UTC)
    if token.expires_at <= current_time:
        return False
    try:
        signature = bytes.fromhex(token.signature)
    except ValueError:
        return False
    return verify(public_key, decision_signature_payload(token), signature)
