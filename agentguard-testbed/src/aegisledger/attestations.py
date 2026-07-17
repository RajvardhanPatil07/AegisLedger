"""Complete, offline-verifiable authorization and settlement attestations."""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated, Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from eth_hash.auto import keccak
from pydantic import Field, StringConstraints, field_validator, model_validator

from .canonical import canonical_json
from .contracts import (
    Address,
    DecisionTokenV1,
    Hex32,
    ProposalV1,
    SignedTransactionV1,
    StrictModel,
)
from .decisions import verify_decision_token
from .signing import TransactionBindingV1

HexPublicKey = Annotated[str, StringConstraints(pattern=r"^0x04[0-9a-f]{128}$")]
HexSignature = Annotated[str, StringConstraints(pattern=r"^0x[0-9a-f]{130}$")]


class EnclaveEvidenceV1(StrictModel):
    schema_version: Literal["aegisledger.enclave_evidence.v1"]
    mode: Literal["local-process-or-nitro", "aws-nitro"]
    build_measurement: Annotated[str, StringConstraints(min_length=1, max_length=256)]
    signer_identity: Address
    secp256k1_public_key: HexPublicKey
    transaction_hash: Hex32
    proposal_hash: Hex32
    policy_version_id: uuid.UUID
    policy_hash: Hex32
    state_version: Annotated[int, Field(ge=0)]
    reservation_id: uuid.UUID
    wallet: Address
    principal_id: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    chain_id: Annotated[int, Field(gt=0)]
    wallet_nonce: Annotated[int, Field(ge=0)]
    decision_id: uuid.UUID
    decision_nonce: uuid.UUID
    expires_at: datetime
    issued_at: datetime
    evidence_hash: Hex32
    evidence_signature: HexSignature

    @field_validator(
        "policy_version_id",
        "reservation_id",
        "decision_id",
        "decision_nonce",
        mode="before",
    )
    @classmethod
    def parse_uuid(cls, value: object) -> uuid.UUID:
        if isinstance(value, uuid.UUID):
            return value
        if isinstance(value, str):
            return uuid.UUID(value)
        raise TypeError("identifier must be a UUID string")

    @field_validator("signer_identity", "wallet")
    @classmethod
    def normalize_address(cls, value: str) -> str:
        return value.lower()

    @field_validator("expires_at", "issued_at", mode="before")
    @classmethod
    def parse_datetime(cls, value: object) -> datetime:
        if isinstance(value, datetime):
            return value
        if isinstance(value, str):
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        raise TypeError("timestamp must be an ISO 8601 string")

    @field_validator("expires_at", "issued_at")
    @classmethod
    def normalize_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("evidence timestamps must include a UTC offset")
        return value.astimezone(UTC)

    def unsigned_payload(self) -> bytes:
        return canonical_json(
            self.model_dump(
                mode="json",
                exclude={"evidence_hash", "evidence_signature"},
            )
        )


class SettlementEvidenceV1(StrictModel):
    schema_version: Literal["aegisledger.settlement_evidence.v1"]
    transaction_hash: Hex32
    block_hash: Hex32
    block_number: Annotated[int, Field(ge=0)]
    chain_id: Annotated[int, Field(gt=0)]
    success: bool
    confirmations: Annotated[int, Field(ge=0)]
    observed_at: datetime

    @field_validator("observed_at")
    @classmethod
    def normalize_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("observed_at must include a UTC offset")
        return value.astimezone(UTC)


class CompleteAttestationV1(StrictModel):
    schema_version: Literal["aegisledger.complete_attestation.v1"]
    lifecycle_state: Literal["SIGNED", "SUBMITTED", "SETTLED", "REVERTED"]
    proposal: ProposalV1
    decision: DecisionTokenV1
    transaction_binding: TransactionBindingV1
    signed_transaction: SignedTransactionV1
    enclave_evidence: EnclaveEvidenceV1
    settlement: SettlementEvidenceV1 | None = None

    @model_validator(mode="after")
    def settlement_matches_state(self) -> CompleteAttestationV1:
        terminal = self.lifecycle_state in {"SETTLED", "REVERTED"}
        if terminal != (self.settlement is not None):
            raise ValueError("terminal attestations require settlement evidence")
        return self


@dataclass(frozen=True)
class AttestationVerification:
    valid: bool
    errors: tuple[str, ...]


def verify_complete_attestation(
    attestation: CompleteAttestationV1,
    policy_public_key: Ed25519PublicKey,
    *,
    allowed_build_measurements: set[str],
) -> AttestationVerification:
    errors: list[str] = []
    proposal = attestation.proposal
    decision = attestation.decision
    signed = attestation.signed_transaction
    evidence = attestation.enclave_evidence
    binding = attestation.transaction_binding

    if not verify_decision_token(decision, policy_public_key, now=evidence.issued_at):
        errors.append("policy decision signature is invalid")
    if evidence.issued_at > evidence.expires_at:
        errors.append("enclave evidence was issued after expiry")
    if evidence.build_measurement not in allowed_build_measurements:
        errors.append("signer build measurement is not approved")

    expected = {
        "proposal_hash": proposal.proposal_hash(),
        "policy_version_id": decision.policy_version_id,
        "policy_hash": decision.policy_hash,
        "state_version": decision.state_version,
        "reservation_id": decision.reservation_id,
        "wallet": proposal.wallet,
        "principal_id": proposal.principal_id,
        "chain_id": proposal.chain_id,
        "decision_id": decision.decision_id,
        "decision_nonce": decision.decision_nonce,
    }
    for field_name, expected_value in expected.items():
        if getattr(evidence, field_name) != expected_value:
            errors.append(f"enclave evidence {field_name} binding mismatch")
    if evidence.transaction_hash != signed.eip1559_hash:
        errors.append("enclave evidence transaction hash mismatch")
    if evidence.wallet_nonce != signed.wallet_nonce:
        errors.append("enclave evidence wallet nonce mismatch")
    if evidence.signer_identity != signed.signer_identity.lower():
        errors.append("enclave evidence signer identity mismatch")
    if evidence.expires_at > decision.expires_at or evidence.expires_at > proposal.deadline:
        errors.append("enclave evidence outlives authorization")
    if signed.decision_id != decision.decision_id:
        errors.append("signed transaction decision binding mismatch")
    if signed.wallet != proposal.wallet or signed.chain_id != proposal.chain_id:
        errors.append("signed transaction scope mismatch")
    if binding.wallet != proposal.wallet or binding.chain_id != proposal.chain_id:
        errors.append("transaction binding scope mismatch")
    if binding.wallet_nonce != signed.wallet_nonce:
        errors.append("transaction binding nonce mismatch")
    if binding.asset != proposal.asset or binding.amount != proposal.amount:
        errors.append("transaction binding value mismatch")
    if proposal.intent.kind == "transfer":
        if binding.operation != "transfer" or binding.recipient != proposal.intent.recipient:
            errors.append("transaction binding recipient mismatch")
    elif (
        binding.operation != "swap"
        or binding.contract != proposal.intent.contract
        or binding.selector != proposal.intent.selector
        or binding.calldata != proposal.intent.calldata
    ):
        errors.append("transaction binding contract call mismatch")

    evidence_digest = hashlib.sha256(evidence.unsigned_payload()).digest()
    if evidence.evidence_hash != "0x" + evidence_digest.hex():
        errors.append("enclave evidence hash mismatch")
    public_key = _public_key(evidence.secp256k1_public_key, errors)
    if public_key is not None:
        identity = (
            "0x"
            + keccak(
                public_key.public_bytes(
                    serialization.Encoding.X962,
                    serialization.PublicFormat.UncompressedPoint,
                )[1:]
            )[-20:].hex()
        )
        if identity != evidence.signer_identity:
            errors.append("secp256k1 public key does not match signer identity")
        _verify_raw_signature(
            public_key,
            evidence_digest,
            evidence.evidence_signature,
            "enclave evidence signature is invalid",
            errors,
        )
        _verify_raw_signature(
            public_key,
            bytes.fromhex(signed.eip1559_hash[2:]),
            signed.signature,
            "transaction signature is invalid",
            errors,
        )

    if canonical_json(signed.enclave_evidence) != canonical_json(evidence.model_dump(mode="json")):
        errors.append("signed transaction carries different enclave evidence")

    settlement = attestation.settlement
    if settlement is not None:
        if (
            settlement.transaction_hash != signed.eip1559_hash
            or settlement.chain_id != signed.chain_id
        ):
            errors.append("settlement scope mismatch")
        expected_success = attestation.lifecycle_state == "SETTLED"
        if settlement.success != expected_success:
            errors.append("settlement result does not match lifecycle state")
    return AttestationVerification(not errors, tuple(errors))


def _public_key(
    encoded: str,
    errors: list[str],
) -> ec.EllipticCurvePublicKey | None:
    try:
        return ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256K1(), bytes.fromhex(encoded[2:])
        )
    except ValueError:
        errors.append("secp256k1 public key is invalid")
        return None


def _verify_raw_signature(
    public_key: ec.EllipticCurvePublicKey,
    digest: bytes,
    signature: str,
    message: str,
    errors: list[str],
) -> None:
    raw = bytes.fromhex(signature[2:])
    r = int.from_bytes(raw[:32], "big")
    s = int.from_bytes(raw[32:64], "big")
    der = utils.encode_dss_signature(r, s)
    try:
        public_key.verify(der, digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    except (InvalidSignature, ValueError):
        errors.append(message)
