"""Strict, versioned contracts shared by the gateway, policy service, and signer."""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from .canonical import canonical_json, uuid7

Hex32 = Annotated[str, StringConstraints(pattern=r"^0x[0-9a-f]{64}$")]
Address = Annotated[str, StringConstraints(pattern=r"^0x[0-9a-fA-F]{40}$")]
AssetId = Annotated[str, StringConstraints(pattern=r"^[A-Z][A-Z0-9._:-]{1,63}$")]
Selector = Annotated[str, StringConstraints(pattern=r"^0x[0-9a-fA-F]{8}$")]
HexData = Annotated[str, StringConstraints(pattern=r"^0x(?:[0-9a-fA-F]{2})+$")]
IdempotencyKey = Annotated[str, StringConstraints(min_length=8, max_length=128)]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class TransferIntentV1(StrictModel):
    kind: Literal["transfer"]
    recipient: Address

    @field_validator("recipient")
    @classmethod
    def normalize_recipient(cls, value: str) -> str:
        return value.lower()


class SwapIntentV1(StrictModel):
    kind: Literal["swap"]
    contract: Address
    selector: Selector
    calldata: Annotated[str, StringConstraints(pattern=r"^0x(?:[0-9a-fA-F]{2})*$")]
    minimum_output: Annotated[int, Field(ge=0)]
    output_asset: AssetId

    @field_validator("contract")
    @classmethod
    def normalize_contract(cls, value: str) -> str:
        return value.lower()

    @field_validator("selector", "calldata")
    @classmethod
    def normalize_hex(cls, value: str) -> str:
        return value.lower()


IntentV1 = Annotated[TransferIntentV1 | SwapIntentV1, Field(discriminator="kind")]


class ProposalV1(StrictModel):
    schema_version: Literal["aegisledger.proposal.v1"]
    proposal_id: uuid.UUID = Field(default_factory=uuid7)
    principal_id: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    wallet: Address
    chain_id: Annotated[int, Field(gt=0)]
    asset: AssetId
    amount: Annotated[int, Field(gt=0)]
    intent: IntentV1
    deadline: datetime
    idempotency_key: IdempotencyKey
    mandate_id: uuid.UUID | None = None
    quote_reference: Annotated[str, StringConstraints(min_length=1, max_length=256)] | None = None

    @field_validator("proposal_id", mode="before")
    @classmethod
    def require_uuid7(cls, value: object) -> uuid.UUID:
        if isinstance(value, str):
            value = uuid.UUID(value)
        if not isinstance(value, uuid.UUID):
            raise TypeError("proposal_id must be a UUID")
        if value.version != 7:
            raise ValueError("proposal_id must be UUIDv7")
        return value

    @field_validator("wallet")
    @classmethod
    def normalize_wallet(cls, value: str) -> str:
        return value.lower()

    @field_validator("deadline", mode="before")
    @classmethod
    def parse_iso_deadline(cls, value):
        if isinstance(value, str):
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        return value

    @field_validator("deadline")
    @classmethod
    def require_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("deadline must include a UTC offset")
        return value.astimezone(UTC)

    def canonical_payload(self) -> bytes:
        data = self.model_dump(mode="json", exclude_none=True)
        return canonical_json(data)

    def proposal_hash(self) -> str:
        return "0x" + hashlib.sha256(self.canonical_payload()).hexdigest()


class DecisionVerdict(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"


class DecisionTokenV1(StrictModel):
    schema_version: Literal["aegisledger.decision.v1"]
    decision_id: uuid.UUID = Field(default_factory=uuid7)
    proposal_hash: Hex32
    policy_version_id: uuid.UUID
    policy_hash: Hex32
    state_version: Annotated[int, Field(ge=0)]
    reservation_id: uuid.UUID | None
    verdict: DecisionVerdict
    reason_codes: tuple[Annotated[str, StringConstraints(pattern=r"^[A-Z][A-Z0-9_]{1,63}$")], ...]
    expires_at: datetime
    decision_nonce: uuid.UUID = Field(default_factory=uuid7)
    policy_signer: Annotated[str, StringConstraints(min_length=1, max_length=256)]
    signature: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{128}$")]

    @field_validator(
        "decision_id",
        "policy_version_id",
        "reservation_id",
        "decision_nonce",
        mode="before",
    )
    @classmethod
    def parse_identifiers(cls, value: object) -> uuid.UUID | None:
        if value is None or isinstance(value, uuid.UUID):
            return value
        if isinstance(value, str):
            return uuid.UUID(value)
        raise TypeError("identifier must be a UUID string")

    @field_validator("reason_codes", mode="before")
    @classmethod
    def accept_reason_array(cls, value):
        if not isinstance(value, (list, tuple)):
            raise TypeError("reason_codes must be an array")
        return tuple(value)

    @field_validator("verdict", mode="before")
    @classmethod
    def parse_verdict(cls, value: object) -> DecisionVerdict:
        if isinstance(value, DecisionVerdict):
            return value
        if isinstance(value, str):
            return DecisionVerdict(value)
        raise TypeError("verdict must be ALLOW or DENY")

    @field_validator("expires_at", mode="before")
    @classmethod
    def normalize_expiry(cls, value: object) -> datetime:
        if isinstance(value, str):
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if not isinstance(value, datetime):
            raise TypeError("expires_at must be an ISO 8601 timestamp")
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("expires_at must include a UTC offset")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def reservation_matches_verdict(self) -> DecisionTokenV1:
        if self.verdict is DecisionVerdict.ALLOW and self.reservation_id is None:
            raise ValueError("ALLOW decisions require a reservation")
        if self.verdict is DecisionVerdict.DENY and self.reservation_id is not None:
            raise ValueError("DENY decisions cannot carry a reservation")
        return self


class SignedTransactionV1(StrictModel):
    schema_version: Literal["aegisledger.signed_transaction.v1"]
    transaction_id: uuid.UUID = Field(default_factory=uuid7)
    eip712_hash: Hex32
    eip1559_hash: Hex32
    transaction_hash: Hex32
    raw_transaction: HexData
    wallet: Address
    wallet_nonce: Annotated[int, Field(ge=0)]
    chain_id: Annotated[int, Field(gt=0)]
    decision_id: uuid.UUID
    signer_identity: Annotated[str, StringConstraints(min_length=1, max_length=256)]
    enclave_evidence: dict[str, object]
    signature: Annotated[str, StringConstraints(pattern=r"^0x[0-9a-f]{130}$")]

    @field_validator("transaction_id", "decision_id", mode="before")
    @classmethod
    def parse_identifiers(cls, value: object) -> uuid.UUID:
        if isinstance(value, uuid.UUID):
            return value
        if isinstance(value, str):
            return uuid.UUID(value)
        raise TypeError("identifier must be a UUID string")


class LifecycleState(StrEnum):
    PROPOSED = "PROPOSED"
    RESERVED = "RESERVED"
    SIGNED = "SIGNED"
    SUBMITTED = "SUBMITTED"
    SETTLED = "SETTLED"
    DENIED = "DENIED"
    REVERTED = "REVERTED"
    EXPIRED = "EXPIRED"


_ALLOWED_TRANSITIONS = {
    LifecycleState.PROPOSED: {
        LifecycleState.RESERVED,
        LifecycleState.DENIED,
        LifecycleState.EXPIRED,
    },
    LifecycleState.RESERVED: {LifecycleState.SIGNED, LifecycleState.EXPIRED},
    LifecycleState.SIGNED: {LifecycleState.SUBMITTED, LifecycleState.EXPIRED},
    LifecycleState.SUBMITTED: {LifecycleState.SETTLED, LifecycleState.REVERTED},
}


def require_transition(current: LifecycleState, target: LifecycleState) -> None:
    if target not in _ALLOWED_TRANSITIONS.get(current, set()):
        raise ValueError(f"invalid lifecycle transition: {current.value} -> {target.value}")
