"""Strict, versioned contracts shared by the gateway, policy service, and signer."""
from __future__ import annotations

import hashlib
import re
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Annotated, Literal, Union

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator, model_validator

from .canonical import canonical_json, uuid7

Hex32 = Annotated[str, StringConstraints(pattern=r"^0x[0-9a-f]{64}$")]
Address = Annotated[str, StringConstraints(pattern=r"^0x[0-9a-fA-F]{40}$")]
AssetId = Annotated[str, StringConstraints(pattern=r"^[A-Z][A-Z0-9._:-]{1,63}$")]
Selector = Annotated[str, StringConstraints(pattern=r"^0x[0-9a-fA-F]{8}$")]
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


IntentV1 = Annotated[Union[TransferIntentV1, SwapIntentV1], Field(discriminator="kind")]


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

    @field_validator("proposal_id")
    @classmethod
    def require_uuid7(cls, value: uuid.UUID) -> uuid.UUID:
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
        return value.astimezone(timezone.utc)

    @model_validator(mode="after")
    def deadline_must_be_future(self) -> "ProposalV1":
        if self.deadline <= datetime.now(timezone.utc):
            raise ValueError("deadline must be in the future")
        return self

    def canonical_payload(self) -> bytes:
        data = self.model_dump(mode="json", exclude_none=True)
        return canonical_json(data)

    def proposal_hash(self) -> str:
        return "0x" + hashlib.sha256(self.canonical_payload()).hexdigest()


class DecisionVerdict(str, Enum):
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

    @field_validator("reason_codes", mode="before")
    @classmethod
    def accept_reason_array(cls, value):
        if not isinstance(value, (list, tuple)):
            raise TypeError("reason_codes must be an array")
        return tuple(value)

    @field_validator("expires_at")
    @classmethod
    def normalize_expiry(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("expires_at must include a UTC offset")
        return value.astimezone(timezone.utc)

    @model_validator(mode="after")
    def reservation_matches_verdict(self) -> "DecisionTokenV1":
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
    wallet: Address
    wallet_nonce: Annotated[int, Field(ge=0)]
    chain_id: Annotated[int, Field(gt=0)]
    decision_id: uuid.UUID
    signer_identity: Annotated[str, StringConstraints(min_length=1, max_length=256)]
    enclave_evidence: dict[str, str]
    signature: Annotated[str, StringConstraints(pattern=r"^0x[0-9a-f]{130}$")]


class LifecycleState(str, Enum):
    PROPOSED = "PROPOSED"
    RESERVED = "RESERVED"
    SIGNED = "SIGNED"
    SUBMITTED = "SUBMITTED"
    SETTLED = "SETTLED"
    DENIED = "DENIED"
    REVERTED = "REVERTED"
    EXPIRED = "EXPIRED"


_ALLOWED_TRANSITIONS = {
    LifecycleState.PROPOSED: {LifecycleState.RESERVED, LifecycleState.DENIED, LifecycleState.EXPIRED},
    LifecycleState.RESERVED: {LifecycleState.SIGNED, LifecycleState.EXPIRED},
    LifecycleState.SIGNED: {LifecycleState.SUBMITTED, LifecycleState.EXPIRED},
    LifecycleState.SUBMITTED: {LifecycleState.SETTLED, LifecycleState.REVERTED},
}


def require_transition(current: LifecycleState, target: LifecycleState) -> None:
    if target not in _ALLOWED_TRANSITIONS.get(current, set()):
        raise ValueError(f"invalid lifecycle transition: {current.value} -> {target.value}")
