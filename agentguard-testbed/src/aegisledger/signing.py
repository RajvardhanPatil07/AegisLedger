"""Reference authorization checks enforced again inside the isolated signer."""

from __future__ import annotations

import threading
import uuid
from datetime import UTC, datetime
from typing import Annotated, Literal

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from eth_hash.auto import keccak
from pydantic import Field, StringConstraints, field_validator, model_validator

from agentwallet.chain.crypto import address_of

from .contracts import (
    Address,
    AssetId,
    DecisionTokenV1,
    DecisionVerdict,
    Hex32,
    ProposalV1,
    StrictModel,
)
from .decisions import verify_decision_token

HexData = Annotated[str, StringConstraints(pattern=r"^0x(?:[0-9a-fA-F]{2})+$")]


def keccak_hex(value: str) -> str:
    return "0x" + keccak(bytes.fromhex(value[2:])).hex()


class TransactionBindingV1(StrictModel):
    operation: Literal["transfer", "swap"]
    wallet: Address
    chain_id: Annotated[int, Field(gt=0)]
    wallet_nonce: Annotated[int, Field(ge=0)]
    asset: AssetId
    amount: Annotated[int, Field(gt=0)]
    recipient: Address | None
    contract: Address | None
    selector: Annotated[str, StringConstraints(pattern=r"^0x[0-9a-fA-F]{8}$")] | None
    calldata: Annotated[str, StringConstraints(pattern=r"^0x(?:[0-9a-fA-F]{2})*$")]
    value: Annotated[int, Field(ge=0)]
    gas_limit: Annotated[int, Field(gt=0)]
    max_fee_per_gas: Annotated[int, Field(gt=0)]
    max_priority_fee_per_gas: Annotated[int, Field(ge=0)]

    @field_validator("wallet", "recipient", "contract")
    @classmethod
    def normalize_address(cls, value):
        return value.lower() if value is not None else None

    @field_validator("selector", "calldata")
    @classmethod
    def normalize_hex(cls, value):
        return value.lower() if value is not None else None

    @model_validator(mode="after")
    def validate_operation_shape(self) -> TransactionBindingV1:
        if self.operation == "transfer":
            if self.recipient is None or self.contract is not None or self.selector is not None:
                raise ValueError("transfer binding requires only a recipient")
        elif self.contract is None or self.selector is None or self.recipient is not None:
            raise ValueError("swap binding requires a contract and selector")
        if self.max_priority_fee_per_gas > self.max_fee_per_gas:
            raise ValueError("priority fee cannot exceed maximum fee")
        return self


class TransactionSignRequestV1(StrictModel):
    schema_version: Literal["aegisledger.sign_request.v1"]
    proposal: ProposalV1
    decision: DecisionTokenV1
    reservation_id: uuid.UUID
    wallet_nonce: Annotated[int, Field(ge=0)]
    chain_id: Annotated[int, Field(gt=0)]
    transaction: TransactionBindingV1
    eip712_payload: HexData
    eip1559_unsigned_payload: HexData
    eip712_hash: Hex32
    eip1559_hash: Hex32
    expires_at: datetime

    @field_validator("eip712_payload", "eip1559_unsigned_payload")
    @classmethod
    def normalize_payload(cls, value: str) -> str:
        return value.lower()

    @field_validator("expires_at")
    @classmethod
    def normalize_expiry(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("expires_at must include a UTC offset")
        return value.astimezone(UTC)


class SignerAuthorizationError(PermissionError):
    pass


class SignerAuthorizationGate:
    """Fail-closed signer gate; consumes decision and wallet nonces atomically."""

    def __init__(
        self,
        policy_public_key: Ed25519PublicKey,
        allowed_chain_ids: set[int],
        allowed_policy_hashes: set[str] | None = None,
    ) -> None:
        self._policy_public_key = policy_public_key
        self._allowed_chain_ids = frozenset(allowed_chain_ids)
        self._allowed_policy_hashes = (
            frozenset(item.lower() for item in allowed_policy_hashes)
            if allowed_policy_hashes is not None
            else None
        )
        self._used_decisions: set[uuid.UUID] = set()
        self._next_wallet_nonce: dict[tuple[str, int], int] = {}
        self._lock = threading.RLock()

    def validate_and_consume(
        self,
        request: TransactionSignRequestV1,
        *,
        now: datetime | None = None,
    ) -> None:
        current_time = now or datetime.now(UTC)
        with self._lock:
            self._validate(request, current_time)
            self._used_decisions.add(request.decision.decision_nonce)
            key = (request.proposal.wallet, request.chain_id)
            self._next_wallet_nonce[key] = request.wallet_nonce + 1

    def _validate(self, request: TransactionSignRequestV1, current_time: datetime) -> None:
        decision = request.decision
        proposal = request.proposal
        transaction = request.transaction

        if request.expires_at <= current_time:
            raise SignerAuthorizationError("sign request expired")
        if not verify_decision_token(decision, self._policy_public_key, now=current_time):
            raise SignerAuthorizationError("decision signature invalid or expired")
        if decision.policy_signer.lower() != address_of(self._policy_public_key).lower():
            raise SignerAuthorizationError("decision signer identity mismatch")
        if decision.verdict is not DecisionVerdict.ALLOW:
            raise SignerAuthorizationError("decision does not authorize signing")
        if (
            self._allowed_policy_hashes is not None
            and decision.policy_hash.lower() not in self._allowed_policy_hashes
        ):
            raise SignerAuthorizationError("policy version is not approved by signer")
        if proposal.proposal_hash() != decision.proposal_hash:
            raise SignerAuthorizationError("proposal hash does not match decision")
        if request.reservation_id != decision.reservation_id:
            raise SignerAuthorizationError("reservation does not match decision")
        if request.chain_id not in self._allowed_chain_ids:
            raise SignerAuthorizationError("chain is not enabled in signer")
        if request.chain_id != proposal.chain_id or transaction.chain_id != request.chain_id:
            raise SignerAuthorizationError("chain binding mismatch")
        if transaction.wallet != proposal.wallet:
            raise SignerAuthorizationError("wallet binding mismatch")
        if transaction.wallet_nonce != request.wallet_nonce:
            raise SignerAuthorizationError("wallet nonce binding mismatch")
        if request.expires_at > decision.expires_at or request.expires_at > proposal.deadline:
            raise SignerAuthorizationError("sign request outlives authorization")
        if decision.decision_nonce in self._used_decisions:
            raise SignerAuthorizationError("decision replay detected")

        key = (proposal.wallet, request.chain_id)
        expected_nonce = self._next_wallet_nonce.get(key, 0)
        if request.wallet_nonce != expected_nonce:
            raise SignerAuthorizationError(
                f"wallet nonce must be {expected_nonce}, received {request.wallet_nonce}"
            )
        if not request.eip712_payload.startswith("0x1901"):
            raise SignerAuthorizationError("EIP-712 payload must start with 0x1901")
        if not request.eip1559_unsigned_payload.startswith("0x02"):
            raise SignerAuthorizationError("EIP-1559 payload must be a typed transaction")
        if keccak_hex(request.eip712_payload) != request.eip712_hash:
            raise SignerAuthorizationError("EIP-712 hash does not match exact payload")
        if keccak_hex(request.eip1559_unsigned_payload) != request.eip1559_hash:
            raise SignerAuthorizationError("EIP-1559 hash does not match exact payload")

        if transaction.operation != proposal.intent.kind:
            raise SignerAuthorizationError("transaction operation does not match proposal")
        if transaction.asset != proposal.asset:
            raise SignerAuthorizationError("transaction asset does not match proposal")
        if transaction.amount != proposal.amount:
            raise SignerAuthorizationError("transaction amount does not match proposal")
        if proposal.intent.kind == "transfer":
            if transaction.recipient != proposal.intent.recipient:
                raise SignerAuthorizationError("transaction recipient does not match proposal")
        else:
            if transaction.contract != proposal.intent.contract:
                raise SignerAuthorizationError("transaction contract does not match proposal")
            if transaction.selector != proposal.intent.selector:
                raise SignerAuthorizationError("transaction selector does not match proposal")
            if transaction.calldata != proposal.intent.calldata:
                raise SignerAuthorizationError("transaction calldata does not match proposal")
