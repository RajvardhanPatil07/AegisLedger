"""Signed, attenuating mandates with atomic budget and cart replay protection."""
from __future__ import annotations

import hashlib
import threading
import uuid
from datetime import datetime, timezone
from typing import Annotated, Literal

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import Field, StringConstraints, field_validator

from agentwallet.chain.crypto import KeyPair, address_of, verify

from .canonical import canonical_json, uuid7
from .contracts import Address, AssetId, ProposalV1, StrictModel

SignatureHex = Annotated[str, StringConstraints(pattern=r"^(?:|[0-9a-f]{128})$")]


class IntentMandateV1(StrictModel):
    schema_version: Literal["aegisledger.intent_mandate.v1"]
    mandate_id: uuid.UUID | None = Field(default_factory=uuid7)
    issuer: Address
    delegate: Annotated[str, StringConstraints(min_length=1, max_length=256)]
    audience: Annotated[str, StringConstraints(min_length=1, max_length=256)]
    chain_ids: tuple[Annotated[int, Field(gt=0)], ...]
    assets: tuple[AssetId, ...]
    recipients: tuple[Address, ...]
    maximum_amount: Annotated[int, Field(gt=0)]
    expires_at: datetime
    nonce: Annotated[str, StringConstraints(min_length=6, max_length=128)]
    parent_mandate_id: uuid.UUID | None
    signature: SignatureHex

    @field_validator("chain_ids", "assets", "recipients", mode="before")
    @classmethod
    def accept_json_arrays(cls, values):
        if not isinstance(values, (list, tuple)):
            raise TypeError("mandate scope fields must be arrays")
        return tuple(values)

    @field_validator("issuer")
    @classmethod
    def normalize_issuer(cls, value: str) -> str:
        return value.lower()

    @field_validator("recipients")
    @classmethod
    def normalize_recipients(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(sorted({value.lower() for value in values}))

    @field_validator("chain_ids", "assets")
    @classmethod
    def normalize_scope(cls, values: tuple) -> tuple:
        return tuple(sorted(set(values)))

    @field_validator("expires_at")
    @classmethod
    def normalize_expiry(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("expires_at must include a UTC offset")
        return value.astimezone(timezone.utc)

    def signing_payload(self) -> bytes:
        return canonical_json(self.model_dump(mode="json", exclude={"signature"}))

    def intent_hash(self) -> str:
        return "0x" + hashlib.sha256(self.signing_payload()).hexdigest()


class CartMandateV1(StrictModel):
    schema_version: Literal["aegisledger.cart_mandate.v1"]
    cart_id: uuid.UUID | None = Field(default_factory=uuid7)
    merchant: Address
    mandate_id: uuid.UUID
    intent_hash: Annotated[str, StringConstraints(pattern=r"^0x[0-9a-f]{64}$")]
    proposal_hash: Annotated[str, StringConstraints(pattern=r"^0x[0-9a-f]{64}$")]
    chain_id: Annotated[int, Field(gt=0)]
    asset: AssetId
    amount: Annotated[int, Field(gt=0)]
    expires_at: datetime
    nonce: Annotated[str, StringConstraints(min_length=6, max_length=128)]
    signature: SignatureHex

    @field_validator("merchant")
    @classmethod
    def normalize_merchant(cls, value: str) -> str:
        return value.lower()

    @field_validator("expires_at")
    @classmethod
    def normalize_expiry(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("expires_at must include a UTC offset")
        return value.astimezone(timezone.utc)

    def signing_payload(self) -> bytes:
        return canonical_json(self.model_dump(mode="json", exclude={"signature"}))

    def cart_hash(self) -> str:
        return "0x" + hashlib.sha256(self.signing_payload()).hexdigest()


class MandateSigner:
    def __init__(self, keys: KeyPair) -> None:
        self._keys = keys

    def sign_intent(self, mandate: IntentMandateV1) -> IntentMandateV1:
        if mandate.issuer != self._keys.address.lower():
            raise ValueError("intent issuer does not match signing key")
        values = mandate.model_dump(mode="python")
        if values["mandate_id"] is None:
            values["mandate_id"] = uuid7()
        values["signature"] = ""
        unsigned = IntentMandateV1.model_validate(values)
        values["signature"] = self._keys.sign(unsigned.signing_payload()).hex()
        return IntentMandateV1.model_validate(values)

    def sign_cart(self, cart: CartMandateV1) -> CartMandateV1:
        if cart.merchant != self._keys.address.lower():
            raise ValueError("cart merchant does not match signing key")
        values = cart.model_dump(mode="python")
        if values["cart_id"] is None:
            values["cart_id"] = uuid7()
        values["signature"] = ""
        unsigned = CartMandateV1.model_validate(values)
        values["signature"] = self._keys.sign(unsigned.signing_payload()).hex()
        return CartMandateV1.model_validate(values)


class MandateError(PermissionError):
    pass


class MandateLedger:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._mandates: dict[uuid.UUID, IntentMandateV1] = {}
        self._spent: dict[uuid.UUID, int] = {}
        self._revoked: set[uuid.UUID] = set()
        self._intent_nonces: set[tuple[str, str]] = set()
        self._used_cart_hashes: set[str] = set()
        self._used_cart_nonces: set[tuple[str, str]] = set()

    def register(self, mandate: IntentMandateV1, public_key: Ed25519PublicKey) -> None:
        with self._lock:
            if mandate.mandate_id is None:
                raise MandateError("mandate ID is required")
            if address_of(public_key).lower() != mandate.issuer:
                raise MandateError("intent signer does not match issuer")
            if not self._verify_signature(public_key, mandate.signing_payload(), mandate.signature):
                raise MandateError("invalid intent signature")
            if mandate.expires_at <= datetime.now(timezone.utc):
                raise MandateError("mandate expired")
            nonce_key = (mandate.issuer, mandate.nonce)
            if nonce_key in self._intent_nonces:
                raise MandateError("intent nonce replay")
            if mandate.parent_mandate_id is not None:
                parent = self._active(mandate.parent_mandate_id)
                self._require_attenuation(parent, mandate)
            self._mandates[mandate.mandate_id] = mandate
            self._spent[mandate.mandate_id] = 0
            self._intent_nonces.add(nonce_key)

    def revoke(self, mandate_id: uuid.UUID, *, actor: str) -> None:
        with self._lock:
            mandate = self._mandates.get(mandate_id)
            if mandate is None:
                raise MandateError("unknown mandate")
            if actor.lower() != mandate.issuer:
                raise MandateError("only the mandate issuer can revoke")
            self._revoked.add(mandate_id)

    def consumed(self, mandate_id: uuid.UUID) -> int:
        with self._lock:
            return self._spent.get(mandate_id, 0)

    def consume(
        self,
        proposal: ProposalV1,
        cart: CartMandateV1,
        merchant_public_key: Ed25519PublicKey,
        *,
        audience: str,
    ) -> None:
        with self._lock:
            mandate = self._active(cart.mandate_id)
            now = datetime.now(timezone.utc)
            if cart.expires_at <= now:
                raise MandateError("cart expired")
            if address_of(merchant_public_key).lower() != cart.merchant:
                raise MandateError("cart signer does not match merchant")
            if not self._verify_signature(
                merchant_public_key, cart.signing_payload(), cart.signature
            ):
                raise MandateError("invalid cart signature")
            if cart.cart_hash() in self._used_cart_hashes or (
                cart.merchant,
                cart.nonce,
            ) in self._used_cart_nonces:
                raise MandateError("cart replay detected")
            if cart.intent_hash != mandate.intent_hash():
                raise MandateError("cart is bound to a different intent")
            if cart.proposal_hash != proposal.proposal_hash():
                raise MandateError("cart is bound to a different proposal")
            if proposal.mandate_id is not None and proposal.mandate_id != mandate.mandate_id:
                raise MandateError("proposal references a different mandate")
            if audience != mandate.audience:
                raise MandateError("mandate audience mismatch")
            if proposal.principal_id != mandate.delegate:
                raise MandateError("mandate delegate mismatch")
            if proposal.chain_id not in mandate.chain_ids or cart.chain_id != proposal.chain_id:
                raise MandateError("mandate chain mismatch")
            if proposal.asset not in mandate.assets or cart.asset != proposal.asset:
                raise MandateError("mandate asset mismatch")
            if proposal.intent.kind != "transfer":
                raise MandateError("cart mandates currently authorize transfers only")
            if (
                proposal.intent.recipient != cart.merchant
                or proposal.intent.recipient not in mandate.recipients
            ):
                raise MandateError("mandate recipient mismatch")
            if cart.amount != proposal.amount:
                raise MandateError("cart amount does not match proposal")
            spent = self._spent[mandate.mandate_id]
            if spent + proposal.amount > mandate.maximum_amount:
                raise MandateError("mandate budget exceeded")

            self._spent[mandate.mandate_id] = spent + proposal.amount
            self._used_cart_hashes.add(cart.cart_hash())
            self._used_cart_nonces.add((cart.merchant, cart.nonce))

    def _active(self, mandate_id: uuid.UUID) -> IntentMandateV1:
        mandate = self._mandates.get(mandate_id)
        if mandate is None:
            raise MandateError("unknown mandate")
        if mandate_id in self._revoked:
            raise MandateError("mandate revoked")
        if mandate.expires_at <= datetime.now(timezone.utc):
            raise MandateError("mandate expired")
        if mandate.parent_mandate_id is not None:
            self._active(mandate.parent_mandate_id)
        return mandate

    def _require_attenuation(
        self, parent: IntentMandateV1, child: IntentMandateV1
    ) -> None:
        parent_id = parent.mandate_id
        assert parent_id is not None
        remaining = parent.maximum_amount - self._spent[parent_id]
        is_subset = (
            child.issuer == parent.delegate.lower()
            and child.audience == parent.audience
            and set(child.chain_ids).issubset(parent.chain_ids)
            and set(child.assets).issubset(parent.assets)
            and set(child.recipients).issubset(parent.recipients)
            and child.maximum_amount <= remaining
            and child.expires_at <= parent.expires_at
        )
        if not is_subset:
            raise MandateError("delegation must attenuate every parent permission")

    @staticmethod
    def _verify_signature(public_key: Ed25519PublicKey, payload: bytes, signature: str) -> bool:
        try:
            return verify(public_key, payload, bytes.fromhex(signature))
        except ValueError:
            return False

