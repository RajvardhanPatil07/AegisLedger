"""Versioned payment protocol adapters sharing the proposal authorization path."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Annotated, Literal

from pydantic import Field, StringConstraints, field_validator

from .contracts import Address, AssetId, ProposalV1, StrictModel
from .mandates import CartMandateV1


class X402PaymentRequestV1(StrictModel):
    schema_version: Literal["aegisledger.x402_payment.v1"]
    scheme: Literal["exact", "upto"]
    chain_id: Annotated[int, Field(gt=0)]
    asset: AssetId
    amount: Annotated[int, Field(gt=0)]
    pay_to: Address
    resource: Annotated[str, StringConstraints(pattern=r"^https://[^\s]{1,240}$")]
    nonce: Annotated[str, StringConstraints(min_length=8, max_length=96)]
    expires_at: datetime

    @field_validator("pay_to")
    @classmethod
    def normalize_recipient(cls, value: str) -> str:
        return value.lower()

    @field_validator("expires_at")
    @classmethod
    def normalize_expiry(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("expires_at must include a UTC offset")
        normalized = value.astimezone(UTC)
        if normalized <= datetime.now(UTC):
            raise ValueError("payment request is expired")
        return normalized


class X402Adapter:
    def __init__(self, submit_proposal: Callable[[ProposalV1], object]) -> None:
        self._submit_proposal = submit_proposal

    def authorize(
        self,
        request: X402PaymentRequestV1,
        *,
        principal_id: str,
        wallet: str,
    ) -> ProposalV1:
        proposal = ProposalV1.model_validate(
            {
                "schema_version": "aegisledger.proposal.v1",
                "principal_id": principal_id,
                "wallet": wallet,
                "chain_id": request.chain_id,
                "asset": request.asset,
                "amount": request.amount,
                "intent": {"kind": "transfer", "recipient": request.pay_to},
                "deadline": request.expires_at,
                "idempotency_key": f"x402:{request.nonce}",
                "quote_reference": request.resource,
            }
        )
        self._submit_proposal(proposal)
        return proposal


class DelegatedMandateRequestV1(StrictModel):
    schema_version: Literal["aegisledger.delegated_request.v1"]
    proposal: ProposalV1
    cart: CartMandateV1


class DelegatedMandateAdapter:
    def __init__(self, submit_proposal: Callable[[ProposalV1], object]) -> None:
        self._submit_proposal = submit_proposal

    def authorize(self, request: DelegatedMandateRequestV1) -> ProposalV1:
        proposal = request.proposal
        cart = request.cart
        if cart.proposal_hash != proposal.proposal_hash():
            raise ValueError("cart is bound to a different proposal")
        if proposal.mandate_id != cart.mandate_id:
            raise ValueError("proposal is bound to a different mandate")
        if cart.chain_id != proposal.chain_id or cart.asset != proposal.asset:
            raise ValueError("cart scope does not match proposal scope")
        if cart.amount != proposal.amount:
            raise ValueError("cart amount does not match proposal amount")
        if proposal.intent.kind != "transfer" or proposal.intent.recipient != cart.merchant:
            raise ValueError("cart merchant does not match proposal recipient")
        self._submit_proposal(proposal)
        return proposal
