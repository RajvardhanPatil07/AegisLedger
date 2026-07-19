import asyncio
import uuid
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from aegisledger.agents import (
    JsonHttpModelProvider,
    ModelProposalAdapter,
    ModelRequestV1,
    ScriptedModelProvider,
)
from aegisledger.mandates import CartMandateV1
from aegisledger.protocols import (
    DelegatedMandateAdapter,
    DelegatedMandateRequestV1,
    X402Adapter,
    X402PaymentRequestV1,
)

WALLET = "0x" + "12" * 20
MERCHANT = "0x" + "34" * 20


def proposal_document(key="provider-proposal"):
    return {
        "schema_version": "aegisledger.proposal.v1",
        "principal_id": "researcher",
        "wallet": WALLET,
        "chain_id": 31337,
        "asset": "TUSDC",
        "amount": 25,
        "intent": {"kind": "transfer", "recipient": MERCHANT},
        "deadline": datetime.now(UTC) + timedelta(minutes=5),
        "idempotency_key": key,
    }


def request():
    return ModelRequestV1.model_validate(
        {
            "schema_version": "aegisledger.model_request.v1",
            "request_id": "research-request-001",
            "principal_id": "researcher",
            "wallet": WALLET,
            "chain_id": 31337,
            "allowed_assets": ["TUSDC"],
            "task": "Pay the approved research merchant 25 base units",
            "context": {"merchant": MERCHANT},
        }
    )


def test_scripted_and_live_model_adapters_emit_only_strict_proposals():
    submitted = []
    adapter = ModelProposalAdapter(ScriptedModelProvider([proposal_document()]), submitted.append)
    result = asyncio.run(adapter.execute(request()))
    assert result == submitted[0]
    assert result.wallet == WALLET
    assert not hasattr(adapter, "signer")
    assert not hasattr(adapter, "chain")

    invalid = proposal_document("invalid-provider-proposal")
    invalid["unexpected"] = True
    with pytest.raises(ValueError):
        asyncio.run(
            ModelProposalAdapter(ScriptedModelProvider([invalid]), submitted.append).execute(
                request()
            )
        )


def test_json_http_model_provider_validates_remote_output():
    def handler(incoming: httpx.Request) -> httpx.Response:
        assert incoming.url.path == "/model/propose"
        document = proposal_document("live-provider-001")
        document["deadline"] = document["deadline"].isoformat()
        return httpx.Response(200, json={"proposal": document})

    client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), base_url="https://model.test"
    )
    provider = JsonHttpModelProvider(client, endpoint="/model/propose")
    submitted = []
    result = asyncio.run(ModelProposalAdapter(provider, submitted.append).execute(request()))
    asyncio.run(client.aclose())
    assert result.idempotency_key == "live-provider-001"


def test_x402_request_maps_to_same_proposal_gateway():
    submitted = []
    adapter = X402Adapter(submitted.append)
    payment = X402PaymentRequestV1.model_validate(
        {
            "schema_version": "aegisledger.x402_payment.v1",
            "scheme": "exact",
            "chain_id": 31337,
            "asset": "TUSDC",
            "amount": 25,
            "pay_to": MERCHANT,
            "resource": "https://merchant.test/data",
            "nonce": "payment-nonce-001",
            "expires_at": datetime.now(UTC) + timedelta(minutes=5),
        }
    )
    result = adapter.authorize(payment, principal_id="researcher", wallet=WALLET)
    assert result == submitted[0]
    assert result.quote_reference == "https://merchant.test/data"
    assert result.intent.recipient == MERCHANT


def test_delegated_request_rejects_cross_proposal_cart_before_gateway():
    submitted = []
    base = proposal_document("delegated-payment-001")
    from aegisledger.contracts import ProposalV1

    proposal = ProposalV1.model_validate(base)
    cart = CartMandateV1.model_validate(
        {
            "schema_version": "aegisledger.cart_mandate.v1",
            "merchant": MERCHANT,
            "mandate_id": uuid.UUID("01941f29-7c00-7000-8000-000000000001"),
            "intent_hash": "0x" + "11" * 32,
            "proposal_hash": "0x" + "22" * 32,
            "chain_id": 31337,
            "asset": "TUSDC",
            "amount": 25,
            "expires_at": datetime.now(UTC) + timedelta(minutes=5),
            "nonce": "cart-nonce-001",
            "signature": "00" * 64,
        }
    )
    delegated = DelegatedMandateRequestV1(
        schema_version="aegisledger.delegated_request.v1",
        proposal=proposal,
        cart=cart,
    )
    with pytest.raises(ValueError, match="different proposal"):
        DelegatedMandateAdapter(submitted.append).authorize(delegated)
    assert submitted == []
