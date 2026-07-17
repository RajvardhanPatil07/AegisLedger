from datetime import datetime, timedelta, timezone

import pytest

from aegisledger.mandates import (
    CartMandateV1,
    IntentMandateV1,
    MandateError,
    MandateLedger,
    MandateSigner,
)
from aegisledger.contracts import ProposalV1
from agentwallet.chain.crypto import KeyPair

WALLET = "0x" + "12" * 20
MERCHANT = KeyPair.from_seed("mandate-merchant")
AGENT = KeyPair.from_seed("mandate-agent")
USER = KeyPair.from_seed("mandate-user")


def proposal(key="mandate-proposal", amount=100, chain_id=31337, asset="TUSDC"):
    return ProposalV1.model_validate({
        "schema_version": "aegisledger.proposal.v1",
        "principal_id": AGENT.address,
        "wallet": WALLET,
        "chain_id": chain_id,
        "asset": asset,
        "amount": amount,
        "intent": {"kind": "transfer", "recipient": MERCHANT.address},
        "deadline": datetime.now(timezone.utc) + timedelta(minutes=5),
        "idempotency_key": key,
    })


def intent(maximum=500, nonce="intent-001", **overrides):
    data = {
        "schema_version": "aegisledger.intent_mandate.v1",
        "issuer": USER.address,
        "delegate": AGENT.address,
        "audience": "aegisledger-gateway",
        "chain_ids": [31337],
        "assets": ["TUSDC"],
        "recipients": [MERCHANT.address],
        "maximum_amount": maximum,
        "expires_at": datetime.now(timezone.utc) + timedelta(hours=1),
        "nonce": nonce,
        "parent_mandate_id": None,
        "signature": "",
    }
    data.update(overrides)
    return MandateSigner(USER).sign_intent(IntentMandateV1.model_validate(data))


def cart(mandate, item, nonce="cart-001"):
    unsigned = CartMandateV1.model_validate({
        "schema_version": "aegisledger.cart_mandate.v1",
        "merchant": MERCHANT.address,
        "mandate_id": mandate.mandate_id,
        "intent_hash": mandate.intent_hash(),
        "proposal_hash": item.proposal_hash(),
        "chain_id": item.chain_id,
        "asset": item.asset,
        "amount": item.amount,
        "expires_at": datetime.now(timezone.utc) + timedelta(minutes=10),
        "nonce": nonce,
        "signature": "",
    })
    return MandateSigner(MERCHANT).sign_cart(unsigned)


def registered(mandate=None):
    ledger = MandateLedger()
    mandate = mandate or intent()
    ledger.register(mandate, USER.pub)
    return ledger, mandate


def test_cart_is_single_use_and_bound_to_exact_proposal():
    ledger, mandate = registered()
    item = proposal()
    authorization = cart(mandate, item)
    ledger.consume(item, authorization, MERCHANT.pub, audience="aegisledger-gateway")
    with pytest.raises(MandateError, match="replay"):
        ledger.consume(item, authorization, MERCHANT.pub, audience="aegisledger-gateway")

    different = proposal(key="different-proposal", amount=101)
    with pytest.raises(MandateError, match="proposal"):
        ledger.consume(different, cart(mandate, item, nonce="cart-002"), MERCHANT.pub,
                       audience="aegisledger-gateway")


def test_mandate_scope_binds_audience_chain_asset_recipient_and_delegate():
    ledger, mandate = registered()
    item = proposal()
    authorization = cart(mandate, item)
    with pytest.raises(MandateError, match="audience"):
        ledger.consume(item, authorization, MERCHANT.pub, audience="other-service")

    wrong_chain = proposal(key="wrong-chain", chain_id=1)
    with pytest.raises(MandateError, match="chain"):
        ledger.consume(wrong_chain, cart(mandate, wrong_chain, "cart-chain"), MERCHANT.pub,
                       audience="aegisledger-gateway")

    wrong_asset = proposal(key="wrong-asset", asset="OTHER")
    with pytest.raises(MandateError, match="asset"):
        ledger.consume(wrong_asset, cart(mandate, wrong_asset, "cart-asset"), MERCHANT.pub,
                       audience="aegisledger-gateway")


def test_revoked_mandate_and_independent_budgets_fail_closed():
    first = intent(maximum=100, nonce="intent-first")
    second = intent(maximum=100, nonce="intent-second")
    ledger = MandateLedger()
    ledger.register(first, USER.pub)
    ledger.register(second, USER.pub)
    first_item = proposal(key="first-budget", amount=100)
    ledger.consume(first_item, cart(first, first_item, "cart-first"), MERCHANT.pub,
                   audience="aegisledger-gateway")

    second_item = proposal(key="second-budget", amount=100)
    ledger.consume(second_item, cart(second, second_item, "cart-second"), MERCHANT.pub,
                   audience="aegisledger-gateway")
    assert ledger.consumed(first.mandate_id) == ledger.consumed(second.mandate_id) == 100

    ledger.revoke(second.mandate_id, actor=USER.address)
    with pytest.raises(MandateError, match="revoked"):
        ledger.consume(
            proposal(key="after-revoke", amount=1),
            cart(second, proposal(key="after-revoke", amount=1), "cart-revoked"),
            MERCHANT.pub,
            audience="aegisledger-gateway",
        )


def test_delegation_can_only_attenuate_parent_permissions():
    parent = intent(maximum=500, nonce="parent-intent", delegate=AGENT.address)
    ledger, _ = registered(parent)
    child_signer = MandateSigner(AGENT)
    child = IntentMandateV1.model_validate({
        **parent.model_dump(mode="python"),
        "mandate_id": None,
        "issuer": AGENT.address,
        "delegate": "sub-agent",
        "maximum_amount": 200,
        "parent_mandate_id": parent.mandate_id,
        "nonce": "child-intent",
        "signature": "",
    })
    ledger.register(child_signer.sign_intent(child), AGENT.pub)

    widened = child.model_copy(update={"maximum_amount": 600, "nonce": "widened", "signature": ""})
    with pytest.raises(MandateError, match="attenuate"):
        ledger.register(child_signer.sign_intent(widened), AGENT.pub)
