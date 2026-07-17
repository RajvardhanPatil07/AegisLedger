"""AP2 mandate chain verification inside the policy engine."""

from agentwallet.chain.crypto import KeyPair
from agentwallet.guard.engine import Proposal
from agentwallet.payments.mandates import CartMandate, IntentMandate
from agentwallet.testbed import DefenseMode, Testbed

TOTAL = 205_000_000


def build(tb):
    user = KeyPair.from_seed("user-owner")
    merchant = KeyPair.from_seed("vendor-merchant")
    intent = IntentMandate(
        user=user.address,
        agent=f"agent::{tb.seed}",
        max_total=300_000_000,
        allowed_merchants=[merchant.address],
        expires_at=tb.clock + 3600,
        nonce="i1",
    ).sign(user)
    cart = CartMandate(
        merchant=merchant.address,
        intent_hash=intent.hash(),
        items=["dataset-q3"],
        total=TOTAL,
        expires_at=tb.clock + 3600,
    ).sign(merchant)
    return user, merchant, intent, cart


def proposal(tb, amount=TOTAL, to=None):
    to = to or KeyPair.from_seed("vendor-merchant").address
    return Proposal(
        kind="transfer", amount=amount, to=to, purpose="buy", meta={"agent": f"agent::{tb.seed}"}
    )


def test_valid_chain_allows():
    tb = Testbed(mode=DefenseMode.GUARD_STRICT, seed="m1")
    user, merchant, intent, cart = build(tb)
    v = tb.guard.engine.evaluate(
        proposal(tb), mandate_chain=(intent, cart, {"user": user.pub, "merchant": merchant.pub})
    )
    assert v.allow, v.reasons


def test_amount_above_threshold_without_chain_denied():
    tb = Testbed(mode=DefenseMode.GUARD_STRICT, seed="m2")
    v = tb.guard.engine.evaluate(proposal(tb))
    assert not v.allow and any("mandate" in r for r in v.reasons)


def test_forged_intent_signature_denied():
    tb = Testbed(mode=DefenseMode.GUARD_STRICT, seed="m3")
    user, merchant, intent, cart = build(tb)
    impostor = KeyPair.from_seed("impostor")
    intent.signature_hex = impostor.sign(intent.digest()).hex()
    v = tb.guard.engine.evaluate(
        proposal(tb), mandate_chain=(intent, cart, {"user": user.pub, "merchant": merchant.pub})
    )
    assert not v.allow and any("intent signature" in r for r in v.reasons)


def test_cart_not_bound_to_intent_denied():
    tb = Testbed(mode=DefenseMode.GUARD_STRICT, seed="m4")
    user, merchant, intent, cart = build(tb)
    cart.intent_hash = "0" * 64
    cart.sign(merchant)  # re-sign the tampered cart: chain link still broken
    v = tb.guard.engine.evaluate(
        proposal(tb), mandate_chain=(intent, cart, {"user": user.pub, "merchant": merchant.pub})
    )
    assert not v.allow and any("not bound" in r for r in v.reasons)


def test_amount_mismatch_with_cart_denied():
    tb = Testbed(mode=DefenseMode.GUARD_STRICT, seed="m5")
    user, merchant, intent, cart = build(tb)
    v = tb.guard.engine.evaluate(
        proposal(tb, amount=TOTAL + 1),
        mandate_chain=(intent, cart, {"user": user.pub, "merchant": merchant.pub}),
    )
    assert not v.allow and any("cart total" in r for r in v.reasons)


def test_intent_budget_exceeded_denied():
    tb = Testbed(mode=DefenseMode.GUARD_STRICT, seed="m6")
    user, merchant, intent, cart = build(tb)
    intent.max_total = 100_000_000  # below cart total
    intent.sign(user)
    cart = CartMandate(
        merchant=merchant.address,
        intent_hash=intent.hash(),
        items=["dataset-q3"],
        total=TOTAL,
        expires_at=tb.clock + 3600,
    ).sign(merchant)
    v = tb.guard.engine.evaluate(
        proposal(tb), mandate_chain=(intent, cart, {"user": user.pub, "merchant": merchant.pub})
    )
    assert not v.allow and any("budget" in r for r in v.reasons)


def test_expired_intent_denied():
    tb = Testbed(mode=DefenseMode.GUARD_STRICT, seed="m7")
    user, merchant, intent, cart = build(tb)
    intent.expires_at = tb.clock - 1
    intent.sign(user)
    cart = CartMandate(
        merchant=merchant.address,
        intent_hash=intent.hash(),
        items=["x"],
        total=TOTAL,
        expires_at=tb.clock + 3600,
    ).sign(merchant)
    v = tb.guard.engine.evaluate(
        proposal(tb), mandate_chain=(intent, cart, {"user": user.pub, "merchant": merchant.pub})
    )
    assert not v.allow and any("expired" in r for r in v.reasons)
