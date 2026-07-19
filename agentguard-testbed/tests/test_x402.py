"""x402 flow: honest payments settle; forged, replayed, expired, and
guard-denied authorizations fail."""

from agentwallet.payments.x402 import Facilitator, ResourceServer, X402Client
from agentwallet.testbed import DefenseMode, Testbed


def setup(mode=DefenseMode.GUARD_STRICT, evil=False):
    tb = Testbed(mode=mode, seed="x402-test")
    server = ResourceServer(
        address=tb.vendors["data-api"],
        price=2_000_000,
        resource="r1",
        evil=evil,
        attacker_address=tb.attacker,
        now=lambda: tb.clock,
    )
    client = X402Client(payer=tb.wallet, sign_fn=tb.guard.sign_for_x402)
    fac = Facilitator(tb.chain, now=lambda: tb.clock)
    return tb, server, client, fac


def test_honest_payment_settles():
    tb, server, client, fac = setup()
    req = server.respond_402()
    auth = client.create_authorization(req)
    assert auth is not None
    ok, why = fac.settle(auth)
    assert ok, why
    assert tb.balance(tb.vendors["data-api"]) == 2_000_000


def test_replay_rejected():
    tb, server, client, fac = setup()
    auth = client.create_authorization(server.respond_402())
    assert fac.settle(auth)[0]
    ok, why = fac.settle(auth)
    assert not ok and "replay" in why


def test_expired_rejected():
    tb, server, client, fac = setup()
    req = server.respond_402()
    req.expires_at = tb.clock - 1
    auth = client.create_authorization(req)
    ok, why = fac.settle(auth)
    assert not ok and "expired" in why


def test_forged_signature_rejected():
    tb, server, client, fac = setup()
    auth = client.create_authorization(server.respond_402())
    auth.signature_hex = "00" * 64
    ok, _ = fac.settle(auth)
    assert not ok


def test_evil_server_inflated_payment_blocked_by_guard():
    # Evil server charges 10x and redirects to the attacker; strict policy
    # allowlists only vendors, so the guard never signs.
    tb, server, client, fac = setup(evil=True)
    auth = client.create_authorization(server.respond_402())
    assert auth is None  # guard denied -> no authorization exists
    assert tb.balance(tb.attacker) == 2_000_000_000  # unchanged


def test_evil_server_passes_when_undefended():
    tb, server, client, fac = setup(mode=DefenseMode.UNDEFENDED, evil=True)
    auth = client.create_authorization(server.respond_402())
    assert auth is not None
    assert fac.settle(auth)[0]
    assert tb.balance(tb.attacker) > 2_000_000_000
