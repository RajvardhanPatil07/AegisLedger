"""Security self-checks: trust boundaries, tamper evidence, and bypass attempts."""
import pytest

from agentwallet.testbed import Testbed, DefenseMode
from agentwallet.guard.engine import Proposal
from agentwallet.guard.guard import GuardClient
from agentwallet.chain.ledger import Tx, TxKind


class TestTrustBoundaries:
    def test_agent_handle_is_submit_only(self):
        tb = Testbed(mode=DefenseMode.GUARD_STRICT, seed="sec1")
        with pytest.raises(AttributeError):
            _ = tb.client.signer
        with pytest.raises(AttributeError):
            _ = tb.client.engine

    def test_deny_means_no_settlement(self):
        tb = Testbed(mode=DefenseMode.GUARD_STRICT, seed="sec2")
        before = tb.balance(tb.wallet)
        r = tb.client.submit(Proposal(kind="transfer", amount=900_000_000,
                                      to=tb.attacker, purpose="bypass-attempt"))
        assert not r.verdict.allow
        tb.mine()
        assert tb.balance(tb.wallet) == before

    def test_engine_has_no_signing_capability(self):
        tb = Testbed(mode=DefenseMode.GUARD_STRICT, seed="sec3")
        assert not hasattr(tb.guard.engine, "sign")
        assert not hasattr(tb.guard.engine, "_signer")


class TestAuditTamperEvidence:
    def test_audit_chain_valid(self):
        tb = Testbed(mode=DefenseMode.GUARD_STRICT, seed="sec4")
        tb.client.submit(Proposal(kind="transfer", amount=1_000_000,
                                  to=tb.vendors["data-api"], purpose="ok"))
        tb.client.submit(Proposal(kind="transfer", amount=2_000_000,
                                  to=tb.vendors["data-api"], purpose="ok2"))
        assert tb.guard.verify_audit_chain()

    def test_audit_tampering_detected(self):
        tb = Testbed(mode=DefenseMode.GUARD_STRICT, seed="sec5")
        tb.client.submit(Proposal(kind="transfer", amount=1_000_000,
                                  to=tb.vendors["data-api"], purpose="ok"))
        tb.client.submit(Proposal(kind="transfer", amount=2_000_000,
                                  to=tb.vendors["data-api"], purpose="ok2"))
        tb.mine()
        # Attacker rewrites history: mark a settled entry as not settled.
        next(entry for entry in tb.guard.audit if entry.settled).settled = False
        assert not tb.guard.verify_audit_chain()


class TestContractWalletBypassResistance:
    def test_direct_mempool_submission_reverted(self):
        """Host compromise: attacker bypasses the guard entirely and submits a
        raw transaction. On-chain rules still reject it at settlement."""
        tb = Testbed(mode=DefenseMode.CONTRACT_WALLET, seed="sec6")
        attacker_before = tb.balance(tb.attacker)
        tb.compromised_submit(Tx(kind=TxKind.TRANSFER, sender=tb.wallet, to=tb.attacker,
                                 amount=150_000_000, asset="TUSDC"))  # under cap -> allowed
        tb.compromised_submit(Tx(kind=TxKind.TRANSFER, sender=tb.wallet, to=tb.attacker,
                                 amount=900_000_000, asset="TUSDC"))  # over cap -> reverted
        receipts = tb.mine()
        assert receipts[0].success
        assert not receipts[1].success
        assert tb.balance(tb.attacker) - attacker_before == 150_000_000


class TestPolicyParserHardening:
    def test_kill_switch_policy_denies(self):
        from agentwallet.guard.policy import load_policy
        from agentwallet.guard.engine import PolicyEngine
        pol = load_policy("name: k\nkill_switch: true\nper_tx_cap: 999999999\n")
        e = PolicyEngine(pol)
        assert not e.evaluate(Proposal(kind="transfer", amount=1, to="0xaaa")).allow

    def test_x402_nonce_not_reusable_across_flows(self):
        from agentwallet.payments.x402 import Facilitator
        tb = Testbed(mode=DefenseMode.UNDEFENDED, seed="sec7")
        fac = Facilitator(tb.chain, now=lambda: tb.clock)
        fac.used_nonces.add("nonce-x")
        from agentwallet.payments.x402 import PaymentRequirements, PaymentAuthorization
        req = PaymentRequirements(scheme="exact", network="local-test", asset="TUSDC",
                                  amount=1, pay_to="0xaaa", resource="r", nonce="nonce-x",
                                  expires_at=tb.clock + 100)
        auth = PaymentAuthorization(req, tb.wallet, "00" * 32, "00" * 64)
        ok, why = fac.verify(auth)
        assert not ok and "replay" in why
