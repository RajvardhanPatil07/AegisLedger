from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import pytest

from aegisledger.contracts import LifecycleState, ProposalV1
from aegisledger.policy import PolicyV1
from aegisledger.state import MemoryStateStore

WALLET = "0x" + "12" * 20
RECIPIENT = "0x" + "34" * 20


def make_policy(cap=100):
    return PolicyV1.model_validate({
        "schema_version": "aegisledger.policy.v1",
        "name": "atomic-spend-policy",
        "default_action": "deny",
        "enabled_wallets": [WALLET],
        "enabled_principals": ["principal"],
        "enabled_chains": [31337],
        "enabled_assets": ["TUSDC"],
        "allowed_recipients": [RECIPIENT],
        "contract_rules": [],
        "per_transaction_cap": cap,
        "rolling_caps": [{"window_seconds": 3600, "amount": cap}],
        "maximum_transactions_per_hour": 10,
        "mandate_required_above": cap,
        "risk": {
            "maximum_slippage_bps": 50,
            "maximum_quote_age_seconds": 30,
            "deny_on_missing_quote": True,
        },
        "emergency_stop": False,
    })


def make_proposal(key: str, amount=60):
    return ProposalV1.model_validate({
        "schema_version": "aegisledger.proposal.v1",
        "principal_id": "principal",
        "wallet": WALLET,
        "chain_id": 31337,
        "asset": "TUSDC",
        "amount": amount,
        "intent": {"kind": "transfer", "recipient": RECIPIENT},
        "deadline": datetime.now(timezone.utc) + timedelta(minutes=5),
        "idempotency_key": key,
    })


def test_concurrent_reservations_cannot_exceed_rolling_cap():
    store = MemoryStateStore()
    policy = make_policy()
    proposals = [make_proposal(f"parallel-{index:02d}") for index in range(8)]
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda item: store.reserve(item, policy), proposals))
    assert sum(result.record.state is LifecycleState.RESERVED for result in results) == 1
    assert sum(result.record.state is LifecycleState.DENIED for result in results) == 7
    assert store.budget_totals("principal", WALLET, 31337, "TUSDC") == (60, 0)


def test_principal_idempotency_key_returns_original_result():
    store = MemoryStateStore()
    first = store.reserve(make_proposal("same-request"), make_policy())
    duplicate = store.reserve(make_proposal("same-request"), make_policy())
    assert first.created
    assert not duplicate.created
    assert duplicate.record.proposal.proposal_id == first.record.proposal.proposal_id


def test_revert_releases_pending_budget_without_counting_settled():
    store = MemoryStateStore()
    reserved = store.reserve(make_proposal("will-revert"), make_policy()).record
    store.transition(reserved.proposal.proposal_id, LifecycleState.SIGNED)
    store.transition(reserved.proposal.proposal_id, LifecycleState.SUBMITTED)
    store.transition(reserved.proposal.proposal_id, LifecycleState.REVERTED)
    assert store.budget_totals("principal", WALLET, 31337, "TUSDC") == (0, 0)
    retry = store.reserve(make_proposal("after-revert"), make_policy()).record
    assert retry.state is LifecycleState.RESERVED


def test_wallet_and_decision_nonce_uniqueness():
    store = MemoryStateStore()
    proposal = make_proposal("nonce-test")
    store.register_decision_nonce(proposal.proposal_id)
    with pytest.raises(ValueError, match="decision nonce"):
        store.register_decision_nonce(proposal.proposal_id)
    store.register_wallet_nonce(WALLET, 31337, 0)
    with pytest.raises(ValueError, match="wallet nonce"):
        store.register_wallet_nonce(WALLET, 31337, 0)
