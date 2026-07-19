from datetime import UTC, datetime, timedelta

import pytest

from aegisledger.contracts import DecisionVerdict, LifecycleState, ProposalV1
from aegisledger.decisions import DecisionIssuer, verify_decision_token
from aegisledger.policies import PolicyRegistry, PolicyStatus
from aegisledger.policy import PolicyV1
from aegisledger.state import MemoryStateStore

WALLET = "0x" + "12" * 20
RECIPIENT = "0x" + "34" * 20


def make_policy() -> PolicyV1:
    return PolicyV1.model_validate(
        {
            "schema_version": "aegisledger.policy.v1",
            "name": "two-person-policy",
            "default_action": "deny",
            "enabled_wallets": [WALLET],
            "enabled_principals": ["researcher"],
            "enabled_chains": [31337],
            "enabled_assets": ["TUSDC"],
            "allowed_recipients": [RECIPIENT],
            "contract_rules": [],
            "per_transaction_cap": 1_000,
            "rolling_caps": [{"window_seconds": 3600, "amount": 5_000}],
            "maximum_transactions_per_hour": 10,
            "mandate_required_above": 500,
            "risk": {
                "maximum_slippage_bps": 50,
                "maximum_quote_age_seconds": 30,
                "deny_on_missing_quote": True,
            },
            "emergency_stop": False,
        }
    )


def make_proposal() -> ProposalV1:
    return ProposalV1.model_validate(
        {
            "schema_version": "aegisledger.proposal.v1",
            "principal_id": "researcher",
            "wallet": WALLET,
            "chain_id": 31337,
            "asset": "TUSDC",
            "amount": 100,
            "intent": {"kind": "transfer", "recipient": RECIPIENT},
            "deadline": datetime.now(UTC) + timedelta(minutes=5),
            "idempotency_key": "signed-decision-001",
        }
    )


def test_policy_activation_requires_two_distinct_administrators():
    registry = PolicyRegistry()
    version = registry.create(make_policy(), created_by="author")
    registry.approve(version.version_id, "admin-a")
    registry.approve(version.version_id, "admin-a")
    with pytest.raises(PermissionError, match="two distinct"):
        registry.activate(version.version_id, activated_by="admin-a")
    registry.approve(version.version_id, "admin-b")
    active = registry.activate(version.version_id, activated_by="admin-a")
    assert active.status is PolicyStatus.ACTIVE
    assert registry.active().version_id == version.version_id


def test_activating_new_policy_retires_previous_version():
    registry = PolicyRegistry()
    first = registry.create(make_policy(), created_by="author")
    for administrator in ("admin-a", "admin-b"):
        registry.approve(first.version_id, administrator)
    registry.activate(first.version_id, activated_by="admin-a")
    second = registry.create(
        make_policy().model_copy(update={"name": "replacement-policy"}),
        created_by="author",
    )
    for administrator in ("admin-b", "admin-c"):
        registry.approve(second.version_id, administrator)
    registry.activate(second.version_id, activated_by="admin-b")
    assert registry.get(first.version_id).status is PolicyStatus.RETIRED
    assert registry.active().version_id == second.version_id


def test_allow_decision_is_signed_and_bound_to_reservation_and_policy():
    registry = PolicyRegistry()
    version = registry.create(make_policy(), created_by="author")
    registry.approve(version.version_id, "admin-a")
    registry.approve(version.version_id, "admin-b")
    version = registry.activate(version.version_id, activated_by="admin-a")
    store = MemoryStateStore()
    record = store.reserve(make_proposal(), version.policy).record
    assert record.state is LifecycleState.RESERVED

    issuer = DecisionIssuer.from_seed("decision-test")
    token = issuer.issue(record, version)

    assert token.verdict is DecisionVerdict.ALLOW
    assert token.reservation_id == record.reservation_id
    assert token.proposal_hash == record.proposal.proposal_hash()
    assert verify_decision_token(token, issuer.public_key)

    mutated = token.model_copy(update={"state_version": token.state_version + 1})
    assert not verify_decision_token(mutated, issuer.public_key)


def test_denied_decision_has_no_reservation():
    registry = PolicyRegistry()
    stopped = make_policy().model_copy(update={"emergency_stop": True, "per_transaction_cap": 0})
    version = registry.create(stopped, created_by="author")
    registry.approve(version.version_id, "admin-a")
    registry.approve(version.version_id, "admin-b")
    version = registry.activate(version.version_id, activated_by="admin-a")
    record = MemoryStateStore().reserve(make_proposal(), version.policy).record
    token = DecisionIssuer.from_seed("deny-test").issue(record, version)
    assert token.verdict is DecisionVerdict.DENY
    assert token.reservation_id is None
    assert token.reason_codes == ("EMERGENCY_STOP",)
