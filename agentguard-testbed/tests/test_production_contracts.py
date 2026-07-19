from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from aegisledger.canonical import CanonicalizationError, canonical_json, uuid7
from aegisledger.contracts import LifecycleState, ProposalV1, require_transition
from aegisledger.policy import PolicyV1

WALLET = "0x" + "12" * 20
RECIPIENT = "0x" + "34" * 20


def proposal(**overrides):
    data = {
        "schema_version": "aegisledger.proposal.v1",
        "principal_id": "researcher-1",
        "wallet": WALLET,
        "chain_id": 31337,
        "asset": "TUSDC",
        "amount": 100,
        "intent": {"kind": "transfer", "recipient": RECIPIENT},
        "deadline": datetime.now(UTC) + timedelta(minutes=5),
        "idempotency_key": "experiment-0001",
    }
    data.update(overrides)
    return ProposalV1.model_validate(data)


def policy(**overrides):
    data = {
        "schema_version": "aegisledger.policy.v1",
        "name": "research-default",
        "default_action": "deny",
        "enabled_wallets": [WALLET],
        "enabled_principals": ["researcher-1"],
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
    data.update(overrides)
    return PolicyV1.model_validate(data)


def test_proposal_is_strict_and_forbids_unknown_fields():
    with pytest.raises(ValidationError):
        proposal(amount="100")
    with pytest.raises(ValidationError):
        proposal(unexpected=True)


def test_proposal_hash_binds_exact_normalized_payload():
    item = proposal(wallet=WALLET.upper().replace("0X", "0x"))
    assert item.wallet == WALLET
    assert item.proposal_hash().startswith("0x")
    assert len(item.proposal_hash()) == 66


def test_uuid7_is_time_sortable_and_versioned():
    older = uuid7(now_ms=1_000)
    newer = uuid7(now_ms=1_001)
    assert older.version == newer.version == 7
    assert older.int < newer.int


def test_canonical_signed_domains_reject_floats():
    with pytest.raises(CanonicalizationError):
        canonical_json({"amount": 1.0})


def test_policy_forbids_implicit_boolean_and_unknown_nested_fields():
    with pytest.raises(ValidationError):
        policy(emergency_stop="false")
    with pytest.raises(ValidationError):
        policy(
            risk={
                "maximum_slippage_bps": 50,
                "maximum_quote_age_seconds": 30,
                "deny_on_missing_quote": True,
                "allow_when_unavailable": True,
            }
        )


def test_policy_requires_explicit_default_deny_constraints():
    with pytest.raises(ValidationError):
        PolicyV1.model_validate({"schema_version": "aegisledger.policy.v1", "name": "bad"})
    assert policy().default_action == "deny"


def test_lifecycle_only_allows_declared_transitions():
    require_transition(LifecycleState.PROPOSED, LifecycleState.RESERVED)
    require_transition(LifecycleState.SUBMITTED, LifecycleState.REVERTED)
    with pytest.raises(ValueError, match="invalid lifecycle transition"):
        require_transition(LifecycleState.PROPOSED, LifecycleState.SETTLED)
