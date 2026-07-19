from datetime import UTC, datetime, timedelta

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from hypothesis.stateful import RuleBasedStateMachine, invariant, rule
from pydantic import ValidationError

from aegisledger.canonical import CanonicalizationError, canonical_json
from aegisledger.contracts import LifecycleState, ProposalV1
from aegisledger.policy import PolicyV1
from aegisledger.state import MemoryStateStore

WALLET = "0x" + "12" * 20
RECIPIENT = "0x" + "34" * 20
CAP = 1_000


def policy_document():
    return {
        "schema_version": "aegisledger.policy.v1",
        "name": "property-test-policy",
        "default_action": "deny",
        "enabled_wallets": [WALLET],
        "enabled_principals": ["principal"],
        "enabled_chains": [31337],
        "enabled_assets": ["TUSDC"],
        "allowed_recipients": [RECIPIENT],
        "contract_rules": [],
        "per_transaction_cap": 400,
        "rolling_caps": [{"window_seconds": 3600, "amount": CAP}],
        "maximum_transactions_per_hour": 100,
        "mandate_required_above": 400,
        "risk": {
            "maximum_slippage_bps": 50,
            "maximum_quote_age_seconds": 30,
            "deny_on_missing_quote": True,
        },
        "emergency_stop": False,
    }


class AuthorizationStateMachine(RuleBasedStateMachine):
    def __init__(self):
        super().__init__()
        self.store = MemoryStateStore()
        self.policy = PolicyV1.model_validate(policy_document())
        self.pending = []
        self.denied = []
        self.counter = 0

    @rule(amount=st.integers(min_value=1, max_value=400))
    def propose(self, amount):
        self.counter += 1
        proposal = ProposalV1.model_validate(
            {
                "schema_version": "aegisledger.proposal.v1",
                "principal_id": "principal",
                "wallet": WALLET,
                "chain_id": 31337,
                "asset": "TUSDC",
                "amount": amount,
                "intent": {"kind": "transfer", "recipient": RECIPIENT},
                "deadline": datetime.now(UTC) + timedelta(hours=1),
                "idempotency_key": f"state-machine-{self.counter:05d}",
            }
        )
        record = self.store.reserve(proposal, self.policy).record
        if record.state is LifecycleState.RESERVED:
            self.pending.append(record.proposal.proposal_id)
        else:
            self.denied.append(record.proposal.proposal_id)

    @rule(settle=st.booleans())
    def finalize_one(self, settle):
        if not self.pending:
            return
        proposal_id = self.pending.pop(0)
        self.store.transition(proposal_id, LifecycleState.SIGNED)
        self.store.transition(proposal_id, LifecycleState.SUBMITTED)
        self.store.transition(
            proposal_id,
            LifecycleState.SETTLED if settle else LifecycleState.REVERTED,
        )

    @rule()
    def denied_proposal_cannot_be_signed(self):
        if not self.denied:
            return
        with pytest.raises(ValueError, match="invalid lifecycle transition"):
            self.store.transition(self.denied[0], LifecycleState.SIGNED)

    @invariant()
    def pending_plus_settled_never_exceeds_cap(self):
        pending, settled = self.store.budget_totals("principal", WALLET, 31337, "TUSDC")
        assert pending + settled <= CAP


TestAuthorizationStateMachine = AuthorizationStateMachine.TestCase
TestAuthorizationStateMachine.settings = settings(
    max_examples=30,
    stateful_step_count=40,
    deadline=None,
)


@settings(max_examples=50, deadline=None)
@given(
    st.one_of(
        st.none(),
        st.booleans(),
        st.floats(allow_nan=True, allow_infinity=True),
        st.text(max_size=24),
        st.lists(st.integers(), max_size=3),
        st.dictionaries(st.text(max_size=8), st.integers(), max_size=3),
    )
)
def test_policy_parser_never_coerces_invalid_cap(value):
    document = policy_document()
    document["per_transaction_cap"] = value
    with pytest.raises(ValidationError):
        PolicyV1.model_validate(document)


@settings(max_examples=50, deadline=None)
@given(st.floats(allow_nan=True, allow_infinity=True))
def test_canonical_signed_domain_rejects_every_float(value):
    with pytest.raises(CanonicalizationError):
        canonical_json({"amount": value})
