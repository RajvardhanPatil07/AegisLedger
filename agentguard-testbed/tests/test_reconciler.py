from datetime import UTC, datetime, timedelta

from aegisledger.chain import EvmReceipt
from aegisledger.contracts import LifecycleState, ProposalV1
from aegisledger.policy import PolicyV1
from aegisledger.reconciler import MemorySettlementStore, SettlementReconciler
from aegisledger.state import MemoryStateStore

WALLET = "0x" + "12" * 20
RECIPIENT = "0x" + "34" * 20
TX_HASH = "0x" + "ab" * 32


def policy():
    return PolicyV1.model_validate(
        {
            "schema_version": "aegisledger.policy.v1",
            "name": "reconciliation-policy",
            "default_action": "deny",
            "enabled_wallets": [WALLET],
            "enabled_principals": ["principal"],
            "enabled_chains": [31337],
            "enabled_assets": ["TUSDC"],
            "allowed_recipients": [RECIPIENT],
            "contract_rules": [],
            "per_transaction_cap": 100,
            "rolling_caps": [{"window_seconds": 3600, "amount": 100}],
            "maximum_transactions_per_hour": 10,
            "mandate_required_above": 100,
            "risk": {
                "maximum_slippage_bps": 50,
                "maximum_quote_age_seconds": 30,
                "deny_on_missing_quote": True,
            },
            "emergency_stop": False,
        }
    )


def proposal():
    return ProposalV1.model_validate(
        {
            "schema_version": "aegisledger.proposal.v1",
            "principal_id": "principal",
            "wallet": WALLET,
            "chain_id": 31337,
            "asset": "TUSDC",
            "amount": 100,
            "intent": {"kind": "transfer", "recipient": RECIPIENT},
            "deadline": datetime.now(UTC) + timedelta(minutes=5),
            "idempotency_key": "reconciliation-001",
        }
    )


class FakeBackend:
    chain_id = 31337

    def __init__(self):
        self.receipts = {}
        self.failures = 0

    def receipt(self, transaction_hash):
        if self.failures:
            self.failures -= 1
            raise TimeoutError("RPC timeout")
        return self.receipts.get(transaction_hash)


def setup_tracking():
    lifecycle = MemoryStateStore()
    record = lifecycle.reserve(proposal(), policy()).record
    lifecycle.transition(record.proposal.proposal_id, LifecycleState.SIGNED)
    settlements = MemorySettlementStore()
    settlements.register(TX_HASH, record.proposal.proposal_id, chain_id=31337)
    lifecycle.transition(record.proposal.proposal_id, LifecycleState.SUBMITTED)
    return lifecycle, settlements, record


def receipt(block_hash, confirmations, success=True):
    return EvmReceipt(
        transaction_hash=TX_HASH,
        block_hash=block_hash,
        block_number=10,
        success=success,
        confirmations=confirmations,
    )


def test_restart_recovers_submitted_transaction_and_settles_after_finality():
    lifecycle, settlements, record = setup_tracking()
    backend = FakeBackend()
    backend.receipts[TX_HASH] = receipt("0x" + "11" * 32, confirmations=2)

    restarted = SettlementReconciler(lifecycle, settlements, {31337: backend}, finality=2)
    restarted.poll_once()
    assert lifecycle.get(record.proposal.proposal_id).state is LifecycleState.SETTLED
    assert lifecycle.budget_totals("principal", WALLET, 31337, "TUSDC") == (0, 100)

    restarted.poll_once()  # duplicate receipt delivery is idempotent
    assert lifecycle.budget_totals("principal", WALLET, 31337, "TUSDC") == (0, 100)


def test_rpc_timeout_keeps_reservation_pending_for_retry():
    lifecycle, settlements, record = setup_tracking()
    backend = FakeBackend()
    backend.failures = 1
    reconciler = SettlementReconciler(lifecycle, settlements, {31337: backend}, finality=2)
    reconciler.poll_once()
    assert lifecycle.get(record.proposal.proposal_id).state is LifecycleState.SUBMITTED
    assert lifecycle.budget_totals("principal", WALLET, 31337, "TUSDC") == (100, 0)


def test_pre_finality_reorg_replaces_receipt_without_false_settlement():
    lifecycle, settlements, record = setup_tracking()
    backend = FakeBackend()
    backend.receipts[TX_HASH] = receipt("0x" + "11" * 32, confirmations=1)
    reconciler = SettlementReconciler(lifecycle, settlements, {31337: backend}, finality=2)
    reconciler.poll_once()
    assert lifecycle.get(record.proposal.proposal_id).state is LifecycleState.SUBMITTED

    backend.receipts[TX_HASH] = receipt("0x" + "22" * 32, confirmations=2)
    reconciler.poll_once()
    tracked = settlements.get(TX_HASH)
    assert tracked.block_hash == "0x" + "22" * 32
    assert tracked.reorg_count == 1
    assert lifecycle.get(record.proposal.proposal_id).state is LifecycleState.SETTLED


def test_confirmed_revert_releases_reservation_and_never_consumes_settled_budget():
    lifecycle, settlements, record = setup_tracking()
    backend = FakeBackend()
    backend.receipts[TX_HASH] = receipt("0x" + "33" * 32, confirmations=2, success=False)
    SettlementReconciler(lifecycle, settlements, {31337: backend}, finality=2).poll_once()
    assert lifecycle.get(record.proposal.proposal_id).state is LifecycleState.REVERTED
    assert lifecycle.budget_totals("principal", WALLET, 31337, "TUSDC") == (0, 0)
