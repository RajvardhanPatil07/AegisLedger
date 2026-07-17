from datetime import UTC, datetime, timedelta

import pytest

from aegisledger.contracts import ProposalV1
from aegisledger.decisions import DecisionIssuer
from aegisledger.policies import PolicyRegistry
from aegisledger.policy import PolicyV1
from aegisledger.signing import (
    SignerAuthorizationError,
    SignerAuthorizationGate,
    TransactionBindingV1,
    TransactionSignRequestV1,
    keccak_hex,
)
from aegisledger.state import MemoryStateStore

WALLET = "0x" + "12" * 20
RECIPIENT = "0x" + "34" * 20
EIP712_PAYLOAD = "0x1901" + "ab" * 64
EIP1559_PAYLOAD = "0x02" + "cd" * 64


def policy():
    return PolicyV1.model_validate(
        {
            "schema_version": "aegisledger.policy.v1",
            "name": "signer-bound-policy",
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


def proposal(amount=100, chain_id=31337):
    return ProposalV1.model_validate(
        {
            "schema_version": "aegisledger.proposal.v1",
            "principal_id": "researcher",
            "wallet": WALLET,
            "chain_id": chain_id,
            "asset": "TUSDC",
            "amount": amount,
            "intent": {"kind": "transfer", "recipient": RECIPIENT},
            "deadline": datetime.now(UTC) + timedelta(minutes=5),
            "idempotency_key": f"signer-request-{amount}-{chain_id}",
        }
    )


def authorized_request():
    registry = PolicyRegistry()
    version = registry.create(policy(), created_by="author")
    registry.approve(version.version_id, "admin-a")
    registry.approve(version.version_id, "admin-b")
    registry.activate(version.version_id, activated_by="admin-a")
    item = proposal()
    record = MemoryStateStore().reserve(item, version.policy).record
    issuer = DecisionIssuer.from_seed("signer-gate")
    decision = issuer.issue(record, version)
    request = TransactionSignRequestV1(
        schema_version="aegisledger.sign_request.v1",
        proposal=item,
        decision=decision,
        reservation_id=record.reservation_id,
        wallet_nonce=0,
        chain_id=31337,
        transaction=TransactionBindingV1(
            operation="transfer",
            wallet=WALLET,
            chain_id=31337,
            wallet_nonce=0,
            asset="TUSDC",
            amount=100,
            recipient=RECIPIENT,
            contract=None,
            selector=None,
            calldata="0x",
            value=0,
            gas_limit=100_000,
            max_fee_per_gas=1_000_000_000,
            max_priority_fee_per_gas=100_000_000,
        ),
        eip712_payload=EIP712_PAYLOAD,
        eip1559_unsigned_payload=EIP1559_PAYLOAD,
        eip712_hash=keccak_hex(EIP712_PAYLOAD),
        eip1559_hash=keccak_hex(EIP1559_PAYLOAD),
        expires_at=decision.expires_at,
    )
    return request, issuer


def test_gate_accepts_only_exact_transaction_bound_decision():
    request, issuer = authorized_request()
    gate = SignerAuthorizationGate(
        policy_public_key=issuer.public_key,
        allowed_chain_ids={31337},
    )
    gate.validate_and_consume(request)


def test_proposal_or_transaction_mutation_is_rejected():
    request, issuer = authorized_request()
    gate = SignerAuthorizationGate(issuer.public_key, {31337})
    changed_proposal = proposal(amount=101)
    mutated = request.model_copy(update={"proposal": changed_proposal})
    with pytest.raises(SignerAuthorizationError, match="proposal hash"):
        gate.validate_and_consume(mutated)

    request, issuer = authorized_request()
    malformed_hash = request.model_copy(update={"eip1559_hash": request.eip712_hash})
    with pytest.raises(SignerAuthorizationError, match="EIP-1559 hash"):
        SignerAuthorizationGate(issuer.public_key, {31337}).validate_and_consume(malformed_hash)

    request, issuer = authorized_request()
    changed_binding = request.transaction.model_copy(update={"amount": 999})
    with pytest.raises(SignerAuthorizationError, match="transaction amount"):
        SignerAuthorizationGate(issuer.public_key, {31337}).validate_and_consume(
            request.model_copy(update={"transaction": changed_binding})
        )


def test_wrong_chain_expired_and_replayed_requests_are_rejected():
    request, issuer = authorized_request()
    wrong_chain = request.model_copy(update={"chain_id": 1})
    with pytest.raises(SignerAuthorizationError, match="chain"):
        SignerAuthorizationGate(issuer.public_key, {31337}).validate_and_consume(wrong_chain)

    expired = request.model_copy(update={"expires_at": datetime.now(UTC) - timedelta(seconds=1)})
    with pytest.raises(SignerAuthorizationError, match="expired"):
        SignerAuthorizationGate(issuer.public_key, {31337}).validate_and_consume(expired)

    gate = SignerAuthorizationGate(issuer.public_key, {31337})
    gate.validate_and_consume(request)
    with pytest.raises(SignerAuthorizationError, match="replay"):
        gate.validate_and_consume(request)


def test_wallet_nonce_must_be_monotonic_per_wallet_and_chain():
    request, issuer = authorized_request()
    gate = SignerAuthorizationGate(issuer.public_key, {31337})
    with pytest.raises(SignerAuthorizationError, match="wallet nonce"):
        gate.validate_and_consume(request.model_copy(update={"wallet_nonce": 1}))
