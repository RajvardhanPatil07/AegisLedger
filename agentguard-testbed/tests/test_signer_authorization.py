from datetime import UTC, datetime, timedelta

import pytest

from aegisledger.contracts import ProposalV1
from aegisledger.decisions import DecisionIssuer, decision_signature_payload
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
from agentwallet.chain.crypto import KeyPair

WALLET = "0x" + "12" * 20
RECIPIENT = "0x" + "34" * 20
CONTRACT = "0x" + "56" * 20
SELECTOR = "0x12345678"
POLICY_KEYS = KeyPair.from_seed("policy-service::signer-gate")


def _rlp_encode(value):
    if isinstance(value, list):
        payload = b"".join(_rlp_encode(item) for item in value)
        return _rlp_prefix(payload, 0xC0, 0xF7)
    if isinstance(value, int):
        value = b"" if value == 0 else value.to_bytes((value.bit_length() + 7) // 8, "big")
    if len(value) == 1 and value[0] < 0x80:
        return value
    return _rlp_prefix(value, 0x80, 0xB7)


def _rlp_prefix(payload, short_offset, long_offset):
    if len(payload) < 56:
        return bytes([short_offset + len(payload)]) + payload
    encoded_length = len(payload).to_bytes((len(payload).bit_length() + 7) // 8, "big")
    return bytes([long_offset + len(encoded_length)]) + encoded_length + payload


def _eip1559_payload(
    target: str = RECIPIENT,
    *,
    chain_id: int = 31337,
    nonce: int = 0,
    priority_fee: int = 100_000_000,
    max_fee: int = 1_000_000_000,
    gas_limit: int = 100_000,
    value: int = 100,
    calldata: str = "0x",
) -> str:
    fields = [
        chain_id,
        nonce,
        priority_fee,
        max_fee,
        gas_limit,
        bytes.fromhex(target[2:]),
        value,
        bytes.fromhex(calldata[2:]),
        [],
    ]
    return "0x02" + _rlp_encode(fields).hex()


def policy():
    return PolicyV1.model_validate(
        {
            "schema_version": "aegisledger.policy.v1",
            "name": "signer-bound-policy",
            "default_action": "deny",
            "enabled_wallets": [WALLET],
            "enabled_principals": ["researcher"],
            "enabled_chains": [31337],
            "enabled_assets": ["NATIVE:31337"],
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
            "asset": "NATIVE:31337",
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
    issuer = DecisionIssuer(POLICY_KEYS)
    decision = issuer.issue(record, version)
    eip712_payload = "0x1901" + "ab" * 32 + decision.proposal_hash[2:]
    eip1559_payload = _eip1559_payload(RECIPIENT)
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
            asset="NATIVE:31337",
            amount=100,
            recipient=RECIPIENT,
            contract=None,
            selector=None,
            calldata="0x",
            value=100,
            gas_limit=100_000,
            max_fee_per_gas=1_000_000_000,
            max_priority_fee_per_gas=100_000_000,
        ),
        eip712_payload=eip712_payload,
        eip1559_unsigned_payload=eip1559_payload,
        eip712_hash=keccak_hex(eip712_payload),
        eip1559_hash=keccak_hex(eip1559_payload),
        expires_at=decision.expires_at,
    )
    return request, issuer


def _resign(decision, **updates):
    unsigned = decision.model_copy(
        update={**updates, "signature": "0" * 128},
    )
    signature = POLICY_KEYS.sign(decision_signature_payload(unsigned)).hex()
    return unsigned.model_copy(update={"signature": signature})


def _replace_raw(request, **updates):
    transaction = request.transaction
    payload = _eip1559_payload(
        updates.get("target", transaction.recipient or transaction.contract),
        chain_id=updates.get("chain_id", transaction.chain_id),
        nonce=updates.get("nonce", transaction.wallet_nonce),
        priority_fee=updates.get(
            "priority_fee",
            transaction.max_priority_fee_per_gas,
        ),
        max_fee=updates.get("max_fee", transaction.max_fee_per_gas),
        gas_limit=updates.get("gas_limit", transaction.gas_limit),
        value=updates.get("value", transaction.value),
        calldata=updates.get("calldata", transaction.calldata),
    )
    return request.model_copy(
        update={
            "eip1559_unsigned_payload": payload,
            "eip1559_hash": keccak_hex(payload),
        }
    )


def _swap_request():
    request, issuer = authorized_request()
    item = ProposalV1.model_validate(
        {
            "schema_version": "aegisledger.proposal.v1",
            "principal_id": "researcher",
            "wallet": WALLET,
            "chain_id": 31337,
            "asset": "NATIVE:31337",
            "amount": 100,
            "intent": {
                "kind": "swap",
                "contract": CONTRACT,
                "selector": SELECTOR,
                "calldata": SELECTOR,
                "minimum_output": 1,
                "output_asset": "NATIVE:31337",
            },
            "deadline": datetime.now(UTC) + timedelta(minutes=5),
            "idempotency_key": "signer-swap-request",
        }
    )
    decision = _resign(request.decision, proposal_hash=item.proposal_hash())
    transaction = TransactionBindingV1(
        operation="swap",
        wallet=WALLET,
        chain_id=31337,
        wallet_nonce=0,
        asset="NATIVE:31337",
        amount=100,
        recipient=None,
        contract=CONTRACT,
        selector=SELECTOR,
        calldata=SELECTOR,
        value=0,
        gas_limit=100_000,
        max_fee_per_gas=1_000_000_000,
        max_priority_fee_per_gas=100_000_000,
    )
    eip712_payload = "0x1901" + "ab" * 32 + item.proposal_hash()[2:]
    raw_payload = _eip1559_payload(CONTRACT, value=0, calldata=SELECTOR)
    return (
        request.model_copy(
            update={
                "proposal": item,
                "decision": decision,
                "transaction": transaction,
                "eip712_payload": eip712_payload,
                "eip712_hash": keccak_hex(eip712_payload),
                "eip1559_unsigned_payload": raw_payload,
                "eip1559_hash": keccak_hex(raw_payload),
            }
        ),
        issuer,
    )


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


def test_raw_eip1559_recipient_substitution_is_rejected():
    request, issuer = authorized_request()
    substituted = _eip1559_payload("0x" + "56" * 20)
    mutated = request.model_copy(
        update={
            "eip1559_unsigned_payload": substituted,
            "eip1559_hash": keccak_hex(substituted),
        }
    )

    with pytest.raises(SignerAuthorizationError, match="recipient"):
        SignerAuthorizationGate(issuer.public_key, {31337}).validate_and_consume(mutated)


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

    transaction = request.transaction.model_copy(update={"wallet_nonce": 1})
    consistent_nonce = _replace_raw(
        request.model_copy(update={"wallet_nonce": 1, "transaction": transaction}),
        nonce=1,
    )
    with pytest.raises(SignerAuthorizationError, match="wallet nonce must be 0"):
        SignerAuthorizationGate(issuer.public_key, {31337}).validate_and_consume(consistent_nonce)


def test_successful_signing_advances_the_wallet_nonce():
    first, issuer = authorized_request()
    second, _ = authorized_request()
    second_transaction = second.transaction.model_copy(update={"wallet_nonce": 1})
    second = _replace_raw(
        second.model_copy(update={"wallet_nonce": 1, "transaction": second_transaction}),
        nonce=1,
    )

    gate = SignerAuthorizationGate(issuer.public_key, {31337})
    gate.validate_and_consume(first)
    gate.validate_and_consume(second)


def test_expiry_boundary_and_decision_signature_are_fail_closed():
    request, issuer = authorized_request()
    with pytest.raises(SignerAuthorizationError, match="expired"):
        SignerAuthorizationGate(issuer.public_key, {31337}).validate_and_consume(
            request,
            now=request.expires_at,
        )

    signature = request.decision.signature
    forged_decision = request.decision.model_copy(
        update={"signature": ("0" if signature[0] != "0" else "1") + signature[1:]}
    )
    with pytest.raises(SignerAuthorizationError, match="signature"):
        SignerAuthorizationGate(issuer.public_key, {31337}).validate_and_consume(
            request.model_copy(update={"decision": forged_decision})
        )


def test_request_may_expire_exactly_at_the_proposal_deadline():
    request, issuer = authorized_request()
    item = request.proposal.model_copy(update={"deadline": request.decision.expires_at})
    decision = _resign(request.decision, proposal_hash=item.proposal_hash())
    eip712_payload = "0x1901" + "ab" * 32 + item.proposal_hash()[2:]
    boundary_request = request.model_copy(
        update={
            "proposal": item,
            "decision": decision,
            "expires_at": item.deadline,
            "eip712_payload": eip712_payload,
            "eip712_hash": keccak_hex(eip712_payload),
        }
    )

    SignerAuthorizationGate(issuer.public_key, {31337}).validate_and_consume(boundary_request)


def test_policy_identity_version_and_verdict_are_enforced():
    request, issuer = authorized_request()
    wrong_identity = _resign(request.decision, policy_signer="untrusted-policy-service")
    with pytest.raises(SignerAuthorizationError, match="signer identity"):
        SignerAuthorizationGate(issuer.public_key, {31337}).validate_and_consume(
            request.model_copy(update={"decision": wrong_identity})
        )

    request, issuer = authorized_request()
    allowed_hash = request.decision.policy_hash.upper()
    SignerAuthorizationGate(
        issuer.public_key,
        {31337},
        {allowed_hash},
    ).validate_and_consume(request)

    request, issuer = authorized_request()
    unapproved = _resign(request.decision, policy_hash="0x" + "f" * 64)
    with pytest.raises(SignerAuthorizationError, match="policy version"):
        SignerAuthorizationGate(
            issuer.public_key,
            {31337},
            {request.decision.policy_hash},
        ).validate_and_consume(request.model_copy(update={"decision": unapproved}))

    request, issuer = authorized_request()
    denied = _resign(request.decision, verdict=request.decision.verdict.DENY, reservation_id=None)
    with pytest.raises(SignerAuthorizationError, match="does not authorize"):
        SignerAuthorizationGate(issuer.public_key, {31337}).validate_and_consume(
            request.model_copy(update={"decision": denied})
        )


def test_reservation_chain_wallet_and_lifetime_bindings_are_enforced():
    request, issuer = authorized_request()
    with pytest.raises(SignerAuthorizationError, match="reservation"):
        SignerAuthorizationGate(issuer.public_key, {31337}).validate_and_consume(
            request.model_copy(update={"reservation_id": request.decision.decision_nonce})
        )

    request, issuer = authorized_request()
    with pytest.raises(SignerAuthorizationError, match="not enabled"):
        SignerAuthorizationGate(issuer.public_key, {1}).validate_and_consume(request)

    request, issuer = authorized_request()
    changed_proposal = request.proposal.model_copy(update={"chain_id": 1})
    changed_decision = _resign(
        request.decision,
        proposal_hash=changed_proposal.proposal_hash(),
    )
    with pytest.raises(SignerAuthorizationError, match="chain binding"):
        SignerAuthorizationGate(issuer.public_key, {31337}).validate_and_consume(
            request.model_copy(update={"proposal": changed_proposal, "decision": changed_decision})
        )

    request, issuer = authorized_request()
    transaction = request.transaction.model_copy(update={"chain_id": 1})
    with pytest.raises(SignerAuthorizationError, match="chain binding"):
        SignerAuthorizationGate(issuer.public_key, {31337}).validate_and_consume(
            request.model_copy(update={"transaction": transaction})
        )

    request, issuer = authorized_request()
    transaction = request.transaction.model_copy(update={"wallet": "0x" + "ab" * 20})
    with pytest.raises(SignerAuthorizationError, match="wallet binding"):
        SignerAuthorizationGate(issuer.public_key, {31337}).validate_and_consume(
            request.model_copy(update={"transaction": transaction})
        )

    request, issuer = authorized_request()
    too_late = request.model_copy(
        update={"expires_at": request.decision.expires_at + timedelta(seconds=1)}
    )
    with pytest.raises(SignerAuthorizationError, match="outlives"):
        SignerAuthorizationGate(issuer.public_key, {31337}).validate_and_consume(too_late)


def test_typed_payload_prefix_hash_and_proposal_binding_are_enforced():
    request, issuer = authorized_request()
    wrong_prefix = "0x1801" + request.eip712_payload[6:]
    with pytest.raises(SignerAuthorizationError, match="0x1901"):
        SignerAuthorizationGate(issuer.public_key, {31337}).validate_and_consume(
            request.model_copy(
                update={
                    "eip712_payload": wrong_prefix,
                    "eip712_hash": keccak_hex(wrong_prefix),
                }
            )
        )

    request, issuer = authorized_request()
    legacy_transaction = "0x03" + request.eip1559_unsigned_payload[4:]
    with pytest.raises(SignerAuthorizationError, match="typed transaction"):
        SignerAuthorizationGate(issuer.public_key, {31337}).validate_and_consume(
            request.model_copy(
                update={
                    "eip1559_unsigned_payload": legacy_transaction,
                    "eip1559_hash": keccak_hex(legacy_transaction),
                }
            )
        )

    request, issuer = authorized_request()
    with pytest.raises(SignerAuthorizationError, match="EIP-712 hash"):
        SignerAuthorizationGate(issuer.public_key, {31337}).validate_and_consume(
            request.model_copy(update={"eip712_hash": request.eip1559_hash})
        )

    request, issuer = authorized_request()
    unbound = "0x1901" + "ab" * 32 + "cd" * 32
    with pytest.raises(SignerAuthorizationError, match="authorized proposal"):
        SignerAuthorizationGate(issuer.public_key, {31337}).validate_and_consume(
            request.model_copy(
                update={"eip712_payload": unbound, "eip712_hash": keccak_hex(unbound)}
            )
        )

    request, issuer = authorized_request()
    short = request.eip712_payload[:-2]
    with pytest.raises(SignerAuthorizationError, match="authorized proposal"):
        SignerAuthorizationGate(issuer.public_key, {31337}).validate_and_consume(
            request.model_copy(update={"eip712_payload": short, "eip712_hash": keccak_hex(short)})
        )


def test_transfer_semantic_bindings_are_enforced():
    updates = [
        ({"operation": "swap"}, "operation"),
        ({"asset": "ETH:31337"}, "asset"),
        ({"amount": 101}, "amount"),
        ({"recipient": "0x" + "ab" * 20}, "recipient"),
    ]
    for transaction_updates, message in updates:
        request, issuer = authorized_request()
        transaction = request.transaction.model_copy(update=transaction_updates)
        with pytest.raises(SignerAuthorizationError, match=message):
            SignerAuthorizationGate(issuer.public_key, {31337}).validate_and_consume(
                request.model_copy(update={"transaction": transaction})
            )


def test_swap_semantic_bindings_are_enforced():
    request, issuer = _swap_request()
    SignerAuthorizationGate(issuer.public_key, {31337}).validate_and_consume(request)

    updates = [
        ({"contract": "0x" + "ab" * 20}, "contract"),
        ({"selector": "0x87654321"}, "selector"),
        ({"calldata": "0x87654321"}, "calldata"),
    ]
    for transaction_updates, message in updates:
        request, issuer = _swap_request()
        transaction = request.transaction.model_copy(update=transaction_updates)
        with pytest.raises(SignerAuthorizationError, match=message):
            SignerAuthorizationGate(issuer.public_key, {31337}).validate_and_consume(
                request.model_copy(update={"transaction": transaction})
            )


def test_every_raw_eip1559_field_is_bound_to_the_request():
    mutations = [
        ({"chain_id": 1}, "chain or nonce"),
        ({"nonce": 1}, "chain or nonce"),
        ({"target": "0x" + "ab" * 20}, "recipient"),
        ({"value": 101}, "value"),
        ({"calldata": "0x12"}, "calldata"),
        ({"gas_limit": 99_999}, "gas limit"),
        ({"max_fee": 999_999_999}, "fee"),
        ({"priority_fee": 99_999_999}, "fee"),
    ]
    for raw_updates, message in mutations:
        request, issuer = authorized_request()
        with pytest.raises(SignerAuthorizationError, match=message):
            SignerAuthorizationGate(issuer.public_key, {31337}).validate_and_consume(
                _replace_raw(request, **raw_updates)
            )

    request, issuer = authorized_request()
    malformed = "0x02ff"
    with pytest.raises(SignerAuthorizationError, match="invalid EIP-1559"):
        SignerAuthorizationGate(issuer.public_key, {31337}).validate_and_consume(
            request.model_copy(
                update={
                    "eip1559_unsigned_payload": malformed,
                    "eip1559_hash": keccak_hex(malformed),
                }
            )
        )


def test_transaction_binding_model_normalizes_and_rejects_invalid_shapes():
    binding = TransactionBindingV1(
        operation="transfer",
        wallet="0x" + "AB" * 20,
        chain_id=31337,
        wallet_nonce=0,
        asset="NATIVE:31337",
        amount=100,
        recipient="0x" + "CD" * 20,
        contract=None,
        selector=None,
        calldata="0x",
        value=100,
        gas_limit=100_000,
        max_fee_per_gas=1_000_000_000,
        max_priority_fee_per_gas=100_000_000,
    )
    assert binding.wallet == "0x" + "ab" * 20
    assert binding.recipient == "0x" + "cd" * 20

    data = binding.model_dump(mode="python")
    with pytest.raises(ValueError, match="only a recipient"):
        TransactionBindingV1.model_validate({**data, "contract": CONTRACT})
    with pytest.raises(ValueError, match="native asset"):
        TransactionBindingV1.model_validate({**data, "asset": "ETH:31337"})
    with pytest.raises(ValueError, match="value must equal"):
        TransactionBindingV1.model_validate({**data, "value": 99})
    with pytest.raises(ValueError, match="priority fee"):
        TransactionBindingV1.model_validate(
            {
                **data,
                "max_fee_per_gas": 1,
                "max_priority_fee_per_gas": 2,
            }
        )
