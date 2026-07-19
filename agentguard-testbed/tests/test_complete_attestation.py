import hashlib
from datetime import UTC, datetime, timedelta

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from eth_hash.auto import keccak

from aegisledger.attestations import (
    CompleteAttestationV1,
    EnclaveEvidenceV1,
    SettlementEvidenceV1,
    verify_complete_attestation,
)
from aegisledger.contracts import ProposalV1, SignedTransactionV1
from aegisledger.decisions import DecisionIssuer
from aegisledger.policies import PolicyRegistry
from aegisledger.policy import PolicyV1
from aegisledger.signing import TransactionBindingV1
from aegisledger.state import MemoryStateStore

WALLET = "0x" + "12" * 20
RECIPIENT = "0x" + "34" * 20
BUILD = "sha384:approved-signer-build"


def raw_signature(key, digest):
    der = key.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    r, s = utils.decode_dss_signature(der)
    return "0x" + r.to_bytes(32, "big").hex() + s.to_bytes(32, "big").hex() + "00"


def make_attestation():
    policy = PolicyV1.model_validate(
        {
            "schema_version": "aegisledger.policy.v1",
            "name": "attestation-policy",
            "default_action": "deny",
            "enabled_wallets": [WALLET],
            "enabled_principals": ["principal"],
            "enabled_chains": [31337],
            "enabled_assets": ["NATIVE:31337"],
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
    proposal = ProposalV1.model_validate(
        {
            "schema_version": "aegisledger.proposal.v1",
            "principal_id": "principal",
            "wallet": WALLET,
            "chain_id": 31337,
            "asset": "NATIVE:31337",
            "amount": 100,
            "intent": {"kind": "transfer", "recipient": RECIPIENT},
            "deadline": datetime.now(UTC) + timedelta(minutes=5),
            "idempotency_key": "complete-attestation-001",
        }
    )
    registry = PolicyRegistry()
    version = registry.create(policy, created_by="author")
    record = MemoryStateStore().reserve(proposal, policy).record
    issuer = DecisionIssuer.from_seed("complete-attestation")
    decision = issuer.issue(record, version)

    binding = TransactionBindingV1(
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
        gas_limit=21_000,
        max_fee_per_gas=1,
        max_priority_fee_per_gas=0,
    )
    signing_hash = "0x" + "ab" * 32
    raw_transaction = "0x02c0"
    transaction_hash = "0x" + keccak(bytes.fromhex(raw_transaction[2:])).hex()
    signing_key = ec.generate_private_key(ec.SECP256K1())
    public_bytes = signing_key.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )
    signer_identity = "0x" + keccak(public_bytes[1:])[-20:].hex()
    issued_at = datetime.now(UTC)
    unsigned_evidence = {
        "schema_version": "aegisledger.enclave_evidence.v1",
        "mode": "local-process-or-nitro",
        "build_measurement": BUILD,
        "signer_identity": signer_identity,
        "secp256k1_public_key": "0x" + public_bytes.hex(),
        "transaction_hash": transaction_hash,
        "signing_hash": signing_hash,
        "proposal_hash": proposal.proposal_hash(),
        "policy_version_id": str(decision.policy_version_id),
        "policy_hash": decision.policy_hash,
        "state_version": decision.state_version,
        "reservation_id": str(decision.reservation_id),
        "wallet": proposal.wallet,
        "principal_id": proposal.principal_id,
        "chain_id": proposal.chain_id,
        "wallet_nonce": 0,
        "decision_id": str(decision.decision_id),
        "decision_nonce": str(decision.decision_nonce),
        "expires_at": decision.expires_at.isoformat(),
        "issued_at": issued_at.isoformat(),
    }
    placeholder = EnclaveEvidenceV1.model_validate(
        {
            **unsigned_evidence,
            "evidence_hash": "0x" + "00" * 32,
            "evidence_signature": "0x" + "00" * 65,
        }
    )
    evidence_digest = hashlib.sha256(placeholder.unsigned_payload()).digest()
    evidence = EnclaveEvidenceV1.model_validate(
        {
            **placeholder.model_dump(mode="python"),
            "evidence_hash": "0x" + evidence_digest.hex(),
            "evidence_signature": raw_signature(signing_key, evidence_digest),
        }
    )
    signed = SignedTransactionV1(
        schema_version="aegisledger.signed_transaction.v1",
        eip712_hash="0x" + "cd" * 32,
        eip1559_hash=signing_hash,
        transaction_hash=transaction_hash,
        raw_transaction=raw_transaction,
        wallet=WALLET,
        wallet_nonce=0,
        chain_id=31337,
        decision_id=decision.decision_id,
        signer_identity=signer_identity,
        enclave_evidence=evidence.model_dump(mode="json"),
        signature=raw_signature(signing_key, bytes.fromhex(signing_hash[2:])),
    )
    settlement = SettlementEvidenceV1(
        schema_version="aegisledger.settlement_evidence.v1",
        transaction_hash=transaction_hash,
        block_hash="0x" + "ef" * 32,
        block_number=10,
        chain_id=31337,
        success=True,
        confirmations=2,
        observed_at=datetime.now(UTC),
    )
    complete = CompleteAttestationV1(
        schema_version="aegisledger.complete_attestation.v1",
        lifecycle_state="SETTLED",
        proposal=proposal,
        decision=decision,
        transaction_binding=binding,
        signed_transaction=signed,
        enclave_evidence=evidence,
        settlement=settlement,
    )
    return issuer, complete


def test_complete_attestation_verifies_without_mutable_service_state():
    issuer, complete = make_attestation()
    report = verify_complete_attestation(
        complete,
        issuer.public_key,
        allowed_build_measurements={BUILD},
    )
    assert report.valid, report.errors


def test_attestation_rejects_mutated_evidence_even_when_embedded_copy_is_changed_too():
    issuer, complete = make_attestation()
    changed = complete.enclave_evidence.model_copy(update={"wallet": "0x" + "99" * 20})
    signed = complete.signed_transaction.model_copy(
        update={"enclave_evidence": changed.model_dump(mode="json")}
    )
    forged = complete.model_copy(update={"enclave_evidence": changed, "signed_transaction": signed})
    report = verify_complete_attestation(
        forged,
        issuer.public_key,
        allowed_build_measurements={BUILD},
    )
    assert not report.valid
    assert any("wallet binding" in error or "signature" in error for error in report.errors)


def test_attestation_rejects_transaction_signature_and_unapproved_build():
    issuer, complete = make_attestation()
    forged_signature = "0x" + "00" * 65
    forged = complete.model_copy(
        update={
            "signed_transaction": complete.signed_transaction.model_copy(
                update={"signature": forged_signature}
            )
        }
    )
    report = verify_complete_attestation(
        forged,
        issuer.public_key,
        allowed_build_measurements={"different-build"},
    )
    assert not report.valid
    assert "signer build measurement is not approved" in report.errors
    assert "transaction signature is invalid" in report.errors


def test_attestation_rejects_raw_transaction_hash_substitution():
    issuer, complete = make_attestation()
    forged = complete.model_copy(
        update={
            "signed_transaction": complete.signed_transaction.model_copy(
                update={"raw_transaction": "0x02c1"}
            )
        }
    )

    report = verify_complete_attestation(
        forged,
        issuer.public_key,
        allowed_build_measurements={BUILD},
    )

    assert not report.valid
    assert "signed raw transaction hash mismatch" in report.errors
