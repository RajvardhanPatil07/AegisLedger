import json
import uuid
from types import SimpleNamespace

import pytest
from eth_hash.auto import keccak

from aegisledger.signer_client import GrpcSignerClient, SignerClientError

SIGNER_IDENTITY = "0x" + "12" * 20
PUBLIC_KEY = "0x04" + "34" * 64
SIGNATURE = "0x" + "56" * 65


class RequestFixture:
    def __init__(self):
        self.eip1559_hash = "0x" + "78" * 32
        self.wallet_nonce = 7
        self.chain_id = 31337
        self.decision = SimpleNamespace(decision_id=uuid.uuid4())

    def model_dump_json(self):
        return json.dumps({"schema_version": "aegisledger.sign_request.v1"})


def response_for(request, *, raw_transaction=b"\x02\xc0", transaction_hash=None):
    network_hash = transaction_hash or "0x" + keccak(raw_transaction).hex()
    evidence = {
        "transaction_hash": network_hash,
        "signing_hash": request.eip1559_hash,
        "decision_id": str(request.decision.decision_id),
        "signer_identity": SIGNER_IDENTITY,
    }
    return SimpleNamespace(
        eip1559_hash=request.eip1559_hash,
        wallet_nonce=request.wallet_nonce,
        chain_id=request.chain_id,
        decision_id=str(request.decision.decision_id),
        signer_identity=SIGNER_IDENTITY,
        signature=SIGNATURE,
        enclave_evidence_json=json.dumps(evidence).encode(),
        signed_transaction=raw_transaction,
        transaction_hash=network_hash,
        signing_hash=request.eip1559_hash,
    )


def identity_response():
    return SimpleNamespace(
        signer_identity=SIGNER_IDENTITY,
        secp256k1_public_key=PUBLIC_KEY,
        build_measurement="test-build",
    )


def test_client_serializes_authorization_and_validates_every_response_binding():
    request = RequestFixture()

    def sign_rpc(wire_request, timeout):
        assert timeout == 2.0
        assert json.loads(wire_request.authorization_json) == {
            "schema_version": "aegisledger.sign_request.v1"
        }
        return response_for(request)

    client = GrpcSignerClient(
        "test:50051",
        timeout_seconds=2.0,
        sign_rpc=sign_rpc,
        identity_rpc=lambda _request, _timeout: identity_response(),
    )

    assert client.identity().build_measurement == "test-build"
    result = client.sign(request)
    assert result.signing_hash == request.eip1559_hash
    assert result.transaction_hash == "0x" + keccak(result.signed_transaction).hex()
    assert result.decision_id == request.decision.decision_id


def test_client_rejects_raw_transaction_hash_or_evidence_substitution():
    request = RequestFixture()
    client = GrpcSignerClient(
        "test:50051",
        sign_rpc=lambda _wire, _timeout: response_for(
            request, transaction_hash="0x" + "00" * 32
        ),
        identity_rpc=lambda _request, _timeout: identity_response(),
    )

    with pytest.raises(SignerClientError, match="raw bytes"):
        client.sign(request)

    response = response_for(request)
    evidence = json.loads(response.enclave_evidence_json)
    evidence["decision_id"] = str(uuid.uuid4())
    response.enclave_evidence_json = json.dumps(evidence).encode()
    client = GrpcSignerClient(
        "test:50051",
        sign_rpc=lambda _wire, _timeout: response,
        identity_rpc=lambda _request, _timeout: identity_response(),
    )
    with pytest.raises(SignerClientError, match="evidence"):
        client.sign(request)


def test_network_client_requires_mtls_material_and_host_port_target():
    with pytest.raises(ValueError, match="host:port"):
        GrpcSignerClient("https://signer:50051")
    with pytest.raises(ValueError, match="mTLS"):
        GrpcSignerClient("signer:50051")
