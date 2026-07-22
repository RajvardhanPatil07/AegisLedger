import hashlib
import uuid
from datetime import UTC, datetime, timedelta

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from eth_hash.auto import keccak
from fastapi.testclient import TestClient

from aegisledger.api import ServiceContainer, create_app
from aegisledger.attestations import EnclaveEvidenceV1
from aegisledger.auth import AuthenticationError, Permission, Principal, PrincipalKind, Role
from aegisledger.contracts import LifecycleState
from aegisledger.decisions import DecisionIssuer
from aegisledger.policies import PolicyRegistry
from aegisledger.policy import PolicyV1
from aegisledger.service_accounts import (
    CompositeAuthenticator,
    MemoryServiceAccountStore,
    ServiceAccountManager,
)
from aegisledger.signer_client import SignerIdentity, SignerResult
from aegisledger.state import MemoryStateStore

WALLET = "0x" + "12" * 20
RECIPIENT = "0x" + "34" * 20


def policy_document():
    return {
        "schema_version": "aegisledger.policy.v1",
        "name": "api-research-policy",
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


def proposal_document(principal="researcher"):
    return {
        "schema_version": "aegisledger.proposal.v1",
        "principal_id": principal,
        "wallet": WALLET,
        "chain_id": 31337,
        "asset": "NATIVE:31337",
        "amount": 100,
        "intent": {"kind": "transfer", "recipient": RECIPIENT},
        "deadline": (datetime.now(UTC) + timedelta(minutes=5)).isoformat(),
        "idempotency_key": "api-proposal-001",
    }


def container_with_active_policy():
    registry = PolicyRegistry()
    version = registry.create(PolicyV1.model_validate(policy_document()), created_by="author")
    registry.approve(version.version_id, "admin-a")
    registry.approve(version.version_id, "admin-b")
    registry.activate(version.version_id, activated_by="admin-a")
    return ServiceContainer(
        policies=registry,
        state=MemoryStateStore(),
        decisions=DecisionIssuer.from_seed("api-test"),
    )


def client_for(principal: Principal, container=None):
    services = container or container_with_active_policy()
    app = create_app(services, authenticator=lambda _request: principal)
    return TestClient(app), services


class FakeSigner:
    def __init__(self):
        self.calls = 0
        self.key = ec.generate_private_key(ec.SECP256K1())
        public_bytes = self.key.public_key().public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )
        self.public_key = "0x" + public_bytes.hex()
        self.signer_identity = "0x" + keccak(public_bytes[1:])[-20:].hex()

    def _signature(self, digest: bytes) -> str:
        der = self.key.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        r, s = utils.decode_dss_signature(der)
        return "0x" + r.to_bytes(32, "big").hex() + s.to_bytes(32, "big").hex() + "00"

    def identity(self):
        return SignerIdentity(self.signer_identity, self.public_key, "test-build")

    def sign(self, request):
        self.calls += 1
        raw = b"\x02\xc0"
        transaction_hash = "0x" + keccak(raw).hex()
        issued_at = datetime.now(UTC)
        evidence_body = {
            "schema_version": "aegisledger.enclave_evidence.v1",
            "mode": "local-process-or-nitro",
            "build_measurement": "test-build",
            "signer_identity": self.signer_identity,
            "secp256k1_public_key": self.public_key,
            "transaction_hash": transaction_hash,
            "signing_hash": request.eip1559_hash,
            "proposal_hash": request.decision.proposal_hash,
            "policy_version_id": str(request.decision.policy_version_id),
            "policy_hash": request.decision.policy_hash,
            "state_version": request.decision.state_version,
            "reservation_id": str(request.reservation_id),
            "wallet": request.proposal.wallet,
            "principal_id": request.proposal.principal_id,
            "chain_id": request.chain_id,
            "wallet_nonce": request.wallet_nonce,
            "decision_id": str(request.decision.decision_id),
            "decision_nonce": str(request.decision.decision_nonce),
            "expires_at": request.expires_at.isoformat(),
            "issued_at": issued_at.isoformat(),
            "evidence_hash": "0x" + "00" * 32,
            "evidence_signature": "0x" + "00" * 65,
        }
        placeholder = EnclaveEvidenceV1.model_validate(evidence_body)
        evidence_digest = hashlib.sha256(placeholder.unsigned_payload()).digest()
        evidence = placeholder.model_copy(
            update={
                "evidence_hash": "0x" + evidence_digest.hex(),
                "evidence_signature": self._signature(evidence_digest),
            }
        )
        return SignerResult(
            signing_hash=request.eip1559_hash,
            transaction_hash=transaction_hash,
            signed_transaction=raw,
            wallet_nonce=request.wallet_nonce,
            chain_id=request.chain_id,
            decision_id=request.decision.decision_id,
            signer_identity=self.signer_identity,
            signature=self._signature(bytes.fromhex(request.eip1559_hash[2:])),
            enclave_evidence=evidence.model_dump(mode="json"),
        )


class FakeChain:
    chain_id = 31337

    def __init__(self):
        self.submissions = []

    def submit(self, submission):
        self.submissions.append(submission)
        return submission.transaction_hash

    def receipt(self, _transaction_hash):
        return None


def test_researcher_can_submit_proposal_and_receive_signed_decision():
    client, _ = client_for(Principal(subject="researcher", roles={Role.RESEARCHER}))
    response = client.post("/api/v1/proposals", json=proposal_document())
    assert response.status_code == 202
    body = response.json()
    assert body["state"] == "RESERVED"
    assert body["decision"]["verdict"] == "ALLOW"
    assert body["decision"]["proposal_hash"].startswith("0x")


def test_scoped_service_principal_can_submit_and_read_its_proposal():
    services = container_with_active_policy()
    writer = Principal(
        subject="researcher",
        roles=set(),
        permissions={Permission.PROPOSALS_WRITE},
        kind=PrincipalKind.SERVICE,
        organization_id="acme",
        environment_id="staging",
    )
    client, _ = client_for(writer, services)

    created = client.post("/api/v1/proposals", json=proposal_document())
    status = client.get(f"/api/v1/proposals/{created.json()['proposal_id']}")

    assert created.status_code == 202
    assert status.status_code == 200
    assert status.json()["state"] == "RESERVED"


def test_read_only_service_principal_cannot_submit_or_administer_policy():
    reader = Principal(
        subject="researcher",
        roles=set(),
        permissions={Permission.PROPOSALS_READ},
        kind=PrincipalKind.SERVICE,
        organization_id="acme",
        environment_id="staging",
    )
    client, _ = client_for(reader)

    proposal = client.post("/api/v1/proposals", json=proposal_document())
    policy = client.post("/api/v1/policies", json=policy_document())

    assert proposal.status_code == 403
    assert proposal.json()["error"]["code"] == "FORBIDDEN"
    assert policy.status_code == 403


def test_real_service_bearer_credential_authenticates_the_proposal_api():
    accounts = ServiceAccountManager(
        MemoryServiceAccountStore(),
        organization_id="acme",
        environment_id="staging",
    )
    issued = accounts.issue(
        name="checkout-agent",
        subject="researcher",
        permissions={Permission.PROPOSALS_WRITE},
    )

    def reject_oidc(_request):
        raise AuthenticationError("invalid bearer token")

    app = create_app(
        container_with_active_policy(),
        authenticator=CompositeAuthenticator(reject_oidc, accounts),
    )
    client = TestClient(app)

    response = client.post(
        "/api/v1/proposals",
        json=proposal_document(),
        headers={"authorization": f"Bearer {issued.token}"},
    )

    assert response.status_code == 202
    assert response.json()["state"] == "RESERVED"


def test_expired_proposal_is_retained_as_a_denied_decision():
    client, _ = client_for(Principal(subject="researcher", roles={Role.RESEARCHER}))
    expired = {**proposal_document(), "deadline": (datetime.now(UTC) - timedelta(1)).isoformat()}

    response = client.post("/api/v1/proposals", json=expired)

    assert response.status_code == 202
    assert response.json()["state"] == "DENIED"
    assert response.json()["decision"]["reason_codes"] == ["DEADLINE_EXPIRED"]


def test_execution_signs_and_submits_once_with_server_derived_payload():
    services = container_with_active_policy()
    signer = FakeSigner()
    chain = FakeChain()
    services.signer = signer
    services.chain_backends = {31337: chain}
    client, _ = client_for(Principal(subject="researcher", roles={Role.RESEARCHER}), services)
    proposal = client.post("/api/v1/proposals", json=proposal_document()).json()
    endpoint = f"/api/v1/proposals/{proposal['proposal_id']}/executions"
    request = {
        "wallet_nonce": 0,
        "value": 100,
        "gas_limit": 100_000,
        "max_fee_per_gas": 1_000_000_000,
        "max_priority_fee_per_gas": 100_000_000,
    }

    first = client.post(endpoint, json=request)
    second = client.post(endpoint, json=request)

    assert first.status_code == 202
    assert first.json()["state"] == "SUBMITTED"
    assert first.json()["submitted"] is True
    assert first.json()["created"] is True
    assert second.status_code == 202
    assert second.json()["created"] is False
    assert signer.calls == 1
    assert len(chain.submissions) == 1
    authorization = services.artifacts.get_execution(uuid.UUID(proposal["proposal_id"]))
    assert authorization is not None
    assert authorization.authorization.transaction.recipient == RECIPIENT
    assert authorization.authorization.eip1559_unsigned_payload.startswith("0x02")

    conflict = client.post(endpoint, json={**request, "gas_limit": 200_000})
    assert conflict.status_code == 409


def test_terminal_execution_exposes_idempotent_offline_verifiable_attestation():
    services = container_with_active_policy()
    services.allowed_build_measurements = {"test-build"}
    services.signer = FakeSigner()
    services.chain_backends = {31337: FakeChain()}
    client, _ = client_for(Principal(subject="researcher", roles={Role.RESEARCHER}), services)
    proposal = client.post("/api/v1/proposals", json=proposal_document()).json()
    proposal_id = uuid.UUID(proposal["proposal_id"])
    execution = client.post(
        f"/api/v1/proposals/{proposal_id}/executions",
        json={
            "wallet_nonce": 0,
            "value": 100,
            "gas_limit": 100_000,
            "max_fee_per_gas": 1_000_000_000,
            "max_priority_fee_per_gas": 100_000_000,
        },
    ).json()
    services.settlements.observe(
        execution["transaction_hash"],
        block_hash="0x" + "ef" * 32,
        block_number=10,
        success=True,
        confirmations=2,
    )
    services.state.transition(proposal_id, LifecycleState.SETTLED)

    first = client.get(f"/api/v1/proposals/{proposal_id}/attestation")
    second = client.get(f"/api/v1/proposals/{proposal_id}/attestation")

    assert first.status_code == 200
    assert first.json() == second.json()
    assert first.json()["lifecycle_state"] == "SETTLED"
    assert first.json()["signed_transaction"]["transaction_hash"] == execution["transaction_hash"]
    verification = client.post(
        "/api/v1/attestations/verifications",
        json={"attestation": first.json()},
    )
    assert verification.status_code == 200, verification.json()
    assert verification.json()["valid"] is True


def test_health_checks_distinguish_process_liveness_and_service_readiness():
    client, _ = client_for(Principal(subject="viewer", roles={Role.VIEWER}))
    assert client.get("/health/live").json() == {"status": "ok"}
    assert client.get("/health/ready").json() == {"status": "ready"}


def test_request_body_limit_rejects_oversized_payload_before_validation():
    services = container_with_active_policy()
    services.request_max_bytes = 128
    client, _ = client_for(Principal(subject="researcher", roles={Role.RESEARCHER}), services)

    response = client.post(
        "/api/v1/proposals",
        content=b"x" * 129,
        headers={"content-type": "application/json"},
    )

    assert response.status_code == 413
    assert response.json()["error"]["code"] == "PAYLOAD_TOO_LARGE"


def test_authenticated_requests_are_rate_limited_per_principal():
    services = container_with_active_policy()
    services.rate_limit_requests = 1
    client, _ = client_for(Principal(subject="researcher", roles={Role.RESEARCHER}), services)

    created = client.post("/api/v1/proposals", json=proposal_document())
    limited = client.get(f"/api/v1/proposals/{created.json()['proposal_id']}")

    assert created.status_code == 202
    assert limited.status_code == 429
    assert limited.json()["error"]["code"] == "RATE_LIMITED"


def test_researcher_cannot_submit_for_another_principal():
    client, _ = client_for(Principal(subject="researcher", roles={Role.RESEARCHER}))
    response = client.post("/api/v1/proposals", json=proposal_document("different-user"))
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "PRINCIPAL_MISMATCH"


def test_researcher_cannot_read_another_principals_proposal():
    services = container_with_active_policy()
    owner, _ = client_for(Principal(subject="researcher", roles={Role.RESEARCHER}), services)
    proposal_id = owner.post("/api/v1/proposals", json=proposal_document()).json()["proposal_id"]
    other, _ = client_for(Principal(subject="different-user", roles={Role.RESEARCHER}), services)

    response = other.get(f"/api/v1/proposals/{proposal_id}")

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "FORBIDDEN"


def test_viewer_cannot_submit_proposals():
    client, _ = client_for(Principal(subject="viewer", roles={Role.VIEWER}))
    response = client.post("/api/v1/proposals", json=proposal_document())
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "FORBIDDEN"


def test_policy_activation_api_enforces_two_distinct_approvals():
    container = ServiceContainer(
        policies=PolicyRegistry(),
        state=MemoryStateStore(),
        decisions=DecisionIssuer.from_seed("policy-api-test"),
    )
    admin_a, _ = client_for(Principal(subject="admin-a", roles={Role.POLICY_ADMIN}), container)
    created = admin_a.post("/api/v1/policies", json=policy_document())
    assert created.status_code == 201
    version_id = created.json()["version_id"]
    assert admin_a.post(f"/api/v1/policies/{version_id}/approvals").status_code == 200
    assert admin_a.post(f"/api/v1/policies/{version_id}/activate").status_code == 409

    admin_b, _ = client_for(Principal(subject="admin-b", roles={Role.POLICY_ADMIN}), container)
    assert admin_b.post(f"/api/v1/policies/{version_id}/approvals").status_code == 200
    assert admin_a.post(f"/api/v1/policies/{version_id}/activate").status_code == 200


def test_experiment_api_executes_and_retains_reproducible_results(tmp_path):
    container = container_with_active_policy()
    container.experiment_output_root = tmp_path
    client, _ = client_for(
        Principal(subject="researcher", roles={Role.RESEARCHER}),
        container,
    )
    queued = client.post(
        "/api/v1/experiments",
        json={
            "seed": "api-experiment",
            "scenarios": ["II-tool-poisoning"],
            "runs_per_scenario": 1,
        },
    )
    assert queued.status_code == 202
    experiment_id = queued.json()["experiment_id"]
    result = client.get(f"/api/v1/experiments/{experiment_id}")
    assert result.status_code == 200
    assert result.json()["status"] == "COMPLETED"
    assert result.json()["summary"]["raw_run_count"] == 5


def test_experiment_queue_enforces_per_principal_active_quota():
    from aegisledger.api import ExperimentRequest

    services = container_with_active_policy()
    services.experiment_max_active_per_principal = 1
    request = ExperimentRequest(seed="quota", scenarios=("II-tool-poisoning",), runs_per_scenario=1)
    services.queue_experiment(request, "researcher")

    try:
        services.queue_experiment(request, "researcher")
    except ValueError as error:
        assert "quota" in str(error)
    else:
        raise AssertionError("experiment quota was not enforced")


def test_openapi_exposes_versioned_capabilities_without_raw_signing_or_submission():
    client, _ = client_for(Principal(subject="auditor", roles={Role.AUDITOR}))
    document = client.get("/openapi.json").json()
    paths = document["paths"]
    assert "/api/v1/proposals" in paths
    assert "/api/v1/policies/simulations" in paths
    assert "/api/v1/attestations/verifications" in paths
    assert "/api/v1/experiments" in paths
    forbidden_fragments = ("/sign", "raw-transaction", "submit-transaction")
    assert not any(fragment in path for path in paths for fragment in forbidden_fragments)
    assert document["components"]["securitySchemes"]["BearerAuth"] == {
        "type": "http",
        "scheme": "bearer",
    }
