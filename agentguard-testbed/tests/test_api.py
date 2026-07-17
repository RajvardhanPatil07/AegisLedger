from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient

from aegisledger.api import ServiceContainer, create_app
from aegisledger.auth import Principal, Role
from aegisledger.decisions import DecisionIssuer
from aegisledger.policies import PolicyRegistry
from aegisledger.policy import PolicyV1
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


def proposal_document(principal="researcher"):
    return {
        "schema_version": "aegisledger.proposal.v1",
        "principal_id": principal,
        "wallet": WALLET,
        "chain_id": 31337,
        "asset": "TUSDC",
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


def test_researcher_can_submit_proposal_and_receive_signed_decision():
    client, _ = client_for(Principal(subject="researcher", roles={Role.RESEARCHER}))
    response = client.post("/api/v1/proposals", json=proposal_document())
    assert response.status_code == 202
    body = response.json()
    assert body["state"] == "RESERVED"
    assert body["decision"]["verdict"] == "ALLOW"
    assert body["decision"]["proposal_hash"].startswith("0x")


def test_health_checks_distinguish_process_liveness_and_service_readiness():
    client, _ = client_for(Principal(subject="viewer", roles={Role.VIEWER}))
    assert client.get("/health/live").json() == {"status": "ok"}
    assert client.get("/health/ready").json() == {"status": "ready"}


def test_researcher_cannot_submit_for_another_principal():
    client, _ = client_for(Principal(subject="researcher", roles={Role.RESEARCHER}))
    response = client.post("/api/v1/proposals", json=proposal_document("different-user"))
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "PRINCIPAL_MISMATCH"


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


def test_openapi_exposes_versioned_capabilities_without_raw_signing_or_submission():
    client, _ = client_for(Principal(subject="auditor", roles={Role.AUDITOR}))
    paths = client.get("/openapi.json").json()["paths"]
    assert "/api/v1/proposals" in paths
    assert "/api/v1/policies/simulations" in paths
    assert "/api/v1/attestations/verifications" in paths
    assert "/api/v1/experiments" in paths
    forbidden_fragments = ("/sign", "raw-transaction", "submit-transaction")
    assert not any(fragment in path for path in paths for fragment in forbidden_fragments)
