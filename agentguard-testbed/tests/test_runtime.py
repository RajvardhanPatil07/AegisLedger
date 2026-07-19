import logging
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient
from pydantic import ValidationError
from tests_support import active_services

from aegisledger.api import create_app
from aegisledger.auth import Principal, Role
from aegisledger.observability import JsonLogFormatter, configure_observability
from aegisledger.settings import Settings

ROOT = Path(__file__).resolve().parent.parent


def test_production_configuration_requires_durable_state():
    with pytest.raises(ValidationError, match="production requires postgres"):
        Settings(
            environment="production",
            state_backend="memory",
            policy_signing_seed="test-seed",
            commit_sha="a" * 40,
            _env_file=None,
        )


def test_allowed_build_measurements_accept_csv_environment_value(monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOWED_BUILD_MEASUREMENTS", "trusted-a, trusted-b")

    settings = Settings(
        environment="test",
        state_backend="memory",
        policy_signing_seed="test-seed",
        commit_sha="a" * 40,
        _env_file=None,
    )

    assert settings.allowed_build_measurements == ("trusted-a", "trusted-b")


def test_metrics_and_request_ids_are_exposed_without_entering_signing_path():
    app = create_app(
        active_services(),
        authenticator=lambda _request: Principal(subject="viewer", roles={Role.VIEWER}),
    )
    configure_observability(app, service_name="test-api", otlp_endpoint=None)
    client = TestClient(app)
    response = client.get("/health/live")
    assert response.status_code == 200
    assert response.headers["x-request-id"]
    metrics = client.get("/metrics/")
    assert metrics.status_code == 200
    assert "aegisledger_http_requests_total" in metrics.text


def test_json_log_formatter_emits_machine_readable_context():
    record = logging.LogRecord("test", logging.INFO, __file__, 1, "ready", (), None)
    record.request_id = "request-1"
    formatted = JsonLogFormatter(service_name="test-api").format(record)
    assert '"service":"test-api"' in formatted
    assert '"request_id":"request-1"' in formatted


def test_compose_uses_published_opentelemetry_collector_image():
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))

    assert compose["services"]["otel-collector"]["image"].startswith(
        "ghcr.io/open-telemetry/opentelemetry-collector-releases/"
        "opentelemetry-collector-contrib:0.156.0@sha256:"
    )


def test_all_third_party_runtime_images_are_digest_pinned():
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    built_services = {
        "api",
        "web",
        "signer",
        "experiment-data-init",
        "runtime-secrets-init",
    }

    for name, service in compose["services"].items():
        if name not in built_services:
            assert "@sha256:" in service["image"], f"{name} must use an immutable image digest"


def test_compose_stages_file_backed_secrets_for_nonroot_services():
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    services = compose["services"]
    initializer = services["runtime-secrets-init"]

    assert initializer["user"] == "0:0"
    assert initializer["read_only"] is True
    assert "no-new-privileges:true" in initializer["security_opt"]
    assert initializer["entrypoint"] == ["stage-runtime-secrets"]
    assert set(initializer["volumes"]) == {
        "signer-runtime-secrets:/var/lib/aegisledger-secrets/signer",
        "api-runtime-secrets:/var/lib/aegisledger-secrets/api",
    }
    assert initializer["secrets"] == [
        {
            "source": "signer-private-key",
            "target": "/run/source/signer-private-key",
        },
        {
            "source": "signer-tls-key",
            "target": "/run/source/signer-tls-key",
        },
        {
            "source": "api-client-tls-key",
            "target": "/run/source/api-client-tls-key",
        },
    ]

    for service_name, volume in {
        "signer": "signer-runtime-secrets:/run/secrets:ro",
        "api": "api-runtime-secrets:/run/secrets:ro",
    }.items():
        service = services[service_name]
        assert "secrets" not in service
        assert volume in service["volumes"]
        assert service["depends_on"]["runtime-secrets-init"] == {
            "condition": "service_completed_successfully"
        }

    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    stage_script = (ROOT / "scripts" / "stage_runtime_secrets.sh").read_text(
        encoding="utf-8"
    )
    assert (
        "COPY scripts/stage_runtime_secrets.sh /usr/local/bin/stage-runtime-secrets"
        in dockerfile
    )
    assert "chmod 0400" in stage_script
    assert "65532 65532" in stage_script
    assert "10001 10001" in stage_script


def test_runtime_smoke_is_shipped_in_api_image():
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")

    assert "COPY scripts/runtime_smoke.py /app/scripts/runtime_smoke.py" in dockerfile


def test_compose_api_port_is_loopback_only_and_locally_overridable():
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))

    assert compose["services"]["api"]["ports"] == [
        "127.0.0.1:${AEGIS_API_PORT:-8000}:8000"
    ]


def test_api_runtime_uses_current_digest_pinned_python_base():
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")

    assert (
        "ghcr.io/astral-sh/uv:0.11.29@sha256:"
        "eb2843a1e56fd9e30c7276ce1a52cba86e64c7b385f5e3279a0e08e02dd058fc AS uv"
        in dockerfile
    )
    assert (
        "FROM python:3.13.14-slim-bookworm@sha256:"
        "9d7f287598e1a5a978c015ee176d8216435aaf335ed69ac3c38dd1bbb10e8d64 AS runtime"
        in dockerfile
    )


def test_signer_build_and_runtime_bases_are_digest_pinned():
    dockerfile = (ROOT / "signer" / "Dockerfile").read_text(encoding="utf-8")

    assert (
        "rust:1.97.1-bookworm@sha256:"
        "77fac8b98f9f46062bb680b6d25d5bcaabfc400143952ebc572e924bcbedc3fa AS build"
        in dockerfile
    )
    assert (
        "gcr.io/distroless/cc-debian12:nonroot@sha256:"
        "66aa873a4a14fb164aa01296058efd8253744606d72715e45acface073359faa"
        in dockerfile
    )


def test_console_is_loopback_only_and_has_no_signer_dependency():
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    web = compose["services"]["web"]

    assert web["ports"] == ["127.0.0.1:${AEGIS_WEB_PORT:-4173}:8080"]
    assert set(web["depends_on"]) == {"api"}
    assert web["read_only"] is True
    assert "no-new-privileges:true" in web["security_opt"]
    assert web["healthcheck"]["test"][-1] == "http://127.0.0.1:8080/"


def test_console_images_are_current_and_digest_pinned():
    dockerfile = (ROOT / "web" / "Dockerfile").read_text(encoding="utf-8")

    assert (
        "node:24.17.0-alpine3.24@sha256:"
        "156b55f92e98ccd5ef49578a8cea0df4679826564bad1c9d4ef04462b9f0ded6"
        in dockerfile
    )
    assert (
        "nginx:1.30.4-alpine3.24-slim@sha256:"
        "ddde39c6e51f02fde7410c2e9c234cf2d0a4c7bdbbe176aeb37d8ad7ab4eb58c"
        in dockerfile
    )


def test_keycloak_console_client_is_self_contained_and_emits_api_roles():
    realm = yaml.safe_load(
        (ROOT / "deploy" / "keycloak" / "aegisledger-realm.json").read_text(
            encoding="utf-8"
        )
    )
    client = next(
        item for item in realm["clients"] if item["clientId"] == "aegisledger-console"
    )

    assert client["protocol"] == "openid-connect"
    assert client["defaultClientScopes"] == ["aegisledger-api-audience"]
    mappers = {item["name"]: item for item in client["protocolMappers"]}
    assert mappers["subject"]["protocolMapper"] == "oidc-sub-mapper"
    assert mappers["subject"]["config"]["access.token.claim"] == "true"
    assert mappers["realm-roles"]["config"]["claim.name"] == "realm_access.roles"
    assert mappers["realm-roles"]["config"]["access.token.claim"] == "true"
    assert all(
        user.get("email") and user.get("firstName") and user.get("lastName")
        for user in realm["users"]
    )


def test_formal_checker_has_digest_pinned_container_fallback():
    checker = (ROOT / "scripts" / "check_formal.sh").read_text(encoding="utf-8")

    assert (
        "eclipse-temurin:21-jre-jammy@sha256:"
        "d63bd8d9b171999cbed8576f2c76e874dd4856791a358536e5c4d407e77edc13"
        in checker
    )


def test_security_workflow_enables_containerd_store_for_local_attestations():
    workflow = yaml.safe_load(
        (ROOT.parent / ".github" / "workflows" / "security.yml").read_text(
            encoding="utf-8"
        )
    )
    steps = workflow["jobs"]["container-images"]["steps"]
    setup = next(step for step in steps if step.get("name") == "Enable containerd image store")

    assert setup["uses"] == (
        "docker/setup-docker-action@6d7cfa65f60a9dda7b46e5513fa982536f3c9877"
    )
    daemon_config = yaml.safe_load(setup["with"]["daemon-config"])
    assert daemon_config == {"features": {"containerd-snapshotter": True}}


def test_security_workflow_writes_action_sboms_inside_artifact_directory():
    workflow = yaml.safe_load(
        (ROOT.parent / ".github" / "workflows" / "security.yml").read_text(
            encoding="utf-8"
        )
    )
    steps = workflow["jobs"]["container-images"]["steps"]
    sbom_steps = [
        step for step in steps if step.get("name", "").endswith("CycloneDX SBOM")
    ]

    assert len(sbom_steps) == 3
    assert {step["with"]["output"] for step in sbom_steps} == {
        "agentguard-testbed/artifacts/aegisledger-api.cdx.json",
        "agentguard-testbed/artifacts/aegisledger-signer.cdx.json",
        "agentguard-testbed/artifacts/aegisledger-console.cdx.json",
    }
