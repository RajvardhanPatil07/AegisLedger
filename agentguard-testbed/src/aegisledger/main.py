"""Production application factory."""

from __future__ import annotations

from fastapi import FastAPI

from .api import ServiceContainer, create_app
from .decisions import DecisionIssuer
from .observability import configure_logging, configure_observability
from .policies import PolicyRegistry, PolicyStore
from .policy import PolicyV1
from .postgres import PostgresPolicyStore, PostgresStateStore
from .settings import Settings
from .state import MemoryStateStore, StateStore


def build_services(settings: Settings) -> ServiceContainer:
    state: StateStore
    policies: PolicyStore
    if settings.state_backend == "postgres":
        assert settings.database_url is not None
        state = PostgresStateStore(settings.database_url)
        policies = PostgresPolicyStore(settings.database_url)
    else:
        state = MemoryStateStore()
        policies = PolicyRegistry()

    if settings.bootstrap_development_policy:
        try:
            policies.active()
        except LookupError:
            policy = PolicyV1.model_validate_json(
                settings.development_policy_path.read_text(encoding="utf-8")
            )
            version = policies.create(policy, created_by="development-bootstrap")
            policies.approve(version.version_id, "development-admin-a")
            policies.approve(version.version_id, "development-admin-b")
            policies.activate(version.version_id, activated_by="development-admin-a")

    return ServiceContainer(
        policies=policies,
        state=state,
        decisions=DecisionIssuer.from_seed(
            settings.policy_signing_seed.get_secret_value(),
            lifetime_seconds=settings.policy_decision_lifetime_seconds,
        ),
        allowed_build_measurements=set(settings.allowed_build_measurements),
        experiment_output_root=settings.experiment_output_root,
        commit_sha=settings.commit_sha,
    )


def create_application() -> FastAPI:
    settings = Settings()  # type: ignore[call-arg]
    configure_logging(service_name=settings.service_name, level=settings.log_level)
    application = create_app(build_services(settings))
    configure_observability(
        application,
        service_name=settings.service_name,
        otlp_endpoint=settings.otlp_endpoint,
    )
    return application
