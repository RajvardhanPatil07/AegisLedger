"""Production application factory."""

from __future__ import annotations

from fastapi import FastAPI

from .api import ServiceContainer, create_app
from .artifact_store import (
    AuthorizationArtifactStore,
    MemoryAuthorizationArtifactStore,
    PostgresAuthorizationArtifactStore,
)
from .attestation_store import (
    AttestationStore,
    MemoryAttestationStore,
    PostgresAttestationStore,
)
from .audit import AuditJournal, EventJournal, PostgresAuditJournal
from .chain import ChainBackend, JsonRpcChainBackend
from .decisions import DecisionIssuer
from .experiment_store import ExperimentStore, MemoryExperimentStore, PostgresExperimentStore
from .observability import configure_logging, configure_observability
from .policies import PolicyRegistry, PolicyStore
from .policy import PolicyV1
from .postgres import PostgresPolicyStore, PostgresStateStore
from .rate_limit import MemoryRateLimiter, PostgresRateLimiter, RateLimiter
from .reconciler import (
    MemorySettlementStore,
    PostgresSettlementStore,
    ReceiptBackend,
    SettlementReconciler,
    SettlementStore,
)
from .settings import Settings
from .signer_client import GrpcSignerClient
from .state import MemoryStateStore, StateStore


def build_services(settings: Settings) -> ServiceContainer:
    state: StateStore
    policies: PolicyStore
    artifacts: AuthorizationArtifactStore
    attestations: AttestationStore
    settlements: SettlementStore
    audit: EventJournal
    experiments: ExperimentStore
    rate_limiter: RateLimiter
    if settings.state_backend == "postgres":
        assert settings.database_url is not None
        state = PostgresStateStore(settings.database_url)
        policies = PostgresPolicyStore(settings.database_url)
        artifacts = PostgresAuthorizationArtifactStore(settings.database_url)
        attestations = PostgresAttestationStore(settings.database_url)
        settlements = PostgresSettlementStore(settings.database_url)
        audit = PostgresAuditJournal(settings.database_url)
        experiments = PostgresExperimentStore(settings.database_url)
        rate_limiter = PostgresRateLimiter(settings.database_url)
    else:
        state = MemoryStateStore()
        policies = PolicyRegistry()
        artifacts = MemoryAuthorizationArtifactStore()
        attestations = MemoryAttestationStore()
        settlements = MemorySettlementStore()
        audit = AuditJournal()
        experiments = MemoryExperimentStore()
        rate_limiter = MemoryRateLimiter()

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

    signer = None
    if settings.signer_target is not None:
        assert settings.signer_ca_path is not None
        assert settings.signer_client_certificate_path is not None
        assert settings.signer_client_private_key_path is not None
        signer = GrpcSignerClient(
            settings.signer_target,
            root_ca=settings.signer_ca_path,
            client_certificate=settings.signer_client_certificate_path,
            client_private_key=settings.signer_client_private_key_path,
            timeout_seconds=settings.signer_timeout_seconds,
        )
    chain_backends: dict[int, ChainBackend] = {}
    receipt_backends: dict[int, ReceiptBackend] = {}
    if settings.rpc_url is not None:
        authorization_header = (
            settings.rpc_authorization_header.get_secret_value()
            if settings.rpc_authorization_header is not None
            else None
        )
        backend = JsonRpcChainBackend(
            settings.rpc_url,
            expected_chain_id=settings.rpc_chain_id,
            authorization_header=authorization_header,
            timeout_seconds=settings.rpc_timeout_seconds,
            finality_confirmations=settings.finality_confirmations,
            allow_insecure_http=settings.environment != "production",
        )
        chain_backends[settings.rpc_chain_id] = backend
        receipt_backends[settings.rpc_chain_id] = backend

    services = ServiceContainer(
        policies=policies,
        state=state,
        decisions=DecisionIssuer.from_seed(
            settings.policy_signing_seed.get_secret_value(),
            lifetime_seconds=settings.policy_decision_lifetime_seconds,
        ),
        audit=audit,
        experiments=experiments,
        experiment_max_active_per_principal=settings.experiment_max_active_per_principal,
        rate_limiter=rate_limiter,
        rate_limit_requests=settings.rate_limit_requests,
        rate_limit_window_seconds=settings.rate_limit_window_seconds,
        request_max_bytes=settings.request_max_bytes,
        artifacts=artifacts,
        attestations=attestations,
        signer=signer,
        chain_backends=chain_backends,
        settlements=settlements,
        eip712_domain_separator=settings.eip712_domain_separator,
        allowed_build_measurements=set(settings.allowed_build_measurements),
        experiment_output_root=settings.experiment_output_root,
        commit_sha=settings.commit_sha,
    )
    if chain_backends:
        services.settlement_reconciler = SettlementReconciler(
            state,
            settlements,
            receipt_backends,
            finality=settings.finality_confirmations,
        )
    return services


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
