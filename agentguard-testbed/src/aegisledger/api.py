"""Versioned proposal, policy, attestation, experiment, and audit APIs."""
from __future__ import annotations

import inspect
import json
import uuid
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Union

from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, ConfigDict, Field

from .audit import AuditJournal
from .auth import AuthenticationError, OIDCAuthenticator, Principal, Role
from .canonical import uuid7
from .contracts import DecisionTokenV1, LifecycleState, ProposalV1
from .decisions import DecisionIssuer, verify_decision_token
from .policies import PolicyRegistry, PolicyStatus, PolicyVersion
from .policy import PolicyV1
from .state import MemoryStateStore, ProposalRecord


class ApiError(Exception):
    def __init__(self, status_code: int, code: str, message: str) -> None:
        self.status_code = status_code
        self.code = code
        self.message = message
        super().__init__(message)


class SubmissionResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    proposal_id: uuid.UUID
    state: LifecycleState
    state_version: int
    created: bool
    decision: DecisionTokenV1


class ProposalStatusResponse(BaseModel):
    proposal_id: uuid.UUID
    state: LifecycleState
    state_version: int
    reason_codes: tuple[str, ...]
    reservation_id: uuid.UUID | None


class PolicyVersionResponse(BaseModel):
    version_id: uuid.UUID
    policy_hash: str
    status: PolicyStatus
    approvals: tuple[str, ...]


class PolicySimulationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    policy: PolicyV1
    proposal: ProposalV1


class PolicySimulationResponse(BaseModel):
    verdict: str
    reason_codes: tuple[str, ...]
    policy_hash: str


class AttestationVerificationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: DecisionTokenV1


class AttestationVerificationResponse(BaseModel):
    valid: bool
    signer_identity: str


class ExperimentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    seed: str = Field(min_length=1, max_length=128)
    scenarios: tuple[str, ...] = ()
    runs_per_scenario: int = Field(default=12, gt=0, le=1_000)


class ExperimentResponse(BaseModel):
    experiment_id: uuid.UUID
    status: str
    seed: str


Authenticator = Callable[[Request], Union[Principal, Awaitable[Principal]]]


@dataclass
class ServiceContainer:
    policies: PolicyRegistry
    state: MemoryStateStore
    decisions: DecisionIssuer
    audit: AuditJournal = field(default_factory=AuditJournal)
    issued_decisions: dict[uuid.UUID, DecisionTokenV1] = field(default_factory=dict)
    experiments: dict[uuid.UUID, ExperimentResponse] = field(default_factory=dict)

    def submit(self, proposal: ProposalV1, actor: str) -> SubmissionResponse:
        version = self.policies.active()
        result = self.state.reserve(proposal, version.policy)
        decision = self.issued_decisions.get(result.record.proposal.proposal_id)
        if decision is None:
            decision = self.decisions.issue(result.record, version)
            self.state.register_decision_nonce(decision.decision_nonce)
            self.issued_decisions[result.record.proposal.proposal_id] = decision
            self.audit.append(
                "POLICY_DECISION_ISSUED",
                actor,
                {
                    "proposal_id": str(result.record.proposal.proposal_id),
                    "state": result.record.state.value,
                    "decision_id": str(decision.decision_id),
                    "policy_hash": version.policy_hash,
                },
                aggregate_id=result.record.proposal.proposal_id,
            )
        return SubmissionResponse(
            proposal_id=result.record.proposal.proposal_id,
            state=result.record.state,
            state_version=result.record.state_version,
            created=result.created,
            decision=decision,
        )


def _policy_response(version: PolicyVersion) -> PolicyVersionResponse:
    return PolicyVersionResponse(
        version_id=version.version_id,
        policy_hash=version.policy_hash,
        status=version.status,
        approvals=tuple(sorted(version.approvals)),
    )


def _status_response(record: ProposalRecord) -> ProposalStatusResponse:
    return ProposalStatusResponse(
        proposal_id=record.proposal.proposal_id,
        state=record.state,
        state_version=record.state_version,
        reason_codes=record.reason_codes,
        reservation_id=record.reservation_id,
    )


def create_app(
    services: ServiceContainer,
    *,
    authenticator: Authenticator | None = None,
) -> FastAPI:
    authenticate = authenticator or OIDCAuthenticator.from_environment()
    app = FastAPI(
        title="AegisLedger API",
        version="1.0.0",
        docs_url="/api/docs",
        redoc_url=None,
    )

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > 1_000_000:
            return JSONResponse(
                status_code=413,
                content={"error": {"code": "PAYLOAD_TOO_LARGE", "message": "request body exceeds 1 MB"}},
            )
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        return response

    @app.exception_handler(ApiError)
    async def api_error_handler(_request: Request, exc: ApiError):
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": {"code": exc.code, "message": exc.message}},
        )

    @app.exception_handler(AuthenticationError)
    async def authentication_error_handler(_request: Request, _exc: AuthenticationError):
        return JSONResponse(
            status_code=401,
            headers={"WWW-Authenticate": "Bearer"},
            content={"error": {"code": "UNAUTHENTICATED", "message": "authentication required"}},
        )

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(_request: Request, exc: RequestValidationError):
        return JSONResponse(
            status_code=422,
            content={
                "error": {
                    "code": "VALIDATION_ERROR",
                    "message": "request validation failed",
                    "details": exc.errors(),
                }
            },
        )

    async def current_principal(request: Request) -> Principal:
        value = authenticate(request)
        return await value if inspect.isawaitable(value) else value

    def require_roles(*allowed: Role):
        async def authorize(principal: Principal = Depends(current_principal)) -> Principal:
            if not principal.roles.intersection(allowed):
                raise ApiError(403, "FORBIDDEN", "role does not permit this operation")
            return principal

        return authorize

    @app.get("/health/live", include_in_schema=False)
    async def liveness():
        return {"status": "ok"}

    @app.post("/api/v1/proposals", response_model=SubmissionResponse, status_code=202)
    async def submit_proposal(
        proposal: ProposalV1,
        principal: Principal = Depends(require_roles(Role.RESEARCHER)),
    ):
        if proposal.principal_id != principal.subject:
            raise ApiError(403, "PRINCIPAL_MISMATCH", "proposal principal must match authenticated subject")
        try:
            return services.submit(proposal, principal.subject)
        except LookupError as exc:
            raise ApiError(503, "NO_ACTIVE_POLICY", "no active policy is available") from exc

    @app.get("/api/v1/proposals/{proposal_id}", response_model=ProposalStatusResponse)
    async def proposal_status(
        proposal_id: uuid.UUID,
        _principal: Principal = Depends(
            require_roles(Role.VIEWER, Role.RESEARCHER, Role.POLICY_ADMIN, Role.AUDITOR)
        ),
    ):
        record = services.state.get(proposal_id)
        if record is None:
            raise ApiError(404, "PROPOSAL_NOT_FOUND", "proposal does not exist")
        return _status_response(record)

    @app.post("/api/v1/policies", response_model=PolicyVersionResponse, status_code=201)
    async def create_policy(
        policy: PolicyV1,
        principal: Principal = Depends(require_roles(Role.POLICY_ADMIN)),
    ):
        version = services.policies.create(policy, created_by=principal.subject)
        services.audit.append(
            "POLICY_VERSION_CREATED",
            principal.subject,
            {"version_id": str(version.version_id), "policy_hash": version.policy_hash},
            aggregate_id=version.version_id,
        )
        return _policy_response(version)

    @app.post("/api/v1/policies/{version_id}/approvals", response_model=PolicyVersionResponse)
    async def approve_policy(
        version_id: uuid.UUID,
        principal: Principal = Depends(require_roles(Role.POLICY_ADMIN)),
    ):
        try:
            version = services.policies.approve(version_id, principal.subject)
        except KeyError as exc:
            raise ApiError(404, "POLICY_NOT_FOUND", "policy version does not exist") from exc
        return _policy_response(version)

    @app.post("/api/v1/policies/{version_id}/activate", response_model=PolicyVersionResponse)
    async def activate_policy(
        version_id: uuid.UUID,
        principal: Principal = Depends(require_roles(Role.POLICY_ADMIN)),
    ):
        try:
            version = services.policies.activate(version_id, activated_by=principal.subject)
        except PermissionError as exc:
            raise ApiError(409, "APPROVALS_REQUIRED", str(exc)) from exc
        except KeyError as exc:
            raise ApiError(404, "POLICY_NOT_FOUND", "policy version does not exist") from exc
        services.audit.append(
            "POLICY_VERSION_ACTIVATED",
            principal.subject,
            {"version_id": str(version.version_id), "policy_hash": version.policy_hash},
            aggregate_id=version.version_id,
        )
        return _policy_response(version)

    @app.post("/api/v1/policies/simulations", response_model=PolicySimulationResponse)
    async def simulate_policy(
        request: PolicySimulationRequest,
        _principal: Principal = Depends(require_roles(Role.RESEARCHER, Role.POLICY_ADMIN)),
    ):
        reasons = services.state.simulate(request.proposal, request.policy)
        return PolicySimulationResponse(
            verdict="DENY" if reasons else "ALLOW",
            reason_codes=reasons,
            policy_hash=request.policy.policy_hash(),
        )

    @app.post(
        "/api/v1/attestations/verifications",
        response_model=AttestationVerificationResponse,
    )
    async def verify_attestation(
        request: AttestationVerificationRequest,
        _principal: Principal = Depends(require_roles(Role.AUDITOR, Role.RESEARCHER)),
    ):
        return AttestationVerificationResponse(
            valid=verify_decision_token(request.decision, services.decisions.public_key),
            signer_identity=request.decision.policy_signer,
        )

    @app.post("/api/v1/experiments", response_model=ExperimentResponse, status_code=202)
    async def execute_experiment(
        request: ExperimentRequest,
        _principal: Principal = Depends(require_roles(Role.RESEARCHER)),
    ):
        experiment = ExperimentResponse(experiment_id=uuid7(), status="QUEUED", seed=request.seed)
        services.experiments[experiment.experiment_id] = experiment
        return experiment

    @app.get("/api/v1/experiments/{experiment_id}", response_model=ExperimentResponse)
    async def experiment_result(
        experiment_id: uuid.UUID,
        _principal: Principal = Depends(require_roles(Role.VIEWER, Role.RESEARCHER, Role.AUDITOR)),
    ):
        try:
            return services.experiments[experiment_id]
        except KeyError as exc:
            raise ApiError(404, "EXPERIMENT_NOT_FOUND", "experiment does not exist") from exc

    @app.get("/api/v1/audit/events/stream")
    async def audit_stream(
        _principal: Principal = Depends(require_roles(Role.AUDITOR)),
    ):
        async def events():
            for event in services.audit.events:
                yield f"id: {event.sequence}\nevent: {event.event_type}\ndata: {event.model_dump_json()}\n\n"

        return StreamingResponse(events(), media_type="text/event-stream")

    return app
