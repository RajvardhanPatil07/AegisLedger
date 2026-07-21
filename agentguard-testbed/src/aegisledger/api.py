"""Versioned proposal, policy, attestation, experiment, and audit APIs."""

from __future__ import annotations

import asyncio
import inspect
import logging
import os
import threading
import uuid
from collections.abc import Awaitable, Callable
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from fastapi import BackgroundTasks, Depends, FastAPI, Request, Security
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from starlette.concurrency import run_in_threadpool
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from .artifact_store import (
    AuthorizationArtifactStore,
    MemoryAuthorizationArtifactStore,
    StoredExecutionV1,
)
from .attestation_store import AttestationStore, MemoryAttestationStore
from .attestations import (
    CompleteAttestationV1,
    EnclaveEvidenceV1,
    SettlementEvidenceV1,
    verify_complete_attestation,
)
from .audit import AuditJournal, EventJournal
from .auth import AuthenticationError, OIDCAuthenticator, Permission, Principal, Role
from .chain import ChainBackend, ChainSubmission
from .contracts import DecisionTokenV1, LifecycleState, ProposalV1, SignedTransactionV1
from .decisions import DecisionIssuer, verify_decision_token
from .eip1559 import encode_unsigned_eip1559
from .evaluation import ExperimentRunner, Scenario, create_experiment_spec
from .experiment_store import (
    ExperimentJob,
    ExperimentResponseV1,
    ExperimentStore,
    MemoryExperimentStore,
)
from .policies import PolicyStatus, PolicyStore, PolicyVersion
from .policy import PolicyV1
from .rate_limit import MemoryRateLimiter, RateLimiter
from .reconciler import MemorySettlementStore, SettlementReconciler, SettlementStore
from .signer_client import Signer, SignerClientError
from .signing import TransactionBindingV1, TransactionSignRequestV1, keccak_hex
from .state import ProposalRecord, StateStore


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


class ExecutionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    wallet_nonce: int = Field(ge=0)
    value: int = Field(ge=0)
    gas_limit: int = Field(gt=0)
    max_fee_per_gas: int = Field(gt=0)
    max_priority_fee_per_gas: int = Field(ge=0)

    @model_validator(mode="after")
    def priority_fee_within_maximum(self) -> ExecutionRequest:
        if self.max_priority_fee_per_gas > self.max_fee_per_gas:
            raise ValueError("priority fee cannot exceed maximum fee")
        return self


class ExecutionResponse(BaseModel):
    proposal_id: uuid.UUID
    transaction_id: uuid.UUID
    state: LifecycleState
    state_version: int
    signing_hash: str
    transaction_hash: str
    signer_identity: str
    submitted: bool
    created: bool


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

    decision: DecisionTokenV1 | None = None
    attestation: CompleteAttestationV1 | None = None

    @model_validator(mode="after")
    def exactly_one_artifact(self) -> AttestationVerificationRequest:
        if (self.decision is None) == (self.attestation is None):
            raise ValueError("provide exactly one decision or complete attestation")
        return self


class AttestationVerificationResponse(BaseModel):
    valid: bool
    signer_identity: str
    errors: tuple[str, ...] = ()


class ExperimentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    seed: str = Field(min_length=1, max_length=128)
    scenarios: tuple[Scenario, ...] = ()
    runs_per_scenario: int = Field(default=12, gt=0, le=1_000)

    @field_validator("scenarios", mode="before")
    @classmethod
    def accept_scenario_array(cls, value: object) -> tuple[object, ...]:
        if not isinstance(value, (list, tuple)):
            raise TypeError("scenarios must be an array")
        return tuple(value)


Authenticator = Callable[[Request], Principal | Awaitable[Principal]]
logger = logging.getLogger(__name__)


class RequestBodyLimitMiddleware:
    def __init__(self, app: ASGIApp, *, max_bytes: int) -> None:
        if max_bytes < 1:
            raise ValueError("request body limit must be positive")
        self._app = app
        self._max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return
        headers = dict(scope.get("headers", ()))
        content_length = headers.get(b"content-length")
        if content_length is not None:
            try:
                declared = int(content_length)
            except ValueError:
                await self._reject(scope, receive, send, 400, "INVALID_CONTENT_LENGTH")
                return
            if declared < 0:
                await self._reject(scope, receive, send, 400, "INVALID_CONTENT_LENGTH")
                return
            if declared > self._max_bytes:
                await self._reject(scope, receive, send, 413, "PAYLOAD_TOO_LARGE")
                return

        messages: list[Message] = []
        total = 0
        while True:
            message = await receive()
            messages.append(message)
            if message["type"] == "http.disconnect":
                break
            if message["type"] != "http.request":
                continue
            total += len(message.get("body", b""))
            if total > self._max_bytes:
                await self._reject(scope, receive, send, 413, "PAYLOAD_TOO_LARGE")
                return
            if not message.get("more_body", False):
                break

        index = 0

        async def replay() -> Message:
            nonlocal index
            if index < len(messages):
                message = messages[index]
                index += 1
                return message
            return {"type": "http.request", "body": b"", "more_body": False}

        await self._app(scope, replay, send)

    @staticmethod
    async def _reject(
        scope: Scope,
        receive: Receive,
        send: Send,
        status_code: int,
        code: str,
    ) -> None:
        response = JSONResponse(
            status_code=status_code,
            content={
                "error": {
                    "code": code,
                    "message": "request body exceeds the configured limit"
                    if status_code == 413
                    else "content-length header is invalid",
                }
            },
        )
        await response(scope, receive, send)


@dataclass
class ServiceContainer:
    policies: PolicyStore
    state: StateStore
    decisions: DecisionIssuer
    audit: EventJournal = field(default_factory=AuditJournal)
    artifacts: AuthorizationArtifactStore = field(default_factory=MemoryAuthorizationArtifactStore)
    signer: Signer | None = None
    chain_backends: dict[int, ChainBackend] = field(default_factory=dict)
    settlements: SettlementStore = field(default_factory=MemorySettlementStore)
    attestations: AttestationStore = field(default_factory=MemoryAttestationStore)
    settlement_reconciler: SettlementReconciler | None = None
    settlement_poll_seconds: float = 2.0
    eip712_domain_separator: str = field(default_factory=lambda: "0x" + "00" * 32)
    experiments: ExperimentStore = field(default_factory=MemoryExperimentStore)
    rate_limiter: RateLimiter = field(default_factory=MemoryRateLimiter)
    rate_limit_requests: int = 120
    rate_limit_window_seconds: int = 60
    request_max_bytes: int = 1_000_000
    experiment_max_active_per_principal: int = 2
    allowed_build_measurements: set[str] = field(default_factory=lambda: {"development-unmeasured"})
    experiment_runner: ExperimentRunner = field(default_factory=ExperimentRunner)
    experiment_output_root: Path = field(default_factory=lambda: Path("artifacts/experiments"))
    commit_sha: str = field(default_factory=lambda: os.getenv("AEGISLEDGER_COMMIT_SHA", "0" * 40))
    _execution_lock: threading.RLock = field(
        default_factory=threading.RLock,
        init=False,
        repr=False,
    )

    def submit(self, proposal: ProposalV1, actor: str) -> SubmissionResponse:
        version = self.policies.active()
        result = self.state.reserve(proposal, version.policy)
        decision = self.artifacts.get_decision(result.record.proposal.proposal_id)
        if decision is None:
            candidate = self.decisions.issue(result.record, version)
            decision, created = self.artifacts.put_decision(
                result.record.proposal.proposal_id, candidate
            )
            if created:
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

    def _authorization(
        self,
        record: ProposalRecord,
        decision: DecisionTokenV1,
        request: ExecutionRequest,
    ) -> TransactionSignRequestV1:
        if record.reservation_id is None:
            raise ValueError("proposal has no active reservation")
        proposal = record.proposal
        if proposal.intent.kind == "transfer":
            recipient = proposal.intent.recipient
            contract = None
            selector = None
            calldata = "0x"
            target = recipient
        else:
            recipient = None
            contract = proposal.intent.contract
            selector = proposal.intent.selector
            calldata = proposal.intent.calldata
            target = contract
        transaction = TransactionBindingV1(
            operation=proposal.intent.kind,
            wallet=proposal.wallet,
            chain_id=proposal.chain_id,
            wallet_nonce=request.wallet_nonce,
            asset=proposal.asset,
            amount=proposal.amount,
            recipient=recipient,
            contract=contract,
            selector=selector,
            calldata=calldata,
            value=request.value,
            gas_limit=request.gas_limit,
            max_fee_per_gas=request.max_fee_per_gas,
            max_priority_fee_per_gas=request.max_priority_fee_per_gas,
        )
        unsigned_payload = encode_unsigned_eip1559(
            chain_id=proposal.chain_id,
            nonce=request.wallet_nonce,
            max_priority_fee_per_gas=request.max_priority_fee_per_gas,
            max_fee_per_gas=request.max_fee_per_gas,
            gas_limit=request.gas_limit,
            to=target,
            value=request.value,
            calldata=calldata,
        )
        if len(self.eip712_domain_separator) != 66 or not self.eip712_domain_separator.startswith(
            "0x"
        ):
            raise ValueError("EIP-712 domain separator is invalid")
        eip712_payload = (
            "0x1901" + self.eip712_domain_separator[2:] + decision.proposal_hash[2:]
        )
        return TransactionSignRequestV1(
            schema_version="aegisledger.sign_request.v1",
            proposal=proposal,
            decision=decision,
            reservation_id=record.reservation_id,
            wallet_nonce=request.wallet_nonce,
            chain_id=proposal.chain_id,
            transaction=transaction,
            eip712_payload=eip712_payload,
            eip1559_unsigned_payload=unsigned_payload,
            eip712_hash=keccak_hex(eip712_payload),
            eip1559_hash=keccak_hex(unsigned_payload),
            expires_at=min(decision.expires_at, proposal.deadline),
        )

    @staticmethod
    def _execution_matches_request(
        execution: StoredExecutionV1, request: ExecutionRequest
    ) -> bool:
        transaction = execution.authorization.transaction
        return (
            transaction.wallet_nonce == request.wallet_nonce
            and transaction.value == request.value
            and transaction.gas_limit == request.gas_limit
            and transaction.max_fee_per_gas == request.max_fee_per_gas
            and transaction.max_priority_fee_per_gas == request.max_priority_fee_per_gas
        )

    def execute(
        self,
        proposal_id: uuid.UUID,
        request: ExecutionRequest,
        actor: str,
    ) -> ExecutionResponse:
        with self._execution_lock:
            record = self.state.get(proposal_id)
            if record is None:
                raise KeyError("proposal does not exist")
            if record.proposal.principal_id != actor:
                raise PermissionError("proposal belongs to another principal")
            if self.signer is None:
                raise RuntimeError("isolated signer is not configured")
            backend = self.chain_backends.get(record.proposal.chain_id)
            if backend is None:
                raise RuntimeError("chain backend is not configured")

            execution = self.artifacts.get_execution(proposal_id)
            created = False
            if execution is None:
                if record.state is not LifecycleState.RESERVED:
                    raise ValueError(f"proposal cannot be signed from {record.state.value}")
                decision = self.artifacts.get_decision(proposal_id)
                if decision is None:
                    raise RuntimeError("proposal decision is unavailable")
                authorization = self._authorization(record, decision, request)
                result = self.signer.sign(authorization)
                self.state.register_decision_nonce(decision.decision_nonce)
                self.state.register_wallet_nonce(
                    record.proposal.wallet,
                    record.proposal.chain_id,
                    request.wallet_nonce,
                )
                candidate = StoredExecutionV1.from_signer(proposal_id, authorization, result)
                execution, created = self.artifacts.put_execution(candidate)
                if not self._execution_matches_request(execution, request):
                    raise ValueError("proposal already has a different signed execution")
                record = self.state.transition(proposal_id, LifecycleState.SIGNED)
                self.audit.append(
                    "TRANSACTION_SIGNED",
                    actor,
                    {
                        "proposal_id": str(proposal_id),
                        "transaction_id": str(execution.transaction_id),
                        "transaction_hash": execution.transaction_hash,
                        "signing_hash": execution.signing_hash,
                    },
                    aggregate_id=proposal_id,
                )
            elif not self._execution_matches_request(execution, request):
                raise ValueError("proposal already has a different signed execution")

            if execution.submitted_at is None:
                transaction_hash = backend.submit(
                    ChainSubmission(
                        chain_id=execution.authorization.chain_id,
                        transaction_hash=execution.transaction_hash,
                        raw_transaction=execution.raw_transaction,
                    )
                )
                if transaction_hash.lower() != execution.transaction_hash:
                    raise RuntimeError("chain backend returned a different transaction hash")
                submitted_at = datetime.now(UTC)
                execution = self.artifacts.mark_submitted(
                    proposal_id,
                    submitted_at=submitted_at,
                )
                self.settlements.register(
                    execution.transaction_hash,
                    proposal_id,
                    chain_id=execution.authorization.chain_id,
                )
                current = self.state.get(proposal_id)
                assert current is not None
                if current.state is LifecycleState.SIGNED:
                    record = self.state.transition(proposal_id, LifecycleState.SUBMITTED)
                else:
                    record = current
                self.audit.append(
                    "TRANSACTION_SUBMITTED",
                    actor,
                    {
                        "proposal_id": str(proposal_id),
                        "transaction_id": str(execution.transaction_id),
                        "transaction_hash": execution.transaction_hash,
                    },
                    aggregate_id=proposal_id,
                )
            else:
                current = self.state.get(proposal_id)
                assert current is not None
                if current.state is LifecycleState.SIGNED:
                    self.settlements.register(
                        execution.transaction_hash,
                        proposal_id,
                        chain_id=execution.authorization.chain_id,
                    )
                    record = self.state.transition(proposal_id, LifecycleState.SUBMITTED)
                else:
                    record = current
            return ExecutionResponse(
                proposal_id=proposal_id,
                transaction_id=execution.transaction_id,
                state=record.state,
                state_version=record.state_version,
                signing_hash=execution.signing_hash,
                transaction_hash=execution.transaction_hash,
                signer_identity=execution.signer_identity,
                submitted=execution.submitted_at is not None,
                created=created,
            )

    def complete_attestation(self, proposal_id: uuid.UUID, actor: str) -> CompleteAttestationV1:
        existing = self.attestations.get(proposal_id)
        if existing is not None:
            return existing
        record = self.state.get(proposal_id)
        if record is None:
            raise KeyError("proposal does not exist")
        if record.state not in {LifecycleState.SETTLED, LifecycleState.REVERTED}:
            raise ValueError("complete attestation requires a terminal settlement")
        execution = self.artifacts.get_execution(proposal_id)
        decision = self.artifacts.get_decision(proposal_id)
        if execution is None or decision is None:
            raise RuntimeError("authorization artifacts are incomplete")
        evidence = EnclaveEvidenceV1.model_validate(execution.enclave_evidence)
        observation = self.settlements.observation(execution.transaction_hash)
        if observation is None:
            raise RuntimeError("canonical settlement evidence is unavailable")
        lifecycle_state: Literal["SETTLED", "REVERTED"] = (
            "SETTLED" if record.state is LifecycleState.SETTLED else "REVERTED"
        )
        signed = SignedTransactionV1(
            schema_version="aegisledger.signed_transaction.v1",
            eip712_hash=execution.authorization.eip712_hash,
            eip1559_hash=execution.signing_hash,
            transaction_hash=execution.transaction_hash,
            raw_transaction=execution.raw_transaction,
            wallet=record.proposal.wallet,
            wallet_nonce=execution.authorization.wallet_nonce,
            chain_id=execution.authorization.chain_id,
            decision_id=decision.decision_id,
            signer_identity=execution.signer_identity,
            enclave_evidence=evidence.model_dump(mode="json"),
            signature=execution.signature,
        )
        settlement = SettlementEvidenceV1(
            schema_version="aegisledger.settlement_evidence.v1",
            transaction_hash=observation.transaction_hash,
            block_hash=observation.block_hash,
            block_number=observation.block_number,
            chain_id=observation.chain_id,
            success=observation.success,
            confirmations=observation.confirmations,
            observed_at=observation.observed_at,
        )
        attestation = CompleteAttestationV1(
            schema_version="aegisledger.complete_attestation.v1",
            lifecycle_state=lifecycle_state,
            proposal=record.proposal,
            decision=decision,
            transaction_binding=execution.authorization.transaction,
            signed_transaction=signed,
            enclave_evidence=evidence,
            settlement=settlement,
        )
        report = verify_complete_attestation(
            attestation,
            self.decisions.public_key,
            allowed_build_measurements=self.allowed_build_measurements,
        )
        if not report.valid:
            raise RuntimeError("assembled attestation failed offline verification")
        stored, created = self.attestations.put(proposal_id, attestation)
        if created:
            self.audit.append(
                "COMPLETE_ATTESTATION_CREATED",
                actor,
                {
                    "proposal_id": str(proposal_id),
                    "transaction_hash": execution.transaction_hash,
                    "lifecycle_state": record.state.value,
                },
                aggregate_id=proposal_id,
            )
        return stored

    def queue_experiment(self, request: ExperimentRequest, actor: str) -> ExperimentResponseV1:
        if self.experiments.active_count(actor) >= self.experiment_max_active_per_principal:
            raise ValueError("principal has reached the active experiment quota")
        spec = create_experiment_spec(
            seed=request.seed,
            runs_per_scenario=request.runs_per_scenario,
            scenarios=request.scenarios,
            commit_sha=self.commit_sha,
        )
        response = ExperimentResponseV1(
            experiment_id=spec.experiment_id,
            status="QUEUED",
            seed=spec.seed,
            configuration_hash=spec.configuration_hash,
        )
        return self.experiments.create(
            ExperimentJob(
                response=response,
                request=request.model_dump(mode="json"),
                principal_id=actor,
            )
        ).response

    def run_experiment(self, experiment_id: uuid.UUID) -> None:
        job = self.experiments.claim(experiment_id)
        if job is None:
            return
        queued = job.response
        try:
            request = ExperimentRequest.model_validate(job.request)
            spec = create_experiment_spec(
                seed=request.seed,
                runs_per_scenario=request.runs_per_scenario,
                scenarios=request.scenarios,
                commit_sha=self.commit_sha,
            ).model_copy(update={"experiment_id": experiment_id})
            output = self.experiment_output_root / str(experiment_id)
            artifacts = self.experiment_runner.run(spec, output)
            result = queued.model_copy(
                update={
                    "status": "COMPLETED",
                    "result_uri": str(output / "summary.json"),
                    "summary": artifacts.summary,
                }
            )
        except Exception as exc:
            result = queued.model_copy(
                update={
                    "status": "FAILED",
                    "error": type(exc).__name__,
                }
            )
        self.experiments.finish(result)


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
    bearer_auth = HTTPBearer(auto_error=False, scheme_name="BearerAuth")

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        stop = asyncio.Event()
        tasks: list[asyncio.Task[None]] = []

        async def reconcile() -> None:
            assert services.settlement_reconciler is not None
            while not stop.is_set():
                try:
                    await run_in_threadpool(services.settlement_reconciler.poll_once)
                except Exception:
                    logger.exception("settlement reconciliation iteration failed")
                with suppress(TimeoutError):
                    await asyncio.wait_for(stop.wait(), timeout=services.settlement_poll_seconds)

        if services.settlement_reconciler is not None:
            tasks.append(
                asyncio.create_task(reconcile(), name="aegisledger-settlement-reconciler")
            )
        services.experiments.requeue_running()
        for job in services.experiments.pending():
            tasks.append(
                asyncio.create_task(
                    run_in_threadpool(services.run_experiment, job.response.experiment_id),
                    name=f"aegisledger-experiment-{job.response.experiment_id}",
                )
            )
        yield
        stop.set()
        if tasks:
            await asyncio.gather(*tasks)
        close_signer = getattr(services.signer, "close", None)
        if callable(close_signer):
            await run_in_threadpool(close_signer)
        closed_backends: set[int] = set()
        for backend in services.chain_backends.values():
            if id(backend) in closed_backends:
                continue
            closed_backends.add(id(backend))
            close_backend = getattr(backend, "close", None)
            if callable(close_backend):
                await run_in_threadpool(close_backend)

    app = FastAPI(
        title="AegisLedger API",
        version="0.3.0",
        docs_url="/api/docs",
        redoc_url=None,
        lifespan=lifespan,
    )
    app.add_middleware(RequestBodyLimitMiddleware, max_bytes=services.request_max_bytes)

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
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

    async def current_principal(
        request: Request,
        _credential: HTTPAuthorizationCredentials | None = Security(bearer_auth),
    ) -> Principal:
        value = authenticate(request)
        principal = await value if inspect.isawaitable(value) else value
        rate_subject = (
            f"{principal.organization_id}:{principal.environment_id}:{principal.subject}"
        )
        allowed = await run_in_threadpool(
            services.rate_limiter.consume,
            rate_subject,
            limit=services.rate_limit_requests,
            window_seconds=services.rate_limit_window_seconds,
        )
        if not allowed:
            raise ApiError(429, "RATE_LIMITED", "principal request rate exceeded")
        return principal

    def require_access(
        *,
        roles: tuple[Role, ...] = (),
        permissions: tuple[Permission, ...] = (),
    ):
        if not roles and not permissions:
            raise ValueError("access dependency requires a role or permission")

        async def authorize(principal: Principal = Depends(current_principal)) -> Principal:
            role_allowed = bool(principal.roles.intersection(roles))
            permission_allowed = bool(principal.permissions.intersection(permissions))
            if not role_allowed and not permission_allowed:
                raise ApiError(403, "FORBIDDEN", "credential does not permit this operation")
            return principal

        return authorize

    def require_roles(*allowed: Role):
        return require_access(roles=allowed)

    def enforce_read_scope(record: ProposalRecord, principal: Principal) -> None:
        broad_read_roles = {Role.VIEWER, Role.POLICY_ADMIN, Role.AUDITOR}
        if (
            record.proposal.principal_id != principal.subject
            and not principal.roles.intersection(broad_read_roles)
        ):
            raise ApiError(403, "FORBIDDEN", "proposal belongs to another principal")

    @app.get("/health/live", include_in_schema=False)
    async def liveness():
        return {"status": "ok"}

    @app.get("/health/ready", include_in_schema=False)
    async def readiness():
        try:
            services.state.healthcheck()
            services.artifacts.healthcheck()
            services.attestations.healthcheck()
            services.audit.healthcheck()
            services.experiments.healthcheck()
            services.rate_limiter.healthcheck()
            services.policies.active()
            if services.signer is not None:
                services.signer.identity()
        except Exception as exc:
            return JSONResponse(
                status_code=503,
                content={
                    "status": "not_ready",
                    "reason": type(exc).__name__,
                },
            )
        return {"status": "ready"}

    @app.post("/api/v1/proposals", response_model=SubmissionResponse, status_code=202)
    async def submit_proposal(
        proposal: ProposalV1,
        principal: Principal = Depends(
            require_access(
                roles=(Role.RESEARCHER,),
                permissions=(Permission.PROPOSALS_WRITE,),
            )
        ),
    ):
        if proposal.principal_id != principal.subject:
            raise ApiError(
                403,
                "PRINCIPAL_MISMATCH",
                "proposal principal must match authenticated subject",
            )
        try:
            return services.submit(proposal, principal.subject)
        except LookupError as exc:
            raise ApiError(503, "NO_ACTIVE_POLICY", "no active policy is available") from exc

    @app.get("/api/v1/proposals/{proposal_id}", response_model=ProposalStatusResponse)
    async def proposal_status(
        proposal_id: uuid.UUID,
        principal: Principal = Depends(
            require_access(
                roles=(Role.VIEWER, Role.RESEARCHER, Role.POLICY_ADMIN, Role.AUDITOR),
                permissions=(Permission.PROPOSALS_READ, Permission.PROPOSALS_WRITE),
            )
        ),
    ):
        record = services.state.get(proposal_id)
        if record is None:
            raise ApiError(404, "PROPOSAL_NOT_FOUND", "proposal does not exist")
        enforce_read_scope(record, principal)
        return _status_response(record)

    @app.post(
        "/api/v1/proposals/{proposal_id}/executions",
        response_model=ExecutionResponse,
        status_code=202,
    )
    async def execute_proposal(
        proposal_id: uuid.UUID,
        request: ExecutionRequest,
        principal: Principal = Depends(
            require_access(
                roles=(Role.RESEARCHER,),
                permissions=(Permission.PROPOSALS_WRITE,),
            )
        ),
    ):
        try:
            return await run_in_threadpool(
                services.execute,
                proposal_id,
                request,
                principal.subject,
            )
        except KeyError as exc:
            raise ApiError(404, "PROPOSAL_NOT_FOUND", "proposal does not exist") from exc
        except PermissionError as exc:
            raise ApiError(403, "FORBIDDEN", "proposal belongs to another principal") from exc
        except SignerClientError as exc:
            raise ApiError(503, "SIGNER_UNAVAILABLE", "isolated signing failed") from exc
        except ValueError as exc:
            raise ApiError(409, "EXECUTION_CONFLICT", str(exc)) from exc
        except RuntimeError as exc:
            raise ApiError(503, "EXECUTION_UNAVAILABLE", str(exc)) from exc

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
        _principal: Principal = Depends(
            require_access(
                roles=(Role.RESEARCHER, Role.POLICY_ADMIN),
                permissions=(Permission.POLICIES_SIMULATE,),
            )
        ),
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
        _principal: Principal = Depends(
            require_access(
                roles=(Role.AUDITOR, Role.RESEARCHER),
                permissions=(Permission.ATTESTATIONS_VERIFY,),
            )
        ),
    ):
        if request.attestation is not None:
            report = verify_complete_attestation(
                request.attestation,
                services.decisions.public_key,
                allowed_build_measurements=services.allowed_build_measurements,
            )
            return AttestationVerificationResponse(
                valid=report.valid,
                signer_identity=request.attestation.signed_transaction.signer_identity,
                errors=report.errors,
            )
        assert request.decision is not None
        valid = verify_decision_token(request.decision, services.decisions.public_key)
        return AttestationVerificationResponse(
            valid=valid,
            signer_identity=request.decision.policy_signer,
            errors=() if valid else ("policy decision signature is invalid or expired",),
        )

    @app.get(
        "/api/v1/proposals/{proposal_id}/attestation",
        response_model=CompleteAttestationV1,
    )
    async def proposal_attestation(
        proposal_id: uuid.UUID,
        principal: Principal = Depends(
            require_access(
                roles=(Role.VIEWER, Role.RESEARCHER, Role.AUDITOR),
                permissions=(Permission.PROPOSALS_READ, Permission.PROPOSALS_WRITE),
            )
        ),
    ):
        record = services.state.get(proposal_id)
        if record is None:
            raise ApiError(404, "PROPOSAL_NOT_FOUND", "proposal does not exist")
        enforce_read_scope(record, principal)
        try:
            return await run_in_threadpool(
                services.complete_attestation,
                proposal_id,
                principal.subject,
            )
        except ValueError as exc:
            raise ApiError(409, "ATTESTATION_NOT_READY", str(exc)) from exc
        except RuntimeError as exc:
            raise ApiError(503, "ATTESTATION_UNAVAILABLE", str(exc)) from exc

    @app.post("/api/v1/experiments", response_model=ExperimentResponseV1, status_code=202)
    async def execute_experiment(
        request: ExperimentRequest,
        background_tasks: BackgroundTasks,
        principal: Principal = Depends(require_roles(Role.RESEARCHER)),
    ):
        try:
            experiment = services.queue_experiment(request, principal.subject)
        except ValueError as exc:
            raise ApiError(429, "EXPERIMENT_QUOTA_EXCEEDED", str(exc)) from exc
        background_tasks.add_task(
            services.run_experiment,
            experiment.experiment_id,
        )
        return experiment

    @app.get("/api/v1/experiments/{experiment_id}", response_model=ExperimentResponseV1)
    async def experiment_result(
        experiment_id: uuid.UUID,
        principal: Principal = Depends(require_roles(Role.VIEWER, Role.RESEARCHER, Role.AUDITOR)),
    ):
        job = services.experiments.get(experiment_id)
        if job is None:
            raise ApiError(404, "EXPERIMENT_NOT_FOUND", "experiment does not exist")
        if (
            job.principal_id != principal.subject
            and not principal.roles.intersection({Role.VIEWER, Role.AUDITOR})
        ):
            raise ApiError(403, "FORBIDDEN", "experiment belongs to another principal")
        return job.response

    @app.get("/api/v1/audit/events/stream")
    async def audit_stream(
        _principal: Principal = Depends(require_roles(Role.AUDITOR)),
    ):
        async def events():
            for event in services.audit.events:
                yield (
                    f"id: {event.sequence}\n"
                    f"event: {event.event_type}\n"
                    f"data: {event.model_dump_json()}\n\n"
                )

        return StreamingResponse(events(), media_type="text/event-stream")

    return app
