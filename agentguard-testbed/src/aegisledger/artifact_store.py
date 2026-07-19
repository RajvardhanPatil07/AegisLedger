"""Durable decision and signed-transaction artifact repositories."""

from __future__ import annotations

import json
import threading
import uuid
from datetime import UTC, datetime
from typing import Annotated, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from .canonical import uuid7
from .contracts import Address, DecisionTokenV1, Hex32
from .signer_client import SignerResult
from .signing import HexData, TransactionSignRequestV1


class StoredExecutionV1(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    schema_version: Literal["aegisledger.stored_execution.v1"] = (
        "aegisledger.stored_execution.v1"
    )
    transaction_id: uuid.UUID = Field(default_factory=uuid7)
    proposal_id: uuid.UUID
    authorization: TransactionSignRequestV1
    signing_hash: Hex32
    transaction_hash: Hex32
    raw_transaction: HexData
    signer_identity: Address
    signature: Annotated[str, StringConstraints(pattern=r"^0x[0-9a-f]{130}$")]
    enclave_evidence: dict[str, object]
    signed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    submitted_at: datetime | None = None

    @classmethod
    def from_signer(
        cls,
        proposal_id: uuid.UUID,
        authorization: TransactionSignRequestV1,
        result: SignerResult,
    ) -> StoredExecutionV1:
        return cls(
            proposal_id=proposal_id,
            authorization=authorization,
            signing_hash=result.signing_hash,
            transaction_hash=result.transaction_hash,
            raw_transaction="0x" + result.signed_transaction.hex(),
            signer_identity=result.signer_identity,
            signature=result.signature,
            enclave_evidence=result.enclave_evidence,
        )


class AuthorizationArtifactStore(Protocol):
    def healthcheck(self) -> None: ...

    def put_decision(
        self, proposal_id: uuid.UUID, decision: DecisionTokenV1
    ) -> tuple[DecisionTokenV1, bool]: ...

    def get_decision(self, proposal_id: uuid.UUID) -> DecisionTokenV1 | None: ...

    def put_execution(self, execution: StoredExecutionV1) -> tuple[StoredExecutionV1, bool]: ...

    def get_execution(self, proposal_id: uuid.UUID) -> StoredExecutionV1 | None: ...

    def mark_submitted(
        self, proposal_id: uuid.UUID, *, submitted_at: datetime
    ) -> StoredExecutionV1: ...


class MemoryAuthorizationArtifactStore:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._decisions: dict[uuid.UUID, DecisionTokenV1] = {}
        self._executions: dict[uuid.UUID, StoredExecutionV1] = {}

    def healthcheck(self) -> None:
        return None

    def put_decision(
        self, proposal_id: uuid.UUID, decision: DecisionTokenV1
    ) -> tuple[DecisionTokenV1, bool]:
        with self._lock:
            existing = self._decisions.get(proposal_id)
            if existing is not None:
                return existing, False
            self._decisions[proposal_id] = decision
            return decision, True

    def get_decision(self, proposal_id: uuid.UUID) -> DecisionTokenV1 | None:
        with self._lock:
            return self._decisions.get(proposal_id)

    def put_execution(self, execution: StoredExecutionV1) -> tuple[StoredExecutionV1, bool]:
        with self._lock:
            existing = self._executions.get(execution.proposal_id)
            if existing is not None:
                return existing, False
            self._executions[execution.proposal_id] = execution
            return execution, True

    def get_execution(self, proposal_id: uuid.UUID) -> StoredExecutionV1 | None:
        with self._lock:
            return self._executions.get(proposal_id)

    def mark_submitted(
        self, proposal_id: uuid.UUID, *, submitted_at: datetime
    ) -> StoredExecutionV1:
        with self._lock:
            execution = self._executions[proposal_id]
            if execution.submitted_at is None:
                execution = execution.model_copy(update={"submitted_at": submitted_at})
                self._executions[proposal_id] = execution
            return execution


class PostgresAuthorizationArtifactStore:
    def __init__(self, dsn: str) -> None:
        import psycopg

        self._psycopg = psycopg
        self._dsn = dsn

    def healthcheck(self) -> None:
        with self._psycopg.connect(self._dsn) as connection:
            connection.execute("SELECT 1 FROM decisions LIMIT 1")
            connection.execute("SELECT 1 FROM transactions LIMIT 1")

    def put_decision(
        self, proposal_id: uuid.UUID, decision: DecisionTokenV1
    ) -> tuple[DecisionTokenV1, bool]:
        with self._psycopg.connect(self._dsn) as connection:
            inserted = connection.execute(
                """INSERT INTO decisions
                   (id,proposal_id,policy_version_id,reservation_id,decision_nonce,
                    verdict,reason_codes,state_version,token,expires_at)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s)
                   ON CONFLICT (proposal_id) DO NOTHING RETURNING id""",
                (
                    decision.decision_id,
                    proposal_id,
                    decision.policy_version_id,
                    decision.reservation_id,
                    decision.decision_nonce,
                    decision.verdict.value,
                    list(decision.reason_codes),
                    decision.state_version,
                    decision.model_dump_json(),
                    decision.expires_at,
                ),
            ).fetchone()
            stored = self._get_decision(connection, proposal_id)
            assert stored is not None
            return stored, inserted is not None

    def get_decision(self, proposal_id: uuid.UUID) -> DecisionTokenV1 | None:
        with self._psycopg.connect(self._dsn) as connection:
            return self._get_decision(connection, proposal_id)

    @staticmethod
    def _get_decision(connection, proposal_id: uuid.UUID) -> DecisionTokenV1 | None:
        row = connection.execute(
            "SELECT token FROM decisions WHERE proposal_id=%s",
            (proposal_id,),
        ).fetchone()
        if row is None:
            return None
        token = row[0]
        payload = token if isinstance(token, dict) else json.loads(token)
        return DecisionTokenV1.model_validate_json(json.dumps(payload))

    def put_execution(self, execution: StoredExecutionV1) -> tuple[StoredExecutionV1, bool]:
        with self._psycopg.connect(self._dsn) as connection:
            inserted = connection.execute(
                """INSERT INTO transactions
                   (id,proposal_id,decision_id,wallet,chain_id,wallet_nonce,
                    eip712_hash,eip1559_hash,signed_transaction)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb)
                   ON CONFLICT (proposal_id) DO NOTHING RETURNING id""",
                (
                    execution.transaction_id,
                    execution.proposal_id,
                    execution.authorization.decision.decision_id,
                    execution.authorization.proposal.wallet,
                    execution.authorization.chain_id,
                    execution.authorization.wallet_nonce,
                    execution.authorization.eip712_hash,
                    execution.signing_hash,
                    execution.model_dump_json(),
                ),
            ).fetchone()
            stored = self._get_execution(connection, execution.proposal_id)
            assert stored is not None
            return stored, inserted is not None

    def get_execution(self, proposal_id: uuid.UUID) -> StoredExecutionV1 | None:
        with self._psycopg.connect(self._dsn) as connection:
            return self._get_execution(connection, proposal_id)

    @staticmethod
    def _get_execution(connection, proposal_id: uuid.UUID) -> StoredExecutionV1 | None:
        row = connection.execute(
            "SELECT signed_transaction,submitted_at FROM transactions WHERE proposal_id=%s",
            (proposal_id,),
        ).fetchone()
        if row is None:
            return None
        body = row[0]
        payload = body if isinstance(body, dict) else json.loads(body)
        execution = StoredExecutionV1.model_validate_json(json.dumps(payload))
        if row[1] is not None and execution.submitted_at is None:
            execution = execution.model_copy(update={"submitted_at": row[1]})
        return execution

    def mark_submitted(
        self, proposal_id: uuid.UUID, *, submitted_at: datetime
    ) -> StoredExecutionV1:
        with self._psycopg.connect(self._dsn) as connection:
            connection.execute(
                """UPDATE transactions SET submitted_at=COALESCE(submitted_at,%s)
                   WHERE proposal_id=%s""",
                (submitted_at, proposal_id),
            )
            stored = self._get_execution(connection, proposal_id)
            if stored is None:
                raise KeyError(f"unknown execution for proposal {proposal_id}")
            return stored
