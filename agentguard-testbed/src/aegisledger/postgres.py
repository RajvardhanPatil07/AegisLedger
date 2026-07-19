"""PostgreSQL state adapter with serializable, scope-locked authorization."""

from __future__ import annotations

import json
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from .canonical import uuid7
from .contracts import LifecycleState, ProposalV1, require_transition
from .policies import PolicyStatus, PolicyVersion
from .policy import PolicyV1
from .state import (
    ProposalRecord,
    ReservationResult,
    static_policy_reasons,
)


class PostgresStateStore:
    def __init__(self, dsn: str, *, serialization_retries: int = 3) -> None:
        import psycopg

        if serialization_retries < 1:
            raise ValueError("serialization_retries must be positive")
        self._psycopg = psycopg
        self._dsn = dsn
        self._serialization_retries = serialization_retries

    @contextmanager
    def _transaction(self) -> Iterator[Any]:
        with self._psycopg.connect(self._dsn) as connection:
            connection.execute("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
            yield connection

    def get(self, proposal_id: uuid.UUID) -> ProposalRecord | None:
        with self._psycopg.connect(self._dsn) as connection:
            return self._record(connection, proposal_id)

    def healthcheck(self) -> None:
        with self._psycopg.connect(self._dsn) as connection:
            connection.execute("SELECT 1").fetchone()

    def reserve(self, proposal: ProposalV1, policy: PolicyV1) -> ReservationResult:
        retryable = (
            self._psycopg.errors.SerializationFailure,
            self._psycopg.errors.DeadlockDetected,
        )
        for attempt in range(self._serialization_retries):
            try:
                return self._reserve_once(proposal, policy)
            except retryable:
                if attempt + 1 == self._serialization_retries:
                    raise
        raise RuntimeError("unreachable serialization retry state")

    def _reserve_once(self, proposal: ProposalV1, policy: PolicyV1) -> ReservationResult:
        scope = f"{proposal.principal_id}:{proposal.wallet}:{proposal.chain_id}:{proposal.asset}"
        with self._transaction() as connection:
            connection.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                (scope,),
            )
            duplicate = connection.execute(
                "SELECT id FROM proposals WHERE principal_id=%s AND idempotency_key=%s",
                (proposal.principal_id, proposal.idempotency_key),
            ).fetchone()
            if duplicate is not None:
                record = self._record(connection, duplicate[0])
                assert record is not None
                return ReservationResult(record=record, created=False)

            reasons = self._scope_reasons(connection, proposal, policy)
            state = LifecycleState.DENIED if reasons else LifecycleState.RESERVED
            connection.execute(
                """INSERT INTO proposals
                   (id,schema_version,principal_id,idempotency_key,wallet,chain_id,asset,amount,
                    proposal_hash,body,state,state_version,reason_codes,deadline)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s,1,%s,%s)""",
                (
                    proposal.proposal_id,
                    proposal.schema_version,
                    proposal.principal_id,
                    proposal.idempotency_key,
                    proposal.wallet,
                    proposal.chain_id,
                    proposal.asset,
                    proposal.amount,
                    proposal.proposal_hash(),
                    proposal.model_dump_json(exclude_none=True),
                    state.value,
                    reasons,
                    proposal.deadline,
                ),
            )
            if not reasons:
                connection.execute(
                    """INSERT INTO reservations (id,proposal_id,amount,status)
                       VALUES (%s,%s,%s,'ACTIVE')""",
                    (uuid7(), proposal.proposal_id, proposal.amount),
                )
            record = self._record(connection, proposal.proposal_id)
            assert record is not None
            return ReservationResult(record=record, created=True)

    def simulate(self, proposal: ProposalV1, policy: PolicyV1) -> tuple[str, ...]:
        with self._transaction() as connection:
            return tuple(self._scope_reasons(connection, proposal, policy))

    def transition(
        self,
        proposal_id: uuid.UUID,
        target: LifecycleState,
    ) -> ProposalRecord:
        with self._transaction() as connection:
            record = self._record(connection, proposal_id, for_update=True)
            if record is None:
                raise KeyError(f"unknown proposal {proposal_id}")
            require_transition(record.state, target)
            if target in {LifecycleState.EXPIRED, LifecycleState.REVERTED}:
                connection.execute(
                    """UPDATE reservations SET status='RELEASED', released_at=now()
                       WHERE proposal_id=%s AND status='ACTIVE'""",
                    (proposal_id,),
                )
            elif target is LifecycleState.SETTLED:
                updated = connection.execute(
                    """UPDATE reservations SET status='SETTLED', settled_at=now()
                       WHERE proposal_id=%s AND status='ACTIVE' RETURNING id""",
                    (proposal_id,),
                ).fetchone()
                if updated is None:
                    raise ValueError("settlement requires an active reservation")
            connection.execute(
                """UPDATE proposals
                   SET state=%s, state_version=state_version+1, updated_at=now()
                   WHERE id=%s""",
                (target.value, proposal_id),
            )
            updated_record = self._record(connection, proposal_id)
            assert updated_record is not None
            return updated_record

    def register_decision_nonce(self, nonce: uuid.UUID) -> None:
        try:
            with self._transaction() as connection:
                connection.execute(
                    "INSERT INTO decision_nonce_uses (nonce) VALUES (%s)",
                    (nonce,),
                )
        except self._psycopg.errors.UniqueViolation as exc:
            raise ValueError("decision nonce already used") from exc

    def register_wallet_nonce(self, wallet: str, chain_id: int, nonce: int) -> None:
        try:
            with self._transaction() as connection:
                connection.execute(
                    """INSERT INTO wallet_nonce_uses (wallet,chain_id,nonce)
                       VALUES (%s,%s,%s)""",
                    (wallet.lower(), chain_id, nonce),
                )
        except self._psycopg.errors.UniqueViolation as exc:
            raise ValueError("wallet nonce already used") from exc

    def budget_totals(
        self,
        principal: str,
        wallet: str,
        chain_id: int,
        asset: str,
    ) -> tuple[int, int]:
        with self._psycopg.connect(self._dsn) as connection:
            row = connection.execute(
                """SELECT
                     COALESCE(SUM(r.amount) FILTER (WHERE r.status='ACTIVE'),0),
                     COALESCE(SUM(r.amount) FILTER (WHERE r.status='SETTLED'),0)
                   FROM reservations r JOIN proposals p ON p.id=r.proposal_id
                   WHERE p.principal_id=%s AND p.wallet=%s AND p.chain_id=%s AND p.asset=%s""",
                (principal, wallet.lower(), chain_id, asset),
            ).fetchone()
            assert row is not None
            return int(row[0]), int(row[1])

    def _record(
        self,
        connection: Any,
        proposal_id: uuid.UUID,
        *,
        for_update: bool = False,
    ) -> ProposalRecord | None:
        if for_update:
            query = """SELECT p.body,p.state,p.state_version,p.reason_codes,
                              p.created_at,p.updated_at,r.id
                       FROM proposals p LEFT JOIN reservations r ON r.proposal_id=p.id
                       WHERE p.id=%s FOR UPDATE OF p"""
        else:
            query = """SELECT p.body,p.state,p.state_version,p.reason_codes,
                              p.created_at,p.updated_at,r.id
                       FROM proposals p LEFT JOIN reservations r ON r.proposal_id=p.id
                       WHERE p.id=%s"""
        row = connection.execute(query, (proposal_id,)).fetchone()
        if row is None:
            return None
        body = row[0]
        encoded = json.dumps(body) if isinstance(body, dict) else str(body)
        proposal = ProposalV1.model_validate_json(encoded)
        return ProposalRecord(
            proposal=proposal,
            state=LifecycleState(row[1]),
            state_version=int(row[2]),
            reason_codes=tuple(row[3] or ()),
            reservation_id=row[6],
            created_at=row[4],
            updated_at=row[5],
        )

    def _scope_reasons(
        self,
        connection: Any,
        proposal: ProposalV1,
        policy: PolicyV1,
    ) -> list[str]:
        reasons = static_policy_reasons(proposal, policy)
        if reasons == ["EMERGENCY_STOP"]:
            return reasons
        for cap in policy.rolling_caps:
            row = connection.execute(
                """SELECT COALESCE(SUM(r.amount),0)
                   FROM reservations r JOIN proposals p ON p.id=r.proposal_id
                   WHERE p.principal_id=%s AND p.wallet=%s AND p.chain_id=%s AND p.asset=%s
                     AND r.status IN ('ACTIVE','SETTLED')
                     AND r.created_at >= now() - make_interval(secs => %s)""",
                (
                    proposal.principal_id,
                    proposal.wallet,
                    proposal.chain_id,
                    proposal.asset,
                    cap.window_seconds,
                ),
            ).fetchone()
            assert row is not None
            if int(row[0]) + proposal.amount > cap.amount:
                reasons.append("ROLLING_CAP_EXCEEDED")
                break
        recent = connection.execute(
            """SELECT COUNT(*)
               FROM reservations r JOIN proposals p ON p.id=r.proposal_id
               WHERE p.principal_id=%s AND p.wallet=%s AND p.chain_id=%s AND p.asset=%s
                 AND r.status IN ('ACTIVE','SETTLED')
                 AND r.created_at >= now() - interval '1 hour'""",
            (proposal.principal_id, proposal.wallet, proposal.chain_id, proposal.asset),
        ).fetchone()
        assert recent is not None
        if int(recent[0]) + 1 > policy.maximum_transactions_per_hour:
            reasons.append("VELOCITY_EXCEEDED")
        return reasons


class PostgresPolicyStore:
    def __init__(self, dsn: str) -> None:
        import psycopg

        self._psycopg = psycopg
        self._dsn = dsn

    @contextmanager
    def _transaction(self) -> Iterator[Any]:
        with self._psycopg.connect(self._dsn) as connection:
            connection.execute("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
            yield connection

    def create(self, policy: PolicyV1, *, created_by: str) -> PolicyVersion:
        version_id = uuid7()
        with self._transaction() as connection:
            connection.execute(
                """INSERT INTO policy_versions
                   (id,schema_version,policy_hash,document,status,created_by)
                   VALUES (%s,%s,%s,%s::jsonb,'DRAFT',%s)""",
                (
                    version_id,
                    policy.schema_version,
                    policy.policy_hash(),
                    policy.model_dump_json(),
                    created_by,
                ),
            )
            version = self._get(connection, version_id)
            assert version is not None
            return version

    def approve(self, version_id: uuid.UUID, administrator_id: str) -> PolicyVersion:
        with self._transaction() as connection:
            version = self._get(connection, version_id, for_update=True)
            if version is None:
                raise KeyError(f"unknown policy version {version_id}")
            if version.status in {PolicyStatus.ACTIVE, PolicyStatus.RETIRED}:
                raise ValueError("active or retired policies are immutable")
            connection.execute(
                """INSERT INTO policy_approvals (policy_version_id,administrator_id)
                   VALUES (%s,%s) ON CONFLICT DO NOTHING""",
                (version_id, administrator_id),
            )
            count_row = connection.execute(
                "SELECT COUNT(*) FROM policy_approvals WHERE policy_version_id=%s",
                (version_id,),
            ).fetchone()
            assert count_row is not None
            if int(count_row[0]) >= 2:
                connection.execute(
                    "UPDATE policy_versions SET status='APPROVED' WHERE id=%s",
                    (version_id,),
                )
            approved = self._get(connection, version_id)
            assert approved is not None
            return approved

    def activate(self, version_id: uuid.UUID, *, activated_by: str) -> PolicyVersion:
        with self._transaction() as connection:
            version = self._get(connection, version_id, for_update=True)
            if version is None:
                raise KeyError(f"unknown policy version {version_id}")
            approvals_row = connection.execute(
                "SELECT COUNT(*) FROM policy_approvals WHERE policy_version_id=%s",
                (version_id,),
            ).fetchone()
            assert approvals_row is not None
            if int(approvals_row[0]) < 2:
                raise PermissionError(
                    "policy activation requires two distinct administrator approvals"
                )
            connection.execute(
                """UPDATE policy_versions SET status='RETIRED'
                   WHERE status='ACTIVE' AND id<>%s""",
                (version_id,),
            )
            connection.execute(
                """UPDATE policy_versions
                   SET status='ACTIVE', activated_at=now(), activated_by=%s
                   WHERE id=%s""",
                (activated_by, version_id),
            )
            active = self._get(connection, version_id)
            assert active is not None
            return active

    def get(self, version_id: uuid.UUID) -> PolicyVersion:
        with self._psycopg.connect(self._dsn) as connection:
            version = self._get(connection, version_id)
            if version is None:
                raise KeyError(f"unknown policy version {version_id}")
            return version

    def active(self) -> PolicyVersion:
        with self._psycopg.connect(self._dsn) as connection:
            row = connection.execute(
                "SELECT id FROM policy_versions WHERE status='ACTIVE'"
            ).fetchone()
            if row is None:
                raise LookupError("no active policy")
            version = self._get(connection, row[0])
            assert version is not None
            return version

    def list(self) -> tuple[PolicyVersion, ...]:
        with self._psycopg.connect(self._dsn) as connection:
            identifiers = connection.execute(
                "SELECT id FROM policy_versions ORDER BY created_at"
            ).fetchall()
            versions = [self._get(connection, row[0]) for row in identifiers]
            return tuple(version for version in versions if version is not None)

    def _get(
        self,
        connection: Any,
        version_id: uuid.UUID,
        *,
        for_update: bool = False,
    ) -> PolicyVersion | None:
        if for_update:
            query = """SELECT id,document,policy_hash,status,created_by,created_at,
                              activated_at,activated_by
                       FROM policy_versions WHERE id=%s FOR UPDATE"""
        else:
            query = """SELECT id,document,policy_hash,status,created_by,created_at,
                              activated_at,activated_by
                       FROM policy_versions WHERE id=%s"""
        row = connection.execute(query, (version_id,)).fetchone()
        if row is None:
            return None
        approvals = connection.execute(
            """SELECT administrator_id FROM policy_approvals
               WHERE policy_version_id=%s ORDER BY administrator_id""",
            (version_id,),
        ).fetchall()
        document = row[1]
        encoded = json.dumps(document) if isinstance(document, dict) else str(document)
        return PolicyVersion(
            version_id=row[0],
            policy=PolicyV1.model_validate_json(encoded),
            policy_hash=row[2],
            status=PolicyStatus(row[3]),
            created_by=row[4],
            created_at=row[5],
            approvals={item[0] for item in approvals},
            activated_at=row[6],
            activated_by=row[7],
        )
