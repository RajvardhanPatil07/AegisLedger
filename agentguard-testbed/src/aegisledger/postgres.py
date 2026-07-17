"""PostgreSQL reservation adapter with serializable, scope-locked decisions."""
from __future__ import annotations

import uuid
from collections.abc import Iterator
from contextlib import contextmanager

from .canonical import uuid7
from .contracts import LifecycleState, ProposalV1
from .policy import PolicyV1
from .state import static_policy_reasons


class PostgresStateStore:
    def __init__(self, dsn: str) -> None:
        import psycopg

        self._psycopg = psycopg
        self._dsn = dsn

    @contextmanager
    def _transaction(self) -> Iterator:
        with self._psycopg.connect(self._dsn) as connection:
            connection.execute("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
            with connection.transaction():
                yield connection

    def reserve(
        self,
        proposal: ProposalV1,
        policy: PolicyV1,
    ) -> tuple[LifecycleState, uuid.UUID | None, tuple[str, ...]]:
        scope = f"{proposal.principal_id}:{proposal.wallet}:{proposal.chain_id}:{proposal.asset}"
        with self._transaction() as connection:
            connection.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))", (scope,))
            existing = connection.execute(
                "SELECT state, id FROM proposals WHERE principal_id=%s AND idempotency_key=%s",
                (proposal.principal_id, proposal.idempotency_key),
            ).fetchone()
            if existing:
                reservation = connection.execute(
                    "SELECT id FROM reservations WHERE proposal_id=%s", (existing[1],)
                ).fetchone()
                return LifecycleState(existing[0]), reservation[0] if reservation else None, ()

            reasons = self._scope_reasons(connection, proposal, policy)
            state = LifecycleState.DENIED if reasons else LifecycleState.RESERVED
            connection.execute(
                """INSERT INTO proposals
                   (id,schema_version,principal_id,idempotency_key,wallet,chain_id,asset,amount,
                    proposal_hash,body,state,state_version,deadline)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s,1,%s)""",
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
                    proposal.deadline,
                ),
            )
            reservation_id = None
            if not reasons:
                reservation_id = uuid7()
                connection.execute(
                    """INSERT INTO reservations (id,proposal_id,amount,status)
                       VALUES (%s,%s,%s,'ACTIVE')""",
                    (reservation_id, proposal.proposal_id, proposal.amount),
                )
            return state, reservation_id, tuple(reasons)

    def _scope_reasons(self, connection, proposal: ProposalV1, policy: PolicyV1) -> list[str]:
        reasons = static_policy_reasons(proposal, policy)
        if reasons == ["EMERGENCY_STOP"]:
            return reasons
        for cap in policy.rolling_caps:
            row = connection.execute(
                """SELECT COALESCE(SUM(r.amount),0), COUNT(*)
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
        if int(recent[0]) + 1 > policy.maximum_transactions_per_hour:
            reasons.append("VELOCITY_EXCEEDED")
        return reasons
