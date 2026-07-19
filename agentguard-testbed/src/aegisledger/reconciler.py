"""Restart-safe settlement reconciliation with finality and pre-finality reorg handling."""

from __future__ import annotations

import json
import threading
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

import httpx

from .canonical import uuid7
from .chain import EvmReceipt
from .contracts import LifecycleState
from .state import StateStore


class ReceiptBackend(Protocol):
    @property
    def chain_id(self) -> int: ...

    def receipt(self, transaction_hash: str) -> EvmReceipt | None: ...


class SettlementStore(Protocol):
    def register(self, transaction_hash: str, proposal_id: uuid.UUID, *, chain_id: int) -> None: ...

    def pending(self) -> tuple[TrackedTransaction, ...]: ...

    def observe(
        self,
        transaction_hash: str,
        *,
        block_hash: str,
        block_number: int,
        success: bool,
        confirmations: int,
    ) -> None: ...

    def complete(self, transaction_hash: str, status: str) -> None: ...

    def observation(self, transaction_hash: str) -> SettlementObservation | None: ...


@dataclass(frozen=True)
class SettlementObservation:
    transaction_hash: str
    block_hash: str
    block_number: int
    chain_id: int
    success: bool
    confirmations: int
    observed_at: datetime


@dataclass
class TrackedTransaction:
    transaction_hash: str
    proposal_id: uuid.UUID
    chain_id: int
    status: str = "PENDING"
    block_hash: str | None = None
    block_number: int | None = None
    success: bool | None = None
    confirmations: int = 0
    reorg_count: int = 0
    observed_at: datetime | None = None


class MemorySettlementStore:
    """Test adapter mirroring the durable transactions/settlements tables."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._transactions: dict[str, TrackedTransaction] = {}
        self._proposals: dict[uuid.UUID, str] = {}

    def register(self, transaction_hash: str, proposal_id: uuid.UUID, *, chain_id: int) -> None:
        with self._lock:
            if transaction_hash in self._transactions:
                existing = self._transactions[transaction_hash]
                if existing.proposal_id == proposal_id and existing.chain_id == chain_id:
                    return
                raise ValueError("transaction hash is already bound")
            if proposal_id in self._proposals:
                raise ValueError("proposal already has a transaction")
            tracked = TrackedTransaction(transaction_hash, proposal_id, chain_id)
            self._transactions[transaction_hash] = tracked
            self._proposals[proposal_id] = transaction_hash

    def pending(self) -> tuple[TrackedTransaction, ...]:
        with self._lock:
            return tuple(item for item in self._transactions.values() if item.status == "PENDING")

    def observe(
        self,
        transaction_hash: str,
        *,
        block_hash: str,
        block_number: int,
        success: bool,
        confirmations: int,
    ) -> None:
        with self._lock:
            tracked = self._transactions[transaction_hash]
            if tracked.block_hash is not None and tracked.block_hash != block_hash:
                tracked.reorg_count += 1
            tracked.block_hash = block_hash
            tracked.block_number = block_number
            tracked.success = success
            tracked.confirmations = confirmations
            tracked.observed_at = datetime.now(UTC)

    def complete(self, transaction_hash: str, status: str) -> None:
        if status not in {"SETTLED", "REVERTED"}:
            raise ValueError("invalid terminal settlement status")
        with self._lock:
            self._transactions[transaction_hash].status = status

    def get(self, transaction_hash: str) -> TrackedTransaction:
        with self._lock:
            return self._transactions[transaction_hash]

    def observation(self, transaction_hash: str) -> SettlementObservation | None:
        with self._lock:
            tracked = self._transactions.get(transaction_hash)
            if (
                tracked is None
                or tracked.block_hash is None
                or tracked.block_number is None
                or tracked.success is None
                or tracked.observed_at is None
            ):
                return None
            return SettlementObservation(
                transaction_hash=tracked.transaction_hash,
                block_hash=tracked.block_hash,
                block_number=tracked.block_number,
                chain_id=tracked.chain_id,
                success=tracked.success,
                confirmations=tracked.confirmations,
                observed_at=tracked.observed_at,
            )


class PostgresSettlementStore:
    """Restart-safe settlement observations backed by transactions and settlements."""

    def __init__(self, dsn: str) -> None:
        import psycopg

        self._psycopg = psycopg
        self._dsn = dsn

    def register(self, transaction_hash: str, proposal_id: uuid.UUID, *, chain_id: int) -> None:
        with self._psycopg.connect(self._dsn) as connection:
            row = connection.execute(
                """SELECT signed_transaction,chain_id FROM transactions
                   WHERE proposal_id=%s AND submitted_at IS NOT NULL""",
                (proposal_id,),
            ).fetchone()
            if row is None:
                raise ValueError("submitted transaction is not durable")
            body = row[0] if isinstance(row[0], dict) else json.loads(row[0])
            if int(row[1]) != chain_id or str(body.get("transaction_hash", "")).lower() != (
                transaction_hash.lower()
            ):
                raise ValueError("durable transaction binding mismatch")

    def pending(self) -> tuple[TrackedTransaction, ...]:
        with self._psycopg.connect(self._dsn) as connection:
            rows = connection.execute(
                """SELECT t.signed_transaction,t.proposal_id,t.chain_id,
                          s.block_hash,s.confirmations,
                          COALESCE((SELECT COUNT(*) FROM settlements old
                            WHERE old.transaction_id=t.id AND NOT old.canonical),0)
                   FROM transactions t
                   JOIN proposals p ON p.id=t.proposal_id
                   LEFT JOIN LATERAL (
                     SELECT block_hash,confirmations FROM settlements
                     WHERE transaction_id=t.id AND canonical
                     ORDER BY observed_at DESC LIMIT 1
                   ) s ON true
                   WHERE t.submitted_at IS NOT NULL AND p.state='SUBMITTED'"""
            ).fetchall()
            tracked = []
            for body, proposal_id, chain_id, block_hash, confirmations, reorg_count in rows:
                payload = body if isinstance(body, dict) else json.loads(body)
                tracked.append(
                    TrackedTransaction(
                        transaction_hash=str(payload["transaction_hash"]).lower(),
                        proposal_id=proposal_id,
                        chain_id=int(chain_id),
                        block_hash=block_hash,
                        confirmations=int(confirmations or 0),
                        reorg_count=int(reorg_count),
                    )
                )
            return tuple(tracked)

    def observe(
        self,
        transaction_hash: str,
        *,
        block_hash: str,
        block_number: int,
        success: bool,
        confirmations: int,
    ) -> None:
        with self._psycopg.connect(self._dsn) as connection:
            row = connection.execute(
                """SELECT id FROM transactions
                   WHERE signed_transaction->>'transaction_hash'=%s""",
                (transaction_hash,),
            ).fetchone()
            if row is None:
                raise KeyError(f"unknown transaction {transaction_hash}")
            transaction_id = row[0]
            connection.execute(
                """UPDATE settlements SET canonical=false
                   WHERE transaction_id=%s AND canonical AND block_hash<>%s""",
                (transaction_id, block_hash),
            )
            connection.execute(
                """INSERT INTO settlements
                   (id,transaction_id,block_hash,block_number,transaction_index,
                    success,confirmations,canonical,receipt)
                   VALUES (%s,%s,%s,%s,0,%s,%s,true,%s::jsonb)
                   ON CONFLICT (transaction_id,block_hash) DO UPDATE SET
                     success=EXCLUDED.success,
                     confirmations=EXCLUDED.confirmations,
                     canonical=true,
                     receipt=EXCLUDED.receipt,
                     observed_at=now()""",
                (
                    uuid7(),
                    transaction_id,
                    block_hash,
                    block_number,
                    success,
                    confirmations,
                    json.dumps(
                        {
                            "transaction_hash": transaction_hash,
                            "block_hash": block_hash,
                            "block_number": block_number,
                            "success": success,
                            "confirmations": confirmations,
                        }
                    ),
                ),
            )

    def complete(self, transaction_hash: str, status: str) -> None:
        if status not in {"SETTLED", "REVERTED"}:
            raise ValueError("invalid terminal settlement status")
        with self._psycopg.connect(self._dsn) as connection:
            exists = connection.execute(
                """SELECT 1 FROM transactions t JOIN proposals p ON p.id=t.proposal_id
                   WHERE t.signed_transaction->>'transaction_hash'=%s AND p.state=%s""",
                (transaction_hash, status),
            ).fetchone()
            if exists is None:
                raise RuntimeError("lifecycle transition was not durably committed")

    def observation(self, transaction_hash: str) -> SettlementObservation | None:
        with self._psycopg.connect(self._dsn) as connection:
            row = connection.execute(
                """SELECT s.block_hash,s.block_number,t.chain_id,s.success,
                          s.confirmations,s.observed_at
                   FROM transactions t JOIN settlements s ON s.transaction_id=t.id
                   WHERE t.signed_transaction->>'transaction_hash'=%s AND s.canonical
                   ORDER BY s.observed_at DESC LIMIT 1""",
                (transaction_hash,),
            ).fetchone()
            if row is None:
                return None
            return SettlementObservation(
                transaction_hash=transaction_hash.lower(),
                block_hash=str(row[0]).lower(),
                block_number=int(row[1]),
                chain_id=int(row[2]),
                success=bool(row[3]),
                confirmations=int(row[4]),
                observed_at=row[5],
            )


class SettlementReconciler:
    def __init__(
        self,
        lifecycle: StateStore,
        settlements: SettlementStore,
        backends: Mapping[int, ReceiptBackend],
        *,
        finality: int,
    ) -> None:
        if finality < 1:
            raise ValueError("finality must be positive")
        for chain_id, backend in backends.items():
            if getattr(backend, "chain_id", None) != chain_id:
                raise ValueError("backend registry chain ID mismatch")
        self._lifecycle = lifecycle
        self._settlements = settlements
        self._backends = dict(backends)
        self._finality = finality

    def poll_once(self) -> None:
        for tracked in self._settlements.pending():
            backend = self._backends.get(tracked.chain_id)
            if backend is None:
                continue
            try:
                receipt = backend.receipt(tracked.transaction_hash)
            except (TimeoutError, httpx.TimeoutException):
                continue
            if receipt is None:
                continue
            if receipt.transaction_hash.lower() != tracked.transaction_hash.lower():
                raise RuntimeError("backend returned a receipt for a different transaction")
            self._settlements.observe(
                tracked.transaction_hash,
                block_hash=receipt.block_hash,
                block_number=receipt.block_number,
                success=receipt.success,
                confirmations=receipt.confirmations,
            )
            if receipt.confirmations < self._finality:
                continue
            target = LifecycleState.SETTLED if receipt.success else LifecycleState.REVERTED
            record = self._lifecycle.get(tracked.proposal_id)
            if record is None:
                raise RuntimeError("tracked settlement references an unknown proposal")
            if record.state is LifecycleState.SUBMITTED:
                self._lifecycle.transition(tracked.proposal_id, target)
            self._settlements.complete(tracked.transaction_hash, target.value)
