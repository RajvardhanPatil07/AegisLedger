"""Restart-safe settlement reconciliation with finality and pre-finality reorg handling."""

from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass
from typing import Protocol

import httpx

from .chain import EvmReceipt
from .contracts import LifecycleState
from .state import StateStore


class ReceiptBackend(Protocol):
    chain_id: int

    def receipt(self, transaction_hash: str) -> EvmReceipt | None: ...


@dataclass
class TrackedTransaction:
    transaction_hash: str
    proposal_id: uuid.UUID
    chain_id: int
    status: str = "PENDING"
    block_hash: str | None = None
    confirmations: int = 0
    reorg_count: int = 0


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

    def observe(self, transaction_hash: str, *, block_hash: str, confirmations: int) -> None:
        with self._lock:
            tracked = self._transactions[transaction_hash]
            if tracked.block_hash is not None and tracked.block_hash != block_hash:
                tracked.reorg_count += 1
            tracked.block_hash = block_hash
            tracked.confirmations = confirmations

    def complete(self, transaction_hash: str, status: str) -> None:
        if status not in {"SETTLED", "REVERTED"}:
            raise ValueError("invalid terminal settlement status")
        with self._lock:
            self._transactions[transaction_hash].status = status

    def get(self, transaction_hash: str) -> TrackedTransaction:
        with self._lock:
            return self._transactions[transaction_hash]


class SettlementReconciler:
    def __init__(
        self,
        lifecycle: StateStore,
        settlements: MemorySettlementStore,
        backends: dict[int, ReceiptBackend],
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
