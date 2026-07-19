"""Atomic lifecycle and reservation state used by the policy service."""

from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Protocol

from .canonical import uuid7
from .contracts import LifecycleState, ProposalV1, require_transition
from .policy import PolicyV1


def static_policy_reasons(proposal: ProposalV1, policy: PolicyV1) -> list[str]:
    """Evaluate constraints that do not depend on mutable budget state."""
    reasons: list[str] = []
    if policy.emergency_stop:
        return ["EMERGENCY_STOP"]
    if proposal.deadline <= datetime.now(UTC):
        reasons.append("DEADLINE_EXPIRED")
    if proposal.wallet not in policy.enabled_wallets:
        reasons.append("WALLET_NOT_ENABLED")
    if proposal.principal_id not in policy.enabled_principals:
        reasons.append("PRINCIPAL_NOT_ENABLED")
    if proposal.chain_id not in policy.enabled_chains:
        reasons.append("CHAIN_NOT_ENABLED")
    if proposal.asset not in policy.enabled_assets:
        reasons.append("ASSET_NOT_ENABLED")
    if proposal.amount > policy.per_transaction_cap:
        reasons.append("PER_TRANSACTION_CAP_EXCEEDED")
    if proposal.intent.kind == "transfer":
        if proposal.intent.recipient not in policy.allowed_recipients:
            reasons.append("RECIPIENT_NOT_ALLOWED")
    else:
        allowed = {
            (rule.contract, selector.lower())
            for rule in policy.contract_rules
            for selector in rule.selectors
        }
        if (proposal.intent.contract, proposal.intent.selector.lower()) not in allowed:
            reasons.append("CONTRACT_SELECTOR_NOT_ALLOWED")
        if policy.risk.deny_on_missing_quote and proposal.quote_reference is None:
            reasons.append("QUOTE_REQUIRED")
    if proposal.amount > policy.mandate_required_above and proposal.mandate_id is None:
        reasons.append("MANDATE_REQUIRED")
    return reasons


@dataclass
class Reservation:
    reservation_id: uuid.UUID
    proposal_id: uuid.UUID
    principal_id: str
    wallet: str
    chain_id: int
    asset: str
    amount: int
    created_at: datetime
    active: bool = True
    settled: bool = False


@dataclass
class ProposalRecord:
    proposal: ProposalV1
    state: LifecycleState
    state_version: int
    reason_codes: tuple[str, ...] = ()
    reservation_id: uuid.UUID | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass(frozen=True)
class ReservationResult:
    record: ProposalRecord
    created: bool


class StateStore(Protocol):
    def healthcheck(self) -> None: ...

    def get(self, proposal_id: uuid.UUID) -> ProposalRecord | None: ...

    def reserve(self, proposal: ProposalV1, policy: PolicyV1) -> ReservationResult: ...

    def simulate(self, proposal: ProposalV1, policy: PolicyV1) -> tuple[str, ...]: ...

    def transition(self, proposal_id: uuid.UUID, target: LifecycleState) -> ProposalRecord: ...

    def register_decision_nonce(self, nonce: uuid.UUID) -> None: ...

    def register_wallet_nonce(self, wallet: str, chain_id: int, nonce: int) -> None: ...

    def budget_totals(
        self,
        principal: str,
        wallet: str,
        chain_id: int,
        asset: str,
    ) -> tuple[int, int]: ...


class MemoryStateStore:
    """Deterministic store with the same atomic boundary as the PostgreSQL adapter.

    It is used by unit tests and local no-database experiments. Production uses
    the serializable PostgreSQL transaction defined in ``postgres.py``.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._records: dict[uuid.UUID, ProposalRecord] = {}
        self._idempotency: dict[tuple[str, str], uuid.UUID] = {}
        self._reservations: dict[uuid.UUID, Reservation] = {}
        self._decision_nonces: set[uuid.UUID] = set()
        self._wallet_nonces: set[tuple[str, int, int]] = set()
        self._version = 0

    def _next_version(self) -> int:
        self._version += 1
        return self._version

    def healthcheck(self) -> None:
        return None

    def get(self, proposal_id: uuid.UUID) -> ProposalRecord | None:
        with self._lock:
            return self._records.get(proposal_id)

    def reserve(self, proposal: ProposalV1, policy: PolicyV1) -> ReservationResult:
        """Evaluate and reserve in one lock/serializable transaction boundary."""
        with self._lock:
            key = (proposal.principal_id, proposal.idempotency_key)
            duplicate_id = self._idempotency.get(key)
            if duplicate_id is not None:
                return ReservationResult(self._records[duplicate_id], created=False)

            reasons = self._evaluate(proposal, policy)
            if reasons:
                record = ProposalRecord(
                    proposal=proposal,
                    state=LifecycleState.DENIED,
                    state_version=self._next_version(),
                    reason_codes=tuple(reasons),
                )
            else:
                reservation_id = uuid7()
                reservation = Reservation(
                    reservation_id=reservation_id,
                    proposal_id=proposal.proposal_id,
                    principal_id=proposal.principal_id,
                    wallet=proposal.wallet,
                    chain_id=proposal.chain_id,
                    asset=proposal.asset,
                    amount=proposal.amount,
                    created_at=datetime.now(UTC),
                )
                self._reservations[reservation_id] = reservation
                record = ProposalRecord(
                    proposal=proposal,
                    state=LifecycleState.RESERVED,
                    state_version=self._next_version(),
                    reservation_id=reservation_id,
                )
            self._records[proposal.proposal_id] = record
            self._idempotency[key] = proposal.proposal_id
            return ReservationResult(record, created=True)

    def simulate(self, proposal: ProposalV1, policy: PolicyV1) -> tuple[str, ...]:
        with self._lock:
            return tuple(self._evaluate(proposal, policy))

    def _evaluate(self, proposal: ProposalV1, policy: PolicyV1) -> list[str]:
        reasons = static_policy_reasons(proposal, policy)

        active = [
            item
            for item in self._reservations.values()
            if (item.active or item.settled)
            and item.principal_id == proposal.principal_id
            and item.wallet == proposal.wallet
            and item.chain_id == proposal.chain_id
            and item.asset == proposal.asset
        ]
        now = datetime.now(UTC)
        for cap in policy.rolling_caps:
            spent = sum(
                item.amount
                for item in active
                if (now - item.created_at).total_seconds() < cap.window_seconds
            )
            if spent + proposal.amount > cap.amount:
                reasons.append("ROLLING_CAP_EXCEEDED")
                break
        recent_count = sum(1 for item in active if (now - item.created_at).total_seconds() < 3600)
        if recent_count + 1 > policy.maximum_transactions_per_hour:
            reasons.append("VELOCITY_EXCEEDED")
        return reasons

    def transition(self, proposal_id: uuid.UUID, target: LifecycleState) -> ProposalRecord:
        with self._lock:
            record = self._records[proposal_id]
            require_transition(record.state, target)
            if target in {LifecycleState.EXPIRED, LifecycleState.REVERTED}:
                self._release(record)
            if target is LifecycleState.SETTLED:
                reservation = self._required_reservation(record)
                reservation.active = False
                reservation.settled = True
            record.state = target
            record.state_version = self._next_version()
            record.updated_at = datetime.now(UTC)
            return record

    def register_decision_nonce(self, nonce: uuid.UUID) -> None:
        with self._lock:
            if nonce in self._decision_nonces:
                raise ValueError("decision nonce already used")
            self._decision_nonces.add(nonce)

    def register_wallet_nonce(self, wallet: str, chain_id: int, nonce: int) -> None:
        with self._lock:
            key = (wallet.lower(), chain_id, nonce)
            if key in self._wallet_nonces:
                raise ValueError("wallet nonce already used")
            self._wallet_nonces.add(key)

    def _required_reservation(self, record: ProposalRecord) -> Reservation:
        if record.reservation_id is None:
            raise ValueError("lifecycle state has no reservation")
        return self._reservations[record.reservation_id]

    def _release(self, record: ProposalRecord) -> None:
        if record.reservation_id is not None:
            self._reservations[record.reservation_id].active = False

    def budget_totals(
        self,
        principal: str,
        wallet: str,
        chain_id: int,
        asset: str,
    ) -> tuple[int, int]:
        with self._lock:
            matching = [
                item
                for item in self._reservations.values()
                if item.principal_id == principal
                and item.wallet == wallet.lower()
                and item.chain_id == chain_id
                and item.asset == asset
            ]
            pending = sum(item.amount for item in matching if item.active)
            settled = sum(item.amount for item in matching if item.settled)
            return pending, settled
