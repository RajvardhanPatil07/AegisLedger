"""Append-only hash journal, Merkle checkpoints, and trust-independent verification."""
from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable

from pydantic import Field, StringConstraints, field_validator
from typing_extensions import Annotated

from .canonical import canonical_json, uuid7
from .contracts import Hex32, StrictModel

GENESIS_HASH = "0x" + "00" * 32


class AuditEventV1(StrictModel):
    schema_version: str = "aegisledger.audit_event.v1"
    sequence: Annotated[int, Field(gt=0)]
    event_id: uuid.UUID
    event_type: Annotated[str, StringConstraints(pattern=r"^[A-Z][A-Z0-9_]{1,95}$")]
    aggregate_id: uuid.UUID | None = None
    occurred_at: datetime
    actor: Annotated[str, StringConstraints(min_length=1, max_length=256)]
    payload: dict
    previous_hash: Hex32
    event_hash: Hex32

    @field_validator("occurred_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("occurred_at must include a UTC offset")
        return value.astimezone(timezone.utc)


class AuditCheckpointV1(StrictModel):
    schema_version: str = "aegisledger.audit_checkpoint.v1"
    checkpoint_id: uuid.UUID
    first_sequence: Annotated[int, Field(gt=0)]
    last_sequence: Annotated[int, Field(gt=0)]
    event_count: Annotated[int, Field(gt=0)]
    merkle_root: Hex32
    head_hash: Hex32
    created_at: datetime


@dataclass(frozen=True)
class JournalVerification:
    valid: bool
    checked_events: int
    errors: tuple[str, ...]


def _event_payload(event: AuditEventV1) -> bytes:
    return canonical_json(event.model_dump(mode="json", exclude={"event_hash"}))


def _hash_payload(payload: bytes) -> str:
    return "0x" + hashlib.sha256(payload).hexdigest()


def _merkle_root(events: tuple[AuditEventV1, ...] | list[AuditEventV1]) -> str:
    nodes = [bytes.fromhex(event.event_hash[2:]) for event in events]
    if not nodes:
        return GENESIS_HASH
    while len(nodes) > 1:
        if len(nodes) % 2:
            nodes.append(nodes[-1])
        nodes = [
            hashlib.sha256(nodes[index] + nodes[index + 1]).digest()
            for index in range(0, len(nodes), 2)
        ]
    return "0x" + nodes[0].hex()


class AuditJournal:
    def __init__(self, *, now: Callable[[], datetime] | None = None) -> None:
        self._now = now or (lambda: datetime.now(timezone.utc))
        self._events: list[AuditEventV1] = []
        self._last_anchor_count = 0
        self._last_anchor_at = self._now()

    @property
    def events(self) -> tuple[AuditEventV1, ...]:
        return tuple(self._events)

    def append(
        self,
        event_type: str,
        actor: str,
        payload: dict,
        aggregate_id: uuid.UUID | None = None,
    ) -> AuditEventV1:
        previous = self._events[-1].event_hash if self._events else GENESIS_HASH
        placeholder = AuditEventV1(
            sequence=len(self._events) + 1,
            event_id=uuid7(),
            event_type=event_type,
            aggregate_id=aggregate_id,
            occurred_at=self._now(),
            actor=actor,
            payload=payload,
            previous_hash=previous,
            event_hash=GENESIS_HASH,
        )
        event = AuditEventV1.model_validate(
            {**placeholder.model_dump(mode="python"), "event_hash": _hash_payload(_event_payload(placeholder))}
        )
        self._events.append(event)
        return event

    def anchor_due(self) -> bool:
        unanchored = len(self._events) - self._last_anchor_count
        return unanchored >= 100 or (
            unanchored > 0 and self._now() - self._last_anchor_at >= timedelta(minutes=5)
        )

    def checkpoint(self) -> AuditCheckpointV1:
        if not self._events:
            raise ValueError("cannot checkpoint an empty journal")
        checkpoint = AuditCheckpointV1(
            checkpoint_id=uuid7(),
            first_sequence=1,
            last_sequence=len(self._events),
            event_count=len(self._events),
            merkle_root=_merkle_root(self._events),
            head_hash=self._events[-1].event_hash,
            created_at=self._now(),
        )
        self._last_anchor_count = len(self._events)
        self._last_anchor_at = checkpoint.created_at
        return checkpoint


def verify_journal(
    events: tuple[AuditEventV1, ...] | list[AuditEventV1],
    checkpoint: AuditCheckpointV1,
) -> JournalVerification:
    errors: list[str] = []
    if len(events) != checkpoint.event_count:
        errors.append("event count does not match trusted checkpoint")
    if events and events[0].sequence != checkpoint.first_sequence:
        errors.append("first sequence does not match trusted checkpoint")
    if events and events[-1].sequence != checkpoint.last_sequence:
        errors.append("last sequence does not match trusted checkpoint")

    previous = GENESIS_HASH
    for expected_sequence, event in enumerate(events, start=1):
        if event.sequence != expected_sequence:
            errors.append(f"unexpected sequence at position {expected_sequence}")
        if event.previous_hash != previous:
            errors.append(f"previous hash mismatch at sequence {event.sequence}")
        if event.event_hash != _hash_payload(_event_payload(event)):
            errors.append(f"event hash mismatch at sequence {event.sequence}")
        previous = event.event_hash

    if previous != checkpoint.head_hash:
        errors.append("journal head does not match trusted checkpoint")
    if _merkle_root(events) != checkpoint.merkle_root:
        errors.append("Merkle root does not match trusted checkpoint")
    return JournalVerification(not errors, len(events), tuple(errors))

