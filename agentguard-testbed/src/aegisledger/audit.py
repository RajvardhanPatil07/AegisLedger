"""Append-only hash journal, Merkle checkpoints, and trust-independent verification."""

from __future__ import annotations

import hashlib
import os
import re
import threading
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, Any, Protocol

from pydantic import Field, StringConstraints, field_validator

from .canonical import canonical_json, uuid7
from .contracts import Address, Hex32, StrictModel

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
        return value.astimezone(UTC)


class AuditCheckpointV1(StrictModel):
    schema_version: str = "aegisledger.audit_checkpoint.v1"
    checkpoint_id: uuid.UUID
    first_sequence: Annotated[int, Field(gt=0)]
    last_sequence: Annotated[int, Field(gt=0)]
    event_count: Annotated[int, Field(gt=0)]
    merkle_root: Hex32
    head_hash: Hex32
    created_at: datetime


class AnchorReceiptV1(StrictModel):
    schema_version: str = "aegisledger.anchor_receipt.v1"
    checkpoint_id: uuid.UUID
    chain_id: Annotated[int, Field(gt=0)]
    contract: Address
    transaction_hash: Hex32
    block_number: Annotated[int, Field(ge=0)]
    merkle_root: Hex32
    anchored_at: datetime

    @field_validator("contract")
    @classmethod
    def normalize_contract(cls, value: str) -> str:
        return value.lower()

    @field_validator("anchored_at")
    @classmethod
    def normalize_anchor_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("anchored_at must include a UTC offset")
        return value.astimezone(UTC)


@dataclass(frozen=True)
class JournalVerification:
    valid: bool
    checked_events: int
    errors: tuple[str, ...]


@dataclass(frozen=True)
class RetainedObject:
    payload: bytes
    retain_until: datetime
    digest: str


class RetentionStore(Protocol):
    def put_once(self, key: str, payload: bytes, *, retain_until: datetime) -> None: ...

    def read(self, key: str) -> bytes: ...


class AuditAnchor(Protocol):
    def anchor(self, checkpoint: AuditCheckpointV1) -> AnchorReceiptV1: ...


@dataclass(frozen=True)
class AnchoredCheckpoint:
    checkpoint: AuditCheckpointV1
    receipt: AnchorReceiptV1
    history_key: str
    checkpoint_key: str
    receipt_key: str


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
        self._now = now or (lambda: datetime.now(UTC))
        self._events: list[AuditEventV1] = []
        self._last_anchor_count = 0
        self._last_anchor_at = self._now()
        self._lock = threading.RLock()

    @property
    def events(self) -> tuple[AuditEventV1, ...]:
        with self._lock:
            return tuple(self._events)

    def append(
        self,
        event_type: str,
        actor: str,
        payload: dict,
        aggregate_id: uuid.UUID | None = None,
    ) -> AuditEventV1:
        with self._lock:
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
                {
                    **placeholder.model_dump(mode="python"),
                    "event_hash": _hash_payload(_event_payload(placeholder)),
                }
            )
            self._events.append(event)
            return event

    def anchor_due(self) -> bool:
        with self._lock:
            unanchored = len(self._events) - self._last_anchor_count
            return unanchored >= 100 or (
                unanchored > 0 and self._now() - self._last_anchor_at >= timedelta(minutes=5)
            )

    def checkpoint(self) -> AuditCheckpointV1:
        checkpoint = self.snapshot_checkpoint()
        self.mark_anchored(checkpoint)
        return checkpoint

    def snapshot_checkpoint(self) -> AuditCheckpointV1:
        with self._lock:
            if not self._events:
                raise ValueError("cannot checkpoint an empty journal")
            return AuditCheckpointV1(
                checkpoint_id=uuid7(),
                first_sequence=1,
                last_sequence=len(self._events),
                event_count=len(self._events),
                merkle_root=_merkle_root(self._events),
                head_hash=self._events[-1].event_hash,
                created_at=self._now(),
            )

    def mark_anchored(self, checkpoint: AuditCheckpointV1) -> None:
        with self._lock:
            if checkpoint.event_count > len(self._events):
                raise ValueError("checkpoint extends beyond current journal")
            anchored = self._events[: checkpoint.event_count]
            if (
                not anchored
                or checkpoint.last_sequence != anchored[-1].sequence
                or checkpoint.head_hash != anchored[-1].event_hash
                or checkpoint.merkle_root != _merkle_root(anchored)
            ):
                raise ValueError("checkpoint does not match journal history")
            self._last_anchor_count = max(self._last_anchor_count, checkpoint.event_count)
            self._last_anchor_at = checkpoint.created_at


class MemoryRetentionStore:
    def __init__(self) -> None:
        self._objects: dict[str, RetainedObject] = {}
        self._lock = threading.RLock()

    def put_once(self, key: str, payload: bytes, *, retain_until: datetime) -> None:
        _require_retention(retain_until)
        with self._lock:
            if key in self._objects:
                raise FileExistsError(f"retained object already exists: {key}")
            self._objects[key] = RetainedObject(
                payload=bytes(payload),
                retain_until=retain_until.astimezone(UTC),
                digest=_hash_payload(payload),
            )

    def read(self, key: str) -> bytes:
        with self._lock:
            return self._objects[key].payload

    def object_keys(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._objects))


class FilesystemRetentionStore:
    """Write-once local reference store; deployment uses object lock storage."""

    _KEY = re.compile(r"^[a-z0-9][a-z0-9._/-]{0,511}$")

    def __init__(self, root: Path) -> None:
        self._root = root.resolve()
        self._root.mkdir(parents=True, exist_ok=True)

    def put_once(self, key: str, payload: bytes, *, retain_until: datetime) -> None:
        _require_retention(retain_until)
        path = self._path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        envelope = canonical_json(
            {
                "schema_version": "aegisledger.retained_object.v1",
                "retain_until": retain_until.astimezone(UTC).isoformat(),
                "payload_sha256": _hash_payload(payload),
                "payload_hex": payload.hex(),
            }
        )
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
        try:
            os.write(descriptor, envelope)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def read(self, key: str) -> bytes:
        import json

        envelope = json.loads(self._path(key).read_bytes())
        payload = bytes.fromhex(envelope["payload_hex"])
        if _hash_payload(payload) != envelope["payload_sha256"]:
            raise ValueError("retained object digest mismatch")
        return payload

    def _path(self, key: str) -> Path:
        if not self._KEY.fullmatch(key) or ".." in key.split("/"):
            raise ValueError("invalid retention object key")
        path = (self._root / key).resolve()
        if self._root not in path.parents:
            raise ValueError("retention key escapes configured root")
        return path


class S3ObjectLockStore:
    """AWS S3 Object Lock adapter using compliance-mode retention."""

    def __init__(self, client: Any, *, bucket: str, prefix: str = "audit/") -> None:
        self._client = client
        self._bucket = bucket
        self._prefix = prefix

    def put_once(self, key: str, payload: bytes, *, retain_until: datetime) -> None:
        _require_retention(retain_until)
        object_key = self._prefix + key
        try:
            self._client.head_object(Bucket=self._bucket, Key=object_key)
        except Exception as exc:
            response = getattr(exc, "response", {})
            status = response.get("ResponseMetadata", {}).get("HTTPStatusCode")
            if status not in {404, None}:
                raise
        else:
            raise FileExistsError(f"retained object already exists: {key}")
        self._client.put_object(
            Bucket=self._bucket,
            Key=object_key,
            Body=payload,
            ObjectLockMode="COMPLIANCE",
            ObjectLockRetainUntilDate=retain_until.astimezone(UTC),
            Metadata={"sha256": _hash_payload(payload)},
        )

    def read(self, key: str) -> bytes:
        response = self._client.get_object(Bucket=self._bucket, Key=self._prefix + key)
        payload = bytes(response["Body"].read())
        digest = response.get("Metadata", {}).get("sha256")
        if digest is not None and digest != _hash_payload(payload):
            raise ValueError("retained object digest mismatch")
        return payload


class AnchoringService:
    def __init__(
        self,
        store: RetentionStore,
        anchor: AuditAnchor,
        *,
        retention: timedelta,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        if retention <= timedelta(0):
            raise ValueError("retention duration must be positive")
        self._store = store
        self._anchor = anchor
        self._retention = retention
        self._now = now or (lambda: datetime.now(UTC))

    def anchor(self, journal: AuditJournal) -> AnchoredCheckpoint:
        checkpoint = journal.snapshot_checkpoint()
        identifier = str(checkpoint.checkpoint_id)
        history_key = f"history/{identifier}.json"
        checkpoint_key = f"checkpoints/{identifier}.json"
        receipt_key = f"anchors/{identifier}.json"
        retain_until = self._now() + self._retention
        events = journal.events[: checkpoint.event_count]
        self._store.put_once(
            history_key,
            canonical_json({"events": [item.model_dump(mode="json") for item in events]}),
            retain_until=retain_until,
        )
        self._store.put_once(
            checkpoint_key,
            canonical_json(checkpoint.model_dump(mode="json")),
            retain_until=retain_until,
        )
        receipt = self._anchor.anchor(checkpoint)
        if receipt.checkpoint_id != checkpoint.checkpoint_id:
            raise ValueError("anchor receipt references a different checkpoint")
        if receipt.merkle_root != checkpoint.merkle_root:
            raise ValueError("anchor receipt root does not match checkpoint")
        self._store.put_once(
            receipt_key,
            canonical_json(receipt.model_dump(mode="json")),
            retain_until=retain_until,
        )
        journal.mark_anchored(checkpoint)
        return AnchoredCheckpoint(
            checkpoint=checkpoint,
            receipt=receipt,
            history_key=history_key,
            checkpoint_key=checkpoint_key,
            receipt_key=receipt_key,
        )


def _require_retention(retain_until: datetime) -> None:
    if retain_until.tzinfo is None or retain_until.utcoffset() is None:
        raise ValueError("retain_until must include a UTC offset")


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


def verify_anchored_journal(
    events: tuple[AuditEventV1, ...] | list[AuditEventV1],
    checkpoint: AuditCheckpointV1,
    receipt: AnchorReceiptV1,
) -> JournalVerification:
    report = verify_journal(events, checkpoint)
    errors = list(report.errors)
    if receipt.checkpoint_id != checkpoint.checkpoint_id:
        errors.append("external anchor references a different checkpoint")
    if receipt.merkle_root != checkpoint.merkle_root:
        errors.append("external anchor root does not match checkpoint")
    return JournalVerification(not errors, report.checked_events, tuple(errors))
