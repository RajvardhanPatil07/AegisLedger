"""Immutable policy version workflow with two-person activation."""
from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum

from .canonical import uuid7
from .policy import PolicyV1


class PolicyStatus(str, Enum):
    DRAFT = "DRAFT"
    APPROVED = "APPROVED"
    ACTIVE = "ACTIVE"
    RETIRED = "RETIRED"


@dataclass
class PolicyVersion:
    version_id: uuid.UUID
    policy: PolicyV1
    policy_hash: str
    status: PolicyStatus
    created_by: str
    created_at: datetime
    approvals: set[str] = field(default_factory=set)
    activated_at: datetime | None = None
    activated_by: str | None = None


class PolicyRegistry:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._versions: dict[uuid.UUID, PolicyVersion] = {}
        self._active_id: uuid.UUID | None = None

    def create(self, policy: PolicyV1, *, created_by: str) -> PolicyVersion:
        with self._lock:
            version = PolicyVersion(
                version_id=uuid7(),
                policy=policy,
                policy_hash=policy.policy_hash(),
                status=PolicyStatus.DRAFT,
                created_by=created_by,
                created_at=datetime.now(timezone.utc),
            )
            self._versions[version.version_id] = version
            return version

    def approve(self, version_id: uuid.UUID, administrator_id: str) -> PolicyVersion:
        with self._lock:
            version = self.get(version_id)
            if version.status in {PolicyStatus.ACTIVE, PolicyStatus.RETIRED}:
                raise ValueError("active or retired policies are immutable")
            version.approvals.add(administrator_id)
            if len(version.approvals) >= 2:
                version.status = PolicyStatus.APPROVED
            return version

    def activate(self, version_id: uuid.UUID, *, activated_by: str) -> PolicyVersion:
        with self._lock:
            version = self.get(version_id)
            if len(version.approvals) < 2:
                raise PermissionError("policy activation requires two distinct administrator approvals")
            if self._active_id is not None and self._active_id != version_id:
                self._versions[self._active_id].status = PolicyStatus.RETIRED
            version.status = PolicyStatus.ACTIVE
            version.activated_at = datetime.now(timezone.utc)
            version.activated_by = activated_by
            self._active_id = version_id
            return version

    def get(self, version_id: uuid.UUID) -> PolicyVersion:
        try:
            return self._versions[version_id]
        except KeyError as exc:
            raise KeyError(f"unknown policy version {version_id}") from exc

    def active(self) -> PolicyVersion:
        with self._lock:
            if self._active_id is None:
                raise LookupError("no active policy")
            return self._versions[self._active_id]

    def list(self) -> tuple[PolicyVersion, ...]:
        with self._lock:
            return tuple(sorted(self._versions.values(), key=lambda item: item.created_at))

