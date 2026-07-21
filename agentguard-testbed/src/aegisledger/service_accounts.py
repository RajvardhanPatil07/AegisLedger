"""Deployment-scoped, revocable service credentials for agent clients."""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import threading
import uuid
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import Protocol

from .auth import AuthenticationError, Permission, Principal, PrincipalKind
from .canonical import uuid7

_TOKEN_PREFIX = "agsa"  # noqa: S105 - public credential type marker, not a secret
_SECRET_PATTERN = re.compile(r"^[A-Za-z0-9_-]{43}$")
_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]*$")


@dataclass(frozen=True)
class ServiceAccountRecord:
    credential_id: uuid.UUID
    key_id: uuid.UUID
    name: str
    subject: str
    organization_id: str
    environment_id: str
    permissions: frozenset[Permission]
    token_digest: str
    created_at: datetime
    expires_at: datetime | None = None
    revoked_at: datetime | None = None
    last_used_at: datetime | None = None


@dataclass(frozen=True)
class IssuedServiceAccount:
    credential_id: uuid.UUID
    key_id: uuid.UUID
    name: str
    subject: str
    organization_id: str
    environment_id: str
    permissions: frozenset[Permission]
    token: str
    expires_at: datetime | None


class ServiceAccountStore(Protocol):
    def create(self, record: ServiceAccountRecord) -> None: ...

    def get_by_key_id(self, key_id: uuid.UUID) -> ServiceAccountRecord | None: ...

    def revoke(self, credential_id: uuid.UUID, revoked_at: datetime) -> None: ...

    def mark_used(self, credential_id: uuid.UUID, used_at: datetime) -> None: ...


class MemoryServiceAccountStore:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._records: dict[uuid.UUID, ServiceAccountRecord] = {}

    def create(self, record: ServiceAccountRecord) -> None:
        with self._lock:
            if record.key_id in self._records:
                raise ValueError("service credential key already exists")
            self._records[record.key_id] = record

    def get_by_key_id(self, key_id: uuid.UUID) -> ServiceAccountRecord | None:
        with self._lock:
            return self._records.get(key_id)

    def revoke(self, credential_id: uuid.UUID, revoked_at: datetime) -> None:
        with self._lock:
            key_id, record = self._find_credential(credential_id)
            self._records[key_id] = replace(record, revoked_at=revoked_at)

    def mark_used(self, credential_id: uuid.UUID, used_at: datetime) -> None:
        with self._lock:
            key_id, record = self._find_credential(credential_id)
            self._records[key_id] = replace(record, last_used_at=used_at)

    def _find_credential(self, credential_id: uuid.UUID) -> tuple[uuid.UUID, ServiceAccountRecord]:
        for key_id, record in self._records.items():
            if record.credential_id == credential_id:
                return key_id, record
        raise KeyError(f"unknown service credential {credential_id}")


class ServiceAccountManager:
    """Issue and authenticate high-entropy bearer credentials.

    Only a SHA-256 digest is retained. The raw token has 256 bits of random
    entropy and is returned once to the operator that creates it.
    """

    def __init__(
        self,
        store: ServiceAccountStore,
        *,
        organization_id: str,
        environment_id: str,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.store = store
        self.organization_id = _validated_identifier(
            organization_id, field="organization_id", maximum=128
        )
        self.environment_id = _validated_identifier(
            environment_id, field="environment_id", maximum=128
        )
        self._clock = clock or (lambda: datetime.now(UTC))

    def issue(
        self,
        *,
        name: str,
        subject: str,
        permissions: set[Permission] | frozenset[Permission],
        expires_at: datetime | None = None,
    ) -> IssuedServiceAccount:
        name = _validated_identifier(name, field="name", maximum=128)
        subject = _validated_identifier(subject, field="subject", maximum=256)
        granted = frozenset(permissions)
        if not granted:
            raise ValueError("service credential requires at least one permission")
        now = self._now()
        if expires_at is not None:
            expires_at = _as_utc(expires_at)
            if expires_at <= now:
                raise ValueError("service credential expiry must be in the future")
        credential_id = uuid7()
        key_id = uuid7()
        secret = secrets.token_urlsafe(32)
        token = f"{_TOKEN_PREFIX}_{key_id.hex}_{secret}"
        record = ServiceAccountRecord(
            credential_id=credential_id,
            key_id=key_id,
            name=name,
            subject=subject,
            organization_id=self.organization_id,
            environment_id=self.environment_id,
            permissions=granted,
            token_digest=_token_digest(token),
            created_at=now,
            expires_at=expires_at,
        )
        self.store.create(record)
        return IssuedServiceAccount(
            credential_id=credential_id,
            key_id=key_id,
            name=name,
            subject=subject,
            organization_id=self.organization_id,
            environment_id=self.environment_id,
            permissions=granted,
            token=token,
            expires_at=expires_at,
        )

    def authenticate(self, token: str) -> Principal:
        try:
            key_id = _parse_key_id(token)
            record = self.store.get_by_key_id(key_id)
            if record is None:
                raise ValueError
            scope_matches = (
                record.organization_id == self.organization_id
                and record.environment_id == self.environment_id
            )
            digest_matches = hmac.compare_digest(record.token_digest, _token_digest(token))
            now = self._now()
            active = record.revoked_at is None and (
                record.expires_at is None or record.expires_at > now
            )
            if not scope_matches or not digest_matches or not active:
                raise ValueError
        except (TypeError, ValueError):
            raise AuthenticationError("invalid service credential") from None
        self.store.mark_used(record.credential_id, now)
        return Principal(
            subject=record.subject,
            roles=frozenset(),
            permissions=record.permissions,
            kind=PrincipalKind.SERVICE,
            organization_id=record.organization_id,
            environment_id=record.environment_id,
        )

    def revoke(self, credential_id: uuid.UUID) -> None:
        self.store.revoke(credential_id, self._now())

    def _now(self) -> datetime:
        return _as_utc(self._clock())


def _parse_key_id(token: str) -> uuid.UUID:
    prefix, separator, remainder = token.partition("_")
    key_text, second_separator, secret = remainder.partition("_")
    if (
        prefix != _TOKEN_PREFIX
        or separator != "_"
        or second_separator != "_"
        or len(key_text) != 32
        or _SECRET_PATTERN.fullmatch(secret) is None
    ):
        raise ValueError("malformed service credential")
    return uuid.UUID(hex=key_text)


def _token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _validated_identifier(value: str, *, field: str, maximum: int) -> str:
    if not 1 <= len(value) <= maximum or _IDENTIFIER_PATTERN.fullmatch(value) is None:
        raise ValueError(f"invalid {field}")
    return value


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("service credential timestamps must include a UTC offset")
    return value.astimezone(UTC)
