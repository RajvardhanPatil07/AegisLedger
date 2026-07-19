"""Idempotent repositories for complete, offline-verifiable attestations."""

from __future__ import annotations

import json
import threading
import uuid
from typing import Protocol

from .attestations import CompleteAttestationV1
from .canonical import uuid7


class AttestationStore(Protocol):
    def healthcheck(self) -> None: ...

    def get(self, proposal_id: uuid.UUID) -> CompleteAttestationV1 | None: ...

    def put(
        self,
        proposal_id: uuid.UUID,
        attestation: CompleteAttestationV1,
    ) -> tuple[CompleteAttestationV1, bool]: ...


class MemoryAttestationStore:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._items: dict[uuid.UUID, CompleteAttestationV1] = {}

    def healthcheck(self) -> None:
        return None

    def get(self, proposal_id: uuid.UUID) -> CompleteAttestationV1 | None:
        with self._lock:
            return self._items.get(proposal_id)

    def put(
        self,
        proposal_id: uuid.UUID,
        attestation: CompleteAttestationV1,
    ) -> tuple[CompleteAttestationV1, bool]:
        with self._lock:
            existing = self._items.get(proposal_id)
            if existing is not None:
                return existing, False
            if attestation.proposal.proposal_id != proposal_id:
                raise ValueError("attestation proposal binding mismatch")
            self._items[proposal_id] = attestation
            return attestation, True


class PostgresAttestationStore:
    def __init__(self, dsn: str) -> None:
        import psycopg

        self._psycopg = psycopg
        self._dsn = dsn

    def healthcheck(self) -> None:
        with self._psycopg.connect(self._dsn) as connection:
            connection.execute("SELECT 1 FROM attestations LIMIT 1")

    def get(self, proposal_id: uuid.UUID) -> CompleteAttestationV1 | None:
        with self._psycopg.connect(self._dsn) as connection:
            return self._get(connection, proposal_id)

    def put(
        self,
        proposal_id: uuid.UUID,
        attestation: CompleteAttestationV1,
    ) -> tuple[CompleteAttestationV1, bool]:
        if attestation.proposal.proposal_id != proposal_id:
            raise ValueError("attestation proposal binding mismatch")
        with self._psycopg.connect(self._dsn) as connection:
            binding = connection.execute(
                """SELECT d.id,t.id FROM decisions d
                   JOIN transactions t ON t.decision_id=d.id
                   WHERE d.proposal_id=%s""",
                (proposal_id,),
            ).fetchone()
            if binding is None:
                raise ValueError("attestation requires a durable signed transaction")
            if binding[0] != attestation.decision.decision_id:
                raise ValueError("attestation decision binding mismatch")
            inserted = connection.execute(
                """INSERT INTO attestations
                   (id,decision_id,transaction_id,signer_identity,build_measurement,
                    evidence,expires_at)
                   VALUES (%s,%s,%s,%s,%s,%s::jsonb,%s)
                   ON CONFLICT (decision_id) DO NOTHING RETURNING id""",
                (
                    uuid7(),
                    binding[0],
                    binding[1],
                    attestation.enclave_evidence.signer_identity,
                    attestation.enclave_evidence.build_measurement,
                    attestation.model_dump_json(),
                    attestation.enclave_evidence.expires_datetime(),
                ),
            ).fetchone()
            stored = self._get(connection, proposal_id)
            assert stored is not None
            return stored, inserted is not None

    @staticmethod
    def _get(connection, proposal_id: uuid.UUID) -> CompleteAttestationV1 | None:
        row = connection.execute(
            """SELECT a.evidence FROM attestations a
               JOIN decisions d ON d.id=a.decision_id
               WHERE d.proposal_id=%s""",
            (proposal_id,),
        ).fetchone()
        if row is None:
            return None
        body = row[0]
        payload = body if isinstance(body, dict) else json.loads(body)
        return CompleteAttestationV1.model_validate_json(json.dumps(payload))
