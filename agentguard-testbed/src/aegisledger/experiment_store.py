"""Durable experiment jobs with single-claim execution and restart recovery."""

from __future__ import annotations

import json
import threading
import uuid
from dataclasses import dataclass
from typing import Literal, Protocol

from pydantic import BaseModel, ConfigDict


class ExperimentResponseV1(BaseModel):
    model_config = ConfigDict(extra="forbid")

    experiment_id: uuid.UUID
    status: Literal["QUEUED", "RUNNING", "COMPLETED", "FAILED"]
    seed: str
    configuration_hash: str
    result_uri: str | None = None
    summary: dict[str, object] | None = None
    error: str | None = None


@dataclass(frozen=True)
class ExperimentJob:
    response: ExperimentResponseV1
    request: dict[str, object]
    principal_id: str


class ExperimentStore(Protocol):
    def healthcheck(self) -> None: ...

    def create(self, job: ExperimentJob) -> ExperimentJob: ...

    def get(self, experiment_id: uuid.UUID) -> ExperimentJob | None: ...

    def claim(self, experiment_id: uuid.UUID) -> ExperimentJob | None: ...

    def finish(self, response: ExperimentResponseV1) -> ExperimentJob: ...

    def pending(self) -> tuple[ExperimentJob, ...]: ...

    def requeue_running(self) -> int: ...

    def active_count(self, principal_id: str) -> int: ...


class MemoryExperimentStore:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._jobs: dict[uuid.UUID, ExperimentJob] = {}

    def healthcheck(self) -> None:
        return None

    def create(self, job: ExperimentJob) -> ExperimentJob:
        with self._lock:
            if job.response.experiment_id in self._jobs:
                raise ValueError("experiment already exists")
            self._jobs[job.response.experiment_id] = job
            return job

    def get(self, experiment_id: uuid.UUID) -> ExperimentJob | None:
        with self._lock:
            return self._jobs.get(experiment_id)

    def claim(self, experiment_id: uuid.UUID) -> ExperimentJob | None:
        with self._lock:
            job = self._jobs.get(experiment_id)
            if job is None or job.response.status != "QUEUED":
                return None
            claimed = ExperimentJob(
                response=job.response.model_copy(update={"status": "RUNNING"}),
                request=job.request,
                principal_id=job.principal_id,
            )
            self._jobs[experiment_id] = claimed
            return claimed

    def finish(self, response: ExperimentResponseV1) -> ExperimentJob:
        if response.status not in {"COMPLETED", "FAILED"}:
            raise ValueError("finished experiment must be terminal")
        with self._lock:
            job = self._jobs[response.experiment_id]
            finished = ExperimentJob(response, job.request, job.principal_id)
            self._jobs[response.experiment_id] = finished
            return finished

    def pending(self) -> tuple[ExperimentJob, ...]:
        with self._lock:
            return tuple(
                job for job in self._jobs.values() if job.response.status in {"QUEUED", "RUNNING"}
            )

    def requeue_running(self) -> int:
        with self._lock:
            count = 0
            for experiment_id, job in tuple(self._jobs.items()):
                if job.response.status == "RUNNING":
                    self._jobs[experiment_id] = ExperimentJob(
                        job.response.model_copy(update={"status": "QUEUED"}),
                        job.request,
                        job.principal_id,
                    )
                    count += 1
            return count

    def active_count(self, principal_id: str) -> int:
        with self._lock:
            return sum(
                job.principal_id == principal_id
                and job.response.status in {"QUEUED", "RUNNING"}
                for job in self._jobs.values()
            )


class PostgresExperimentStore:
    def __init__(self, dsn: str) -> None:
        import psycopg

        self._psycopg = psycopg
        self._dsn = dsn

    def healthcheck(self) -> None:
        with self._psycopg.connect(self._dsn) as connection:
            connection.execute("SELECT 1 FROM experiments LIMIT 1")

    def create(self, job: ExperimentJob) -> ExperimentJob:
        response = job.response
        with self._psycopg.connect(self._dsn) as connection:
            connection.execute(
                """INSERT INTO experiments
                   (id,schema_version,principal_id,request,status,seed,configuration_hash)
                   VALUES (%s,'aegisledger.experiment_job.v1',%s,%s::jsonb,%s,%s,%s)""",
                (
                    response.experiment_id,
                    job.principal_id,
                    json.dumps(job.request),
                    response.status,
                    response.seed,
                    response.configuration_hash,
                ),
            )
        return job

    def get(self, experiment_id: uuid.UUID) -> ExperimentJob | None:
        with self._psycopg.connect(self._dsn) as connection:
            row = connection.execute(
                """SELECT id,principal_id,request,status,seed,configuration_hash,
                          result_uri,summary,error FROM experiments WHERE id=%s""",
                (experiment_id,),
            ).fetchone()
            return None if row is None else self._job(row)

    def claim(self, experiment_id: uuid.UUID) -> ExperimentJob | None:
        with self._psycopg.connect(self._dsn) as connection:
            row = connection.execute(
                """UPDATE experiments SET status='RUNNING',updated_at=now()
                   WHERE id=%s AND status='QUEUED'
                   RETURNING id,principal_id,request,status,seed,configuration_hash,
                             result_uri,summary,error""",
                (experiment_id,),
            ).fetchone()
            return None if row is None else self._job(row)

    def finish(self, response: ExperimentResponseV1) -> ExperimentJob:
        if response.status not in {"COMPLETED", "FAILED"}:
            raise ValueError("finished experiment must be terminal")
        with self._psycopg.connect(self._dsn) as connection:
            row = connection.execute(
                """UPDATE experiments SET status=%s,result_uri=%s,summary=%s::jsonb,
                          error=%s,updated_at=now()
                   WHERE id=%s AND status='RUNNING'
                   RETURNING id,principal_id,request,status,seed,configuration_hash,
                             result_uri,summary,error""",
                (
                    response.status,
                    response.result_uri,
                    json.dumps(response.summary) if response.summary is not None else None,
                    response.error,
                    response.experiment_id,
                ),
            ).fetchone()
            if row is None:
                raise ValueError("experiment is not running")
            return self._job(row)

    def pending(self) -> tuple[ExperimentJob, ...]:
        with self._psycopg.connect(self._dsn) as connection:
            rows = connection.execute(
                """SELECT id,principal_id,request,status,seed,configuration_hash,
                          result_uri,summary,error FROM experiments
                   WHERE status IN ('QUEUED','RUNNING') ORDER BY created_at"""
            ).fetchall()
            return tuple(self._job(row) for row in rows)

    def requeue_running(self) -> int:
        with self._psycopg.connect(self._dsn) as connection:
            result = connection.execute(
                "UPDATE experiments SET status='QUEUED',updated_at=now() WHERE status='RUNNING'"
            )
            return int(result.rowcount)

    def active_count(self, principal_id: str) -> int:
        with self._psycopg.connect(self._dsn) as connection:
            row = connection.execute(
                """SELECT COUNT(*) FROM experiments
                   WHERE principal_id=%s AND status IN ('QUEUED','RUNNING')""",
                (principal_id,),
            ).fetchone()
            assert row is not None
            return int(row[0])

    @staticmethod
    def _job(row) -> ExperimentJob:
        request = row[2] if isinstance(row[2], dict) else json.loads(row[2])
        summary = row[7] if isinstance(row[7], dict) else json.loads(row[7]) if row[7] else None
        response = ExperimentResponseV1(
            experiment_id=row[0],
            status=row[3],
            seed=row[4],
            configuration_hash=row[5],
            result_uri=row[6],
            summary=summary,
            error=row[8],
        )
        return ExperimentJob(response=response, request=request, principal_id=row[1])
