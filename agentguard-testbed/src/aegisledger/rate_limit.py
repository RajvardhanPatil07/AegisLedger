"""Fixed-window request limiting with memory and PostgreSQL adapters."""

from __future__ import annotations

import threading
from datetime import UTC, datetime, timedelta
from typing import Protocol


class RateLimiter(Protocol):
    def healthcheck(self) -> None: ...

    def consume(self, subject: str, *, limit: int, window_seconds: int) -> bool: ...


class MemoryRateLimiter:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._windows: dict[str, tuple[datetime, int]] = {}

    def healthcheck(self) -> None:
        return None

    def consume(self, subject: str, *, limit: int, window_seconds: int) -> bool:
        _validate(limit, window_seconds)
        now = datetime.now(UTC)
        with self._lock:
            started_at, count = self._windows.get(subject, (now, 0))
            if now - started_at >= timedelta(seconds=window_seconds):
                started_at, count = now, 0
            if count >= limit:
                return False
            self._windows[subject] = (started_at, count + 1)
            return True


class PostgresRateLimiter:
    def __init__(self, dsn: str) -> None:
        import psycopg

        self._psycopg = psycopg
        self._dsn = dsn

    def healthcheck(self) -> None:
        with self._psycopg.connect(self._dsn) as connection:
            connection.execute("SELECT 1 FROM rate_limit_windows LIMIT 1")

    def consume(self, subject: str, *, limit: int, window_seconds: int) -> bool:
        _validate(limit, window_seconds)
        with self._psycopg.connect(self._dsn) as connection:
            connection.execute(
                """INSERT INTO rate_limit_windows (subject,window_started_at,request_count)
                   VALUES (%s,now(),0) ON CONFLICT (subject) DO NOTHING""",
                (subject,),
            )
            row = connection.execute(
                """SELECT window_started_at,request_count FROM rate_limit_windows
                   WHERE subject=%s FOR UPDATE""",
                (subject,),
            ).fetchone()
            assert row is not None
            reset = row[0] <= datetime.now(UTC) - timedelta(seconds=window_seconds)
            count = 0 if reset else int(row[1])
            if count >= limit:
                return False
            if reset:
                connection.execute(
                    """UPDATE rate_limit_windows
                       SET window_started_at=now(),request_count=1,updated_at=now()
                       WHERE subject=%s""",
                    (subject,),
                )
            else:
                connection.execute(
                    """UPDATE rate_limit_windows
                       SET request_count=request_count+1,updated_at=now() WHERE subject=%s""",
                    (subject,),
                )
            return True


def _validate(limit: int, window_seconds: int) -> None:
    if limit < 1 or window_seconds < 1:
        raise ValueError("rate limit and window must be positive")
