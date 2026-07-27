from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
import json
import math
import random
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Awaitable, Callable, Mapping, Optional, Protocol, TypeVar

from agent_roi._serialization import canonical_json, digest_value, to_jsonable
from agent_roi.db import PostgresConnectionFactory, PostgresMigrationManager, fetchone_mapping

T = TypeVar("T")


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class CircuitOpenError(RuntimeError):
    """Raised while a circuit breaker is open."""


class IdempotencyConflict(RuntimeError):
    """Raised when an idempotency key is reused for a different request."""


class IdempotencyInProgress(RuntimeError):
    """Raised when another worker owns an incomplete request."""


@dataclass(frozen=True)
class RetryPolicy:
    max_attempts: int = 3
    initial_backoff_seconds: float = 0.1
    multiplier: float = 2.0
    max_backoff_seconds: float = 10.0
    jitter_ratio: float = 0.1
    retry_exceptions: tuple[type[BaseException], ...] = (OSError, TimeoutError)

    def __post_init__(self) -> None:
        if isinstance(self.max_attempts, bool) or int(self.max_attempts) < 1:
            raise ValueError("max_attempts must be an integer >= 1")
        for name in ("initial_backoff_seconds", "multiplier", "max_backoff_seconds", "jitter_ratio"):
            value = float(getattr(self, name))
            if not math.isfinite(value) or value < 0:
                raise ValueError(f"{name} must be finite and nonnegative")
        if self.multiplier < 1:
            raise ValueError("multiplier must be >= 1")
        if self.jitter_ratio > 1:
            raise ValueError("jitter_ratio must be <= 1")
        if not self.retry_exceptions or not all(
            isinstance(item, type) and issubclass(item, BaseException)
            for item in self.retry_exceptions
        ):
            raise ValueError("retry_exceptions must contain exception classes")

    def should_retry(self, exc: BaseException) -> bool:
        return isinstance(exc, self.retry_exceptions)

    def delay(self, attempt_number: int, *, random_value: Optional[float] = None) -> float:
        base = min(
            self.max_backoff_seconds,
            self.initial_backoff_seconds * (self.multiplier ** max(0, attempt_number - 1)),
        )
        if base == 0 or self.jitter_ratio == 0:
            return base
        sample = random.random() if random_value is None else float(random_value)
        factor = 1 - self.jitter_ratio + (2 * self.jitter_ratio * sample)
        return max(0.0, base * factor)


def retry_call(fn: Callable[[], T], policy: RetryPolicy) -> T:
    for attempt in range(1, policy.max_attempts + 1):
        try:
            return fn()
        except BaseException as exc:
            if attempt >= policy.max_attempts or not policy.should_retry(exc):
                raise
            time.sleep(policy.delay(attempt))
    raise AssertionError("unreachable")


async def aretry_call(fn: Callable[[], Awaitable[T]], policy: RetryPolicy) -> T:
    for attempt in range(1, policy.max_attempts + 1):
        try:
            return await fn()
        except BaseException as exc:
            if attempt >= policy.max_attempts or not policy.should_retry(exc):
                raise
            await asyncio.sleep(policy.delay(attempt))
    raise AssertionError("unreachable")


class CircuitState(str, Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitBreaker:
    """Thread-safe circuit breaker with a single half-open probe."""

    def __init__(
        self,
        *,
        failure_threshold: int = 5,
        recovery_timeout_seconds: float = 30.0,
        success_threshold: int = 1,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if isinstance(failure_threshold, bool) or int(failure_threshold) < 1:
            raise ValueError("failure_threshold must be >= 1")
        if float(recovery_timeout_seconds) <= 0:
            raise ValueError("recovery_timeout_seconds must be > 0")
        if isinstance(success_threshold, bool) or int(success_threshold) < 1:
            raise ValueError("success_threshold must be >= 1")
        self.failure_threshold = int(failure_threshold)
        self.recovery_timeout_seconds = float(recovery_timeout_seconds)
        self.success_threshold = int(success_threshold)
        self.clock = clock
        self._state = CircuitState.CLOSED
        self._failures = 0
        self._successes = 0
        self._opened_at = 0.0
        self._probe_in_flight = False
        self._lock = threading.RLock()

    @property
    def state(self) -> CircuitState:
        with self._lock:
            if self._state is CircuitState.OPEN and self.clock() - self._opened_at >= self.recovery_timeout_seconds:
                self._state = CircuitState.HALF_OPEN
                self._probe_in_flight = False
            return self._state

    def before_call(self) -> None:
        with self._lock:
            state = self.state
            if state is CircuitState.OPEN:
                raise CircuitOpenError("Circuit breaker is open")
            if state is CircuitState.HALF_OPEN:
                if self._probe_in_flight:
                    raise CircuitOpenError("Circuit breaker half-open probe is already in progress")
                self._probe_in_flight = True

    def record_success(self) -> None:
        with self._lock:
            if self._state is CircuitState.HALF_OPEN:
                self._successes += 1
                self._probe_in_flight = False
                if self._successes >= self.success_threshold:
                    self._state = CircuitState.CLOSED
                    self._failures = 0
                    self._successes = 0
            else:
                self._failures = 0

    def record_failure(self) -> None:
        with self._lock:
            self._probe_in_flight = False
            self._successes = 0
            self._failures += 1
            if self._state is CircuitState.HALF_OPEN or self._failures >= self.failure_threshold:
                self._state = CircuitState.OPEN
                self._opened_at = self.clock()

    def call(self, fn: Callable[[], T]) -> T:
        self.before_call()
        try:
            result = fn()
        except BaseException:
            self.record_failure()
            raise
        self.record_success()
        return result

    async def acall(self, fn: Callable[[], Awaitable[T]]) -> T:
        self.before_call()
        try:
            result = await fn()
        except BaseException:
            self.record_failure()
            raise
        self.record_success()
        return result


@dataclass(frozen=True)
class IdempotencyResult:
    status: str
    response: Any = None
    error: str = ""


class IdempotencyStore(Protocol):
    def begin(
        self,
        namespace: str,
        key: str,
        request_digest: str,
        *,
        ttl_seconds: int,
    ) -> IdempotencyResult: ...
    def complete(self, namespace: str, key: str, response: Any) -> None: ...
    def fail(self, namespace: str, key: str, error: str) -> None: ...


class SqliteIdempotencyStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        with self._connection() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS idempotency_records (
                    namespace TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    request_digest TEXT NOT NULL,
                    status TEXT NOT NULL,
                    response_json TEXT,
                    error_text TEXT NOT NULL,
                    created_at_utc TEXT NOT NULL,
                    expires_at_utc TEXT NOT NULL,
                    PRIMARY KEY(namespace,idempotency_key)
                );
                CREATE INDEX IF NOT EXISTS idx_idempotency_expiry ON idempotency_records(expires_at_utc);
                """
            )

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _connection(self):
        from contextlib import contextmanager

        @contextmanager
        def managed():
            conn = self._connect()
            try:
                with conn:
                    yield conn
            finally:
                conn.close()

        return managed()

    def begin(self, namespace: str, key: str, request_digest: str, *, ttl_seconds: int) -> IdempotencyResult:
        if not namespace.strip() or not key.strip():
            raise ValueError("namespace and key are required")
        now = _utc_now()
        expires = now + timedelta(seconds=max(1, int(ttl_seconds)))
        with self._lock, self._connection() as conn:
            conn.execute("DELETE FROM idempotency_records WHERE expires_at_utc < ?", (now.isoformat(),))
            row = conn.execute(
                "SELECT * FROM idempotency_records WHERE namespace=? AND idempotency_key=?",
                (namespace, key),
            ).fetchone()
            if row is not None:
                if row["request_digest"] != request_digest:
                    raise IdempotencyConflict("Idempotency key was used for a different request")
                if row["status"] == "completed":
                    return IdempotencyResult("completed", json.loads(row["response_json"]))
                if row["status"] == "failed":
                    return IdempotencyResult("failed", error=row["error_text"])
                raise IdempotencyInProgress("An idempotent request is already in progress")
            conn.execute(
                "INSERT INTO idempotency_records VALUES (?,?,?,?,?,?,?,?)",
                (namespace, key, request_digest, "pending", None, "", now.isoformat(), expires.isoformat()),
            )
        return IdempotencyResult("started")

    def complete(self, namespace: str, key: str, response: Any) -> None:
        with self._lock, self._connection() as conn:
            cursor = conn.execute(
                """UPDATE idempotency_records SET status='completed',response_json=?,error_text=''
                   WHERE namespace=? AND idempotency_key=? AND status='pending'""",
                (canonical_json(to_jsonable(response)), namespace, key),
            )
            if cursor.rowcount != 1:
                raise KeyError((namespace, key))

    def fail(self, namespace: str, key: str, error: str) -> None:
        with self._lock, self._connection() as conn:
            cursor = conn.execute(
                """UPDATE idempotency_records SET status='failed',error_text=?
                   WHERE namespace=? AND idempotency_key=? AND status='pending'""",
                (str(error), namespace, key),
            )
            if cursor.rowcount != 1:
                raise KeyError((namespace, key))


class PostgresIdempotencyStore:
    def __init__(
        self,
        dsn: str,
        *,
        schema: str = "agent_roi",
        connect_factory: Any = None,
        auto_migrate: bool = True,
    ) -> None:
        self.connection_factory = PostgresConnectionFactory(dsn, schema=schema, connect_factory=connect_factory)
        if auto_migrate:
            PostgresMigrationManager(self.connection_factory).migrate()

    def begin(self, namespace: str, key: str, request_digest: str, *, ttl_seconds: int) -> IdempotencyResult:
        expires = _utc_now() + timedelta(seconds=max(1, int(ttl_seconds)))
        with self.connection_factory.connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("DELETE FROM idempotency_records WHERE expires_at_utc < CURRENT_TIMESTAMP")
                cursor.execute(
                    """INSERT INTO idempotency_records(
                           namespace,idempotency_key,request_digest,status,expires_at_utc
                       ) VALUES (%s,%s,%s,'pending',%s)
                       ON CONFLICT(namespace,idempotency_key) DO NOTHING""",
                    (namespace, key, request_digest, expires.isoformat()),
                )
                inserted = cursor.rowcount == 1
                cursor.execute(
                    "SELECT * FROM idempotency_records WHERE namespace=%s AND idempotency_key=%s FOR UPDATE",
                    (namespace, key),
                )
                row = fetchone_mapping(cursor)
            finally:
                cursor.close()
        if row is None:
            raise RuntimeError("Idempotency record could not be read")
        if str(row["request_digest"]) != request_digest:
            raise IdempotencyConflict("Idempotency key was used for a different request")
        if inserted:
            return IdempotencyResult("started")
        if row["status"] == "completed":
            response = row["response_json"]
            return IdempotencyResult("completed", json.loads(response) if isinstance(response, str) else response)
        if row["status"] == "failed":
            return IdempotencyResult("failed", error=str(row["error_text"]))
        raise IdempotencyInProgress("An idempotent request is already in progress")

    def complete(self, namespace: str, key: str, response: Any) -> None:
        with self.connection_factory.connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute(
                    """UPDATE idempotency_records SET status='completed',response_json=%s::jsonb,
                           error_text='',revision=revision+1
                       WHERE namespace=%s AND idempotency_key=%s AND status='pending'""",
                    (canonical_json(to_jsonable(response)), namespace, key),
                )
                if cursor.rowcount != 1:
                    raise KeyError((namespace, key))
            finally:
                cursor.close()

    def fail(self, namespace: str, key: str, error: str) -> None:
        with self.connection_factory.connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute(
                    """UPDATE idempotency_records SET status='failed',error_text=%s,revision=revision+1
                       WHERE namespace=%s AND idempotency_key=%s AND status='pending'""",
                    (str(error), namespace, key),
                )
                if cursor.rowcount != 1:
                    raise KeyError((namespace, key))
            finally:
                cursor.close()


IdempotencyKeyFactory = Callable[[tuple[Any, ...], Mapping[str, Any]], str]


@dataclass(frozen=True)
class IdempotencyPolicy:
    store: IdempotencyStore
    namespace: str
    key_factory: IdempotencyKeyFactory
    ttl_seconds: int = 86_400

    def __post_init__(self) -> None:
        if not str(self.namespace).strip():
            raise ValueError("Idempotency namespace is required")
        if not callable(self.key_factory):
            raise ValueError("key_factory must be callable")
        if isinstance(self.ttl_seconds, bool) or int(self.ttl_seconds) < 1:
            raise ValueError("ttl_seconds must be >= 1")

    def prepare(self, args: tuple[Any, ...], kwargs: Mapping[str, Any]) -> tuple[str, str, IdempotencyResult]:
        key = str(self.key_factory(args, kwargs)).strip()
        if not key:
            raise ValueError("Idempotency key factory returned an empty key")
        request_digest = digest_value({"args": args, "kwargs": dict(kwargs)})
        result = self.store.begin(self.namespace, key, request_digest, ttl_seconds=self.ttl_seconds)
        return key, request_digest, result
