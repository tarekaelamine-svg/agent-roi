from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
import json
from pathlib import Path
import sqlite3
import threading
import time
from typing import Any, Callable, Mapping, Optional, Protocol
import uuid

from agent_roi._serialization import canonical_json, to_jsonable
from agent_roi.db import (
    PostgresConnectionFactory,
    PostgresMigrationManager,
    fetchall_mappings,
    fetchone_mapping,
)
from agent_roi.runtime.resilience import CircuitBreaker, RetryPolicy, retry_call


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.isoformat()


class OutboxStatus(str, Enum):
    PENDING = "pending"
    LEASED = "leased"
    DELIVERED = "delivered"
    DEAD_LETTER = "dead_letter"


@dataclass(frozen=True)
class OutboxEvent:
    event_id: str
    topic: str
    destination: str
    payload: Mapping[str, Any]
    idempotency_key: str
    status: OutboxStatus = OutboxStatus.PENDING
    attempts: int = 0
    available_at_utc: str = field(default_factory=lambda: _iso(_utc_now()))
    lease_owner: str = ""
    lease_expires_at_utc: str = ""
    last_error: str = ""
    created_at_utc: str = field(default_factory=lambda: _iso(_utc_now()))
    delivered_at_utc: str = ""

    @classmethod
    def create(
        cls,
        *,
        topic: str,
        destination: str,
        payload: Mapping[str, Any],
        idempotency_key: str,
        event_id: str = "",
    ) -> "OutboxEvent":
        for name, value in {
            "topic": topic,
            "destination": destination,
            "idempotency_key": idempotency_key,
        }.items():
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be a non-empty string")
        return cls(
            event_id=event_id or str(uuid.uuid4()),
            topic=topic.strip(),
            destination=destination.strip(),
            payload=dict(to_jsonable(payload)),
            idempotency_key=idempotency_key.strip(),
        )


class OutboxStore(Protocol):
    def enqueue(self, event: OutboxEvent) -> OutboxEvent: ...
    def claim(
        self, *, worker_id: str, limit: int, lease_seconds: int, destination: str = ""
    ) -> tuple[OutboxEvent, ...]: ...
    def mark_delivered(self, event_id: str, *, worker_id: str) -> None: ...
    def reschedule(self, event_id: str, *, worker_id: str, error: str, delay_seconds: float) -> None: ...
    def dead_letter(self, event_id: str, *, worker_id: str, error: str) -> None: ...


def _row_event(row: Mapping[str, Any]) -> OutboxEvent:
    payload = row["payload_json"]
    if isinstance(payload, str):
        payload = json.loads(payload)
    return OutboxEvent(
        event_id=str(row["event_id"]),
        topic=str(row["topic"]),
        destination=str(row["destination"]),
        payload=dict(payload),
        idempotency_key=str(row["idempotency_key"]),
        status=OutboxStatus(str(row["status"])),
        attempts=int(row["attempts"]),
        available_at_utc=str(row["available_at_utc"]),
        lease_owner=str(row.get("lease_owner") or ""),
        lease_expires_at_utc=str(row.get("lease_expires_at_utc") or ""),
        last_error=str(row.get("last_error") or ""),
        created_at_utc=str(row["created_at_utc"]),
        delivered_at_utc=str(row.get("delivered_at_utc") or ""),
    )


class SqliteOutboxStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        with self._connection() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS enterprise_outbox (
                    event_id TEXT PRIMARY KEY,
                    topic TEXT NOT NULL,
                    destination TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    status TEXT NOT NULL,
                    attempts INTEGER NOT NULL,
                    available_at_utc TEXT NOT NULL,
                    lease_owner TEXT,
                    lease_expires_at_utc TEXT,
                    last_error TEXT NOT NULL,
                    created_at_utc TEXT NOT NULL,
                    delivered_at_utc TEXT,
                    UNIQUE(destination,idempotency_key)
                );
                CREATE INDEX IF NOT EXISTS idx_outbox_claim
                  ON enterprise_outbox(status,available_at_utc,destination,created_at_utc);
                CREATE TABLE IF NOT EXISTS enterprise_dead_letters (
                    event_id TEXT PRIMARY KEY,
                    topic TEXT NOT NULL,
                    destination TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    attempts INTEGER NOT NULL,
                    last_error TEXT NOT NULL,
                    created_at_utc TEXT NOT NULL,
                    dead_lettered_at_utc TEXT NOT NULL
                );
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

    def enqueue(self, event: OutboxEvent) -> OutboxEvent:
        with self._lock, self._connection() as conn:
            try:
                conn.execute(
                    "INSERT INTO enterprise_outbox VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        event.event_id,
                        event.topic,
                        event.destination,
                        canonical_json(event.payload),
                        event.idempotency_key,
                        event.status.value,
                        event.attempts,
                        event.available_at_utc,
                        event.lease_owner or None,
                        event.lease_expires_at_utc or None,
                        event.last_error,
                        event.created_at_utc,
                        event.delivered_at_utc or None,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                row = conn.execute(
                    "SELECT * FROM enterprise_outbox WHERE destination=? AND idempotency_key=?",
                    (event.destination, event.idempotency_key),
                ).fetchone()
                if row is None:
                    raise
                return _row_event(dict(row))
        return event

    def claim(
        self, *, worker_id: str, limit: int = 10, lease_seconds: int = 60, destination: str = ""
    ) -> tuple[OutboxEvent, ...]:
        if not worker_id.strip():
            raise ValueError("worker_id is required")
        now = _utc_now()
        lease_expiry = now + timedelta(seconds=max(1, int(lease_seconds)))
        with self._lock, self._connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            clauses = [
                "available_at_utc <= ?",
                "(status='pending' OR (status='leased' AND lease_expires_at_utc < ?))",
            ]
            params: list[Any] = [_iso(now), _iso(now)]
            if destination:
                clauses.append("destination=?")
                params.append(destination)
            params.append(max(1, min(int(limit), 100)))
            rows = conn.execute(
                "SELECT event_id FROM enterprise_outbox WHERE " + " AND ".join(clauses)
                + " ORDER BY created_at_utc LIMIT ?",
                params,
            ).fetchall()
            ids = [row["event_id"] for row in rows]
            for event_id in ids:
                conn.execute(
                    """UPDATE enterprise_outbox SET status='leased',lease_owner=?,
                       lease_expires_at_utc=?,attempts=attempts+1 WHERE event_id=?""",
                    (worker_id, _iso(lease_expiry), event_id),
                )
            result = [
                conn.execute("SELECT * FROM enterprise_outbox WHERE event_id=?", (event_id,)).fetchone()
                for event_id in ids
            ]
        return tuple(_row_event(dict(row)) for row in result if row is not None)

    def mark_delivered(self, event_id: str, *, worker_id: str) -> None:
        with self._lock, self._connection() as conn:
            cursor = conn.execute(
                """UPDATE enterprise_outbox SET status='delivered',delivered_at_utc=?,
                   lease_owner=NULL,lease_expires_at_utc=NULL,last_error=''
                   WHERE event_id=? AND status='leased' AND lease_owner=?""",
                (_iso(_utc_now()), event_id, worker_id),
            )
            if cursor.rowcount != 1:
                raise KeyError(event_id)

    def reschedule(self, event_id: str, *, worker_id: str, error: str, delay_seconds: float) -> None:
        available = _utc_now() + timedelta(seconds=max(0.0, float(delay_seconds)))
        with self._lock, self._connection() as conn:
            cursor = conn.execute(
                """UPDATE enterprise_outbox SET status='pending',available_at_utc=?,
                   lease_owner=NULL,lease_expires_at_utc=NULL,last_error=?
                   WHERE event_id=? AND status='leased' AND lease_owner=?""",
                (_iso(available), str(error)[:4000], event_id, worker_id),
            )
            if cursor.rowcount != 1:
                raise KeyError(event_id)

    def dead_letter(self, event_id: str, *, worker_id: str, error: str) -> None:
        with self._lock, self._connection() as conn:
            row = conn.execute(
                "SELECT * FROM enterprise_outbox WHERE event_id=? AND status='leased' AND lease_owner=?",
                (event_id, worker_id),
            ).fetchone()
            if row is None:
                raise KeyError(event_id)
            conn.execute(
                "INSERT OR REPLACE INTO enterprise_dead_letters VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    row["event_id"],
                    row["topic"],
                    row["destination"],
                    row["payload_json"],
                    row["idempotency_key"],
                    row["attempts"],
                    str(error)[:4000],
                    row["created_at_utc"],
                    _iso(_utc_now()),
                ),
            )
            conn.execute(
                """UPDATE enterprise_outbox SET status='dead_letter',last_error=?,
                   lease_owner=NULL,lease_expires_at_utc=NULL WHERE event_id=?""",
                (str(error)[:4000], event_id),
            )

    def stats(self) -> dict[str, int]:
        with self._connection() as conn:
            rows = conn.execute(
                "SELECT status,COUNT(*) AS count FROM enterprise_outbox GROUP BY status"
            ).fetchall()
        result = {status.value: 0 for status in OutboxStatus}
        result.update({row["status"]: int(row["count"]) for row in rows})
        return result


class PostgresOutboxStore:
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

    def enqueue(self, event: OutboxEvent) -> OutboxEvent:
        with self.connection_factory.connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute(
                    """INSERT INTO enterprise_outbox(
                           event_id,topic,destination,payload_json,idempotency_key,status,attempts,
                           available_at_utc,lease_owner,lease_expires_at_utc,last_error,created_at_utc,delivered_at_utc
                       ) VALUES (%s,%s,%s,%s::jsonb,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                       ON CONFLICT(destination,idempotency_key) DO NOTHING""",
                    (
                        event.event_id,
                        event.topic,
                        event.destination,
                        canonical_json(event.payload),
                        event.idempotency_key,
                        event.status.value,
                        event.attempts,
                        event.available_at_utc,
                        event.lease_owner or None,
                        event.lease_expires_at_utc or None,
                        event.last_error,
                        event.created_at_utc,
                        event.delivered_at_utc or None,
                    ),
                )
                if cursor.rowcount == 0:
                    cursor.execute(
                        "SELECT * FROM enterprise_outbox WHERE destination=%s AND idempotency_key=%s",
                        (event.destination, event.idempotency_key),
                    )
                    row = fetchone_mapping(cursor)
                    if row is not None:
                        return _row_event(row)
            finally:
                cursor.close()
        return event

    def claim(
        self, *, worker_id: str, limit: int = 10, lease_seconds: int = 60, destination: str = ""
    ) -> tuple[OutboxEvent, ...]:
        clauses = [
            "available_at_utc <= CURRENT_TIMESTAMP",
            "(status='pending' OR (status='leased' AND lease_expires_at_utc < CURRENT_TIMESTAMP))",
        ]
        params: list[Any] = []
        if destination:
            clauses.append("destination=%s")
            params.append(destination)
        params.extend([max(1, min(int(limit), 100)), worker_id, max(1, int(lease_seconds))])
        with self.connection_factory.connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute(
                    """WITH candidates AS (
                           SELECT event_id FROM enterprise_outbox WHERE """
                    + " AND ".join(clauses)
                    + """ ORDER BY created_at_utc
                           FOR UPDATE SKIP LOCKED LIMIT %s
                       )
                       UPDATE enterprise_outbox o SET status='leased',lease_owner=%s,
                           lease_expires_at_utc=CURRENT_TIMESTAMP + (%s * INTERVAL '1 second'),
                           attempts=o.attempts+1
                       FROM candidates c WHERE o.event_id=c.event_id RETURNING o.*""",
                    tuple(params),
                )
                rows = fetchall_mappings(cursor)
            finally:
                cursor.close()
        return tuple(_row_event(row) for row in rows)

    def mark_delivered(self, event_id: str, *, worker_id: str) -> None:
        with self.connection_factory.connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute(
                    """UPDATE enterprise_outbox SET status='delivered',delivered_at_utc=CURRENT_TIMESTAMP,
                       lease_owner=NULL,lease_expires_at_utc=NULL,last_error=''
                       WHERE event_id=%s AND status='leased' AND lease_owner=%s""",
                    (event_id, worker_id),
                )
                if cursor.rowcount != 1:
                    raise KeyError(event_id)
            finally:
                cursor.close()

    def reschedule(self, event_id: str, *, worker_id: str, error: str, delay_seconds: float) -> None:
        with self.connection_factory.connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute(
                    """UPDATE enterprise_outbox SET status='pending',
                       available_at_utc=CURRENT_TIMESTAMP + (%s * INTERVAL '1 second'),
                       lease_owner=NULL,lease_expires_at_utc=NULL,last_error=%s
                       WHERE event_id=%s AND status='leased' AND lease_owner=%s""",
                    (max(0.0, float(delay_seconds)), str(error)[:4000], event_id, worker_id),
                )
                if cursor.rowcount != 1:
                    raise KeyError(event_id)
            finally:
                cursor.close()

    def dead_letter(self, event_id: str, *, worker_id: str, error: str) -> None:
        with self.connection_factory.connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute(
                    """WITH moved AS (
                           UPDATE enterprise_outbox SET status='dead_letter',last_error=%s,
                               lease_owner=NULL,lease_expires_at_utc=NULL
                           WHERE event_id=%s AND status='leased' AND lease_owner=%s
                           RETURNING *
                       )
                       INSERT INTO enterprise_dead_letters(
                           event_id,topic,destination,payload_json,idempotency_key,attempts,last_error,created_at_utc
                       ) SELECT event_id,topic,destination,payload_json,idempotency_key,attempts,last_error,created_at_utc
                         FROM moved
                       ON CONFLICT(event_id) DO UPDATE SET attempts=EXCLUDED.attempts,
                         last_error=EXCLUDED.last_error,dead_lettered_at_utc=CURRENT_TIMESTAMP""",
                    (str(error)[:4000], event_id, worker_id),
                )
                if cursor.rowcount != 1:
                    raise KeyError(event_id)
            finally:
                cursor.close()


DeliveryHandler = Callable[[OutboxEvent], None]


class OutboxWorker:
    """Durable delivery worker with retries, circuit breakers, and dead letters."""

    def __init__(
        self,
        store: OutboxStore,
        handlers: Mapping[str, DeliveryHandler],
        *,
        worker_id: str = "",
        retry_policy: RetryPolicy = RetryPolicy(max_attempts=1),
        max_delivery_attempts: int = 8,
        lease_seconds: int = 60,
        circuit_breakers: Optional[Mapping[str, CircuitBreaker]] = None,
    ) -> None:
        self.store = store
        self.handlers = dict(handlers)
        self.worker_id = worker_id or f"worker-{uuid.uuid4()}"
        self.retry_policy = retry_policy
        self.max_delivery_attempts = max(1, int(max_delivery_attempts))
        self.lease_seconds = max(1, int(lease_seconds))
        self.circuit_breakers = dict(circuit_breakers or {})

    def _deliver(self, event: OutboxEvent) -> None:
        try:
            handler = self.handlers[event.destination]
        except KeyError as exc:
            raise KeyError(f"No outbox handler registered for destination {event.destination!r}") from exc
        breaker = self.circuit_breakers.get(event.destination)
        if breaker is None:
            handler(event)
        else:
            breaker.call(lambda: handler(event))

    def run_once(self, *, limit: int = 10, destination: str = "") -> dict[str, int]:
        claimed = self.store.claim(
            worker_id=self.worker_id,
            limit=limit,
            lease_seconds=self.lease_seconds,
            destination=destination,
        )
        delivered = retried = dead_lettered = 0
        for event in claimed:
            try:
                retry_call(lambda event=event: self._deliver(event), self.retry_policy)
            except Exception as exc:
                if event.attempts >= self.max_delivery_attempts:
                    self.store.dead_letter(event.event_id, worker_id=self.worker_id, error=str(exc))
                    dead_lettered += 1
                else:
                    delay = self.retry_policy.delay(max(1, event.attempts))
                    self.store.reschedule(
                        event.event_id,
                        worker_id=self.worker_id,
                        error=f"{type(exc).__name__}: {exc}",
                        delay_seconds=delay,
                    )
                    retried += 1
            else:
                self.store.mark_delivered(event.event_id, worker_id=self.worker_id)
                delivered += 1
        return {
            "claimed": len(claimed),
            "delivered": delivered,
            "retried": retried,
            "dead_lettered": dead_lettered,
        }


class OutboxEventSink:
    """CloudEvent/EventSink adapter that persists delivery before returning."""

    def __init__(self, store: OutboxStore, *, destination: str, topic: str = "telemetry") -> None:
        self.store = store
        self.destination = destination
        self.topic = topic

    def emit(self, event: Any) -> None:
        payload = event.to_dict() if hasattr(event, "to_dict") else dict(event)
        event_id = str(payload.get("id") or uuid.uuid4())
        self.store.enqueue(
            OutboxEvent.create(
                event_id=event_id,
                topic=self.topic,
                destination=self.destination,
                payload=payload,
                idempotency_key=event_id,
            )
        )

class JsonHttpOutboxHandler:
    """Deliver one outbox event to an HTTPS endpoint with idempotency headers."""

    def __init__(
        self,
        endpoint: str,
        *,
        headers: Optional[Mapping[str, str]] = None,
        timeout_seconds: float = 10.0,
        require_https: bool = True,
    ) -> None:
        if require_https and not endpoint.lower().startswith("https://"):
            raise ValueError("Outbox HTTP endpoints must use HTTPS")
        self.endpoint = endpoint
        self.headers = dict(headers or {})
        self.timeout_seconds = float(timeout_seconds)

    def __call__(self, event: OutboxEvent) -> None:
        from urllib import error as urlerror
        from urllib import request as urlrequest

        request = urlrequest.Request(
            self.endpoint,
            method="POST",
            data=canonical_json(
                {
                    "event_id": event.event_id,
                    "topic": event.topic,
                    "payload": dict(event.payload),
                    "attempt": event.attempts,
                }
            ).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Idempotency-Key": event.idempotency_key,
                "X-Agent-ROI-Event-ID": event.event_id,
                **self.headers,
            },
        )
        try:
            with urlrequest.urlopen(request, timeout=self.timeout_seconds) as response:
                if response.status < 200 or response.status >= 300:
                    raise RuntimeError(f"Outbox endpoint returned HTTP {response.status}")
                response.read()
        except urlerror.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Outbox endpoint returned HTTP {exc.code}: {detail}") from exc
        except OSError as exc:
            raise RuntimeError("Outbox endpoint is unavailable") from exc
