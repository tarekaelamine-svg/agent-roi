from __future__ import annotations

import hashlib
import json
import os
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
import threading
from typing import Any, Dict, Iterator, Optional, Protocol, TextIO

from .event import AuditEvent, _stable_json

try:  # pragma: no cover - platform-specific
    import fcntl  # type: ignore
except ImportError:  # pragma: no cover - Windows
    fcntl = None  # type: ignore

try:  # pragma: no cover - platform-specific
    import msvcrt  # type: ignore
except ImportError:  # pragma: no cover - non-Windows
    msvcrt = None  # type: ignore


class AuditIntegrityError(RuntimeError):
    """Raised when an audit file is malformed or its hash chain is invalid."""


class AuditStore(Protocol):
    hash_chain: bool

    def append(self, event: AuditEvent) -> None: ...
    def last_hash(self, correlation_id: str) -> Optional[str]: ...
    def record(
        self,
        *,
        correlation_id: str,
        run_id: str,
        event_type: str,
        payload: Dict[str, Any],
    ) -> AuditEvent: ...


@dataclass
class InMemoryAuditStore:
    """Process-local audit store with atomic event creation and append."""

    hash_chain: bool = True
    events: list[AuditEvent] = field(default_factory=list, init=False)
    _last_hash_cache: Dict[str, str] = field(default_factory=dict, init=False, repr=False)
    _lock: threading.RLock = field(default_factory=threading.RLock, init=False, repr=False)

    def record(
        self,
        *,
        correlation_id: str,
        run_id: str,
        event_type: str,
        payload: Dict[str, Any],
    ) -> AuditEvent:
        with self._lock:
            previous = self._last_hash_cache.get(str(correlation_id))
            event = AuditEvent.create(
                str(correlation_id),
                str(run_id),
                str(event_type),
                payload,
                previous,
                self.hash_chain,
            )
            self.events.append(event)
            if event.hash:
                self._last_hash_cache[event.correlation_id] = event.hash
            return event

    def append(self, event: AuditEvent) -> None:
        with self._lock:
            expected_prev = self._last_hash_cache.get(event.correlation_id)
            if event.prev_hash != expected_prev:
                raise AuditIntegrityError(
                    "Audit append rejected because prev_hash is stale or invalid"
                )
            self.events.append(event)
            if event.hash:
                self._last_hash_cache[event.correlation_id] = event.hash

    def last_hash(self, correlation_id: str) -> Optional[str]:
        with self._lock:
            return self._last_hash_cache.get(str(correlation_id))

    def verify(self) -> int:
        with self._lock:
            last_by_correlation: Dict[str, str] = {}
            for index, event in enumerate(self.events, start=1):
                expected_prev = last_by_correlation.get(event.correlation_id)
                if event.prev_hash != expected_prev:
                    raise AuditIntegrityError(
                        f"Audit event {index} has an invalid prev_hash"
                    )
                payload = event.to_dict()
                event_hash = payload.pop("hash")
                if self.hash_chain:
                    computed = hashlib.sha256(
                        _stable_json(payload).encode("utf-8")
                    ).hexdigest()
                    if computed != event_hash:
                        raise AuditIntegrityError(
                            f"Audit event {index} has an invalid hash"
                        )
                    last_by_correlation[event.correlation_id] = str(event_hash)
                elif event_hash is not None:
                    raise AuditIntegrityError(
                        f"Audit event {index} unexpectedly contains a hash"
                    )
            return len(self.events)


@dataclass
class JsonlAuditStore:
    """Cross-process-safe, tamper-evident JSONL audit store.

    The file lock covers reading the current chain tail, creating the next
    event, and appending it. This prevents two processes from building events
    against the same stale predecessor.
    """

    path: str | Path = "sentinel_audit.jsonl"
    hash_chain: bool = True
    _lock: threading.RLock = field(default_factory=threading.RLock, init=False, repr=False)

    def __post_init__(self) -> None:
        self.path = Path(self.path)

    def _ensure_dir(self) -> None:
        if self.path.is_symlink():
            raise ValueError(f"Audit path must not be a symbolic link: {self.path}")
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            os.chmod(self.path.parent, 0o700)
        except OSError:
            pass

    @staticmethod
    def _lock_file(handle: TextIO, exclusive: bool) -> None:
        if fcntl is not None:  # pragma: no branch
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
        elif msvcrt is not None:  # pragma: no cover - Windows
            handle.seek(0)
            mode = msvcrt.LK_LOCK if exclusive else msvcrt.LK_RLCK
            # Use a fixed one-byte region so lock and unlock lengths match
            # even when the audit file grows while held.
            msvcrt.locking(handle.fileno(), mode, 1)

    @staticmethod
    def _unlock_file(handle: TextIO) -> None:
        if fcntl is not None:  # pragma: no branch
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        elif msvcrt is not None:  # pragma: no cover - Windows
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)

    @staticmethod
    def _read_objects_from_handle(handle: TextIO) -> list[dict]:
        handle.seek(0)
        objects: list[dict] = []
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                raise AuditIntegrityError(
                    f"Malformed audit JSON on line {line_number}"
                ) from exc
            if not isinstance(obj, dict):
                raise AuditIntegrityError(
                    f"Audit line {line_number} must contain a JSON object"
                )
            objects.append(obj)
        return objects

    @staticmethod
    def _last_hash_from_objects(objects: list[dict], correlation_id: str) -> Optional[str]:
        last: Optional[str] = None
        for obj in objects:
            if str(obj.get("correlation_id", "")) == correlation_id and obj.get("hash"):
                last = str(obj["hash"])
        return last

    def _read_objects(self) -> list[dict]:
        if not self.path.exists():
            return []
        with self.path.open("r", encoding="utf-8") as handle:
            self._lock_file(handle, exclusive=False)
            try:
                return self._read_objects_from_handle(handle)
            finally:
                self._unlock_file(handle)

    def record(
        self,
        *,
        correlation_id: str,
        run_id: str,
        event_type: str,
        payload: Dict[str, Any],
    ) -> AuditEvent:
        self._ensure_dir()
        correlation_id = str(correlation_id)
        with self._lock:
            with self.path.open("a+", encoding="utf-8") as handle:
                self._lock_file(handle, exclusive=True)
                try:
                    objects = self._read_objects_from_handle(handle)
                    previous = self._last_hash_from_objects(objects, correlation_id)
                    event = AuditEvent.create(
                        correlation_id,
                        str(run_id),
                        str(event_type),
                        payload,
                        previous,
                        self.hash_chain,
                    )
                    handle.seek(0, os.SEEK_END)
                    handle.write(_stable_json(event.to_dict()))
                    handle.write("\n")
                    handle.flush()
                    os.fsync(handle.fileno())
                    try:
                        os.chmod(self.path, 0o600)
                    except OSError:
                        pass
                    return event
                finally:
                    self._unlock_file(handle)

    def append(self, event: AuditEvent) -> None:
        """Append a pre-built event, rejecting a stale predecessor safely."""
        self._ensure_dir()
        payload = event.to_dict()
        with self._lock:
            with self.path.open("a+", encoding="utf-8") as handle:
                self._lock_file(handle, exclusive=True)
                try:
                    objects = self._read_objects_from_handle(handle)
                    expected_prev = self._last_hash_from_objects(
                        objects, event.correlation_id
                    )
                    if payload.get("prev_hash") != expected_prev:
                        raise AuditIntegrityError(
                            "Audit append rejected because prev_hash is stale or invalid"
                        )
                    handle.seek(0, os.SEEK_END)
                    handle.write(_stable_json(payload))
                    handle.write("\n")
                    handle.flush()
                    os.fsync(handle.fileno())
                    try:
                        os.chmod(self.path, 0o600)
                    except OSError:
                        pass
                finally:
                    self._unlock_file(handle)

    def last_hash(self, correlation_id: str) -> Optional[str]:
        correlation_id = str(correlation_id)
        with self._lock:
            return self._last_hash_from_objects(self._read_objects(), correlation_id)

    def verify(self) -> int:
        """Verify JSON integrity and all per-correlation hash chains."""
        with self._lock:
            objects = self._read_objects()
            last_by_correlation: Dict[str, str] = {}

            for index, obj in enumerate(objects, start=1):
                correlation_id = str(obj.get("correlation_id", ""))
                if not correlation_id:
                    raise AuditIntegrityError(
                        f"Audit event {index} is missing correlation_id"
                    )

                expected_prev = last_by_correlation.get(correlation_id)
                if obj.get("prev_hash") != expected_prev:
                    raise AuditIntegrityError(
                        f"Audit event {index} has an invalid prev_hash"
                    )

                event_hash = obj.get("hash")
                if self.hash_chain:
                    if not isinstance(event_hash, str) or not event_hash:
                        raise AuditIntegrityError(
                            f"Audit event {index} is missing its hash"
                        )
                    base = dict(obj)
                    base.pop("hash", None)
                    computed = hashlib.sha256(
                        _stable_json(base).encode("utf-8")
                    ).hexdigest()
                    if computed != event_hash:
                        raise AuditIntegrityError(
                            f"Audit event {index} has an invalid hash"
                        )
                    last_by_correlation[correlation_id] = event_hash
                elif event_hash is not None:
                    raise AuditIntegrityError(
                        f"Audit event {index} unexpectedly contains a hash"
                    )

            return len(objects)


@dataclass
class SqliteAuditStore:
    """Transactional audit store for sustained and concurrent workloads.

    SQLite ``BEGIN IMMEDIATE`` serializes chain-tail selection and insertion in
    one transaction. Each event remains independently hash-verifiable and can
    be exported to canonical JSONL for external review.
    """

    path: str | Path = "sentinel_audit.sqlite3"
    hash_chain: bool = True
    timeout_seconds: float = 30.0
    _lock: threading.RLock = field(default_factory=threading.RLock, init=False, repr=False)

    def __post_init__(self) -> None:
        import math

        self.path = Path(self.path)
        timeout = float(self.timeout_seconds)
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("timeout_seconds must be finite and > 0")
        self.timeout_seconds = timeout
        self._ensure_schema()

    def _connect(self):
        import sqlite3

        connection = sqlite3.connect(
            self.path,
            timeout=self.timeout_seconds,
            isolation_level=None,
        )
        connection.execute(f"PRAGMA busy_timeout={int(self.timeout_seconds * 1000)}")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA foreign_keys=ON")
        return connection

    @contextmanager
    def _connection(self) -> Iterator[Any]:
        """Yield a configured SQLite connection and always close it."""
        connection = self._connect()
        try:
            yield connection
        finally:
            connection.close()

    def _ensure_schema(self) -> None:
        if self.path.is_symlink():
            raise ValueError(f"Audit path must not be a symbolic link: {self.path}")
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with self._connection() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_events (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL UNIQUE,
                    correlation_id TEXT NOT NULL,
                    run_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    event_json TEXT NOT NULL,
                    event_hash TEXT
                )
                """
            )
            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_audit_correlation_sequence
                ON audit_events(correlation_id, sequence DESC)
                """
            )
        try:
            os.chmod(self.path.parent, 0o700)
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    @staticmethod
    def _event_from_json(event_json: str) -> AuditEvent:
        try:
            obj = json.loads(event_json)
        except json.JSONDecodeError as exc:
            raise AuditIntegrityError("Malformed audit event JSON in SQLite") from exc
        if not isinstance(obj, dict):
            raise AuditIntegrityError("SQLite audit event must be a JSON object")
        try:
            return AuditEvent(
                event_id=str(obj["event_id"]),
                correlation_id=str(obj["correlation_id"]),
                run_id=str(obj["run_id"]),
                ts_epoch_ms=int(obj["ts_epoch_ms"]),
                event_type=str(obj["event_type"]),
                payload=dict(obj["payload"]),
                prev_hash=obj.get("prev_hash"),
                hash=obj.get("hash"),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise AuditIntegrityError("Malformed audit event fields in SQLite") from exc

    def record(
        self,
        *,
        correlation_id: str,
        run_id: str,
        event_type: str,
        payload: Dict[str, Any],
    ) -> AuditEvent:
        correlation_id = str(correlation_id)
        with self._lock, self._connection() as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    """
                    SELECT event_json FROM audit_events
                    WHERE correlation_id = ?
                    ORDER BY sequence DESC LIMIT 1
                    """,
                    (correlation_id,),
                ).fetchone()
                previous = self._event_from_json(str(row[0])).hash if row else None
                event = AuditEvent.create(
                    correlation_id,
                    str(run_id),
                    str(event_type),
                    payload,
                    previous,
                    self.hash_chain,
                )
                connection.execute(
                    """
                    INSERT INTO audit_events(
                        event_id, correlation_id, run_id, event_type,
                        event_json, event_hash
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event.event_id,
                        event.correlation_id,
                        event.run_id,
                        event.event_type,
                        _stable_json(event.to_dict()),
                        event.hash,
                    ),
                )
                connection.commit()
                return event
            except Exception:
                connection.rollback()
                raise

    def append(self, event: AuditEvent) -> None:
        with self._lock, self._connection() as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    """
                    SELECT event_json FROM audit_events
                    WHERE correlation_id = ?
                    ORDER BY sequence DESC LIMIT 1
                    """,
                    (event.correlation_id,),
                ).fetchone()
                previous = self._event_from_json(str(row[0])).hash if row else None
                if event.prev_hash != previous:
                    raise AuditIntegrityError(
                        "Audit append rejected because prev_hash is stale or invalid"
                    )
                connection.execute(
                    """
                    INSERT INTO audit_events(
                        event_id, correlation_id, run_id, event_type,
                        event_json, event_hash
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event.event_id,
                        event.correlation_id,
                        event.run_id,
                        event.event_type,
                        _stable_json(event.to_dict()),
                        event.hash,
                    ),
                )
                connection.commit()
            except Exception:
                connection.rollback()
                raise

    def last_hash(self, correlation_id: str) -> Optional[str]:
        with self._lock, self._connection() as connection:
            row = connection.execute(
                """
                SELECT event_json FROM audit_events
                WHERE correlation_id = ?
                ORDER BY sequence DESC LIMIT 1
                """,
                (str(correlation_id),),
            ).fetchone()
            return self._event_from_json(str(row[0])).hash if row else None

    def _events(self) -> list[AuditEvent]:
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT sequence, event_id, correlation_id, run_id, event_type,
                       event_json, event_hash
                FROM audit_events ORDER BY sequence
                """
            ).fetchall()
        events: list[AuditEvent] = []
        for row in rows:
            sequence, event_id, correlation_id, run_id, event_type, event_json, event_hash = row
            event = self._event_from_json(str(event_json))
            if (
                event.event_id != str(event_id)
                or event.correlation_id != str(correlation_id)
                or event.run_id != str(run_id)
                or event.event_type != str(event_type)
                or event.hash != event_hash
            ):
                raise AuditIntegrityError(
                    f"SQLite audit row {sequence} metadata does not match event_json"
                )
            events.append(event)
        return events

    def verify(self) -> int:
        events = self._events()
        last_by_correlation: Dict[str, str] = {}
        for index, event in enumerate(events, start=1):
            expected_prev = last_by_correlation.get(event.correlation_id)
            if event.prev_hash != expected_prev:
                raise AuditIntegrityError(
                    f"Audit event {index} has an invalid prev_hash"
                )
            payload = event.to_dict()
            event_hash = payload.pop("hash")
            if self.hash_chain:
                if not isinstance(event_hash, str) or not event_hash:
                    raise AuditIntegrityError(
                        f"Audit event {index} is missing its hash"
                    )
                computed = hashlib.sha256(
                    _stable_json(payload).encode("utf-8")
                ).hexdigest()
                if computed != event_hash:
                    raise AuditIntegrityError(
                        f"Audit event {index} has an invalid hash"
                    )
                last_by_correlation[event.correlation_id] = event_hash
            elif event_hash is not None:
                raise AuditIntegrityError(
                    f"Audit event {index} unexpectedly contains a hash"
                )
        return len(events)

    def export_jsonl(self, path: str | Path) -> Path:
        target = Path(path)
        if target.is_symlink():
            raise ValueError(f"Export path must not be a symbolic link: {target}")
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        temporary = target.with_name(f".{target.name}.{os.getpid()}.tmp")
        try:
            with temporary.open("w", encoding="utf-8") as handle:
                for event in self._events():
                    handle.write(_stable_json(event.to_dict()))
                    handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            temporary.replace(target)
            try:
                os.chmod(target, 0o600)
            except OSError:
                pass
        finally:
            if temporary.exists():
                temporary.unlink()
        return target
