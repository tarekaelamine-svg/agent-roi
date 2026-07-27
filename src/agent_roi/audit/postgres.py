from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from .event import AuditEvent, _stable_json
from .store import AuditIntegrityError


class PostgresAuditStore:
    """Transactional, multi-host audit store for PostgreSQL.

    Each correlation chain is protected by a transaction-scoped advisory lock,
    ensuring that selecting the current tail and inserting the next event are
    atomic across processes and hosts.
    """

    hash_chain: bool

    def __init__(
        self,
        dsn: str = "",
        *,
        hash_chain: bool = True,
        table_name: str = "agent_roi_audit_events",
        schema: str = "public",
        connection_factory: Optional[Callable[[], Any]] = None,
        initialize: bool = True,
    ) -> None:
        if not table_name.replace("_", "").isalnum():
            raise ValueError("table_name must contain only letters, numbers, and underscores")
        if not schema.replace("_", "").isalnum():
            raise ValueError("schema must contain only letters, numbers, and underscores")
        if connection_factory is None and not dsn.strip():
            raise ValueError("dsn or connection_factory is required")
        self.dsn = dsn
        self.hash_chain = bool(hash_chain)
        self.table_name = table_name
        self.schema = schema
        self.qualified_table_name = f'"{schema}"."{table_name}"'
        self._connection_factory = connection_factory
        if initialize:
            self.initialize()

    def _connect(self) -> Any:
        if self._connection_factory is not None:
            return self._connection_factory()
        try:
            import psycopg  # type: ignore
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise RuntimeError(
                "PostgreSQL audit storage requires psycopg. Install agent-roi[postgres]."
            ) from exc
        return psycopg.connect(self.dsn)

    def initialize(self) -> None:
        conn = self._connect()
        try:
            with conn.cursor() as cursor:
                cursor.execute(f'CREATE SCHEMA IF NOT EXISTS "{self.schema}"')
                cursor.execute(
                    f"""CREATE TABLE IF NOT EXISTS {self.qualified_table_name} (
                        sequence_id BIGSERIAL PRIMARY KEY,
                        event_id UUID NOT NULL UNIQUE,
                        correlation_id TEXT NOT NULL,
                        run_id TEXT NOT NULL,
                        ts_epoch_ms BIGINT NOT NULL,
                        event_type TEXT NOT NULL,
                        payload_json JSONB NOT NULL,
                        prev_hash CHAR(64),
                        event_hash CHAR(64),
                        event_json JSONB NOT NULL
                    )"""
                )
                cursor.execute(
                    f"CREATE INDEX IF NOT EXISTS idx_{self.table_name}_correlation_sequence "
                    f"ON {self.qualified_table_name}(correlation_id, sequence_id)"
                )
                cursor.execute(
                    f"CREATE INDEX IF NOT EXISTS idx_{self.table_name}_run "
                    f"ON {self.qualified_table_name}(run_id)"
                )
            conn.commit()
        finally:
            conn.close()

    @staticmethod
    def _lock_chain(cursor: Any, correlation_id: str) -> None:
        cursor.execute(
            "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
            (correlation_id,),
        )

    def _tail(self, cursor: Any, correlation_id: str) -> Optional[str]:
        cursor.execute(
            f"SELECT event_hash FROM {self.qualified_table_name} "
            "WHERE correlation_id=%s ORDER BY sequence_id DESC LIMIT 1",
            (correlation_id,),
        )
        row = cursor.fetchone()
        return None if row is None or row[0] is None else str(row[0]).strip()

    def _insert(self, cursor: Any, event: AuditEvent) -> None:
        payload = event.to_dict()
        cursor.execute(
            f"""INSERT INTO {self.qualified_table_name}
                (event_id, correlation_id, run_id, ts_epoch_ms, event_type,
                 payload_json, prev_hash, event_hash, event_json)
                VALUES (%s, %s, %s, %s, %s, %s::jsonb, %s, %s, %s::jsonb)""",
            (
                event.event_id,
                event.correlation_id,
                event.run_id,
                event.ts_epoch_ms,
                event.event_type,
                _stable_json(event.payload),
                event.prev_hash,
                event.hash,
                _stable_json(payload),
            ),
        )

    def record(
        self,
        *,
        correlation_id: str,
        run_id: str,
        event_type: str,
        payload: Dict[str, Any],
    ) -> AuditEvent:
        correlation_id = str(correlation_id)
        conn = self._connect()
        try:
            with conn.cursor() as cursor:
                self._lock_chain(cursor, correlation_id)
                previous = self._tail(cursor, correlation_id)
                event = AuditEvent.create(
                    correlation_id,
                    str(run_id),
                    str(event_type),
                    payload,
                    previous,
                    self.hash_chain,
                )
                self._insert(cursor, event)
            conn.commit()
            return event
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def append(self, event: AuditEvent) -> None:
        conn = self._connect()
        try:
            with conn.cursor() as cursor:
                self._lock_chain(cursor, event.correlation_id)
                expected = self._tail(cursor, event.correlation_id)
                if event.prev_hash != expected:
                    raise AuditIntegrityError(
                        "Audit append rejected because prev_hash is stale or invalid"
                    )
                self._insert(cursor, event)
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def last_hash(self, correlation_id: str) -> Optional[str]:
        conn = self._connect()
        try:
            with conn.cursor() as cursor:
                return self._tail(cursor, str(correlation_id))
        finally:
            conn.close()

    @staticmethod
    def _normalize_json(value: Any) -> dict[str, Any]:
        if isinstance(value, str):
            try:
                value = json.loads(value)
            except (TypeError, ValueError, json.JSONDecodeError) as exc:
                raise AuditIntegrityError("PostgreSQL audit event_json is not valid JSON") from exc
        if not isinstance(value, dict):
            raise AuditIntegrityError("PostgreSQL audit event_json must be an object")
        return value

    def verify(self, correlation_id: str = "") -> int:
        conn = self._connect()
        try:
            with conn.cursor() as cursor:
                if correlation_id:
                    cursor.execute(
                        f"""SELECT event_id::text, correlation_id, run_id, ts_epoch_ms,
                                   event_type, payload_json, prev_hash, event_hash, event_json
                            FROM {self.qualified_table_name} WHERE correlation_id=%s
                            ORDER BY sequence_id""",
                        (correlation_id,),
                    )
                else:
                    cursor.execute(
                        f"""SELECT event_id::text, correlation_id, run_id, ts_epoch_ms,
                                   event_type, payload_json, prev_hash, event_hash, event_json
                            FROM {self.qualified_table_name} ORDER BY sequence_id"""
                    )
                rows = cursor.fetchall()
        finally:
            conn.close()

        tails: dict[str, str] = {}
        for index, row in enumerate(rows, start=1):
            event_json = self._normalize_json(row[8])
            payload_json = row[5] if isinstance(row[5], dict) else json.loads(row[5])
            denormalized = {
                "event_id": str(row[0]),
                "correlation_id": str(row[1]),
                "run_id": str(row[2]),
                "ts_epoch_ms": int(row[3]),
                "event_type": str(row[4]),
                "payload": payload_json,
                "prev_hash": None if row[6] is None else str(row[6]).strip(),
                "hash": None if row[7] is None else str(row[7]).strip(),
            }
            if event_json != denormalized:
                raise AuditIntegrityError(
                    f"PostgreSQL audit event {index} denormalized columns do not match event_json"
                )
            expected_prev = tails.get(denormalized["correlation_id"])
            if denormalized["prev_hash"] != expected_prev:
                raise AuditIntegrityError(f"PostgreSQL audit event {index} has an invalid prev_hash")
            event_hash = denormalized.pop("hash")
            if self.hash_chain:
                computed = hashlib.sha256(_stable_json(denormalized).encode("utf-8")).hexdigest()
                if computed != event_hash:
                    raise AuditIntegrityError(f"PostgreSQL audit event {index} has an invalid hash")
                tails[denormalized["correlation_id"]] = str(event_hash)
            elif event_hash is not None:
                raise AuditIntegrityError(
                    f"PostgreSQL audit event {index} unexpectedly contains a hash"
                )
        return len(rows)

    def export_jsonl(self, path: str | Path, *, correlation_id: str = "") -> Path:
        conn = self._connect()
        try:
            with conn.cursor() as cursor:
                if correlation_id:
                    cursor.execute(
                        f"SELECT event_json FROM {self.qualified_table_name} WHERE correlation_id=%s ORDER BY sequence_id",
                        (correlation_id,),
                    )
                else:
                    cursor.execute(
                        f"SELECT event_json FROM {self.qualified_table_name} ORDER BY sequence_id"
                    )
                rows = cursor.fetchall()
        finally:
            conn.close()
        output = Path(path)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            "".join(_stable_json(self._normalize_json(row[0])) + "\n" for row in rows),
            encoding="utf-8",
        )
        return output
