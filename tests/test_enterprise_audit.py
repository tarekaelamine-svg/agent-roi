from __future__ import annotations

import json
from pathlib import Path
import socket
import threading
import time

import pytest

from agent_roi import SentinelRunner
from agent_roi.audit import AuditIntegrityError, RemoteAuditStore, SqliteAuditStore
from agent_roi.audit.postgres import PostgresAuditStore
from agent_roi.enterprise.control_plane import (
    ControlPlaneService,
    HMACPolicySigner,
    SqliteControlPlaneStore,
    create_fastapi_app,
)


class FakePostgresDB:
    def __init__(self) -> None:
        self.rows: list[dict] = []
        self.next_sequence = 1

    def connect(self):
        return FakeConnection(self)


class FakeConnection:
    def __init__(self, db: FakePostgresDB) -> None:
        self.db = db
        self.closed = False

    def cursor(self):
        return FakeCursor(self.db)

    def commit(self):
        return None

    def rollback(self):
        return None

    def close(self):
        self.closed = True


class FakeCursor:
    def __init__(self, db: FakePostgresDB) -> None:
        self.db = db
        self.results = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def execute(self, sql, params=None):
        normalized = " ".join(sql.split()).lower()
        params = params or ()
        if normalized.startswith("create ") or "pg_advisory_xact_lock" in normalized:
            self.results = []
        elif normalized.startswith("select event_hash"):
            correlation_id = params[0]
            matching = [row for row in self.db.rows if row["correlation_id"] == correlation_id]
            self.results = [] if not matching else [(matching[-1]["event_hash"],)]
        elif normalized.startswith("insert into"):
            (
                event_id,
                correlation_id,
                run_id,
                ts_epoch_ms,
                event_type,
                payload_json,
                prev_hash,
                event_hash,
                event_json,
            ) = params
            self.db.rows.append(
                {
                    "sequence_id": self.db.next_sequence,
                    "event_id": event_id,
                    "correlation_id": correlation_id,
                    "run_id": run_id,
                    "ts_epoch_ms": ts_epoch_ms,
                    "event_type": event_type,
                    "payload_json": json.loads(payload_json),
                    "prev_hash": prev_hash,
                    "event_hash": event_hash,
                    "event_json": json.loads(event_json),
                }
            )
            self.db.next_sequence += 1
            self.results = []
        elif "select event_id::text" in normalized:
            rows = self.db.rows
            if "where correlation_id=%s" in normalized:
                rows = [row for row in rows if row["correlation_id"] == params[0]]
            self.results = [
                (
                    row["event_id"],
                    row["correlation_id"],
                    row["run_id"],
                    row["ts_epoch_ms"],
                    row["event_type"],
                    row["payload_json"],
                    row["prev_hash"],
                    row["event_hash"],
                    row["event_json"],
                )
                for row in rows
            ]
        elif normalized.startswith("select event_json"):
            rows = self.db.rows
            if "where correlation_id=%s" in normalized:
                rows = [row for row in rows if row["correlation_id"] == params[0]]
            self.results = [(row["event_json"],) for row in rows]
        else:
            raise AssertionError(f"Unsupported SQL in fake: {normalized}")

    def fetchone(self):
        return self.results[0] if self.results else None

    def fetchall(self):
        return list(self.results)


def test_postgres_audit_store_transactional_chain_and_tamper_detection(tmp_path: Path) -> None:
    db = FakePostgresDB()
    store = PostgresAuditStore(connection_factory=db.connect)
    first = store.record(
        correlation_id="corr", run_id="run", event_type="start", payload={"x": 1}
    )
    second = store.record(
        correlation_id="corr", run_id="run", event_type="complete", payload={"x": 2}
    )
    assert second.prev_hash == first.hash
    assert store.verify() == 2
    exported = store.export_jsonl(tmp_path / "audit.jsonl")
    assert len(exported.read_text().splitlines()) == 2
    db.rows[1]["event_type"] = "tampered"
    with pytest.raises(AuditIntegrityError, match="denormalized"):
        store.verify()


def _run_uvicorn(app):
    uvicorn = pytest.importorskip("uvicorn")
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    server = uvicorn.Server(
        uvicorn.Config(app, host="127.0.0.1", port=port, log_level="critical")
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 5
    while not server.started and time.time() < deadline:
        time.sleep(0.02)
    return server, thread, port


@pytest.mark.filterwarnings("ignore:websockets.*:DeprecationWarning")
@pytest.mark.filterwarnings("ignore:websockets.server.*:DeprecationWarning")
def test_remote_audit_store_runs_against_central_service(tmp_path: Path) -> None:
    signer = HMACPolicySigner(b"a" * 32)
    service = ControlPlaneService(
        SqliteControlPlaneStore(tmp_path / "control.sqlite3"),
        signers={signer.key_id: signer},
        default_signer_key_id=signer.key_id,
    )
    central = SqliteAuditStore(tmp_path / "central-audit.sqlite3")
    app = create_fastapi_app(service, audit_store=central)
    server, thread, port = _run_uvicorn(app)
    try:
        remote = RemoteAuditStore(
            f"http://127.0.0.1:{port}", require_https=False
        )
        result = SentinelRunner(audit_store=remote).run(lambda ctx, _: "ok", None)
        assert result.output == "ok"
        assert remote.verify(result.correlation_id) == 4
        assert remote.last_hash(result.correlation_id)
    finally:
        server.should_exit = True
        thread.join(timeout=5)
