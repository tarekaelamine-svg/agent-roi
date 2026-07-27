from __future__ import annotations

import sqlite3

from agent_roi.enterprise import (
    OutboxEvent,
    OutboxEventSink,
    OutboxStatus,
    OutboxWorker,
    SqliteOutboxStore,
)
from agent_roi.runtime import RetryPolicy


def _event(key: str = "key-1", destination: str = "siem") -> OutboxEvent:
    return OutboxEvent.create(
        topic="audit",
        destination=destination,
        payload={"event": "tool_completed"},
        idempotency_key=key,
    )


def _read_row(path, event_id):
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute("SELECT * FROM enterprise_outbox WHERE event_id=?", (event_id,)).fetchone()
        return dict(row) if row is not None else None
    finally:
        conn.close()


def test_sqlite_outbox_enqueue_is_idempotent_and_claim_is_leased(tmp_path) -> None:
    path = tmp_path / "outbox.sqlite3"
    store = SqliteOutboxStore(path)
    first = store.enqueue(_event())
    duplicate = store.enqueue(_event())
    assert duplicate.event_id == first.event_id
    claimed = store.claim(worker_id="worker-1", limit=10, lease_seconds=30)
    assert len(claimed) == 1
    assert claimed[0].status is OutboxStatus.LEASED
    assert claimed[0].attempts == 1
    assert store.claim(worker_id="worker-2", limit=10, lease_seconds=30) == ()


def test_outbox_worker_delivers_and_records_completion(tmp_path) -> None:
    path = tmp_path / "outbox.sqlite3"
    store = SqliteOutboxStore(path)
    event = store.enqueue(_event())
    delivered: list[str] = []
    worker = OutboxWorker(
        store,
        {"siem": lambda item: delivered.append(item.event_id)},
        worker_id="worker",
    )
    assert worker.run_once() == {"claimed": 1, "delivered": 1, "retried": 0, "dead_lettered": 0}
    assert delivered == [event.event_id]
    row = _read_row(path, event.event_id)
    assert row["status"] == "delivered"
    assert row["delivered_at_utc"]


def test_outbox_worker_reschedules_then_dead_letters(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr("agent_roi.enterprise.outbox.time.sleep", lambda _: None)
    path = tmp_path / "outbox.sqlite3"
    store = SqliteOutboxStore(path)
    event = store.enqueue(_event())
    worker = OutboxWorker(
        store,
        {"siem": lambda item: (_ for _ in ()).throw(OSError("offline"))},
        worker_id="worker",
        retry_policy=RetryPolicy(max_attempts=1, initial_backoff_seconds=0, jitter_ratio=0),
        max_delivery_attempts=2,
    )
    first = worker.run_once()
    assert first["retried"] == 1
    second = worker.run_once()
    assert second["dead_lettered"] == 1
    row = _read_row(path, event.event_id)
    assert row["status"] == "dead_letter"
    conn = sqlite3.connect(path)
    try:
        assert conn.execute("SELECT COUNT(*) FROM enterprise_dead_letters").fetchone()[0] == 1
    finally:
        conn.close()


def test_outbox_worker_isolates_unknown_destination_in_dead_letter(tmp_path) -> None:
    path = tmp_path / "outbox.sqlite3"
    store = SqliteOutboxStore(path)
    store.enqueue(_event(destination="missing"))
    worker = OutboxWorker(store, {}, worker_id="worker", max_delivery_attempts=1)
    result = worker.run_once()
    assert result["dead_lettered"] == 1


def test_outbox_event_sink_persists_cloudevent_like_payload(tmp_path) -> None:
    path = tmp_path / "outbox.sqlite3"
    store = SqliteOutboxStore(path)
    sink = OutboxEventSink(store, destination="splunk", topic="telemetry")
    sink.emit({"id": "evt-1", "type": "com.agentroi.test", "data": {"x": 1}})
    claimed = store.claim(worker_id="worker", limit=1, lease_seconds=30)
    assert claimed[0].event_id == "evt-1"
    assert claimed[0].payload["data"] == {"x": 1}
