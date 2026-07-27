from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path

import pytest

from agent_roi.audit.event import AuditEvent
from agent_roi.audit.store import (
    AuditIntegrityError,
    InMemoryAuditStore,
    JsonlAuditStore,
    SqliteAuditStore,
)


def event(correlation="c", previous=None, *, chain=True):
    return AuditEvent.create(correlation, "r", "e", {"x": 1}, previous, chain)


def test_inmemory_chain_and_no_chain_integrity_errors() -> None:
    store = InMemoryAuditStore()
    first = store.record(correlation_id="c", run_id="r", event_type="e", payload={})
    with pytest.raises(AuditIntegrityError, match="stale"):
        store.append(event(previous=None))
    bad_prev = AuditEvent(**{**first.to_dict(), "event_id": "x", "prev_hash": "bad"})
    store.events.append(bad_prev)
    with pytest.raises(AuditIntegrityError, match="prev_hash"):
        store.verify()

    store = InMemoryAuditStore(hash_chain=True)
    good = store.record(correlation_id="c", run_id="r", event_type="e", payload={})
    store.events[0] = AuditEvent(**{**good.to_dict(), "hash": "bad"})
    with pytest.raises(AuditIntegrityError, match="invalid hash"):
        store.verify()

    no_chain = InMemoryAuditStore(hash_chain=False)
    no_chain.events.append(event(chain=True))
    with pytest.raises(AuditIntegrityError, match="unexpectedly"):
        no_chain.verify()
    plain = event(chain=False)
    no_chain = InMemoryAuditStore(hash_chain=False)
    no_chain.append(plain)
    assert no_chain.verify() == 1


def test_jsonl_validation_append_permissions_and_symlink(tmp_path: Path, monkeypatch) -> None:
    target = tmp_path / "audit.jsonl"
    store = JsonlAuditStore(target)
    assert store.last_hash("c") is None
    monkeypatch.setattr(os, "chmod", lambda *a: (_ for _ in ()).throw(OSError()))
    first = store.record(correlation_id="c", run_id="r", event_type="e", payload={})
    with pytest.raises(AuditIntegrityError, match="stale"):
        store.append(event("c", None))
    second = event("c", first.hash)
    store.append(second)
    assert store.verify() == 2
    assert store.last_hash("c") == second.hash

    target.write_text("\nnot-json\n", encoding="utf-8")
    with pytest.raises(AuditIntegrityError, match="Malformed"):
        store.verify()
    target.write_text("[]\n", encoding="utf-8")
    with pytest.raises(AuditIntegrityError, match="JSON object"):
        store.verify()
    target.write_text(json.dumps({"event_type":"x","prev_hash":None,"hash":"x"})+"\n", encoding="utf-8")
    with pytest.raises(AuditIntegrityError, match="correlation_id"):
        store.verify()
    target.write_text(json.dumps({"correlation_id":"c","event_type":"x","prev_hash":None,"hash":None})+"\n", encoding="utf-8")
    with pytest.raises(AuditIntegrityError, match="missing its hash"):
        store.verify()
    target.write_text(json.dumps({"correlation_id":"c","event_type":"x","prev_hash":None,"hash":"bad"})+"\n", encoding="utf-8")
    with pytest.raises(AuditIntegrityError, match="invalid hash"):
        store.verify()
    no_chain = JsonlAuditStore(target, hash_chain=False)
    with pytest.raises(AuditIntegrityError, match="unexpectedly"):
        no_chain.verify()

    link = tmp_path / "link.jsonl"
    link.symlink_to(target)
    with pytest.raises(ValueError, match="symbolic"):
        JsonlAuditStore(link).record(correlation_id="c",run_id="r",event_type="e",payload={})


def test_sqlite_validation_rollback_export_and_tampering(tmp_path: Path, monkeypatch) -> None:
    for bad in (0, -1, float("inf"), float("nan")):
        with pytest.raises(ValueError):
            SqliteAuditStore(tmp_path / f"bad-{str(bad)}.db", timeout_seconds=bad)
    path = tmp_path / "audit.db"
    monkeypatch.setattr(os, "chmod", lambda *a: (_ for _ in ()).throw(OSError()))
    store = SqliteAuditStore(path)
    assert store.last_hash("none") is None
    with pytest.raises(AuditIntegrityError, match="Malformed audit event JSON"):
        store._event_from_json("bad")
    with pytest.raises(AuditIntegrityError, match="JSON object"):
        store._event_from_json("[]")
    with pytest.raises(AuditIntegrityError, match="fields"):
        store._event_from_json("{}")

    first = store.record(correlation_id="c", run_id="r", event_type="e", payload={})
    with pytest.raises(AuditIntegrityError, match="stale"):
        store.append(event("c", None))
    store.append(event("c", first.hash))
    assert store.verify() == 2
    link = tmp_path / "export-link"
    existing = tmp_path / "existing"
    existing.write_text("x")
    link.symlink_to(existing)
    with pytest.raises(ValueError, match="symbolic"):
        store.export_jsonl(link)
    assert store.export_jsonl(tmp_path / "out" / "audit.jsonl").is_file()

    conn = sqlite3.connect(path)
    conn.execute("UPDATE audit_events SET event_type='tampered' WHERE sequence=1")
    conn.commit(); conn.close()
    with pytest.raises(AuditIntegrityError, match="metadata"):
        store.verify()

    store2 = SqliteAuditStore(tmp_path / "rollback.db")
    original = store2._connect
    class FailingConnection:
        def __init__(self, inner): self.inner=inner; self.rolled=False
        def execute(self, sql, params=()):
            if sql.strip().startswith("INSERT INTO audit_events"): raise sqlite3.OperationalError("fail")
            return self.inner.execute(sql, params)
        def commit(self): return self.inner.commit()
        def rollback(self): self.rolled=True; return self.inner.rollback()
        def close(self): return self.inner.close()
    failing = FailingConnection(original())
    monkeypatch.setattr(store2, "_connect", lambda: failing)
    with pytest.raises(sqlite3.OperationalError):
        store2.record(correlation_id="c", run_id="r", event_type="e", payload={})
    assert failing.rolled
