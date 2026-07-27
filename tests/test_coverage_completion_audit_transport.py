from __future__ import annotations

import builtins
import io
import json
from copy import deepcopy
from pathlib import Path
from urllib.error import HTTPError

import pytest

from agent_roi.audit import AuditEvent, AuditIntegrityError
from agent_roi.audit.postgres import PostgresAuditStore
from agent_roi.audit.remote import RemoteAuditStore


class DB:
    def __init__(self): self.rows=[]; self.next=1; self.fail_insert=False; self.commits=0; self.rollbacks=0; self.closed=0
    def connect(self): return Conn(self)
class Conn:
    def __init__(self,db): self.db=db
    def cursor(self): return Cursor(self.db)
    def commit(self): self.db.commits+=1
    def rollback(self): self.db.rollbacks+=1
    def close(self): self.db.closed+=1
class Cursor:
    def __init__(self,db): self.db=db; self.results=[]
    def __enter__(self): return self
    def __exit__(self,*a): return False
    def execute(self,sql,params=None):
        n=" ".join(sql.split()).lower(); p=params or ()
        if n.startswith("create ") or "pg_advisory_xact_lock" in n: self.results=[]; return
        if n.startswith("select event_hash"):
            m=[r for r in self.db.rows if r["correlation_id"]==p[0]]; self.results=[] if not m else [(m[-1]["event_hash"],)]; return
        if n.startswith("insert into"):
            if self.db.fail_insert: raise RuntimeError("insert")
            event_id,correlation_id,run_id,ts,event_type,payload,prev,h,event_json=p
            self.db.rows.append({"sequence":self.db.next,"event_id":event_id,"correlation_id":correlation_id,"run_id":run_id,"ts_epoch_ms":ts,"event_type":event_type,"payload_json":json.loads(payload),"prev_hash":prev,"event_hash":h,"event_json":json.loads(event_json)})
            self.db.next+=1; self.results=[]; return
        if "select event_id::text" in n:
            rows=self.db.rows
            if "where correlation_id=%s" in n: rows=[r for r in rows if r["correlation_id"]==p[0]]
            self.results=[(r["event_id"],r["correlation_id"],r["run_id"],r["ts_epoch_ms"],r["event_type"],r["payload_json"],r["prev_hash"],r["event_hash"],r["event_json"]) for r in rows]; return
        if n.startswith("select event_json"):
            rows=self.db.rows
            if "where correlation_id=%s" in n: rows=[r for r in rows if r["correlation_id"]==p[0]]
            self.results=[(r["event_json"],) for r in rows]; return
        raise AssertionError(n)
    def fetchone(self): return self.results[0] if self.results else None
    def fetchall(self): return list(self.results)


def test_postgres_audit_constructor_import_record_append_and_export(tmp_path: Path, monkeypatch):
    for kwargs in ({"table_name":"bad-name"},{"schema":"bad-name"},{}):
        with pytest.raises(ValueError): PostgresAuditStore(initialize=False,**kwargs)
    db=DB(); store=PostgresAuditStore(connection_factory=db.connect)
    first=store.record(correlation_id="c",run_id="r",event_type="start",payload={"x":1})
    assert store.last_hash("c")==first.hash and store.verify("c")==1
    exported=store.export_jsonl(tmp_path/"a.jsonl",correlation_id="c"); assert "start" in exported.read_text()
    stale=AuditEvent.create("c","r","x",{},None,True)
    with pytest.raises(AuditIntegrityError,match="stale"): store.append(stale)
    db.fail_insert=True
    with pytest.raises(RuntimeError): store.record(correlation_id="c",run_id="r",event_type="bad",payload={})
    assert db.rollbacks>=2

    original=builtins.__import__
    def block(name,*a,**k):
        if name=="psycopg": raise ImportError()
        return original(name,*a,**k)
    monkeypatch.setattr(builtins,"__import__",block)
    with pytest.raises(RuntimeError,match="psycopg"): PostgresAuditStore("dsn",initialize=False)._connect()


def test_postgres_audit_verify_all_integrity_failures(tmp_path: Path):
    db=DB(); store=PostgresAuditStore(connection_factory=db.connect,initialize=False)
    e=store.record(correlation_id="c",run_id="r",event_type="x",payload={})
    original=deepcopy(db.rows[0])
    cases=[]
    cases.append(("event_json", "not-json", "event_json"))
    cases.append(("event_json", [], "must be an object"))
    bad=dict(original["event_json"]); bad["event_type"]="changed"; cases.append(("event_json",bad,"denormalized"))
    bad_prev=deepcopy(original); bad_prev["prev_hash"]="bad"; bad_prev["event_json"]["prev_hash"]="bad"; cases.append(("row",bad_prev,"invalid prev_hash"))
    bad_hash=deepcopy(original); bad_hash["event_hash"]="0"*64; bad_event=dict(bad_hash["event_json"]); bad_event["hash"]="0"*64; bad_hash["event_json"]=bad_event; cases.append(("row",bad_hash,"invalid hash"))
    for kind,value,match in cases:
        db.rows[0]=deepcopy(original)
        if kind=="event_json": db.rows[0]["event_json"]=value
        else: db.rows[0]=value
        with pytest.raises((AuditIntegrityError,json.JSONDecodeError),match=match): store.verify()
    # hash disabled accepts no hash and rejects an unexpected hash
    db2=DB(); nohash=PostgresAuditStore(connection_factory=db2.connect,hash_chain=False,initialize=False)
    nohash.record(correlation_id="c",run_id="r",event_type="x",payload={}); assert nohash.verify()==1
    db2.rows[0]["event_hash"]="x"; db2.rows[0]["event_json"]["hash"]="x"
    with pytest.raises(AuditIntegrityError,match="unexpectedly"): nohash.verify()
    # _normalize_json directly
    with pytest.raises(AuditIntegrityError): store._normalize_json(1)


class HTTPResponse:
    def __init__(self,payload=b""): self.payload=payload
    def __enter__(self): return self
    def __exit__(self,*a): return False
    def read(self): return self.payload


def event_dict():
    return AuditEvent.create("c","r","x",{},None,True).to_dict()


def test_remote_audit_all_transport_paths(monkeypatch):
    with pytest.raises(ValueError): RemoteAuditStore("http://x")
    seen=[]
    monkeypatch.setattr("agent_roi.audit.remote.urlrequest.urlopen",lambda req,timeout: seen.append(req) or HTTPResponse(json.dumps(event_dict()).encode()))
    remote=RemoteAuditStore("https://x/",bearer_token="t")
    event=remote.record(correlation_id="c",run_id="r",event_type="x",payload={})
    assert event.correlation_id=="c" and seen[0].headers["Authorization"]=="Bearer t"
    monkeypatch.setattr(remote,"_request",lambda *a,**k:event.to_dict())
    remote.append(event)
    changed=event.to_dict(); changed["event_type"]="changed"
    monkeypatch.setattr(remote,"_request",lambda *a,**k:changed)
    with pytest.raises(AuditIntegrityError): remote.append(event)
    monkeypatch.setattr(remote,"_request",lambda *a,**k:{"last_hash":"h"})
    assert remote.last_hash("a/b")=="h"
    monkeypatch.setattr(remote,"_request",lambda *a,**k:None)
    assert remote.last_hash("x") is None
    monkeypatch.setattr(remote,"_request",lambda *a,**k:{"events_verified":"3"})
    assert remote.verify("a/b")==3

    err=HTTPError("u",400,"bad",{},io.BytesIO(b"detail"))
    monkeypatch.setattr("agent_roi.audit.remote.urlrequest.urlopen",lambda *a,**k: (_ for _ in ()).throw(err))
    with pytest.raises(RuntimeError,match="HTTP 400"): RemoteAuditStore("https://x")._request("GET","/")
    monkeypatch.setattr("agent_roi.audit.remote.urlrequest.urlopen",lambda *a,**k: (_ for _ in ()).throw(OSError()))
    with pytest.raises(RuntimeError,match="unavailable"): RemoteAuditStore("https://x")._request("GET","/")
    monkeypatch.setattr("agent_roi.audit.remote.urlrequest.urlopen",lambda *a,**k: HTTPResponse())
    assert RemoteAuditStore("https://x")._request("GET","/") is None
