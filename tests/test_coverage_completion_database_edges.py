from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import builtins
import json
import sys
import time
from types import SimpleNamespace
from typing import Any

import pytest

from agent_roi.approvals import ApprovalRecord, ApprovalRequest, ApprovalStatus
from agent_roi.approvals.postgres import PostgresApprovalRepository
from agent_roi.audit import AuditEvent, AuditIntegrityError
from agent_roi.audit.postgres import PostgresAuditStore
from agent_roi.db.core import (
    DatabaseConfigurationError, Migration, MigrationError, PostgresConnectionFactory,
    PostgresMigrationManager, fetchall_mappings, fetchone_mapping, load_postgres_migrations,
    row_to_mapping, split_sql_statements,
)
from agent_roi.enterprise.outbox import OutboxEvent, OutboxStatus, PostgresOutboxStore
from agent_roi.roi.postgres import PostgresROILedger, _iso, _json_value
from agent_roi.runtime.resilience import (
    IdempotencyConflict, IdempotencyInProgress, PostgresIdempotencyStore,
)
from agent_roi.runtime.tools import ApprovalGrant


@dataclass
class Step:
    contains: str
    rows: list[Any]
    rowcount: int = 0
    error: Exception | None = None


class DB:
    def __init__(self, steps=(), *, dsn="dsn"):
        self.steps=list(steps); self.calls=[]; self.commits=0; self.rollbacks=0; self.closes=0; self.dsn=dsn
    def connect(self, dsn="dsn", **kwargs):
        assert dsn==self.dsn
        return Conn(self)
    def factory(self): return Conn(self)
    def done(self): assert not self.steps, self.steps


class Conn:
    def __init__(self, db): self.db=db
    def cursor(self): return Cursor(self.db)
    def commit(self): self.db.commits+=1
    def rollback(self): self.db.rollbacks+=1
    def close(self): self.db.closes+=1


class Cursor:
    description=None
    def __init__(self,db): self.db=db; self.rows=[]; self.rowcount=0
    def __enter__(self): return self
    def __exit__(self,*a): return False
    def execute(self,sql,params=None):
        normalized=" ".join(str(sql).split()); params=tuple(params or ())
        self.db.calls.append((normalized,params))
        if normalized.startswith("CREATE SCHEMA") or normalized.startswith("SET search_path"):
            self.rows=[]; self.rowcount=0; return
        if not self.db.steps: raise AssertionError(f"Unexpected SQL: {normalized}")
        step=self.db.steps.pop(0); assert step.contains.lower() in normalized.lower(),(step.contains,normalized)
        if step.error: raise step.error
        self.rows=list(step.rows); self.rowcount=step.rowcount
        if self.rows and isinstance(self.rows[0],dict): self.description=[(k,) for k in self.rows[0]]
    def fetchone(self): return self.rows[0] if self.rows else None
    def fetchall(self): return list(self.rows)
    def close(self): pass


def test_db_core_validation_parsing_mapping_and_connection(monkeypatch):
    for args in ((0,"x","sql"),(1,"","sql"),(1,"x","")):
        with pytest.raises(ValueError): Migration(*args)
    with pytest.raises(DatabaseConfigurationError): PostgresConnectionFactory("")
    with pytest.raises(DatabaseConfigurationError): PostgresConnectionFactory("dsn",schema="bad-name")

    db=DB()
    factory=PostgresConnectionFactory("dsn",connect_factory=db.connect,connect_kwargs={"x":1})
    # connect factory sees kwargs; use a flexible wrapper
    factory._connect_factory=lambda dsn,**kw: Conn(db)
    with factory.connection() as conn: assert isinstance(conn,Conn)
    assert db.commits==1 and db.closes==1
    with pytest.raises(RuntimeError):
        with factory.connection(): raise RuntimeError("boom")
    assert db.rollbacks==1

    original_import=builtins.__import__
    def block(name,*args,**kwargs):
        if name=="psycopg" or name.startswith("psycopg."): raise ImportError(name)
        return original_import(name,*args,**kwargs)
    monkeypatch.setattr(builtins,"__import__",block)
    with pytest.raises(RuntimeError,match="psycopg"):
        PostgresConnectionFactory("dsn")._connect()

    sql="""-- comment;\nSELECT 'a;''b'; /* x;y */ SELECT \"a;b\"; DO $tag$ BEGIN RAISE NOTICE ';'; END $tag$; SELECT 'a\\\'b';"""
    parts=split_sql_statements(sql)
    assert len(parts)==4 and "NOTICE" in parts[2]
    for malformed in ("SELECT 'x", "DO $$ x", "/* x"):
        with pytest.raises(MigrationError): split_sql_statements(malformed)

    class Col: 
        def __init__(self,name): self.name=name
    c=SimpleNamespace(description=[Col("a"),("b",)],fetchone=lambda:(1,2),fetchall=lambda:[(3,4)])
    assert row_to_mapping(c,{"x":1})=={"x":1}
    assert fetchone_mapping(c)=={"a":1,"b":2}
    assert fetchall_mappings(c)==({"a":3,"b":4},)
    with pytest.raises(ValueError): row_to_mapping(c,None)
    with pytest.raises(TypeError): row_to_mapping(SimpleNamespace(description=None),(1,))


def test_migration_manager_versions_conflicts_and_wrapping(monkeypatch):
    # current version none/mapping/tuple
    for rows,expected in (([],0),([{"version":2}],2),([(3,)],3)):
        db=DB([Step("CREATE TABLE",[]),Step("SELECT COALESCE",rows)])
        assert PostgresMigrationManager(PostgresConnectionFactory("dsn",connect_factory=db.connect),migrations=[]).current_version()==expected

    migrations=[Migration(1,"one","SELECT 1; SELECT 'x;';"),Migration(2,"two","SELECT 2")]
    db=DB([Step("pg_advisory",[]),Step("CREATE TABLE",[]),Step("SELECT version",[(1,"one")]),Step("SELECT 2",[]),Step("INSERT INTO",[])])
    manager=PostgresMigrationManager(PostgresConnectionFactory("dsn",connect_factory=db.connect),migrations=migrations)
    assert manager.migrate()==(2,)
    db=DB([Step("pg_advisory",[]),Step("CREATE TABLE",[]),Step("SELECT version",[(1,"wrong")])])
    with pytest.raises(MigrationError,match="previously applied"):
        PostgresMigrationManager(PostgresConnectionFactory("dsn",connect_factory=db.connect),migrations=migrations).migrate()
    db=DB([Step("pg_advisory",[],error=RuntimeError("db"))])
    with pytest.raises(MigrationError,match="migration failed"):
        PostgresMigrationManager(PostgresConnectionFactory("dsn",connect_factory=db.connect),migrations=migrations).migrate(target_version=1)

    class Item:
        def __init__(self,name,text="SELECT 1"): self.name=name; self.text=text
        def read_text(self,encoding): return self.text
    class Root:
        def iterdir(self): return [Item("0001_one.sql"),Item("note.txt"),Item("0001_two.sql")]
    monkeypatch.setattr("agent_roi.db.core.resources.files",lambda _:Root())
    with pytest.raises(MigrationError,match="unique"):
        load_postgres_migrations()


def request(now=None):
    now=now or int(time.time()*1000)
    return ApprovalRequest(request_id="r",checkpoint_id="c",action_digest="a"*64,organization_id="o",environment="prod",agent_id="a",correlation_id="co",run_id="ru",tool_name="t",tool_version="1",risk="high",estimated_cost_usd=1,arguments_digest="b"*64,policy_digest="d"*64,created_at_epoch_ms=now,expires_at_epoch_ms=now+10000)


def test_postgres_approval_all_remaining_paths(monkeypatch):
    monkeypatch.setattr("agent_roi.approvals.postgres.PostgresMigrationManager.migrate",lambda self:None)
    PostgresApprovalRepository("dsn",connect_factory=DB().connect)
    rec=ApprovalRecord(request(),ApprovalStatus.PENDING)
    db=DB([Step("UPDATE approval_records",[(2,)])]); assert PostgresApprovalRepository("dsn",connect_factory=db.connect,auto_migrate=False).save_record(rec,expected_revision=1)==2
    db=DB([Step("UPDATE approval_records",[])]);
    with pytest.raises(ValueError,match="revision conflict"): PostgresApprovalRepository("dsn",connect_factory=db.connect,auto_migrate=False).save_record(rec,expected_revision=1)
    db=DB([Step("SELECT * FROM approval_records",[])])
    with pytest.raises(KeyError): PostgresApprovalRepository("dsn",connect_factory=db.connect,auto_migrate=False).get_record("x")
    row={"checkpoint_id":"c","request_json":json.dumps(request().to_dict()),"status":"pending","external_id":"","decided_by":"","decision_reason":"","decided_at_epoch_ms":None}
    db=DB([Step("SELECT checkpoint_id",[{"checkpoint_id":"c"}]),Step("SELECT * FROM approval_records",[row])])
    pending=PostgresApprovalRepository("dsn",connect_factory=db.connect,auto_migrate=False).pending(organization_id="o",environment="prod",limit=999,offset=-1)
    assert len(pending)==1
    grant=ApprovalGrant("a"*64,"u",int(time.time()*1000)+10000,"c")
    db=DB([Step("UPDATE approval_grants",[(3,)])]); assert PostgresApprovalRepository("dsn",connect_factory=db.connect,auto_migrate=False).save_grant(grant,expected_revision=2)==3
    db=DB([Step("UPDATE approval_grants",[])])
    with pytest.raises(ValueError): PostgresApprovalRepository("dsn",connect_factory=db.connect,auto_migrate=False).save_grant(grant,expected_revision=2)
    expired={"action_digest":"a"*64,"approved_by":"u","expires_at_epoch_ms":0,"checkpoint_id":"","reason":""}
    db=DB([Step("SELECT * FROM approval_grants",[expired])])
    with pytest.raises(KeyError): PostgresApprovalRepository("dsn",connect_factory=db.connect,auto_migrate=False).get_grant("a"*64)
    db=DB([Step("UPDATE approval_grants SET consumed",[])])
    with pytest.raises(KeyError): PostgresApprovalRepository("dsn",connect_factory=db.connect,auto_migrate=False).consume_grant("a"*64)


def roi_row(status="proposed",revision=1):
    return {"opportunity_id":"r","organization_id":"o","agent_id":"a","business_unit":"b","business_owner":"u","title":"t","value_type":"cost_savings","value_period":"one_time","status":status,"currency_code":"USD","baseline_cents":100,"forecast_cents":50,"confidence":.5,"source_key":"s","measurement_start":"","measurement_end":"","created_at_utc":"2026","created_by":"u","metadata_json":"{}","revision":revision}


def test_postgres_roi_validation_conflicts_and_summary(monkeypatch):
    monkeypatch.setattr("agent_roi.roi.postgres.PostgresMigrationManager.migrate",lambda self:None)
    PostgresROILedger("dsn",connect_factory=DB().connect)
    assert _json_value('{"x":1}')=={"x":1} and _iso(datetime(2026,1,1,tzinfo=timezone.utc)).startswith("2026")
    ledger=PostgresROILedger("dsn",connect_factory=DB().connect,auto_migrate=False)
    base=dict(organization_id="o",agent_id="a",business_unit="b",business_owner="u",title="t",value_type="cost_savings",value_period="one_time",baseline_usd=1,forecast_value_usd=1,confidence=.5,source_key="s",created_by="u")
    for update,match in (({"organization_id":""},"organization_id"),({"confidence":2},"confidence"),({"currency_code":"US"},"currency"),({"value_type":"bad"},"Invalid")):
        with pytest.raises(ValueError,match=match): ledger.create_opportunity(**{**base,**update})
    db=DB([Step("INSERT INTO roi_opportunities",[],error=RuntimeError("dup"))])
    with pytest.raises(ValueError,match="source_key"): PostgresROILedger("dsn",connect_factory=db.connect,auto_migrate=False).create_opportunity(**base)
    db=DB([Step("SELECT * FROM roi_opportunities",[])])
    with pytest.raises(KeyError): PostgresROILedger("dsn",connect_factory=db.connect,auto_migrate=False).get_opportunity("x")
    db=DB([Step("SELECT * FROM roi_opportunities",[roi_row()])])
    assert len(PostgresROILedger("dsn",connect_factory=db.connect,auto_migrate=False).list_opportunities(organization_id="o",agent_id="a",status="proposed",limit=999,offset=-1))==1

    ledger=PostgresROILedger("dsn",connect_factory=DB().connect,auto_migrate=False)
    monkeypatch.setattr(ledger,"get_opportunity",lambda _: PostgresROILedger._row_to_opportunity(roi_row()))
    with pytest.raises(ValueError,match="Invalid ROI status"): ledger.transition("r","validated",changed_by="u")
    db=DB([Step("UPDATE roi_opportunities",[],rowcount=0)]); ledger=PostgresROILedger("dsn",connect_factory=db.connect,auto_migrate=False); monkeypatch.setattr(ledger,"get_opportunity",lambda _: PostgresROILedger._row_to_opportunity(roi_row()))
    with pytest.raises(ValueError,match="revision conflict"): ledger.transition("r","approved",changed_by="u")

    proposed=PostgresROILedger._row_to_opportunity(roi_row())
    ledger=PostgresROILedger("dsn",connect_factory=DB().connect,auto_migrate=False); monkeypatch.setattr(ledger,"get_opportunity",lambda _:proposed)
    with pytest.raises(ValueError,match="in-progress"): ledger.record_value("r",stage="realized",amount_usd=1,evidence_key="e",recorded_by="u")
    with pytest.raises(ValueError,match="required"): ledger.record_value("r",stage="forecast",amount_usd=1,evidence_key="",recorded_by="u")
    active=PostgresROILedger._row_to_opportunity(roi_row("in_progress"))
    db=DB([Step("INSERT INTO roi_values",[],error=RuntimeError("dup"))]); ledger=PostgresROILedger("dsn",connect_factory=db.connect,auto_migrate=False); monkeypatch.setattr(ledger,"get_opportunity",lambda _:active)
    with pytest.raises(ValueError,match="already been counted"): ledger.record_value("r",stage="realized",amount_usd=1,evidence_key="e",recorded_by="u")

    ledger=PostgresROILedger("dsn",connect_factory=DB().connect,auto_migrate=False); monkeypatch.setattr(ledger,"get_opportunity",lambda _:active)
    with pytest.raises(ValueError,match="does not match"): ledger.record_cost(organization_id="other",agent_id="a",opportunity_id="r",cost_type="model",amount_usd=1,currency_code="USD",evidence_key="e",recorded_by="u")
    with pytest.raises(ValueError,match="required"): ledger.record_cost(organization_id="o",agent_id="a",cost_type="model",amount_usd=1,currency_code="USD",evidence_key="",recorded_by="u")
    db=DB([Step("INSERT INTO roi_costs",[],error=RuntimeError("dup"))]); ledger=PostgresROILedger("dsn",connect_factory=db.connect,auto_migrate=False)
    with pytest.raises(ValueError,match="already been counted"): ledger.record_cost(organization_id="o",agent_id="a",cost_type="model",amount_usd=1,currency_code="USD",evidence_key="e",recorded_by="u")

    # Summary with no selected currency and mixed currencies is rejected, empty produces zeros.
    db=DB([Step("SELECT * FROM roi_opportunities",[]),Step("SELECT opportunity_id",[]),Step("SELECT agent_id",[])])
    summary=PostgresROILedger("dsn",connect_factory=db.connect,auto_migrate=False).portfolio_summary(organization_id="o")
    assert summary["net_validated_value_usd"]==0
    rows=[{**roi_row(),"currency_code":"USD"},{**roi_row(),"opportunity_id":"r2","currency_code":"EUR"}]
    db=DB([Step("SELECT * FROM roi_opportunities",rows)])
    with pytest.raises(ValueError,match="currency"): PostgresROILedger("dsn",connect_factory=db.connect,auto_migrate=False).portfolio_summary(organization_id="o")


def outbox_event():
    return OutboxEvent(event_id="e",topic="t",destination="d",payload={"x":1},idempotency_key="i",status=OutboxStatus.PENDING,attempts=0,available_at_utc="2026",created_at_utc="2026")


def test_postgres_outbox_all_mutation_paths(monkeypatch):
    monkeypatch.setattr("agent_roi.enterprise.outbox.PostgresMigrationManager.migrate",lambda self:None)
    PostgresOutboxStore("dsn",connect_factory=DB().connect)
    event=outbox_event()
    row={"event_id":"old","topic":"t","destination":"d","payload_json":"{\"x\":2}","idempotency_key":"i","status":"pending","attempts":0,"available_at_utc":"2026","lease_owner":None,"lease_expires_at_utc":None,"last_error":"","created_at_utc":"2026","delivered_at_utc":None}
    db=DB([Step("INSERT INTO enterprise_outbox",[],rowcount=0),Step("SELECT * FROM enterprise_outbox",[row])]); assert PostgresOutboxStore("dsn",connect_factory=db.connect,auto_migrate=False).enqueue(event).event_id=="old"
    db=DB([Step("INSERT INTO enterprise_outbox",[],rowcount=1)]); assert PostgresOutboxStore("dsn",connect_factory=db.connect,auto_migrate=False).enqueue(event) is event
    for method,contains,kwargs in (
        ("mark_delivered","UPDATE enterprise_outbox",{"event_id":"e","worker_id":"w"}),
        ("reschedule","UPDATE enterprise_outbox",{"event_id":"e","worker_id":"w","error":"x","delay_seconds":-1}),
        ("dead_letter","WITH moved",{"event_id":"e","worker_id":"w","error":"x"}),
    ):
        db=DB([Step(contains,[],rowcount=1)]); getattr(PostgresOutboxStore("dsn",connect_factory=db.connect,auto_migrate=False),method)(**kwargs)
        db=DB([Step(contains,[],rowcount=0)])
        with pytest.raises(KeyError): getattr(PostgresOutboxStore("dsn",connect_factory=db.connect,auto_migrate=False),method)(**kwargs)


def test_postgres_idempotency_all_statuses(monkeypatch):
    monkeypatch.setattr("agent_roi.runtime.resilience.PostgresMigrationManager.migrate",lambda self:None)
    PostgresIdempotencyStore("dsn",connect_factory=DB().connect)
    def begin(rows,inserted=0,digest="d"):
        db=DB([Step("DELETE FROM",[]),Step("INSERT INTO",[],rowcount=inserted),Step("SELECT *",rows)])
        return PostgresIdempotencyStore("dsn",connect_factory=db.connect,auto_migrate=False).begin("n","k",digest,ttl_seconds=1)
    with pytest.raises(RuntimeError): begin([])
    with pytest.raises(IdempotencyConflict): begin([{"request_digest":"x","status":"pending"}])
    assert begin([{"request_digest":"d","status":"pending"}],inserted=1).status=="started"
    assert begin([{"request_digest":"d","status":"completed","response_json":"{\"x\":1}"}]).response=={"x":1}
    assert begin([{"request_digest":"d","status":"failed","error_text":"bad"}]).error=="bad"
    with pytest.raises(IdempotencyInProgress): begin([{"request_digest":"d","status":"pending"}])
    for method,contains,args in (("complete","UPDATE idempotency",("n","k",{"x":1})),("fail","UPDATE idempotency",("n","k","bad"))):
        db=DB([Step(contains,[],rowcount=1)]); getattr(PostgresIdempotencyStore("dsn",connect_factory=db.connect,auto_migrate=False),method)(*args)
        db=DB([Step(contains,[],rowcount=0)])
        with pytest.raises(KeyError): getattr(PostgresIdempotencyStore("dsn",connect_factory=db.connect,auto_migrate=False),method)(*args)
