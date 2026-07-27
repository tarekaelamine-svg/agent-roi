from __future__ import annotations

import asyncio
import io
import time
from urllib import error as urlerror

import pytest

from agent_roi.enterprise.outbox import (
    JsonHttpOutboxHandler, OutboxEvent, OutboxEventSink, OutboxStatus,
    OutboxWorker, SqliteOutboxStore, _row_event,
)
from agent_roi.runtime.resilience import (
    CircuitBreaker, CircuitOpenError, CircuitState, IdempotencyConflict,
    IdempotencyInProgress, IdempotencyPolicy, RetryPolicy,
    SqliteIdempotencyStore, aretry_call, retry_call,
)


def test_retry_policy_sync_async_and_validation(monkeypatch) -> None:
    for kwargs in [
        {"max_attempts":0}, {"max_attempts":True}, {"initial_backoff_seconds":-1},
        {"multiplier":0.5}, {"jitter_ratio":1.1}, {"retry_exceptions":()},
        {"retry_exceptions":("bad",)},
    ]:
        with pytest.raises(ValueError): RetryPolicy(**kwargs)
    p=RetryPolicy(max_attempts=3, initial_backoff_seconds=1, multiplier=2, max_backoff_seconds=3, jitter_ratio=.5)
    assert p.delay(1, random_value=0)==.5
    assert p.delay(3, random_value=1)==4.5
    p0=RetryPolicy(initial_backoff_seconds=0, jitter_ratio=.5)
    assert p0.delay(1)==0
    attempts=[]
    monkeypatch.setattr(time,"sleep",lambda d: attempts.append(d))
    def fn():
        if len(attempts)<1: raise OSError("retry")
        return "ok"
    assert retry_call(fn,p)=="ok"
    with pytest.raises(ValueError): retry_call(lambda: (_ for _ in ()).throw(ValueError()),p)

    async def run():
        count=0
        async def afn():
            nonlocal count
            count+=1
            if count<2: raise OSError()
            return "ok"
        assert await aretry_call(afn,RetryPolicy(max_attempts=2,initial_backoff_seconds=0))=="ok"
        async def bad(): raise ValueError()
        with pytest.raises(ValueError): await aretry_call(bad,p)
    asyncio.run(run())


def test_circuit_breaker_full_state_machine() -> None:
    now=[0.0]
    for kwargs in [{"failure_threshold":0},{"failure_threshold":True},{"recovery_timeout_seconds":0},{"success_threshold":0},{"success_threshold":True}]:
        with pytest.raises(ValueError): CircuitBreaker(**kwargs)
    b=CircuitBreaker(failure_threshold=2,recovery_timeout_seconds=5,success_threshold=2,clock=lambda:now[0])
    with pytest.raises(RuntimeError): b.call(lambda: (_ for _ in ()).throw(RuntimeError("x")))
    with pytest.raises(RuntimeError): b.call(lambda: (_ for _ in ()).throw(RuntimeError("x")))
    assert b.state is CircuitState.OPEN
    with pytest.raises(CircuitOpenError): b.before_call()
    now[0]=6
    assert b.state is CircuitState.HALF_OPEN
    b.before_call()
    with pytest.raises(CircuitOpenError,match="probe"): b.before_call()
    b.record_success()
    assert b.state is CircuitState.HALF_OPEN
    b.before_call(); b.record_success()
    assert b.state is CircuitState.CLOSED
    assert b.call(lambda:"ok")=="ok"
    b.record_failure(); b.record_failure(); now[0]=12
    async def ok(): return "async"
    assert asyncio.run(b.acall(ok))=="async"
    b.record_failure(); b.record_failure(); now[0]=18
    async def bad(): raise OSError()
    with pytest.raises(OSError): asyncio.run(b.acall(bad))


def test_sqlite_idempotency_and_policy(tmp_path) -> None:
    store=SqliteIdempotencyStore(tmp_path/"id.db")
    with pytest.raises(ValueError): store.begin("","k","d",ttl_seconds=1)
    assert store.begin("n","k","d",ttl_seconds=1).status=="started"
    with pytest.raises(IdempotencyInProgress): store.begin("n","k","d",ttl_seconds=1)
    with pytest.raises(IdempotencyConflict): store.begin("n","k","other",ttl_seconds=1)
    store.complete("n","k",{"ok":1})
    result=store.begin("n","k","d",ttl_seconds=1)
    assert result.status=="completed" and result.response=={"ok":1}
    with pytest.raises(KeyError): store.complete("n","missing",{})
    assert store.begin("n","f","df",ttl_seconds=1).status=="started"
    store.fail("n","f","bad")
    assert store.begin("n","f","df",ttl_seconds=1).error=="bad"
    with pytest.raises(KeyError): store.fail("n","missing","bad")
    for kwargs in [
        {"store":store,"namespace":"","key_factory":lambda a,k:"x"},
        {"store":store,"namespace":"n","key_factory":None},
        {"store":store,"namespace":"n","key_factory":lambda a,k:"x","ttl_seconds":0},
    ]:
        with pytest.raises(ValueError): IdempotencyPolicy(**kwargs)
    policy=IdempotencyPolicy(store,"other",lambda a,k:"key")
    key,digest,res=policy.prepare((1,),{"x":2})
    assert key=="key" and len(digest)==64 and res.status=="started"
    with pytest.raises(ValueError): IdempotencyPolicy(store,"empty",lambda a,k:" ").prepare((),{})


def test_sqlite_outbox_lifecycle_worker_and_http(tmp_path, monkeypatch) -> None:
    for field in ("topic","destination","idempotency_key"):
        kwargs={"topic":"t","destination":"d","payload":{},"idempotency_key":"k"}; kwargs[field]=""
        with pytest.raises(ValueError): OutboxEvent.create(**kwargs)
    store=SqliteOutboxStore(tmp_path/"out.db")
    event=OutboxEvent.create(topic="t",destination="d",payload={"x":1},idempotency_key="k")
    assert store.enqueue(event).event_id==event.event_id
    assert store.enqueue(OutboxEvent.create(topic="other",destination="d",payload={},idempotency_key="k")).event_id==event.event_id
    with pytest.raises(ValueError): store.claim(worker_id=" ")
    claimed=store.claim(worker_id="w",destination="d",lease_seconds=0,limit=500)
    assert claimed[0].status is OutboxStatus.LEASED and claimed[0].attempts==1
    with pytest.raises(KeyError): store.mark_delivered("no",worker_id="w")
    with pytest.raises(KeyError): store.reschedule("no",worker_id="w",error="x",delay_seconds=0)
    with pytest.raises(KeyError): store.dead_letter("no",worker_id="w",error="x")
    store.reschedule(event.event_id,worker_id="w",error="retry",delay_seconds=0)
    claimed=store.claim(worker_id="w",destination="d")
    store.mark_delivered(event.event_id,worker_id="w")
    assert store.stats()["delivered"]==1

    retry_event=store.enqueue(OutboxEvent.create(topic="t",destination="retry",payload={},idempotency_key="r"))
    worker=OutboxWorker(store,{"retry":lambda e: (_ for _ in ()).throw(OSError("down"))},worker_id="w2",retry_policy=RetryPolicy(max_attempts=1,initial_backoff_seconds=0),max_delivery_attempts=2)
    first=worker.run_once(destination="retry"); assert first["retried"]==1
    second=worker.run_once(destination="retry"); assert second["dead_lettered"]==1
    assert store.stats()["dead_letter"]==1
    missing=store.enqueue(OutboxEvent.create(topic="t",destination="missing",payload={},idempotency_key="m"))
    assert OutboxWorker(store,{},worker_id="w3",max_delivery_attempts=1).run_once(destination="missing")["dead_lettered"]==1

    sink=OutboxEventSink(store,destination="sink")
    sink.emit({"message":"x"})
    class Obj:
        def to_dict(self): return {"id":"fixed","x":1}
    sink.emit(Obj())
    assert len(store.claim(worker_id="sink-worker",destination="sink"))==2

    with pytest.raises(ValueError): JsonHttpOutboxHandler("http://x")
    handler=JsonHttpOutboxHandler("http://x",require_https=False)
    class Response:
        def __init__(self,status): self.status=status
        def __enter__(self): return self
        def __exit__(self,*a): return False
        def read(self): return b""
    monkeypatch.setattr("urllib.request.urlopen",lambda *a,**k:Response(204))
    handler(event)
    monkeypatch.setattr("urllib.request.urlopen",lambda *a,**k:Response(500))
    with pytest.raises(RuntimeError,match="500"): handler(event)
    err=urlerror.HTTPError("u",400,"bad",{},io.BytesIO(b"detail"))
    monkeypatch.setattr("urllib.request.urlopen",lambda *a,**k:(_ for _ in ()).throw(err))
    with pytest.raises(RuntimeError,match="detail"): handler(event)
    monkeypatch.setattr("urllib.request.urlopen",lambda *a,**k:(_ for _ in ()).throw(OSError()))
    with pytest.raises(RuntimeError,match="unavailable"): handler(event)
