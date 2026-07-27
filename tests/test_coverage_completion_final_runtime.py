from __future__ import annotations

import asyncio
import concurrent.futures
import os
import sys
import time
from types import SimpleNamespace

import pytest

from agent_roi import Guardrails, SentinelRunner
from agent_roi.approvals.base import ApprovalRecord, ApprovalRequest, ApprovalStatus
from agent_roi.approvals.outbox import OutboxApprovalProvider
from agent_roi.audit.store import InMemoryAuditStore
from agent_roi.control.guardrails import GuardrailViolation
from agent_roi.enterprise.control_plane import ControlPlaneClient
from agent_roi.enterprise.telemetry import (
    AzureLogAnalyticsSink,
    CloudEvent,
    CloudWatchLogsSink,
    ElasticEventSink,
    EventDeliveryError,
    OpenTelemetrySink,
    configure_otlp_sink,
)
from agent_roi.runtime.context import SentinelContext
from agent_roi.runtime.executor import _hard_sync_timeout, _safe_repr
from agent_roi.runtime.resilience import CircuitBreaker, IdempotencyPolicy, IdempotencyResult
from agent_roi.runtime.tools import ApprovalGrant, ToolRegistry


class _Response:
    def __init__(self, status=200): self.status = status
    def __enter__(self): return self
    def __exit__(self, *args): return False


class _IdemStore:
    def __init__(self, result): self.result=result; self.completed=[]; self.failed=[]
    def begin(self, namespace, key, request_digest, *, ttl_seconds): return self.result
    def complete(self, namespace, key, response): self.completed.append((namespace,key,response))
    def fail(self, namespace, key, error): self.failed.append((namespace,key,error))


def test_outbox_approval_provider_and_enterprise_lazy_attribute() -> None:
    events=[]
    store=SimpleNamespace(enqueue=lambda event: events.append(event))
    provider=OutboxApprovalProvider(store,destination="queue")
    now=int(time.time()*1000)
    request=ApprovalRequest(
        request_id="r", checkpoint_id="c", action_digest="a"*64,
        organization_id="o", environment="prod", agent_id="a",
        correlation_id="co", run_id="ru", tool_name="t", tool_version="1",
        risk="high", estimated_cost_usd=1, arguments_digest="b"*64,
        policy_digest="d"*64, created_at_epoch_ms=now, expires_at_epoch_ms=now+10000,
    )
    assert provider.submit(request)=="r"
    provider.update(ApprovalRecord(request=request,status=ApprovalStatus.APPROVED,external_id="e",decided_by="u",reason="ok",decided_at_epoch_ms=now))
    assert len(events)==2 and events[0].destination=="queue"

    import agent_roi.enterprise as enterprise
    assert enterprise.__getattr__("EnterpriseSentinelRunner").__name__ == "EnterpriseSentinelRunner"
    with pytest.raises(AttributeError): enterprise.__getattr__("missing")


def test_control_plane_client_rollout_paths(monkeypatch) -> None:
    client=ControlPlaneClient("https://control.example")
    calls=[]
    monkeypatch.setattr(client,"_request",lambda *a,**k: calls.append((a,k)) or {"ok":True})
    assert client.start_rollout(organization_id="o/x",name="p",environment="prod",candidate_version="2",candidate_percentage=10,seed="s")=={"ok":True}
    client.cancel_rollout("o/x","p","prod")
    assert calls[0][0][1].startswith("/v1/organizations/o%2Fx/") and calls[1][0][0]=="DELETE"


def test_telemetry_remaining_delivery_cloudwatch_and_otlp(monkeypatch) -> None:
    event=CloudEvent(type="com.agentroi.run_failed",source="s",data={"elapsed_ms":1})
    monkeypatch.setattr("agent_roi.enterprise.telemetry.urlrequest.urlopen",lambda *a,**k: (_ for _ in ()).throw(OSError("down")))
    with pytest.raises(EventDeliveryError,match="Elasticsearch"):
        ElasticEventSink("http://x","i",require_https=False).emit(event)
    import base64
    with pytest.raises(EventDeliveryError,match="Azure"):
        AzureLogAnalyticsSink("w",base64.b64encode(b"a"*32).decode()).emit(event)

    class Boto:
        @staticmethod
        def client(name,region_name=None):
            assert name=="logs"
            return SimpleNamespace(put_log_events=lambda **kwargs: {})
    monkeypatch.setitem(sys.modules,"boto3",Boto)
    sink=CloudWatchLogsSink("g","s",region_name="us-east-1")
    sink.emit(CloudEvent(type="x",source="s",data={}))

    # Replace the exporter/provider classes so the success path remains deterministic
    # and does not start background network delivery.
    import opentelemetry.metrics as ot_metrics
    import opentelemetry.trace as ot_trace
    import opentelemetry.exporter.otlp.proto.http.metric_exporter as metric_exporter
    import opentelemetry.exporter.otlp.proto.http.trace_exporter as trace_exporter
    import opentelemetry.sdk.metrics as sdk_metrics
    import opentelemetry.sdk.metrics.export as sdk_metric_export
    import opentelemetry.sdk.resources as sdk_resources
    import opentelemetry.sdk.trace as sdk_trace
    import opentelemetry.sdk.trace.export as sdk_trace_export

    class Metric:
        def add(self,*a,**k): pass
        def record(self,*a,**k): pass
    class Meter:
        def create_counter(self,*a,**k): return Metric()
        def create_histogram(self,*a,**k): return Metric()
    class FakeMeterProvider:
        def __init__(self,**kwargs): self.kwargs=kwargs
        def get_meter(self,*a): return Meter()
    class Span:
        def __enter__(self): return self
        def __exit__(self,*a): return False
        def add_event(self,*a,**k): pass
        def set_status(self,*a): pass
    class Tracer:
        def start_as_current_span(self,*a,**k): return Span()
    class FakeTraceProvider:
        def __init__(self,**kwargs): self.kwargs=kwargs; self.processors=[]
        def add_span_processor(self,value): self.processors.append(value)
        def get_tracer(self,*a): return Tracer()
    class Exporter:
        def __init__(self,**kwargs): self.kwargs=kwargs
    class Wrapper:
        def __init__(self,value): self.value=value

    monkeypatch.setattr(metric_exporter,"OTLPMetricExporter",Exporter)
    monkeypatch.setattr(trace_exporter,"OTLPSpanExporter",Exporter)
    monkeypatch.setattr(sdk_metrics,"MeterProvider",FakeMeterProvider)
    monkeypatch.setattr(sdk_metric_export,"PeriodicExportingMetricReader",Wrapper)
    monkeypatch.setattr(sdk_resources.Resource,"create",staticmethod(lambda value:value))
    monkeypatch.setattr(sdk_trace,"TracerProvider",FakeTraceProvider)
    monkeypatch.setattr(sdk_trace_export,"BatchSpanProcessor",Wrapper)
    monkeypatch.setattr(ot_trace,"set_tracer_provider",lambda provider:None)
    monkeypatch.setattr(ot_metrics,"set_meter_provider",lambda provider:None)
    with pytest.raises(ValueError,match="endpoint"):
        configure_otlp_sink("",insecure=True)
    configured=configure_otlp_sink("http://collector.example",insecure=True,headers={"x":"y"})
    assert isinstance(configured,OpenTelemetrySink)
    configured.emit(CloudEvent(type="com.agentroi.run.completed",source="s",data={"elapsed_ms":1}))


def test_open_telemetry_status_import_failure_is_nonfatal(monkeypatch) -> None:
    class Metric:
        def add(self,*a,**k): pass
        def record(self,*a,**k): pass
    class Meter:
        def create_counter(self,*a,**k): return Metric()
        def create_histogram(self,*a,**k): return Metric()
    class MP:
        def get_meter(self,*a): return Meter()
    class Span:
        def __enter__(self): return self
        def __exit__(self,*a): return False
        def add_event(self,*a,**k): pass
        def set_status(self,*a): pass
    class Tracer:
        def start_as_current_span(self,*a,**k): return Span()
    class TP:
        def get_tracer(self,*a): return Tracer()
    sink=OpenTelemetrySink(tracer_provider=TP(),meter_provider=MP())
    # Force the local import inside emit to fail while preserving the already-built sink.
    monkeypatch.setitem(sys.modules,"opentelemetry.trace",None)
    sink.emit(CloudEvent(type="com.agentroi.run_failed",source="s",data={}))


@pytest.mark.asyncio
async def test_context_remaining_guardrail_async_idempotency_and_circuit_paths() -> None:
    ctx=SentinelContext(guardrails=Guardrails(max_steps=3,max_tool_calls=3,max_cost_usd=3))
    assert ctx.guardrails is not None
    ctx.bump_tool_call(); ctx.add_cost(1)

    reg=ToolRegistry(); reg.add("approval",lambda:1,requires_approval=True)
    bad_grant=ApprovalGrant("0"*64,"u",int(time.time()*1000)+10000)
    approval_ctx=SentinelContext(tool_registry=reg,approval_callback=lambda *a: bad_grant)
    with pytest.raises(GuardrailViolation): approval_ctx.call_tool("approval")

    completed=_IdemStore(IdempotencyResult("completed",response=7))
    failed=_IdemStore(IdempotencyResult("failed",error="boom"))
    for store, expected in ((completed,7),(failed,None)):
        registry=ToolRegistry()
        async def handler(): return 9
        registry.add("i",handler,idempotency_policy=IdempotencyPolicy(store,"n",lambda a,k:"key"))
        current=SentinelContext(tool_registry=registry)
        if expected is None:
            with pytest.raises(GuardrailViolation,match="Previous"): await current.acall_tool("i")
        else:
            assert await current.acall_tool("i")==expected

    started=_IdemStore(IdempotencyResult("started"))
    breaker=CircuitBreaker(failure_threshold=2,recovery_timeout_seconds=1)
    registry=ToolRegistry(); registry.add("sync",lambda:5,circuit_breaker=breaker,idempotency_policy=IdempotencyPolicy(started,"n",lambda a,k:"key"))
    assert await SentinelContext(tool_registry=registry).acall_tool("sync")==5
    assert started.completed[0][2]==5


def test_executor_defensive_constructor_repr_and_thread_timeout_paths() -> None:
    class BadRepr:
        def __repr__(self): raise RuntimeError("bad")
    assert _safe_repr(BadRepr())=="<unreprable>"

    def worker():
        with _hard_sync_timeout(0.1):
            return 1
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        with pytest.raises(RuntimeError,match="main thread"): pool.submit(worker).result()

    with pytest.raises(ValueError,match="audit_hash_chain"):
        SentinelRunner(audit_store=InMemoryAuditStore(hash_chain=False),audit_hash_chain=True)
    principal=SimpleNamespace(organization_id="other")
    with pytest.raises(ValueError,match="principal organization"):
        SentinelRunner(principal=principal,organization_id="acme")
    with pytest.raises(ValueError,match="finite"):
        SentinelRunner(run_timeout_seconds=0)
    with pytest.raises(ValueError,match="ToolRegistry"):
        SentinelRunner(guardrails=Guardrails(require_registered_tools=True))


@pytest.mark.asyncio
async def test_executor_async_approval_result_path() -> None:
    registry=ToolRegistry(); registry.add("approval",lambda:1,requires_approval=True)
    runner=SentinelRunner(tool_registry=registry)
    async def agent(ctx,payload):
        return await ctx.acall_tool("approval")
    result=await runner.arun(agent,None)
    assert result.outcome.value=="human_review" and "approval_checkpoint" in result.output
