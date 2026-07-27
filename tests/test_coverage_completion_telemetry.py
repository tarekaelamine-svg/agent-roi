from __future__ import annotations

import base64
import io
from urllib import error as urlerror

import pytest

from agent_roi.enterprise.telemetry import (
    AzureLogAnalyticsSink, CloudEvent, CloudWatchLogsSink, CompositeEventSink,
    DatadogEventSink, ElasticEventSink, EventDeliveryError, HttpCloudEventSink,
    InMemoryEventSink, OpenTelemetrySink, SplunkHECSink, runtime_event,
)


class Response:
    def __init__(self,status=200): self.status=status
    def __enter__(self): return self
    def __exit__(self,*a): return False
    def read(self): return b""


def test_event_subject_composite_and_runtime_event() -> None:
    event=CloudEvent(type="x",source="s",subject="sub",data={"when":object()})
    assert event.to_dict()["subject"]=="sub"
    good=InMemoryEventSink()
    class Bad:
        def emit(self,e): raise RuntimeError("bad")
    open_sink=CompositeEventSink([good,Bad()],fail_closed=False)
    open_sink.emit(event)
    assert good.events and open_sink.failures[0][0]=="Bad"
    r=runtime_event(event_type="run_completed",payload={"x":1},source="/a",organization_id="o",environment="e",agent_id="a",correlation_id="c",run_id="r")
    assert r.type=="com.agentroi.run.completed" and r.data["organization_id"]=="o"


def test_http_sink_validation_and_failure_modes(monkeypatch) -> None:
    event=CloudEvent(type="x",source="s",data={})
    with pytest.raises(ValueError): HttpCloudEventSink("http://x")
    sink=HttpCloudEventSink("http://x",require_https=False)
    monkeypatch.setattr("agent_roi.enterprise.telemetry.urlrequest.urlopen",lambda *a,**k:Response(204))
    sink.emit(event)
    monkeypatch.setattr("agent_roi.enterprise.telemetry.urlrequest.urlopen",lambda *a,**k:Response(500))
    with pytest.raises(EventDeliveryError,match="500"): sink.emit(event)
    err=urlerror.HTTPError("u",400,"bad",{},io.BytesIO(b"detail"))
    monkeypatch.setattr("agent_roi.enterprise.telemetry.urlrequest.urlopen",lambda *a,**k:(_ for _ in ()).throw(err))
    with pytest.raises(EventDeliveryError,match="detail"): sink.emit(event)
    monkeypatch.setattr("agent_roi.enterprise.telemetry.urlrequest.urlopen",lambda *a,**k:(_ for _ in ()).throw(OSError()))
    with pytest.raises(EventDeliveryError,match="unavailable"): sink.emit(event)


def test_splunk_elastic_azure_datadog_error_and_auth_branches(monkeypatch) -> None:
    event=CloudEvent(type="x",source="s",data={})
    with pytest.raises(ValueError): SplunkHECSink("http://x","t")
    with pytest.raises(ValueError): SplunkHECSink("https://x"," ")
    splunk=SplunkHECSink("http://x","t",index="idx",require_https=False)
    monkeypatch.setattr("agent_roi.enterprise.telemetry.urlrequest.urlopen",lambda *a,**k:Response(500))
    with pytest.raises(EventDeliveryError): splunk.emit(event)
    monkeypatch.setattr("agent_roi.enterprise.telemetry.urlrequest.urlopen",lambda *a,**k:(_ for _ in ()).throw(OSError()))
    with pytest.raises(EventDeliveryError): splunk.emit(event)

    with pytest.raises(ValueError): ElasticEventSink("http://x","i")
    with pytest.raises(ValueError): ElasticEventSink("https://x"," ")
    elastic=ElasticEventSink("http://x","i",bearer_token="b",require_https=False)
    captured={}
    def capture(req,timeout): captured["auth"]=req.headers.get("Authorization"); return Response(201)
    monkeypatch.setattr("agent_roi.enterprise.telemetry.urlrequest.urlopen",capture)
    elastic.emit(event); assert captured["auth"]=="Bearer b"
    monkeypatch.setattr("agent_roi.enterprise.telemetry.urlrequest.urlopen",lambda *a,**k:Response(500))
    with pytest.raises(EventDeliveryError): elastic.emit(event)

    with pytest.raises(ValueError): AzureLogAnalyticsSink("","x")
    with pytest.raises(ValueError): AzureLogAnalyticsSink("w","x",log_type="bad-dash")
    azure=AzureLogAnalyticsSink("w",base64.b64encode(b"a"*32).decode())
    monkeypatch.setattr("agent_roi.enterprise.telemetry.urlrequest.urlopen",lambda *a,**k:Response(202))
    azure.emit(event)
    monkeypatch.setattr("agent_roi.enterprise.telemetry.urlrequest.urlopen",lambda *a,**k:Response(500))
    with pytest.raises(EventDeliveryError): azure.emit(event)

    with pytest.raises(ValueError): DatadogEventSink(" ")
    with pytest.raises(ValueError): DatadogEventSink("k",site="bad/site")
    dd=DatadogEventSink("k")
    monkeypatch.setattr("agent_roi.enterprise.telemetry.urlrequest.urlopen",lambda *a,**k:Response(500))
    with pytest.raises(EventDeliveryError): dd.emit(event)
    monkeypatch.setattr("agent_roi.enterprise.telemetry.urlrequest.urlopen",lambda *a,**k:(_ for _ in ()).throw(OSError()))
    with pytest.raises(EventDeliveryError): dd.emit(event)


def test_open_telemetry_fake_providers_all_metric_paths(monkeypatch) -> None:
    class Metric:
        def __init__(self): self.calls=[]
        def add(self,*a): self.calls.append(a)
        def record(self,*a): self.calls.append(a)
    class Meter:
        def __init__(self): self.metrics=[]
        def create_counter(self,*a,**k): m=Metric(); self.metrics.append(m); return m
        def create_histogram(self,*a,**k): m=Metric(); self.metrics.append(m); return m
    class MeterProvider:
        def __init__(self): self.meter=Meter()
        def get_meter(self,name): return self.meter
    class Span:
        def __init__(self): self.status=None
        def __enter__(self): return self
        def __exit__(self,*a): return False
        def add_event(self,*a,**k): pass
        def set_status(self,s): self.status=s
    class Tracer:
        def __init__(self): self.spans=[]
        def start_as_current_span(self,*a,**k): s=Span(); self.spans.append(s); return s
    class TraceProvider:
        def __init__(self): self.tracer=Tracer()
        def get_tracer(self,name): return self.tracer
    tp,mp=TraceProvider(),MeterProvider()
    sink=OpenTelemetrySink(tracer_provider=tp,meter_provider=mp)
    attrs=sink._attributes(CloudEvent(type="x",source="s",data={"organization_id":"o","ignored":[]},id="i"))
    assert attrs["agent_roi.organization_id"]=="o" and "agent_roi.ignored" not in attrs
    sink.emit(CloudEvent(type="com.agentroi.run.completed",source="s",data={"elapsed_ms":2,"cost_usd":1}))
    sink.emit(CloudEvent(type="com.agentroi.approval.completed",source="s",data={"elapsed_ms":3,"cost_usd":-1}))
    sink.emit(CloudEvent(type="com.agentroi.run_failed",source="s",data={"elapsed_ms":"bad"}))
    assert any(m.calls for m in mp.meter.metrics)


def test_cloudwatch_validation_sequence_and_error() -> None:
    with pytest.raises(ValueError): CloudWatchLogsSink("","s",client=object())
    class Client:
        def __init__(self): self.calls=0
        def put_log_events(self,**kwargs):
            self.calls+=1
            if self.calls==3: raise RuntimeError("down")
            return {"nextSequenceToken":f"t{self.calls}"}
    client=Client(); sink=CloudWatchLogsSink("g","s",client=client)
    event=CloudEvent(type="x",source="s",data={})
    sink.emit(event); sink.emit(event)
    with pytest.raises(EventDeliveryError): sink.emit(event)
