from __future__ import annotations

from base64 import b64encode
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
from typing import Any

import pytest

from agent_roi.enterprise.telemetry import (
    AzureLogAnalyticsSink,
    CloudEvent,
    CompositeEventSink,
    ElasticEventSink,
    EventDeliveryError,
    HttpCloudEventSink,
    InMemoryEventSink,
    OpenTelemetrySink,
    SplunkHECSink,
)


class _CollectorHandler(BaseHTTPRequestHandler):
    records: list[dict[str, Any]] = []

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        try:
            body = json.loads(raw)
        except Exception:
            body = raw.decode("utf-8")
        self.__class__.records.append(
            {"path": self.path, "headers": dict(self.headers), "body": body}
        )
        response = json.dumps({"id": "external-1", "text": "success"}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def log_message(self, format, *args):  # noqa: A003
        return


def _server():
    _CollectorHandler.records = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _CollectorHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def test_cloud_event_and_composite_sink() -> None:
    memory = InMemoryEventSink()
    event = CloudEvent(type="com.agentroi.run.completed", source="/agents/a", data={"status": "ok"})
    CompositeEventSink([memory]).emit(event)
    assert memory.events[0].to_dict()["specversion"] == "1.0"
    assert memory.events[0].data["status"] == "ok"


def test_composite_sink_fail_closed() -> None:
    class Broken:
        def emit(self, event):
            raise RuntimeError("down")

    sink = CompositeEventSink([Broken()], fail_closed=True)
    with pytest.raises(EventDeliveryError):
        sink.emit(CloudEvent(type="x", source="y", data={}))


def test_http_splunk_and_elastic_sinks_send_expected_payloads() -> None:
    server, thread = _server()
    endpoint = f"http://127.0.0.1:{server.server_port}"
    event = CloudEvent(type="com.agentroi.tool.completed", source="/agents/a", data={"tool_name": "lookup"})
    try:
        HttpCloudEventSink(endpoint + "/events", require_https=False).emit(event)
        SplunkHECSink(endpoint, "token", require_https=False).emit(event)
        ElasticEventSink(endpoint, "agent-roi", api_key="key", require_https=False).emit(event)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
    assert _CollectorHandler.records[0]["headers"]["Content-Type"].startswith("application/cloudevents+json")
    assert _CollectorHandler.records[1]["path"] == "/services/collector/event"
    assert _CollectorHandler.records[1]["headers"]["Authorization"] == "Splunk token"
    assert _CollectorHandler.records[2]["path"] == "/agent-roi/_doc"
    assert _CollectorHandler.records[2]["headers"]["Authorization"] == "ApiKey key"


def test_azure_log_analytics_signature_is_stable() -> None:
    shared_key = b64encode(b"a" * 32).decode("ascii")
    sink = AzureLogAnalyticsSink("workspace", shared_key)
    signature = sink._signature(100, "Mon, 01 Jan 2026 00:00:00 GMT")
    assert signature.startswith("SharedKey workspace:")
    assert signature == sink._signature(100, "Mon, 01 Jan 2026 00:00:00 GMT")


def test_open_telemetry_sink_emits_span() -> None:
    pytest.importorskip("opentelemetry.sdk")
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    sink = OpenTelemetrySink(tracer_provider=provider)
    sink.emit(
        CloudEvent(
            type="com.agentroi.run.completed",
            source="/agents/a",
            data={"elapsed_ms": 12, "status": "ok", "cost_usd": 0.2},
        )
    )
    spans = exporter.get_finished_spans()
    assert len(spans) == 1
    assert spans[0].name == "com.agentroi.run.completed"


def test_datadog_and_cloudwatch_sinks(monkeypatch) -> None:
    from agent_roi.enterprise.telemetry import CloudWatchLogsSink, DatadogEventSink

    event = CloudEvent(
        type="com.agentroi.authorization.denied",
        source="/agents/a",
        data={"status": "denied"},
    )
    captured = {}

    class Response:
        status = 202
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return False

    def fake_urlopen(request, timeout):
        captured["url"] = request.full_url
        captured["api_key"] = request.headers["Dd-api-key"]
        captured["body"] = json.loads(request.data)
        return Response()

    monkeypatch.setattr(
        "agent_roi.enterprise.telemetry.urlrequest.urlopen", fake_urlopen
    )
    DatadogEventSink("api-key", tags="env:prod").emit(event)
    assert captured["api_key"] == "api-key"
    assert captured["body"][0]["ddtags"] == "env:prod"

    class CloudWatchClient:
        calls = []
        def put_log_events(self, **kwargs):
            self.calls.append(kwargs)
            return {"nextSequenceToken": f"token-{len(self.calls)}"}

    client = CloudWatchClient()
    cloudwatch = CloudWatchLogsSink("/agent-roi/prod", "agent-a", client=client)
    cloudwatch.emit(event)
    cloudwatch.emit(event)
    assert "sequenceToken" not in client.calls[0]
    assert client.calls[1]["sequenceToken"] == "token-1"
    assert "com.agentroi.authorization.denied" in client.calls[0]["logEvents"][0]["message"]


def test_otlp_plaintext_requires_explicit_insecure_mode() -> None:
    from agent_roi.enterprise.telemetry import configure_otlp_sink

    with pytest.raises(ValueError, match="insecure=True"):
        configure_otlp_sink("http://collector.example")


def test_otlp_rejects_non_http_endpoint() -> None:
    from agent_roi.enterprise.telemetry import configure_otlp_sink

    with pytest.raises(ValueError, match="HTTP or HTTPS"):
        configure_otlp_sink("file:///tmp/collector")
