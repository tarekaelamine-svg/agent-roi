from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import base64
import hashlib
import hmac
import json
import threading
from typing import Any, Iterable, Mapping, Optional, Protocol
from urllib import error as urlerror
from urllib import parse as urlparse
from urllib import request as urlrequest
import uuid

from agent_roi._serialization import canonical_json, to_jsonable


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class CloudEvent:
    type: str
    source: str
    data: Mapping[str, Any]
    subject: str = ""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    time: str = field(default_factory=_utc_now)
    specversion: str = "1.0"
    datacontenttype: str = "application/json"

    def to_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "specversion": self.specversion,
            "id": self.id,
            "source": self.source,
            "type": self.type,
            "time": self.time,
            "datacontenttype": self.datacontenttype,
            "data": to_jsonable(dict(self.data)),
        }
        if self.subject:
            value["subject"] = self.subject
        return value


class EventSink(Protocol):
    def emit(self, event: CloudEvent) -> None: ...


class EventDeliveryError(RuntimeError):
    """Raised when an enterprise event sink cannot accept an event."""


class InMemoryEventSink:
    def __init__(self) -> None:
        self.events: list[CloudEvent] = []
        self._lock = threading.RLock()

    def emit(self, event: CloudEvent) -> None:
        with self._lock:
            self.events.append(event)


class CompositeEventSink:
    def __init__(
        self,
        sinks: Iterable[EventSink],
        *,
        fail_closed: bool = False,
    ) -> None:
        self.sinks = tuple(sinks)
        self.fail_closed = bool(fail_closed)
        self.failures: list[tuple[str, str]] = []

    def emit(self, event: CloudEvent) -> None:
        errors: list[Exception] = []
        for sink in self.sinks:
            try:
                sink.emit(event)
            except Exception as exc:
                self.failures.append((type(sink).__name__, str(exc)))
                errors.append(exc)
        if errors and self.fail_closed:
            raise EventDeliveryError(
                f"{len(errors)} enterprise event sink(s) failed"
            ) from errors[0]


class HttpCloudEventSink:
    """CloudEvents 1.0 structured-mode publisher over HTTPS."""

    def __init__(
        self,
        endpoint: str,
        *,
        headers: Optional[Mapping[str, str]] = None,
        timeout_seconds: float = 10.0,
        require_https: bool = True,
    ) -> None:
        if require_https and not endpoint.lower().startswith("https://"):
            raise ValueError("Enterprise CloudEvent endpoints must use HTTPS")
        self.endpoint = endpoint
        self.headers = dict(headers or {})
        self.timeout_seconds = float(timeout_seconds)

    def emit(self, event: CloudEvent) -> None:
        body = canonical_json(event.to_dict()).encode("utf-8")
        headers = {
            "Content-Type": "application/cloudevents+json; charset=utf-8",
            "Accept": "application/json",
            **self.headers,
        }
        req = urlrequest.Request(self.endpoint, data=body, method="POST", headers=headers)
        try:
            with urlrequest.urlopen(req, timeout=self.timeout_seconds) as response:
                if response.status < 200 or response.status >= 300:
                    raise EventDeliveryError(f"CloudEvent endpoint returned HTTP {response.status}")
        except urlerror.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise EventDeliveryError(
                f"CloudEvent endpoint returned HTTP {exc.code}: {detail}"
            ) from exc
        except OSError as exc:
            raise EventDeliveryError("CloudEvent endpoint is unavailable") from exc


class SplunkHECSink:
    def __init__(
        self,
        endpoint: str,
        token: str,
        *,
        index: str = "",
        source: str = "agent-roi",
        sourcetype: str = "_json",
        timeout_seconds: float = 10.0,
        require_https: bool = True,
    ) -> None:
        if require_https and not endpoint.lower().startswith("https://"):
            raise ValueError("Splunk HEC endpoints must use HTTPS")
        if not token.strip():
            raise ValueError("Splunk HEC token is required")
        self.endpoint = endpoint.rstrip("/") + "/services/collector/event"
        self.token = token.strip()
        self.index = index
        self.source = source
        self.sourcetype = sourcetype
        self.timeout_seconds = float(timeout_seconds)

    def emit(self, event: CloudEvent) -> None:
        envelope: dict[str, Any] = {
            "time": datetime.fromisoformat(event.time).timestamp(),
            "host": event.source,
            "source": self.source,
            "sourcetype": self.sourcetype,
            "event": event.to_dict(),
        }
        if self.index:
            envelope["index"] = self.index
        req = urlrequest.Request(
            self.endpoint,
            data=canonical_json(envelope).encode("utf-8"),
            method="POST",
            headers={
                "Authorization": f"Splunk {self.token}",
                "Content-Type": "application/json",
            },
        )
        try:
            with urlrequest.urlopen(req, timeout=self.timeout_seconds) as response:
                if response.status not in {200, 201}:
                    raise EventDeliveryError(f"Splunk HEC returned HTTP {response.status}")
        except (OSError, urlerror.HTTPError) as exc:
            raise EventDeliveryError("Splunk HEC delivery failed") from exc


class ElasticEventSink:
    """Index CloudEvents into Elasticsearch-compatible HTTP endpoints."""

    def __init__(
        self,
        endpoint: str,
        index: str,
        *,
        api_key: str = "",
        bearer_token: str = "",
        timeout_seconds: float = 10.0,
        require_https: bool = True,
    ) -> None:
        if require_https and not endpoint.lower().startswith("https://"):
            raise ValueError("Elasticsearch endpoints must use HTTPS")
        if not index.strip():
            raise ValueError("Elasticsearch index is required")
        self.url = endpoint.rstrip("/") + f"/{index.strip()}/_doc"
        self.api_key = api_key
        self.bearer_token = bearer_token
        self.timeout_seconds = float(timeout_seconds)

    def emit(self, event: CloudEvent) -> None:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"ApiKey {self.api_key}"
        elif self.bearer_token:
            headers["Authorization"] = f"Bearer {self.bearer_token}"
        req = urlrequest.Request(
            self.url,
            data=canonical_json(event.to_dict()).encode("utf-8"),
            method="POST",
            headers=headers,
        )
        try:
            with urlrequest.urlopen(req, timeout=self.timeout_seconds) as response:
                if response.status not in {200, 201}:
                    raise EventDeliveryError(f"Elasticsearch returned HTTP {response.status}")
        except (OSError, urlerror.HTTPError) as exc:
            raise EventDeliveryError("Elasticsearch delivery failed") from exc


class AzureLogAnalyticsSink:
    """Microsoft Sentinel/Log Analytics Data Collector API sink."""

    def __init__(
        self,
        workspace_id: str,
        shared_key: str,
        *,
        log_type: str = "AgentROI",
        timeout_seconds: float = 10.0,
    ) -> None:
        if not workspace_id.strip() or not shared_key.strip():
            raise ValueError("workspace_id and shared_key are required")
        if not log_type.replace("_", "").isalnum():
            raise ValueError("log_type must contain only letters, numbers, or underscores")
        self.workspace_id = workspace_id.strip()
        self.shared_key = shared_key.strip()
        self.log_type = log_type
        self.timeout_seconds = float(timeout_seconds)

    def _signature(self, content_length: int, date_value: str) -> str:
        string_to_hash = f"POST\n{content_length}\napplication/json\nx-ms-date:{date_value}\n/api/logs"
        decoded_key = base64.b64decode(self.shared_key)
        digest = hmac.new(decoded_key, string_to_hash.encode("utf-8"), hashlib.sha256).digest()
        return f"SharedKey {self.workspace_id}:{base64.b64encode(digest).decode('ascii')}"

    def emit(self, event: CloudEvent) -> None:
        body = canonical_json([event.to_dict()]).encode("utf-8")
        date_value = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")
        endpoint = (
            f"https://{self.workspace_id}.ods.opinsights.azure.com"
            "/api/logs?api-version=2016-04-01"
        )
        req = urlrequest.Request(
            endpoint,
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Authorization": self._signature(len(body), date_value),
                "Log-Type": self.log_type,
                "x-ms-date": date_value,
                "time-generated-field": "time",
            },
        )
        try:
            with urlrequest.urlopen(req, timeout=self.timeout_seconds) as response:
                if response.status not in {200, 202}:
                    raise EventDeliveryError(
                        f"Azure Log Analytics returned HTTP {response.status}"
                    )
        except (OSError, urlerror.HTTPError) as exc:
            raise EventDeliveryError("Azure Log Analytics delivery failed") from exc


class OpenTelemetrySink:
    """Maps Agent-ROI events to OpenTelemetry spans, counters, and histograms."""

    def __init__(
        self,
        *,
        service_name: str = "agent-roi",
        tracer_provider: Any = None,
        meter_provider: Any = None,
    ) -> None:
        try:
            from opentelemetry import metrics, trace  # type: ignore
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise RuntimeError(
                "OpenTelemetry support requires agent-roi[observability]."
            ) from exc
        self._trace = trace
        self._metrics = metrics
        self.tracer = (
            tracer_provider.get_tracer(service_name)
            if tracer_provider is not None
            else trace.get_tracer(service_name)
        )
        self.meter = (
            meter_provider.get_meter(service_name)
            if meter_provider is not None
            else metrics.get_meter(service_name)
        )
        self.event_counter = self.meter.create_counter(
            "agent_roi.events",
            unit="{event}",
            description="Agent-ROI control and audit events",
        )
        self.cost_counter = self.meter.create_counter(
            "agent_roi.cost.usd",
            unit="USD",
            description="Recorded Agent-ROI execution cost",
        )
        self.approval_latency = self.meter.create_histogram(
            "agent_roi.approval.latency",
            unit="ms",
            description="Approval workflow latency",
        )
        self.run_latency = self.meter.create_histogram(
            "agent_roi.run.duration",
            unit="ms",
            description="Agent run duration",
        )

    @staticmethod
    def _attributes(event: CloudEvent) -> dict[str, Any]:
        data = event.data
        attrs: dict[str, Any] = {
            "event.type": event.type,
            "event.source": event.source,
            "event.id": event.id,
        }
        for key in (
            "organization_id",
            "environment",
            "agent_id",
            "run_id",
            "correlation_id",
            "tool_name",
            "risk",
            "outcome",
            "status",
        ):
            value = data.get(key)
            if isinstance(value, (str, bool, int, float)):
                attrs[f"agent_roi.{key}"] = value
        return attrs

    def emit(self, event: CloudEvent) -> None:
        attrs = self._attributes(event)
        self.event_counter.add(1, attrs)
        cost = event.data.get("cost_usd")
        if isinstance(cost, (int, float)) and cost >= 0:
            self.cost_counter.add(float(cost), attrs)
        elapsed = event.data.get("elapsed_ms")
        if isinstance(elapsed, (int, float)) and elapsed >= 0:
            if event.type.endswith("run_completed"):
                self.run_latency.record(float(elapsed), attrs)
            elif "approval" in event.type:
                self.approval_latency.record(float(elapsed), attrs)
        with self.tracer.start_as_current_span(event.type, attributes=attrs) as span:
            span.add_event("agent_roi.event", attributes={"cloudevent.id": event.id})
            if event.type.endswith("run_failed") or event.type.endswith("authorization_denied"):
                try:
                    from opentelemetry.trace import Status, StatusCode  # type: ignore
                    span.set_status(Status(StatusCode.ERROR))
                except Exception:
                    pass


def runtime_event(
    *,
    event_type: str,
    payload: Mapping[str, Any],
    source: str,
    subject: str = "",
    organization_id: str = "",
    environment: str = "",
    agent_id: str = "",
    correlation_id: str = "",
    run_id: str = "",
) -> CloudEvent:
    normalized_type = event_type.replace("_", ".")
    data = {
        **dict(payload),
        "organization_id": organization_id,
        "environment": environment,
        "agent_id": agent_id,
        "correlation_id": correlation_id,
        "run_id": run_id,
    }
    return CloudEvent(
        type=f"com.agentroi.{normalized_type}",
        source=source,
        subject=subject,
        data=data,
    )


class DatadogEventSink:
    """Publish CloudEvents to the Datadog Logs intake API."""

    def __init__(
        self,
        api_key: str,
        *,
        site: str = "datadoghq.com",
        service: str = "agent-roi",
        tags: str = "",
        timeout_seconds: float = 10.0,
    ) -> None:
        if not api_key.strip():
            raise ValueError("Datadog API key is required")
        if not site.strip() or "/" in site:
            raise ValueError("Datadog site must be a hostname")
        self.api_key = api_key.strip()
        self.endpoint = f"https://http-intake.logs.{site.strip()}/api/v2/logs"
        self.service = service
        self.tags = tags
        self.timeout_seconds = float(timeout_seconds)

    def emit(self, event: CloudEvent) -> None:
        payload = {
            "ddsource": "agent-roi",
            "service": self.service,
            "ddtags": self.tags,
            "hostname": event.source,
            "message": canonical_json(event.to_dict()),
        }
        req = urlrequest.Request(
            self.endpoint,
            data=canonical_json([payload]).encode("utf-8"),
            method="POST",
            headers={
                "Content-Type": "application/json",
                "DD-API-KEY": self.api_key,
            },
        )
        try:
            with urlrequest.urlopen(req, timeout=self.timeout_seconds) as response:
                if response.status not in {200, 202}:
                    raise EventDeliveryError(
                        f"Datadog Logs intake returned HTTP {response.status}"
                    )
        except (OSError, urlerror.HTTPError) as exc:
            raise EventDeliveryError("Datadog event delivery failed") from exc


class CloudWatchLogsSink:
    """Publish canonical CloudEvents to an AWS CloudWatch Logs stream.

    A boto3-compatible client can be injected, which keeps boto3 optional and
    makes the sink usable with workload-identity credential providers.
    """

    def __init__(
        self,
        log_group: str,
        log_stream: str,
        *,
        client: Any = None,
        region_name: str = "",
    ) -> None:
        if not log_group.strip() or not log_stream.strip():
            raise ValueError("CloudWatch log_group and log_stream are required")
        if client is None:
            try:
                import boto3  # type: ignore
            except ImportError as exc:  # pragma: no cover - optional dependency
                raise RuntimeError(
                    "CloudWatch support requires boto3 or an injected client."
                ) from exc
            client = boto3.client("logs", region_name=region_name or None)
        self.client = client
        self.log_group = log_group
        self.log_stream = log_stream
        self._sequence_token = ""
        self._lock = threading.RLock()

    def emit(self, event: CloudEvent) -> None:
        entry = {
            "timestamp": int(datetime.fromisoformat(event.time).timestamp() * 1000),
            "message": canonical_json(event.to_dict()),
        }
        with self._lock:
            kwargs: dict[str, Any] = {
                "logGroupName": self.log_group,
                "logStreamName": self.log_stream,
                "logEvents": [entry],
            }
            if self._sequence_token:
                kwargs["sequenceToken"] = self._sequence_token
            try:
                response = self.client.put_log_events(**kwargs)
            except Exception as exc:
                raise EventDeliveryError("CloudWatch Logs delivery failed") from exc
            self._sequence_token = str(response.get("nextSequenceToken", ""))


def configure_otlp_sink(
    endpoint: str,
    *,
    service_name: str = "agent-roi",
    headers: Optional[Mapping[str, str]] = None,
    insecure: bool = False,
) -> OpenTelemetrySink:
    """Configure OTLP trace and metric exporters and return an event sink.

    OTLP provides the standard integration path for Grafana, Datadog, Splunk,
    Azure Monitor, Elastic, and other enterprise observability backends.
    """
    try:
        from opentelemetry import metrics, trace  # type: ignore
        from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter  # type: ignore
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter  # type: ignore
        from opentelemetry.sdk.metrics import MeterProvider  # type: ignore
        from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader  # type: ignore
        from opentelemetry.sdk.resources import Resource  # type: ignore
        from opentelemetry.sdk.trace import TracerProvider  # type: ignore
        from opentelemetry.sdk.trace.export import BatchSpanProcessor  # type: ignore
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise RuntimeError(
            "OTLP support requires agent-roi[observability]."
        ) from exc
    endpoint = endpoint.strip().rstrip("/")
    if not endpoint:
        raise ValueError("OTLP endpoint is required")
    scheme = urlparse.urlparse(endpoint).scheme.lower()
    if scheme not in {"http", "https"}:
        raise ValueError("OTLP endpoint must use HTTP or HTTPS")
    if scheme == "http" and not insecure:
        raise ValueError("Plaintext OTLP endpoints require insecure=True")
    resource = Resource.create({"service.name": service_name})
    trace_provider = TracerProvider(resource=resource)
    trace_exporter = OTLPSpanExporter(
        endpoint=endpoint + "/v1/traces",
        headers=dict(headers or {}),
    )
    trace_provider.add_span_processor(BatchSpanProcessor(trace_exporter))
    metric_reader = PeriodicExportingMetricReader(
        OTLPMetricExporter(
            endpoint=endpoint + "/v1/metrics",
            headers=dict(headers or {}),
        )
    )
    meter_provider = MeterProvider(resource=resource, metric_readers=[metric_reader])
    trace.set_tracer_provider(trace_provider)
    metrics.set_meter_provider(meter_provider)
    return OpenTelemetrySink(
        service_name=service_name,
        tracer_provider=trace_provider,
        meter_provider=meter_provider,
    )
