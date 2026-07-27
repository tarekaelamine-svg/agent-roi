from __future__ import annotations

import asyncio
from contextlib import contextmanager
from dataclasses import asdict, dataclass
import inspect
import math
import signal
import threading
import time
from typing import Any, Callable, Dict, Iterable, Iterator, Optional, Tuple, cast

from .context import SentinelContext
from agent_roi._serialization import digest_value
from .tools import ApprovalCallback, HumanApprovalRequired, ToolRegistry
from ..control.guardrails import Guardrails
from ..control.decision import DecisionPolicy, ConfidenceInputs, DecisionOutcome
from ..audit.event import AuditEvent
from ..audit.redact import DEFAULT_REDACTED_KEYS, redact
from ..audit.store import InMemoryAuditStore, AuditStore
from agent_roi.enterprise.telemetry import EventSink, runtime_event


@dataclass(frozen=True)
class SentinelResult:
    outcome: DecisionOutcome
    confidence: float
    output: Any
    correlation_id: str
    run_id: str
    ctx_snapshot: Dict[str, Any]


def _safe_repr(value: Any, *, max_len: int = 2000) -> str:
    try:
        rendered = repr(value)
        return rendered if len(rendered) <= max_len else rendered[: max_len - 3] + "..."
    except Exception:
        return "<unreprable>"


@contextmanager
def _hard_sync_timeout(seconds: Optional[float]) -> Iterator[None]:
    if seconds is None:
        yield
        return
    if not hasattr(signal, "SIGALRM") or threading.current_thread() is not threading.main_thread():
        raise RuntimeError(
            "Hard synchronous run timeouts require a Unix main thread; use SentinelRunner.arun() on this platform"
        )

    def _raise_timeout(signum: int, frame: Any) -> None:
        raise TimeoutError(f"Sentinel run exceeded {seconds:.3f} seconds")

    previous_handler = signal.getsignal(signal.SIGALRM)
    signal.signal(signal.SIGALRM, _raise_timeout)
    previous_timer = signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)
        if previous_timer[0] > 0:
            signal.setitimer(signal.ITIMER_REAL, *previous_timer)


class SentinelRunner:
    def __init__(
        self,
        *,
        name: str = "sentinel_run",
        guardrails: Optional[Guardrails] = None,
        decision_policy: Optional[DecisionPolicy] = None,
        audit_store: Optional[AuditStore] = None,
        audit_hash_chain: bool = True,
        metadata: Optional[Dict[str, Any]] = None,
        tool_registry: Optional[ToolRegistry] = None,
        approval_callback: Optional[ApprovalCallback] = None,
        capture_input: bool = False,
        capture_output: bool = False,
        redacted_keys: Optional[set[str] | frozenset[str]] = None,
        run_timeout_seconds: Optional[float] = None,
        organization_id: str = "",
        environment: str = "",
        agent_id: str = "",
        principal: Any = None,
        authorizer: Any = None,
        event_sinks: Optional[Iterable[EventSink]] = None,
        fail_on_event_sink_error: bool = False,
        event_source: str = "",
    ) -> None:
        self.name = name
        self.guardrails = guardrails or Guardrails()
        self.decision_policy = decision_policy or DecisionPolicy()
        self.audit_store = audit_store or InMemoryAuditStore(hash_chain=audit_hash_chain)
        store_hash_chain = getattr(self.audit_store, "hash_chain", audit_hash_chain)
        if bool(store_hash_chain) != bool(audit_hash_chain):
            raise ValueError("audit_hash_chain must match the configured audit store")
        self.audit_hash_chain = bool(audit_hash_chain)
        self.metadata = dict(metadata or {})
        self.tool_registry = tool_registry.freeze() if tool_registry is not None else None
        self.approval_callback = approval_callback
        self.capture_input = bool(capture_input)
        self.capture_output = bool(capture_output)
        self.redacted_keys = frozenset(redacted_keys or DEFAULT_REDACTED_KEYS)
        self.organization_id = str(organization_id).strip()
        self.environment = str(environment).strip()
        self.agent_id = str(agent_id).strip()
        self.principal = principal
        self.authorizer = authorizer
        if self.principal is not None and self.organization_id:
            principal_org = str(getattr(self.principal, "organization_id", ""))
            if principal_org and principal_org != self.organization_id:
                raise ValueError("principal organization_id does not match runner organization_id")
        self.event_sinks = tuple(event_sinks or ())
        self.fail_on_event_sink_error = bool(fail_on_event_sink_error)
        self.event_sink_errors: list[dict[str, str]] = []
        self.event_source = event_source or (
            f"/organizations/{self.organization_id}/agents/{self.agent_id}"
            if self.organization_id and self.agent_id
            else f"urn:agent-roi:{self.name}"
        )
        if run_timeout_seconds is not None:
            timeout = float(run_timeout_seconds)
            if not math.isfinite(timeout) or timeout <= 0:
                raise ValueError("run_timeout_seconds must be finite and > 0")
            self.run_timeout_seconds: Optional[float] = timeout
        else:
            self.run_timeout_seconds = None

        if self.guardrails.require_registered_tools and self.tool_registry is None:
            raise ValueError(
                "Guardrails.require_registered_tools=True requires a ToolRegistry"
            )

        self.policy_digest = digest_value(
            {
                "guardrails": asdict(self.guardrails),
                "decision_policy": asdict(self.decision_policy),
                "registered_tools": (
                    self.tool_registry.manifest() if self.tool_registry is not None else []
                ),
            }
        )

    def _log(self, ctx: SentinelContext, event_type: str, payload: Dict[str, Any]) -> None:
        safe_payload = redact(payload, blocked_keys=self.redacted_keys)
        record = getattr(self.audit_store, "record", None)
        if callable(record):
            event = record(
                correlation_id=ctx.correlation_id,
                run_id=ctx.run_id,
                event_type=event_type,
                payload=safe_payload,
            )
        else:
            # Compatibility fallback for third-party stores implementing the older
            # append/last_hash protocol. Such stores should add atomic record().
            previous = self.audit_store.last_hash(ctx.correlation_id)
            event = AuditEvent.create(
                correlation_id=ctx.correlation_id,
                run_id=ctx.run_id,
                event_type=event_type,
                payload=safe_payload,
                prev_hash=previous,
                hash_chain=self.audit_hash_chain,
            )
            self.audit_store.append(event)

        if not self.event_sinks:
            return
        cloud_event = runtime_event(
            event_type=event_type,
            payload={**safe_payload, "audit_event_id": event.event_id},
            source=self.event_source,
            subject=str(safe_payload.get("tool_name", self.agent_id or self.name)),
            organization_id=self.organization_id,
            environment=self.environment,
            agent_id=self.agent_id,
            correlation_id=ctx.correlation_id,
            run_id=ctx.run_id,
        )
        for sink in self.event_sinks:
            try:
                sink.emit(cloud_event)
            except Exception as exc:
                self.event_sink_errors.append(
                    {"sink": type(sink).__name__, "error": str(exc), "event_type": event_type}
                )
                if self.fail_on_event_sink_error:
                    raise

    @staticmethod
    def _normalize_agent_return(
        agent_return: Any,
    ) -> Tuple[Any, Optional[ConfidenceInputs]]:
        if (
            isinstance(agent_return, tuple)
            and len(agent_return) == 2
            and isinstance(agent_return[1], ConfidenceInputs)
        ):
            output, confidence = cast(Tuple[Any, ConfidenceInputs], agent_return)
            return output, confidence
        return agent_return, None

    def _new_context(self) -> SentinelContext:
        metadata = {"name": self.name, **self.metadata}
        holder: Dict[str, SentinelContext] = {}

        def emitter(event_type: str, payload: Dict[str, Any]) -> None:
            self._log(holder["ctx"], event_type, payload)

        ctx = SentinelContext(
            metadata=metadata,
            guardrails=self.guardrails,
            tool_registry=self.tool_registry,
            approval_callback=self.approval_callback,
            audit_emitter=emitter,
            policy_digest=self.policy_digest,
            principal=self.principal,
            authorizer=self.authorizer,
            organization_id=self.organization_id,
            environment=self.environment,
            agent_id=self.agent_id,
        )
        holder["ctx"] = ctx
        return ctx

    def _start(self, ctx: SentinelContext, input_data: Any) -> float:
        started = time.perf_counter()
        start_payload: Dict[str, Any] = {
            "input_type": type(input_data).__name__,
            "deterministic_declared": self.guardrails.deterministic,
            "policy_digest": self.policy_digest,
            "organization_id": self.organization_id,
            "environment": self.environment,
            "agent_id": self.agent_id,
            "principal_subject": getattr(self.principal, "subject", ""),
            "ctx": ctx.snapshot(),
        }
        if self.capture_input:
            start_payload["input_preview"] = _safe_repr(
                redact(input_data, blocked_keys=self.redacted_keys)
            )
        self._log(ctx, "run_started", start_payload)
        ctx.bump_step()
        return started

    def _success(
        self,
        ctx: SentinelContext,
        started: float,
        agent_return: Any,
        confidence_inputs: Optional[ConfidenceInputs],
    ) -> SentinelResult:
        output, confidence_from_agent = self._normalize_agent_return(agent_return)
        output_payload: Dict[str, Any] = {"output_type": type(output).__name__}
        if self.capture_output:
            output_payload["output_preview"] = _safe_repr(
                redact(output, blocked_keys=self.redacted_keys)
            )
        self._log(ctx, "agent_output", output_payload)

        inputs = confidence_inputs or confidence_from_agent or ConfidenceInputs()
        confidence = self.decision_policy.score(inputs)
        outcome = self.decision_policy.decide(inputs)
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        self._log(
            ctx,
            "decision_made",
            {"confidence": confidence, "outcome": outcome.value, "inputs": asdict(inputs)},
        )
        self._log(
            ctx,
            "run_completed",
            {"status": "ok", "elapsed_ms": elapsed_ms, "ctx": ctx.snapshot()},
        )
        return SentinelResult(
            outcome=outcome,
            confidence=confidence,
            output=output,
            correlation_id=ctx.correlation_id,
            run_id=ctx.run_id,
            ctx_snapshot=ctx.snapshot(),
        )

    def _approval_result(
        self, ctx: SentinelContext, started: float, exc: HumanApprovalRequired
    ) -> SentinelResult:
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        self._log(
            ctx,
            "decision_made",
            {
                "confidence": 0.0,
                "outcome": DecisionOutcome.HUMAN_REVIEW.value,
                "reason": "approval_required",
                "action_digest": exc.checkpoint.get("action_digest"),
            },
        )
        self._log(
            ctx,
            "run_completed",
            {"status": "pending_approval", "elapsed_ms": elapsed_ms, "ctx": ctx.snapshot()},
        )
        return SentinelResult(
            outcome=DecisionOutcome.HUMAN_REVIEW,
            confidence=0.0,
            output={"approval_checkpoint": exc.checkpoint},
            correlation_id=ctx.correlation_id,
            run_id=ctx.run_id,
            ctx_snapshot=ctx.snapshot(),
        )

    def _failure(self, ctx: SentinelContext, started: float, exc: Exception) -> None:
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        self._log(
            ctx,
            "run_failed",
            {"error_type": type(exc).__name__, "elapsed_ms": elapsed_ms, "ctx": ctx.snapshot()},
        )
        self._log(
            ctx,
            "run_completed",
            {"status": "error", "elapsed_ms": elapsed_ms, "ctx": ctx.snapshot()},
        )

    def run(
        self,
        agent_fn: Callable[[SentinelContext, Any], Any],
        input_data: Any,
        *,
        confidence_inputs: Optional[ConfidenceInputs] = None,
    ) -> SentinelResult:
        if inspect.iscoroutinefunction(agent_fn):
            raise TypeError("Asynchronous agents require await SentinelRunner.arun(...)")
        ctx = self._new_context()
        started = self._start(ctx, input_data)
        try:
            with _hard_sync_timeout(self.run_timeout_seconds):
                agent_return = agent_fn(ctx, input_data)
            if inspect.isawaitable(agent_return):
                close = getattr(agent_return, "close", None)
                if callable(close):
                    close()
                raise TypeError("Agent returned an awaitable; use SentinelRunner.arun(...)")
            return self._success(ctx, started, agent_return, confidence_inputs)
        except HumanApprovalRequired as exc:
            return self._approval_result(ctx, started, exc)
        except Exception as exc:
            self._failure(ctx, started, exc)
            raise

    async def arun(
        self,
        agent_fn: Callable[[SentinelContext, Any], Any],
        input_data: Any,
        *,
        confidence_inputs: Optional[ConfidenceInputs] = None,
    ) -> SentinelResult:
        ctx = self._new_context()
        started = self._start(ctx, input_data)
        try:
            if inspect.iscoroutinefunction(agent_fn):
                awaitable = agent_fn(ctx, input_data)
            else:
                if self.run_timeout_seconds is not None:
                    raise TypeError(
                        "arun() with run_timeout_seconds requires an async agent; "
                        "a timed-out worker thread cannot be safely cancelled"
                    )
                value = agent_fn(ctx, input_data)
                if inspect.isawaitable(value):
                    awaitable = value
                else:
                    return self._success(ctx, started, value, confidence_inputs)
            if self.run_timeout_seconds is not None:
                agent_return = await asyncio.wait_for(
                    awaitable, timeout=self.run_timeout_seconds
                )
            else:
                agent_return = await awaitable
            return self._success(ctx, started, agent_return, confidence_inputs)
        except HumanApprovalRequired as exc:
            return self._approval_result(ctx, started, exc)
        except Exception as exc:
            self._failure(ctx, started, exc)
            raise
