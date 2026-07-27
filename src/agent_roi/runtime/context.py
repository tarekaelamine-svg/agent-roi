from __future__ import annotations

import asyncio
from copy import deepcopy
from dataclasses import dataclass
import inspect
import time
from types import MappingProxyType
import uuid
from typing import Any, Callable, Dict, Mapping, Optional, TypeVar

from agent_roi.control.guardrails import GuardrailViolation, Guardrails
from agent_roi._serialization import digest_value
from .resilience import aretry_call, retry_call
from .tools import (
    ApprovalCallback,
    ApprovalGrant,
    HumanApprovalRequired,
    ToolRegistry,
    ToolSpec,
)

T = TypeVar("T")
_MISSING = object()


@dataclass(frozen=True)
class RunState:
    steps: int = 0
    tool_calls: int = 0
    cost_usd: float = 0.0


class SentinelContext:
    """Read-only agent facade over runner-owned execution controls.

    Runtime counters and control references are not exposed as mutable public
    fields. This prevents accidental or ordinary agent-side disabling of
    controls. It is not a security sandbox for hostile code executing in the
    same Python interpreter.
    """

    __slots__ = (
        "_correlation_id",
        "_run_id",
        "_started_at_epoch_ms",
        "_metadata",
        "_steps",
        "_tool_calls",
        "_cost_usd",
        "_guardrails",
        "_tool_registry",
        "_approval_callback",
        "_audit_emitter",
        "_policy_digest",
        "_principal",
        "_authorizer",
        "_organization_id",
        "_environment",
        "_agent_id",
    )

    def __init__(
        self,
        *,
        correlation_id: Optional[str] = None,
        run_id: Optional[str] = None,
        started_at_epoch_ms: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None,
        state: Optional[RunState] = None,
        guardrails: Optional[Guardrails] = None,
        tool_registry: Optional[ToolRegistry] = None,
        approval_callback: Optional[ApprovalCallback] = None,
        audit_emitter: Optional[Callable[[str, Dict[str, Any]], None]] = None,
        policy_digest: str = "",
        principal: Any = None,
        authorizer: Any = None,
        organization_id: str = "",
        environment: str = "",
        agent_id: str = "",
    ) -> None:
        initial = state or RunState()
        object.__setattr__(self, "_correlation_id", correlation_id or str(uuid.uuid4()))
        object.__setattr__(self, "_run_id", run_id or str(uuid.uuid4()))
        object.__setattr__(
            self,
            "_started_at_epoch_ms",
            int(started_at_epoch_ms or int(time.time() * 1000)),
        )
        object.__setattr__(self, "_metadata", deepcopy(metadata or {}))
        object.__setattr__(self, "_steps", int(initial.steps))
        object.__setattr__(self, "_tool_calls", int(initial.tool_calls))
        object.__setattr__(self, "_cost_usd", float(initial.cost_usd))
        object.__setattr__(self, "_guardrails", guardrails)
        object.__setattr__(self, "_tool_registry", tool_registry)
        object.__setattr__(self, "_approval_callback", approval_callback)
        object.__setattr__(self, "_audit_emitter", audit_emitter)
        object.__setattr__(self, "_policy_digest", str(policy_digest))
        object.__setattr__(self, "_principal", principal)
        object.__setattr__(self, "_authorizer", authorizer)
        object.__setattr__(self, "_organization_id", str(organization_id))
        object.__setattr__(self, "_environment", str(environment))
        object.__setattr__(self, "_agent_id", str(agent_id))

    @property
    def correlation_id(self) -> str:
        return self._correlation_id

    @property
    def run_id(self) -> str:
        return self._run_id

    @property
    def started_at_epoch_ms(self) -> int:
        return self._started_at_epoch_ms

    @property
    def metadata(self) -> Mapping[str, Any]:
        return MappingProxyType(deepcopy(self._metadata))

    @property
    def state(self) -> RunState:
        return RunState(self._steps, self._tool_calls, self._cost_usd)

    @property
    def guardrails(self) -> Optional[Guardrails]:
        return self._guardrails

    @property
    def principal(self) -> Any:
        return self._principal

    @property
    def organization_id(self) -> str:
        return self._organization_id

    @property
    def environment(self) -> str:
        return self._environment

    @property
    def agent_id(self) -> str:
        return self._agent_id

    def __setattr__(self, name: str, value: Any) -> None:
        raise AttributeError("SentinelContext controls and state are read-only")

    def _emit(self, event_type: str, payload: Dict[str, Any]) -> None:
        if self._audit_emitter is not None:
            self._audit_emitter(event_type, payload)

    def bump_step(self) -> None:
        prospective = self._steps + 1
        if self._guardrails is not None:
            self._guardrails.validate_limits(
                prospective, self._tool_calls, self._cost_usd
            )
        object.__setattr__(self, "_steps", prospective)

    def bump_tool_call(self) -> None:
        prospective = self._tool_calls + 1
        if self._guardrails is not None:
            self._guardrails.validate_limits(self._steps, prospective, self._cost_usd)
        object.__setattr__(self, "_tool_calls", prospective)

    def add_cost(self, amount_usd: float) -> None:
        amount = Guardrails.validate_cost_amount(amount_usd)
        prospective = self._cost_usd + amount
        if self._guardrails is not None:
            self._guardrails.validate_limits(self._steps, self._tool_calls, prospective)
        object.__setattr__(self, "_cost_usd", prospective)

    @staticmethod
    def _callable_identity(fn: Callable[..., Any]) -> Dict[str, str]:
        return {
            "module": getattr(fn, "__module__", ""),
            "qualname": getattr(
                fn, "__qualname__", getattr(fn, "__name__", type(fn).__name__)
            ),
        }

    def _resolve_tool(
        self,
        tool_name: str,
        fn_or_first_arg: Any,
        remaining_args: tuple[Any, ...],
    ) -> tuple[Callable[..., T], tuple[Any, ...], Optional[ToolSpec[Any]]]:
        spec = self._tool_registry.get(tool_name) if self._tool_registry is not None else None

        if spec is not None:
            if callable(fn_or_first_arg):
                if fn_or_first_arg is not spec.handler:
                    raise GuardrailViolation(
                        f"Tool '{tool_name}' callable does not match its registered handler"
                    )
                return spec.handler, remaining_args, spec
            args = (
                remaining_args
                if fn_or_first_arg is _MISSING
                else (fn_or_first_arg, *remaining_args)
            )
            return spec.handler, args, spec

        require_registered = bool(
            self._guardrails is not None and self._guardrails.require_registered_tools
        )
        if require_registered:
            raise GuardrailViolation(f"Tool '{tool_name}' is not registered")

        if fn_or_first_arg is _MISSING or not callable(fn_or_first_arg):
            raise TypeError(
                "Unregistered tools require the legacy form "
                "ctx.call_tool(name, callable, *args)"
            )
        return fn_or_first_arg, remaining_args, None

    @staticmethod
    def _estimated_cost(
        spec: Optional[ToolSpec[Any]],
        call_args: tuple[Any, ...],
        kwargs: Dict[str, Any],
        caller_cost: Optional[float],
    ) -> float:
        registered_minimum = spec.default_cost_usd if spec is not None else 0.0
        if spec is not None and spec.cost_estimator is not None:
            estimated = Guardrails.validate_cost_amount(
                spec.cost_estimator(call_args, dict(kwargs))
            )
            registered_minimum = max(registered_minimum, estimated)

        if caller_cost is None:
            return registered_minimum
        requested = Guardrails.validate_cost_amount(caller_cost)
        if spec is not None and requested < registered_minimum:
            raise GuardrailViolation(
                f"Tool '{spec.name}' cost cannot be lower than the registered estimate "
                f"({requested:.4f} < {registered_minimum:.4f})"
            )
        return max(registered_minimum, requested)

    def _approval_checkpoint(
        self,
        *,
        tool_name: str,
        spec: ToolSpec[Any],
        call_args: tuple[Any, ...],
        kwargs: Dict[str, Any],
        selected_cost: float,
        handler_identity: Dict[str, str],
    ) -> Dict[str, Any]:
        action = {
            "tool_name": tool_name,
            "tool_version": spec.version,
            "handler": handler_identity,
            "risk": spec.risk,
            "cost_usd": selected_cost,
            "args": call_args,
            "kwargs": kwargs,
            "policy_digest": self._policy_digest,
            "principal_subject": getattr(self._principal, "subject", ""),
            "organization_id": self._organization_id,
            "environment": self._environment,
            "agent_id": self._agent_id,
        }
        action_digest = digest_value(action)
        expires = int(time.time() * 1000) + spec.approval_ttl_seconds * 1000
        checkpoint_id = digest_value(
            {
                "correlation_id": self._correlation_id,
                "run_id": self._run_id,
                "action_digest": action_digest,
                "expires_at_epoch_ms": expires,
            }
        )
        return {
            "checkpoint_id": checkpoint_id,
            "correlation_id": self._correlation_id,
            "run_id": self._run_id,
            "tool_name": tool_name,
            "tool_version": spec.version,
            "risk": spec.risk,
            "estimated_cost_usd": selected_cost,
            "action_digest": action_digest,
            "policy_digest": self._policy_digest,
            "arguments_digest": digest_value({"args": call_args, "kwargs": kwargs}),
            "created_at_epoch_ms": int(time.time() * 1000),
            "expires_at_epoch_ms": expires,
            "principal_subject": getattr(self._principal, "subject", ""),
            "organization_id": self._organization_id,
            "environment": self._environment,
            "agent_id": self._agent_id,
        }

    def _authorize_access(self, tool_name: str, spec: Optional[ToolSpec[Any]]) -> None:
        if self._authorizer is None:
            return
        if self._principal is None:
            self._emit(
                "authorization_denied",
                {"tool_name": tool_name, "reason": "missing_principal"},
            )
            raise GuardrailViolation("An authenticated principal is required")
        context = {
            "organization_id": self._organization_id,
            "environment": self._environment,
            "agent_id": self._agent_id,
            "risk": spec.risk if spec is not None else "unclassified",
            "tool_version": spec.version if spec is not None else "legacy",
        }
        allowed = bool(
            self._authorizer.authorize(
                self._principal,
                "tool.execute",
                tool_name,
                context=context,
            )
        )
        payload = {
            "tool_name": tool_name,
            "allowed": allowed,
            "principal_subject": getattr(self._principal, "subject", ""),
            **context,
        }
        self._emit("authorization_decision", payload)
        if not allowed:
            self._emit("authorization_denied", payload)
            raise GuardrailViolation(
                f"Principal is not authorized to execute tool '{tool_name}'"
            )

    def _authorize(
        self,
        *,
        spec: Optional[ToolSpec[Any]],
        call_args: tuple[Any, ...],
        kwargs: Dict[str, Any],
        checkpoint: Optional[Dict[str, Any]],
    ) -> None:
        if spec is None or not spec.requires_approval:
            return
        response: Any = False
        if self._approval_callback is not None:
            callback = self._approval_callback
            try:
                signature = inspect.signature(callback)
                supports_checkpoint = any(
                    parameter.kind is inspect.Parameter.VAR_POSITIONAL
                    for parameter in signature.parameters.values()
                ) or len(signature.parameters) >= 4
            except (TypeError, ValueError):
                supports_checkpoint = False
            if supports_checkpoint:
                response = callback(spec, call_args, dict(kwargs), checkpoint)
            else:
                response = callback(spec, call_args, dict(kwargs))
        if isinstance(response, ApprovalGrant):
            assert checkpoint is not None
            try:
                response.validate(checkpoint)
            except ValueError as exc:
                raise GuardrailViolation(str(exc)) from exc
            self._emit(
                "approval_granted",
                {
                    "tool_name": spec.name,
                    "risk": spec.risk,
                    "action_digest": checkpoint["action_digest"],
                    "checkpoint_id": checkpoint["checkpoint_id"],
                    "approved_by": response.approved_by,
                    "reason": response.reason,
                },
            )
            return
        if response is True:
            if self._guardrails is not None and self._guardrails.require_bound_approval_grants:
                raise GuardrailViolation(
                    "This policy requires a payload-bound ApprovalGrant; boolean approval is not sufficient"
                )
            assert checkpoint is not None
            self._emit(
                "approval_granted",
                {
                    "tool_name": spec.name,
                    "risk": spec.risk,
                    "action_digest": checkpoint["action_digest"],
                    "checkpoint_id": checkpoint["checkpoint_id"],
                    "approved_by": "synchronous_callback",
                },
            )
            return
        assert checkpoint is not None
        self._emit("approval_required", checkpoint)
        raise HumanApprovalRequired(checkpoint)

    def _prepare_call(
        self,
        tool_name: str,
        fn_or_first_arg: Any,
        args: tuple[Any, ...],
        kwargs: Dict[str, Any],
        cost_usd: Optional[float],
        *,
        async_mode: bool,
    ) -> tuple[
        Callable[..., T],
        tuple[Any, ...],
        Optional[ToolSpec[Any]],
        float,
        Dict[str, Any],
    ]:
        if self._guardrails is not None:
            self._guardrails.validate_tool_allowed(tool_name)
        handler, call_args, spec = self._resolve_tool(tool_name, fn_or_first_arg, args)
        self._authorize_access(tool_name, spec)
        if not async_mode and inspect.iscoroutinefunction(handler):
            raise GuardrailViolation(
                f"Tool '{tool_name}' is asynchronous; use ctx.acall_tool() and SentinelRunner.arun()"
            )
        if not async_mode and spec is not None and spec.timeout_seconds is not None:
            raise GuardrailViolation(
                f"Tool '{tool_name}' declares timeout_seconds; execute it through acall_tool/arun "
                "or enforce a timeout inside the synchronous handler"
            )
        if (
            async_mode
            and spec is not None
            and spec.timeout_seconds is not None
            and not inspect.iscoroutinefunction(handler)
        ):
            raise GuardrailViolation(
                f"Tool '{tool_name}' is synchronous; an asyncio timeout cannot cancel its worker thread. "
                "Use an async handler or enforce the timeout inside the handler."
            )
        selected_cost = self._estimated_cost(spec, call_args, kwargs, cost_usd)
        risk = spec.risk if spec is not None else "unclassified"
        requires_approval = bool(spec is not None and spec.requires_approval)
        identity = self._callable_identity(handler)
        checkpoint = (
            self._approval_checkpoint(
                tool_name=tool_name,
                spec=spec,
                call_args=call_args,
                kwargs=kwargs,
                selected_cost=selected_cost,
                handler_identity=identity,
            )
            if requires_approval and spec is not None
            else None
        )
        event_base = {
            "tool_name": tool_name,
            "tool_version": spec.version if spec is not None else "legacy",
            "risk": risk,
            "requires_approval": requires_approval,
            "cost_usd": selected_cost,
            "arguments_digest": digest_value({"args": call_args, "kwargs": kwargs}),
            "action_digest": checkpoint.get("action_digest") if checkpoint else None,
            "handler": identity,
            "principal_subject": getattr(self._principal, "subject", ""),
            "organization_id": self._organization_id,
            "environment": self._environment,
            "agent_id": self._agent_id,
            "retry_max_attempts": spec.retry_policy.max_attempts if spec and spec.retry_policy else 1,
            "circuit_breaker": bool(spec and spec.circuit_breaker),
            "idempotent": bool(spec and spec.idempotency_policy),
        }
        self._emit("tool_requested", event_base)
        self._authorize(
            spec=spec, call_args=call_args, kwargs=kwargs, checkpoint=checkpoint
        )

        prospective_calls = self._tool_calls + 1
        prospective_cost = self._cost_usd + selected_cost
        if self._guardrails is not None:
            self._guardrails.validate_limits(
                self._steps, prospective_calls, prospective_cost
            )
        object.__setattr__(self, "_tool_calls", prospective_calls)
        object.__setattr__(self, "_cost_usd", prospective_cost)
        self._emit("tool_authorized", event_base)
        self._emit("tool_started", event_base)
        return handler, call_args, spec, selected_cost, event_base

    def _execute_sync(
        self,
        handler: Callable[..., T],
        call_args: tuple[Any, ...],
        kwargs: Dict[str, Any],
        spec: Optional[ToolSpec[Any]],
    ) -> T:
        idempotency_key: Optional[str] = None
        idempotency_started = False
        if spec is not None and spec.idempotency_policy is not None:
            idempotency_key, _, idempotency_result = spec.idempotency_policy.prepare(call_args, kwargs)
            if idempotency_result.status == "completed":
                return idempotency_result.response
            if idempotency_result.status == "failed":
                raise GuardrailViolation(
                    f"Previous idempotent execution failed: {idempotency_result.error}"
                )
            idempotency_started = True

        def raw_call() -> T:
            return handler(*call_args, **kwargs)

        def protected_call() -> T:
            if spec is not None and spec.circuit_breaker is not None:
                return spec.circuit_breaker.call(raw_call)
            return raw_call()

        try:
            if spec is not None and spec.retry_policy is not None:
                result = retry_call(protected_call, spec.retry_policy)
            else:
                result = protected_call()
            if inspect.isawaitable(result):
                close = getattr(result, "close", None)
                if callable(close):
                    close()
                raise GuardrailViolation(
                    f"Tool '{spec.name if spec else 'legacy'}' returned an awaitable; use ctx.acall_tool()"
                )
        except Exception as exc:
            if idempotency_started and spec is not None and spec.idempotency_policy is not None and idempotency_key is not None:
                spec.idempotency_policy.store.fail(
                    spec.idempotency_policy.namespace, idempotency_key, f"{type(exc).__name__}: {exc}"
                )
            raise
        if idempotency_started and spec is not None and spec.idempotency_policy is not None and idempotency_key is not None:
            spec.idempotency_policy.store.complete(
                spec.idempotency_policy.namespace, idempotency_key, result
            )
        return result

    async def _execute_async(
        self,
        handler: Callable[..., T],
        call_args: tuple[Any, ...],
        kwargs: Dict[str, Any],
        spec: Optional[ToolSpec[Any]],
    ) -> T:
        idempotency_key: Optional[str] = None
        idempotency_started = False
        if spec is not None and spec.idempotency_policy is not None:
            idempotency_key, _, idempotency_result = spec.idempotency_policy.prepare(call_args, kwargs)
            if idempotency_result.status == "completed":
                return idempotency_result.response
            if idempotency_result.status == "failed":
                raise GuardrailViolation(
                    f"Previous idempotent execution failed: {idempotency_result.error}"
                )
            idempotency_started = True

        async def raw_call() -> T:
            if inspect.iscoroutinefunction(handler):
                awaitable = handler(*call_args, **kwargs)
            else:
                awaitable = asyncio.to_thread(handler, *call_args, **kwargs)
            if spec is not None and spec.timeout_seconds is not None:
                return await asyncio.wait_for(awaitable, timeout=spec.timeout_seconds)
            return await awaitable

        async def protected_call() -> T:
            if spec is not None and spec.circuit_breaker is not None:
                return await spec.circuit_breaker.acall(raw_call)
            return await raw_call()

        try:
            if spec is not None and spec.retry_policy is not None:
                result = await aretry_call(protected_call, spec.retry_policy)
            else:
                result = await protected_call()
        except Exception as exc:
            if idempotency_started and spec is not None and spec.idempotency_policy is not None and idempotency_key is not None:
                spec.idempotency_policy.store.fail(
                    spec.idempotency_policy.namespace, idempotency_key, f"{type(exc).__name__}: {exc}"
                )
            raise
        if idempotency_started and spec is not None and spec.idempotency_policy is not None and idempotency_key is not None:
            spec.idempotency_policy.store.complete(
                spec.idempotency_policy.namespace, idempotency_key, result
            )
        return result

    def call_tool(
        self,
        tool_name: str,
        fn_or_first_arg: Any = _MISSING,
        *args: Any,
        cost_usd: Optional[float] = None,
        **kwargs: Any,
    ) -> T:
        handler, call_args, spec, _, event_base = self._prepare_call(
            tool_name, fn_or_first_arg, args, dict(kwargs), cost_usd, async_mode=False
        )

        started = time.perf_counter()
        try:
            result = self._execute_sync(handler, call_args, dict(kwargs), spec)
        except Exception as exc:
            self._emit(
                "tool_failed",
                {
                    **event_base,
                    "elapsed_ms": int((time.perf_counter() - started) * 1000),
                    "error_type": type(exc).__name__,
                },
            )
            raise

        self._emit(
            "tool_completed",
            {
                **event_base,
                "elapsed_ms": int((time.perf_counter() - started) * 1000),
                "result_type": type(result).__name__,
            },
        )
        return result

    async def acall_tool(
        self,
        tool_name: str,
        fn_or_first_arg: Any = _MISSING,
        *args: Any,
        cost_usd: Optional[float] = None,
        **kwargs: Any,
    ) -> T:
        handler, call_args, spec, _, event_base = self._prepare_call(
            tool_name, fn_or_first_arg, args, dict(kwargs), cost_usd, async_mode=True
        )
        started = time.perf_counter()
        try:
            result = await self._execute_async(handler, call_args, dict(kwargs), spec)
        except Exception as exc:
            self._emit(
                "tool_failed",
                {
                    **event_base,
                    "elapsed_ms": int((time.perf_counter() - started) * 1000),
                    "error_type": type(exc).__name__,
                },
            )
            raise
        self._emit(
            "tool_completed",
            {
                **event_base,
                "elapsed_ms": int((time.perf_counter() - started) * 1000),
                "result_type": type(result).__name__,
            },
        )
        return result

    def snapshot(self) -> Dict[str, Any]:
        return {
            "correlation_id": self._correlation_id,
            "run_id": self._run_id,
            "started_at_epoch_ms": self._started_at_epoch_ms,
            "metadata": deepcopy(self._metadata),
            "principal_subject": getattr(self._principal, "subject", ""),
            "organization_id": self._organization_id,
            "environment": self._environment,
            "agent_id": self._agent_id,
            "state": {
                "steps": self._steps,
                "tool_calls": self._tool_calls,
                "cost_usd": self._cost_usd,
            },
        }
