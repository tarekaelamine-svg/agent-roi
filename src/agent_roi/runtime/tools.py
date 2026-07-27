from __future__ import annotations

from dataclasses import dataclass
import inspect
import math
import time
from typing import Any, Callable, Dict, Generic, Optional, TypeVar, Union

from .resilience import CircuitBreaker, IdempotencyPolicy, RetryPolicy

T = TypeVar("T")


class ToolRegistrationError(ValueError):
    """Raised when a tool registry entry is invalid or ambiguous."""


class HumanApprovalRequired(RuntimeError):
    """Raised before a protected tool executes when approval is unavailable."""

    def __init__(self, checkpoint: Dict[str, Any]):
        self.checkpoint = checkpoint
        tool_name = checkpoint.get("tool_name", "unknown")
        super().__init__(f"Human approval is required before executing tool '{tool_name}'")


@dataclass(frozen=True)
class ApprovalGrant:
    """Approval bound to one canonical tool action digest."""

    action_digest: str
    approved_by: str
    expires_at_epoch_ms: int
    checkpoint_id: Optional[str] = None
    reason: str = ""

    def __post_init__(self) -> None:
        if (
            not isinstance(self.action_digest, str)
            or len(self.action_digest) != 64
            or any(character not in "0123456789abcdefABCDEF" for character in self.action_digest)
        ):
            raise ValueError("action_digest must be a SHA-256 hex digest")
        if not isinstance(self.approved_by, str) or not self.approved_by.strip():
            raise ValueError("approved_by must be a non-empty string")
        object.__setattr__(self, "approved_by", self.approved_by.strip())
        if isinstance(self.expires_at_epoch_ms, bool) or not isinstance(
            self.expires_at_epoch_ms, int
        ):
            raise ValueError("expires_at_epoch_ms must be an integer")

    def validate(self, checkpoint: Dict[str, Any]) -> None:
        if self.action_digest != checkpoint.get("action_digest"):
            raise ValueError("Approval grant does not match the requested action")
        if self.checkpoint_id and self.checkpoint_id != checkpoint.get("checkpoint_id"):
            raise ValueError("Approval grant does not match the checkpoint")
        now_ms = int(time.time() * 1000)
        if now_ms > self.expires_at_epoch_ms:
            raise ValueError("Approval grant has expired")


CostEstimator = Callable[[tuple[Any, ...], Dict[str, Any]], float]


@dataclass(frozen=True)
class ToolSpec(Generic[T]):
    name: str
    handler: Callable[..., T]
    description: str = ""
    risk: str = "low"
    requires_approval: bool = False
    default_cost_usd: float = 0.0
    version: str = "1"
    approval_ttl_seconds: int = 900
    cost_estimator: Optional[CostEstimator] = None
    timeout_seconds: Optional[float] = None
    retry_policy: Optional[RetryPolicy] = None
    circuit_breaker: Optional[CircuitBreaker] = None
    idempotency_policy: Optional[IdempotencyPolicy] = None

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name.strip():
            raise ToolRegistrationError("Tool name must be a non-empty string")
        if not callable(self.handler):
            raise ToolRegistrationError(f"Handler for tool '{self.name}' must be callable")
        if not isinstance(self.requires_approval, bool):
            raise ToolRegistrationError("requires_approval must be a boolean")
        cost = float(self.default_cost_usd)
        if not math.isfinite(cost) or cost < 0:
            raise ToolRegistrationError("default_cost_usd must be finite and nonnegative")
        if not isinstance(self.version, str) or not self.version.strip():
            raise ToolRegistrationError("version must be a non-empty string")
        if (
            isinstance(self.approval_ttl_seconds, bool)
            or not isinstance(self.approval_ttl_seconds, int)
            or self.approval_ttl_seconds < 1
        ):
            raise ToolRegistrationError("approval_ttl_seconds must be an integer >= 1")
        if self.cost_estimator is not None and not callable(self.cost_estimator):
            raise ToolRegistrationError("cost_estimator must be callable")
        if self.retry_policy is not None and not isinstance(self.retry_policy, RetryPolicy):
            raise ToolRegistrationError("retry_policy must be a RetryPolicy")
        if self.circuit_breaker is not None and not isinstance(self.circuit_breaker, CircuitBreaker):
            raise ToolRegistrationError("circuit_breaker must be a CircuitBreaker")
        if self.idempotency_policy is not None and not isinstance(self.idempotency_policy, IdempotencyPolicy):
            raise ToolRegistrationError("idempotency_policy must be an IdempotencyPolicy")
        timeout = self.timeout_seconds
        if timeout is not None:
            timeout = float(timeout)
            if not math.isfinite(timeout) or timeout <= 0:
                raise ToolRegistrationError("timeout_seconds must be finite and > 0")
        object.__setattr__(self, "name", self.name.strip())
        object.__setattr__(self, "risk", str(self.risk or "unknown").strip().lower())
        object.__setattr__(self, "default_cost_usd", cost)
        object.__setattr__(self, "version", self.version.strip())
        object.__setattr__(self, "timeout_seconds", timeout)

    @property
    def is_async(self) -> bool:
        return inspect.iscoroutinefunction(self.handler)


class ToolRegistry:
    """Binds public tool names to trusted callables and execution metadata."""

    def __init__(self) -> None:
        self._tools: Dict[str, ToolSpec[Any]] = {}
        self._frozen = False

    def register(self, spec: ToolSpec[Any], *, replace: bool = False) -> ToolSpec[Any]:
        if self._frozen:
            raise ToolRegistrationError("ToolRegistry is frozen and cannot be modified")
        if spec.name in self._tools and not replace:
            raise ToolRegistrationError(f"Tool '{spec.name}' is already registered")
        self._tools[spec.name] = spec
        return spec

    def add(
        self,
        name: str,
        handler: Callable[..., T],
        *,
        description: str = "",
        risk: str = "low",
        requires_approval: bool = False,
        default_cost_usd: float = 0.0,
        version: str = "1",
        approval_ttl_seconds: int = 900,
        cost_estimator: Optional[CostEstimator] = None,
        timeout_seconds: Optional[float] = None,
        retry_policy: Optional[RetryPolicy] = None,
        circuit_breaker: Optional[CircuitBreaker] = None,
        idempotency_policy: Optional[IdempotencyPolicy] = None,
        replace: bool = False,
    ) -> ToolSpec[T]:
        spec: ToolSpec[T] = ToolSpec(
            name=name,
            handler=handler,
            description=description,
            risk=risk,
            requires_approval=requires_approval,
            default_cost_usd=default_cost_usd,
            version=version,
            approval_ttl_seconds=approval_ttl_seconds,
            cost_estimator=cost_estimator,
            timeout_seconds=timeout_seconds,
            retry_policy=retry_policy,
            circuit_breaker=circuit_breaker,
            idempotency_policy=idempotency_policy,
        )
        self.register(spec, replace=replace)
        return spec

    def get(self, name: str) -> Optional[ToolSpec[Any]]:
        return self._tools.get(name)

    def require(self, name: str) -> ToolSpec[Any]:
        spec = self.get(name)
        if spec is None:
            raise ToolRegistrationError(f"Tool '{name}' is not registered")
        return spec

    def names(self) -> frozenset[str]:
        return frozenset(self._tools)

    def freeze(self) -> "ToolRegistry":
        self._frozen = True
        return self

    @property
    def is_frozen(self) -> bool:
        return self._frozen

    def manifest(self) -> list[Dict[str, Any]]:
        return [
            {
                "name": spec.name,
                "version": spec.version,
                "risk": spec.risk,
                "requires_approval": spec.requires_approval,
                "default_cost_usd": spec.default_cost_usd,
                "timeout_seconds": spec.timeout_seconds,
                "retry_max_attempts": spec.retry_policy.max_attempts if spec.retry_policy else 1,
                "circuit_breaker": spec.circuit_breaker is not None,
                "idempotent": spec.idempotency_policy is not None,
                "handler_module": getattr(spec.handler, "__module__", ""),
                "handler_qualname": getattr(
                    spec.handler,
                    "__qualname__",
                    getattr(spec.handler, "__name__", type(spec.handler).__name__),
                ),
            }
            for _, spec in sorted(self._tools.items())
        ]


ApprovalResponse = Union[bool, ApprovalGrant]
# Existing three-argument callbacks remain supported. New callbacks may accept
# the payload-bound checkpoint as a fourth argument.
ApprovalCallback = Callable[..., ApprovalResponse]
