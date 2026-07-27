from __future__ import annotations

from dataclasses import dataclass
import math
from typing import Iterable, Optional, FrozenSet


class GuardrailViolation(RuntimeError):
    """Raised when a runtime control is violated."""


@dataclass(frozen=True)
class Guardrails:
    """Execution limits applied by :class:`SentinelContext`.

    ``allowed_tools=None`` preserves the package's backwards-compatible
    allow-all behavior. Production callers should provide an explicit set and
    enable ``require_registered_tools`` so names are bound to trusted handlers.

    ``deterministic`` is an execution declaration exposed in metadata; the
    library cannot make a non-deterministic model or external service
    deterministic on its own.
    """

    max_steps: int = 10
    max_tool_calls: int = 20
    max_cost_usd: float = 1.00
    deterministic: bool = True
    allowed_tools: Optional[FrozenSet[str]] = None
    require_registered_tools: bool = False
    require_bound_approval_grants: bool = False

    def __post_init__(self) -> None:
        if isinstance(self.max_steps, bool) or not isinstance(self.max_steps, int) or self.max_steps < 1:
            raise ValueError("max_steps must be an integer >= 1")
        if (
            isinstance(self.max_tool_calls, bool)
            or not isinstance(self.max_tool_calls, int)
            or self.max_tool_calls < 0
        ):
            raise ValueError("max_tool_calls must be an integer >= 0")
        if not isinstance(self.deterministic, bool):
            raise ValueError("deterministic must be a boolean")
        if not isinstance(self.require_registered_tools, bool):
            raise ValueError("require_registered_tools must be a boolean")
        if not isinstance(self.require_bound_approval_grants, bool):
            raise ValueError("require_bound_approval_grants must be a boolean")

        max_cost = float(self.max_cost_usd)
        if not math.isfinite(max_cost) or max_cost < 0:
            raise ValueError("max_cost_usd must be finite and >= 0")
        object.__setattr__(self, "max_cost_usd", max_cost)

        if self.allowed_tools is not None:
            if isinstance(self.allowed_tools, str):
                raise ValueError("allowed_tools must be an iterable of non-empty tool names")
            normalized = self._normalize_tool_names(self.allowed_tools)
            object.__setattr__(self, "allowed_tools", normalized)

    @staticmethod
    def _normalize_tool_names(values: Iterable[str]) -> FrozenSet[str]:
        names = []
        for value in values:
            if not isinstance(value, str) or not value.strip():
                raise ValueError("allowed_tools must contain only non-empty strings")
            names.append(value.strip())
        return frozenset(names)

    @staticmethod
    def validate_cost_amount(amount_usd: float) -> float:
        try:
            amount = float(amount_usd)
        except (TypeError, ValueError) as exc:
            raise GuardrailViolation("Cost must be numeric") from exc
        if not math.isfinite(amount) or amount < 0:
            raise GuardrailViolation("Cost must be finite and nonnegative")
        return amount

    def validate_tool_allowed(self, tool_name: str) -> None:
        if not isinstance(tool_name, str) or not tool_name.strip():
            raise GuardrailViolation("Tool name must be a non-empty string")
        if self.allowed_tools is not None and tool_name not in self.allowed_tools:
            raise GuardrailViolation(f"Tool '{tool_name}' is not allowlisted.")

    def validate_limits(self, steps: int, tool_calls: int, cost_usd: float) -> None:
        if steps < 0 or tool_calls < 0:
            raise GuardrailViolation("Execution counters cannot be negative")
        cost = self.validate_cost_amount(cost_usd)
        if steps > self.max_steps:
            raise GuardrailViolation(f"Max steps exceeded: {steps} > {self.max_steps}")
        if tool_calls > self.max_tool_calls:
            raise GuardrailViolation(
                f"Max tool calls exceeded: {tool_calls} > {self.max_tool_calls}"
            )
        if cost > self.max_cost_usd:
            raise GuardrailViolation(
                f"Max cost exceeded: {cost:.4f} > {self.max_cost_usd:.4f}"
            )
