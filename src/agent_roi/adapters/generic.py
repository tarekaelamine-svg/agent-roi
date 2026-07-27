from __future__ import annotations

from dataclasses import dataclass
from functools import wraps
from typing import Any, Callable, Optional, TypeVar

from agent_roi.runtime.context import SentinelContext
from agent_roi.runtime.tools import CostEstimator, ToolRegistry, ToolSpec

T = TypeVar("T")


def controlled_tool(
    registry: ToolRegistry,
    *,
    name: str = "",
    description: str = "",
    risk: str = "low",
    requires_approval: bool = False,
    default_cost_usd: float = 0.0,
    version: str = "1",
    approval_ttl_seconds: int = 900,
    cost_estimator: Optional[CostEstimator] = None,
    timeout_seconds: Optional[float] = None,
) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """Register a trusted callable without coupling it to one agent framework."""

    def decorator(fn: Callable[..., T]) -> Callable[..., T]:
        tool_name = name or fn.__name__
        registry.add(
            tool_name,
            fn,
            description=description or (fn.__doc__ or "").strip(),
            risk=risk,
            requires_approval=requires_approval,
            default_cost_usd=default_cost_usd,
            version=version,
            approval_ttl_seconds=approval_ttl_seconds,
            cost_estimator=cost_estimator,
            timeout_seconds=timeout_seconds,
        )
        setattr(fn, "__agent_roi_tool_name__", tool_name)
        return fn

    return decorator


@dataclass(frozen=True)
class BoundToolExecutor:
    context: SentinelContext

    def invoke(self, tool_name: str, *args: Any, cost_usd: float | None = None, **kwargs: Any) -> Any:
        return self.context.call_tool(tool_name, *args, cost_usd=cost_usd, **kwargs)

    async def ainvoke(
        self, tool_name: str, *args: Any, cost_usd: float | None = None, **kwargs: Any
    ) -> Any:
        return await self.context.acall_tool(tool_name, *args, cost_usd=cost_usd, **kwargs)


def bind_context(context: SentinelContext) -> BoundToolExecutor:
    return BoundToolExecutor(context)
