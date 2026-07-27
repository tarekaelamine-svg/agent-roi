from __future__ import annotations

from typing import Any, Callable

from agent_roi.runtime.context import SentinelContext
from agent_roi.runtime.tools import ToolRegistry


class AutoGenAdapter:
    """Build an AutoGen-compatible controlled function map."""

    def __init__(self, registry: ToolRegistry) -> None:
        self.registry = registry

    def function_map(self, context: SentinelContext) -> dict[str, Callable[..., Any]]:
        result: dict[str, Callable[..., Any]] = {}
        for name in self.registry.names():
            def controlled(*args: Any, __name: str = name, **kwargs: Any) -> Any:
                return context.call_tool(__name, *args, **kwargs)
            controlled.__name__ = name
            controlled.__doc__ = self.registry.require(name).description
            result[name] = controlled
        return result
