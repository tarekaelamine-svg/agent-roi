from __future__ import annotations

from typing import Any, Callable, Mapping

from agent_roi.runtime.context import SentinelContext
from agent_roi.runtime.tools import ToolRegistry


class LangChainAdapter:
    """Duck-typed LangChain tool and AgentAction bridge.

    No LangChain dependency is required. ``execute_action`` accepts objects with
    ``tool`` and ``tool_input`` attributes or equivalent mappings. ``function_map``
    returns callables suitable for StructuredTool/function registration.
    """

    def __init__(self, registry: ToolRegistry) -> None:
        self.registry = registry

    @staticmethod
    def _parse_action(action: Any) -> tuple[str, Any]:
        if isinstance(action, Mapping):
            name = action.get("tool") or action.get("name")
            value = action.get("tool_input", action.get("arguments", {}))
        else:
            name = getattr(action, "tool", getattr(action, "name", ""))
            value = getattr(action, "tool_input", getattr(action, "arguments", {}))
        if not isinstance(name, str) or not name.strip():
            raise ValueError("LangChain action is missing a tool name")
        return name.strip(), value

    @staticmethod
    def _invoke(context: SentinelContext, name: str, tool_input: Any) -> Any:
        if isinstance(tool_input, Mapping):
            return context.call_tool(name, **dict(tool_input))
        return context.call_tool(name, tool_input)

    @staticmethod
    async def _ainvoke(context: SentinelContext, name: str, tool_input: Any) -> Any:
        if isinstance(tool_input, Mapping):
            return await context.acall_tool(name, **dict(tool_input))
        return await context.acall_tool(name, tool_input)

    def execute_action(self, context: SentinelContext, action: Any) -> Any:
        name, value = self._parse_action(action)
        return self._invoke(context, name, value)

    async def aexecute_action(self, context: SentinelContext, action: Any) -> Any:
        name, value = self._parse_action(action)
        return await self._ainvoke(context, name, value)

    def function_map(self, context: SentinelContext) -> dict[str, Callable[..., Any]]:
        functions: dict[str, Callable[..., Any]] = {}
        for name in self.registry.names():
            def controlled(*args: Any, __name: str = name, **kwargs: Any) -> Any:
                return context.call_tool(__name, *args, **kwargs)
            controlled.__name__ = name
            controlled.__doc__ = self.registry.require(name).description
            functions[name] = controlled
        return functions
