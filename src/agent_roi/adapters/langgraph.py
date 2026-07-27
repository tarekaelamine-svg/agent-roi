from __future__ import annotations

from typing import Any, Awaitable, Callable, Mapping

from agent_roi.runtime.context import SentinelContext


class LangGraphAdapter:
    """Runtime-bound tool node functions for LangGraph-style state graphs."""

    def __init__(self, context: SentinelContext) -> None:
        self.context = context

    def tool_node(
        self,
        *,
        name_field: str = "name",
        arguments_field: str = "arguments",
        result_field: str = "result",
    ) -> Callable[[Mapping[str, Any]], dict[str, Any]]:
        def node(state: Mapping[str, Any]) -> dict[str, Any]:
            name = str(state.get(name_field, ""))
            arguments = state.get(arguments_field, {})
            if not isinstance(arguments, Mapping):
                raise ValueError("LangGraph tool arguments must be a mapping")
            return {result_field: self.context.call_tool(name, **dict(arguments))}

        return node

    def async_tool_node(
        self,
        *,
        name_field: str = "name",
        arguments_field: str = "arguments",
        result_field: str = "result",
    ) -> Callable[[Mapping[str, Any]], Awaitable[dict[str, Any]]]:
        async def node(state: Mapping[str, Any]) -> dict[str, Any]:
            name = str(state.get(name_field, ""))
            arguments = state.get(arguments_field, {})
            if not isinstance(arguments, Mapping):
                raise ValueError("LangGraph tool arguments must be a mapping")
            return {result_field: await self.context.acall_tool(name, **dict(arguments))}

        return node
