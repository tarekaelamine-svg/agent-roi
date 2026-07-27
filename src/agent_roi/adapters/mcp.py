from __future__ import annotations

import inspect
from typing import Any, Mapping

from agent_roi.runtime.context import SentinelContext
from agent_roi.runtime.tools import ToolRegistry, ToolSpec


class MCPAdapter:
    """Govern MCP client calls through the Agent-ROI tool registry."""

    def __init__(self, client: Any) -> None:
        if not hasattr(client, "call_tool"):
            raise TypeError("MCP client must provide call_tool(name, arguments)")
        self.client = client

    def register_tool(
        self,
        registry: ToolRegistry,
        name: str,
        *,
        remote_name: str = "",
        description: str = "",
        risk: str = "medium",
        requires_approval: bool = False,
        default_cost_usd: float = 0.0,
        version: str = "1",
        timeout_seconds: float | None = None,
    ) -> ToolSpec[Any]:
        target = remote_name or name
        client_call = self.client.call_tool
        if inspect.iscoroutinefunction(client_call):
            async def handler(arguments: Mapping[str, Any]) -> Any:
                return await client_call(target, dict(arguments))
        else:
            def handler(arguments: Mapping[str, Any]) -> Any:
                return client_call(target, dict(arguments))
        return registry.add(
            name,
            handler,
            description=description,
            risk=risk,
            requires_approval=requires_approval,
            default_cost_usd=default_cost_usd,
            version=version,
            timeout_seconds=timeout_seconds,
        )

    def execute(self, context: SentinelContext, name: str, arguments: Mapping[str, Any]) -> Any:
        return context.call_tool(name, dict(arguments))

    async def aexecute(
        self, context: SentinelContext, name: str, arguments: Mapping[str, Any]
    ) -> Any:
        return await context.acall_tool(name, dict(arguments))
