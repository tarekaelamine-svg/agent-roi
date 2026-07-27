from __future__ import annotations

from typing import Any, Mapping

from agent_roi.runtime.context import SentinelContext


class SemanticKernelAdapter:
    """Adapter for Semantic Kernel function invocation contexts."""

    @staticmethod
    def parse(invocation: Any) -> tuple[str, dict[str, Any]]:
        if isinstance(invocation, Mapping):
            plugin = str(invocation.get("plugin_name", invocation.get("pluginName", ""))).strip()
            function = str(invocation.get("function_name", invocation.get("functionName", invocation.get("name", "")))).strip()
            arguments = invocation.get("arguments", {})
        else:
            plugin = str(getattr(invocation, "plugin_name", "")).strip()
            function = str(getattr(invocation, "function_name", getattr(invocation, "name", ""))).strip()
            arguments = getattr(invocation, "arguments", {})
        if not function:
            raise ValueError("Semantic Kernel invocation is missing a function name")
        if not isinstance(arguments, Mapping):
            try:
                arguments = dict(arguments)
            except Exception as exc:
                raise ValueError("Semantic Kernel arguments must be mapping-compatible") from exc
        return f"{plugin}.{function}" if plugin else function, dict(arguments)

    def execute(self, context: SentinelContext, invocation: Any) -> Any:
        name, arguments = self.parse(invocation)
        return context.call_tool(name, **arguments)

    async def aexecute(self, context: SentinelContext, invocation: Any) -> Any:
        name, arguments = self.parse(invocation)
        return await context.acall_tool(name, **arguments)
