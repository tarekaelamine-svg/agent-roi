from __future__ import annotations

from typing import Any, Mapping

from agent_roi.runtime.context import SentinelContext


class VertexAIAdapter:
    """Duck-typed Google Vertex AI/Gemini function-call adapter."""

    @staticmethod
    def parse(function_call: Any) -> tuple[str, dict[str, Any]]:
        if isinstance(function_call, Mapping):
            call = function_call.get("functionCall", function_call.get("function_call", function_call))
            name = call.get("name")
            arguments = call.get("args", call.get("arguments", {}))
        else:
            name = getattr(function_call, "name", "")
            arguments = getattr(function_call, "args", {})
        if not isinstance(name, str) or not name.strip():
            raise ValueError("Vertex function call is missing a name")
        if not isinstance(arguments, Mapping):
            raise ValueError("Vertex function arguments must be a mapping")
        return name.strip(), dict(arguments)

    def execute(self, context: SentinelContext, function_call: Any) -> dict[str, Any]:
        name, arguments = self.parse(function_call)
        return {"name": name, "response": {"result": context.call_tool(name, **arguments)}}

    async def aexecute(self, context: SentinelContext, function_call: Any) -> dict[str, Any]:
        name, arguments = self.parse(function_call)
        return {"name": name, "response": {"result": await context.acall_tool(name, **arguments)}}
