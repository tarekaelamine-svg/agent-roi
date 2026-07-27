from __future__ import annotations

from typing import Any, Mapping

from agent_roi.runtime.context import SentinelContext


class FunctionCallAdapter:
    """Generic function-call adapter for platform SDKs with name/arguments payloads."""

    name_keys = ("name", "function")
    argument_keys = ("arguments", "args", "parameters", "input")

    def parse(self, call: Mapping[str, Any]) -> tuple[str, dict[str, Any]]:
        name = next((str(call[key]).strip() for key in self.name_keys if call.get(key)), "")
        if not name:
            raise ValueError("Function call is missing a name")
        value: Any = {}
        for key in self.argument_keys:
            if key in call:
                value = call[key]
                break
        if not isinstance(value, Mapping):
            raise ValueError("Function-call arguments must be a mapping")
        return name, dict(value)

    def execute(self, context: SentinelContext, call: Mapping[str, Any]) -> Any:
        name, arguments = self.parse(call)
        return context.call_tool(name, **arguments)

    async def aexecute(self, context: SentinelContext, call: Mapping[str, Any]) -> Any:
        name, arguments = self.parse(call)
        return await context.acall_tool(name, **arguments)
