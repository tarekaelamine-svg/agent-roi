from __future__ import annotations

import inspect
import json
from typing import Any, Mapping, get_type_hints

from agent_roi.runtime.context import SentinelContext
from agent_roi.runtime.tools import ToolRegistry, ToolSpec


def _json_type(annotation: Any) -> str:
    if annotation in {int}:
        return "integer"
    if annotation in {float}:
        return "number"
    if annotation in {bool}:
        return "boolean"
    if annotation in {list, tuple, set, frozenset}:
        return "array"
    if annotation in {dict, Mapping}:
        return "object"
    return "string"


class OpenAIAgentsAdapter:
    """Duck-typed adapter for OpenAI function-tool payloads.

    It does not import an OpenAI SDK. Tool definitions and tool-call objects are
    ordinary dictionaries, making the adapter compatible across SDK versions.
    """

    def __init__(self, registry: ToolRegistry) -> None:
        self.registry = registry

    def tool_definitions(self) -> list[dict[str, Any]]:
        definitions: list[dict[str, Any]] = []
        for name in sorted(self.registry.names()):
            spec = self.registry.require(name)
            signature = inspect.signature(spec.handler)
            try:
                type_hints = get_type_hints(spec.handler)
            except Exception:
                type_hints = {}
            properties: dict[str, Any] = {}
            required: list[str] = []
            for parameter in signature.parameters.values():
                if parameter.kind in {
                    inspect.Parameter.VAR_POSITIONAL,
                    inspect.Parameter.VAR_KEYWORD,
                }:
                    continue
                properties[parameter.name] = {
                    "type": _json_type(type_hints.get(parameter.name, parameter.annotation)),
                }
                if parameter.default is inspect.Parameter.empty:
                    required.append(parameter.name)
            definitions.append(
                {
                    "type": "function",
                    "function": {
                        "name": spec.name,
                        "description": spec.description,
                        "parameters": {
                            "type": "object",
                            "properties": properties,
                            "required": required,
                            "additionalProperties": False,
                        },
                    },
                }
            )
        return definitions

    @staticmethod
    def _parse_call(tool_call: Any) -> tuple[str, dict[str, Any]]:
        if isinstance(tool_call, Mapping):
            function = tool_call.get("function", tool_call)
            name = function.get("name")
            arguments = function.get("arguments", {})
        else:
            function = getattr(tool_call, "function", tool_call)
            name = getattr(function, "name", None)
            arguments = getattr(function, "arguments", {})
        if not isinstance(name, str) or not name.strip():
            raise ValueError("OpenAI tool call is missing function.name")
        if isinstance(arguments, str):
            try:
                arguments = json.loads(arguments or "{}")
            except json.JSONDecodeError as exc:
                raise ValueError("OpenAI tool arguments are not valid JSON") from exc
        if not isinstance(arguments, Mapping):
            raise ValueError("OpenAI tool arguments must be an object")
        return name, dict(arguments)

    def execute(self, context: SentinelContext, tool_call: Any) -> Any:
        name, arguments = self._parse_call(tool_call)
        return context.call_tool(name, **arguments)

    async def aexecute(self, context: SentinelContext, tool_call: Any) -> Any:
        name, arguments = self._parse_call(tool_call)
        return await context.acall_tool(name, **arguments)
