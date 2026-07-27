from __future__ import annotations

from typing import Any, Mapping

from agent_roi.runtime.context import SentinelContext


class BedrockAgentsAdapter:
    """Adapter for Amazon Bedrock Agents action-group invocation payloads."""

    @staticmethod
    def parse(event: Mapping[str, Any]) -> tuple[str, dict[str, Any]]:
        name = str(event.get("function") or event.get("apiPath") or "").strip()
        if not name:
            raise ValueError("Bedrock invocation is missing function or apiPath")
        parameters = event.get("parameters", [])
        arguments: dict[str, Any] = {}
        if isinstance(parameters, Mapping):
            arguments = dict(parameters)
        elif isinstance(parameters, list):
            for parameter in parameters:
                if not isinstance(parameter, Mapping) or not parameter.get("name"):
                    raise ValueError("Bedrock parameters must contain name/value mappings")
                arguments[str(parameter["name"])] = parameter.get("value")
        else:
            raise ValueError("Bedrock parameters must be a list or mapping")
        return name, arguments

    def execute(self, context: SentinelContext, event: Mapping[str, Any]) -> dict[str, Any]:
        name, arguments = self.parse(event)
        result = context.call_tool(name, **arguments)
        return self.response(event, result)

    async def aexecute(self, context: SentinelContext, event: Mapping[str, Any]) -> dict[str, Any]:
        name, arguments = self.parse(event)
        result = await context.acall_tool(name, **arguments)
        return self.response(event, result)

    @staticmethod
    def response(event: Mapping[str, Any], result: Any) -> dict[str, Any]:
        return {
            "messageVersion": str(event.get("messageVersion", "1.0")),
            "response": {
                "actionGroup": event.get("actionGroup", ""),
                "function": event.get("function", event.get("apiPath", "")),
                "functionResponse": {"responseBody": {"TEXT": {"body": str(result)}}},
            },
            "sessionAttributes": dict(event.get("sessionAttributes", {})),
            "promptSessionAttributes": dict(event.get("promptSessionAttributes", {})),
        }
