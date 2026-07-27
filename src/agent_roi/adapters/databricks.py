from __future__ import annotations

from typing import Any, Mapping

from agent_roi.runtime.context import SentinelContext
from .openai import OpenAIAgentsAdapter


class DatabricksMosaicAIAdapter(OpenAIAgentsAdapter):
    """Adapter for Mosaic AI/OpenAI-compatible tool calls and agent messages."""

    def execute_message(self, context: SentinelContext, message: Mapping[str, Any]) -> list[dict[str, Any]]:
        responses: list[dict[str, Any]] = []
        for call in message.get("tool_calls", []):
            result = self.execute(context, call)
            call_id = call.get("id", "") if isinstance(call, Mapping) else getattr(call, "id", "")
            responses.append({"role": "tool", "tool_call_id": str(call_id), "content": str(result)})
        return responses

    async def aexecute_message(self, context: SentinelContext, message: Mapping[str, Any]) -> list[dict[str, Any]]:
        responses: list[dict[str, Any]] = []
        for call in message.get("tool_calls", []):
            result = await self.aexecute(context, call)
            call_id = call.get("id", "") if isinstance(call, Mapping) else getattr(call, "id", "")
            responses.append({"role": "tool", "tool_call_id": str(call_id), "content": str(result)})
        return responses
