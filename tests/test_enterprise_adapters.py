from __future__ import annotations

import asyncio
import json
from unittest.mock import patch

import pytest

from agent_roi import Guardrails, SentinelRunner, ToolRegistry
from agent_roi.adapters import (
    ControlledHTTPAdapter,
    LangGraphAdapter,
    MCPAdapter,
    OpenAIAgentsAdapter,
    controlled_tool,
)


def test_controlled_tool_and_openai_adapter() -> None:
    registry = ToolRegistry()

    @controlled_tool(registry, description="Add values", version="1")
    def add(a: int, b: int) -> int:
        return a + b

    adapter = OpenAIAgentsAdapter(registry)
    definition = adapter.tool_definitions()[0]
    assert definition["function"]["name"] == "add"
    runner = SentinelRunner(
        guardrails=Guardrails(allowed_tools=frozenset({"add"}), require_registered_tools=True),
        tool_registry=registry,
    )
    result = runner.run(
        lambda ctx, _: adapter.execute(
            ctx,
            {"function": {"name": "add", "arguments": json.dumps({"a": 2, "b": 3})}},
        ),
        None,
    )
    assert result.output == 5


def test_langgraph_tool_node() -> None:
    registry = ToolRegistry()
    registry.add("multiply", lambda a, b: a * b)
    runner = SentinelRunner(
        guardrails=Guardrails(
            allowed_tools=frozenset({"multiply"}), require_registered_tools=True
        ),
        tool_registry=registry,
    )
    result = runner.run(
        lambda ctx, _: LangGraphAdapter(ctx).tool_node()(
            {"name": "multiply", "arguments": {"a": 4, "b": 5}}
        ),
        None,
    )
    assert result.output == {"result": 20}


def test_mcp_adapter_sync_and_async() -> None:
    class SyncClient:
        def call_tool(self, name, arguments):
            return {"name": name, **arguments}

    sync_registry = ToolRegistry()
    MCPAdapter(SyncClient()).register_tool(sync_registry, "remote")
    sync_runner = SentinelRunner(
        guardrails=Guardrails(allowed_tools=frozenset({"remote"}), require_registered_tools=True),
        tool_registry=sync_registry,
    )
    assert sync_runner.run(
        lambda ctx, _: ctx.call_tool("remote", {"x": 1}), None
    ).output["x"] == 1

    class AsyncClient:
        async def call_tool(self, name, arguments):
            return {"name": name, **arguments}

    async def execute():
        registry = ToolRegistry()
        MCPAdapter(AsyncClient()).register_tool(registry, "remote")
        runner = SentinelRunner(
            guardrails=Guardrails(
                allowed_tools=frozenset({"remote"}), require_registered_tools=True
            ),
            tool_registry=registry,
        )
        return await runner.arun(
            lambda ctx, _: ctx.acall_tool("remote", {"x": 2}), None
        )

    assert asyncio.run(execute()).output["x"] == 2


def test_controlled_http_adapter_enforces_host_method_and_size() -> None:
    adapter = ControlledHTTPAdapter(
        allowed_hosts={"api.example.com"},
        allowed_methods={"POST"},
        max_response_bytes=100,
    )
    with pytest.raises(ValueError, match="HTTPS"):
        adapter.request("http://api.example.com/x", method="POST")
    with pytest.raises(PermissionError, match="host"):
        adapter.request("https://evil.example/x", method="POST")
    with pytest.raises(PermissionError, match="method"):
        adapter.request("https://api.example.com/x", method="GET")

    class Response:
        status = 200
        headers = {"Content-Type": "application/json"}
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def read(self, size): return b'{"ok": true}'

    with patch("agent_roi.adapters.http.urlrequest.urlopen", return_value=Response()):
        response = adapter.request(
            "https://api.example.com/x", method="POST", json_body={"x": 1}
        )
    assert response["body"] == {"ok": True}


def _platform_runner():
    registry = ToolRegistry()
    registry.add("add", lambda a, b: int(a) + int(b), description="Add values")
    return registry, SentinelRunner(
        guardrails=Guardrails(
            allowed_tools=frozenset({"add"}), require_registered_tools=True
        ),
        tool_registry=registry,
    )


def test_langchain_autogen_and_azure_adapters() -> None:
    from agent_roi.adapters import AutoGenAdapter, AzureAIFoundryAdapter, LangChainAdapter

    registry, runner = _platform_runner()

    def agent(ctx, _):
        langchain = LangChainAdapter(registry)
        action_result = langchain.execute_action(
            ctx, {"tool": "add", "tool_input": {"a": 1, "b": 2}}
        )
        autogen_result = AutoGenAdapter(registry).function_map(ctx)["add"](a=3, b=4)
        azure_result = AzureAIFoundryAdapter(registry).execute(
            ctx, {"function": {"name": "add", "arguments": '{"a": 5, "b": 6}'}}
        )
        return action_result, autogen_result, azure_result

    assert runner.run(agent, None).output == (3, 7, 11)


def test_bedrock_vertex_semantic_kernel_and_generic_platform_adapters() -> None:
    from agent_roi.adapters import (
        BedrockAgentsAdapter,
        FunctionCallAdapter,
        SemanticKernelAdapter,
        VertexAIAdapter,
    )

    registry, runner = _platform_runner()

    def agent(ctx, _):
        bedrock = BedrockAgentsAdapter().execute(
            ctx,
            {
                "actionGroup": "math",
                "function": "add",
                "parameters": [
                    {"name": "a", "value": 2},
                    {"name": "b", "value": 8},
                ],
            },
        )
        vertex = VertexAIAdapter().execute(
            ctx, {"functionCall": {"name": "add", "args": {"a": 4, "b": 9}}}
        )
        semantic = SemanticKernelAdapter().execute(
            ctx, {"function_name": "add", "arguments": {"a": 10, "b": 1}}
        )
        generic = FunctionCallAdapter().execute(
            ctx, {"name": "add", "parameters": {"a": 7, "b": 7}}
        )
        return bedrock, vertex, semantic, generic

    output = runner.run(agent, None).output
    assert output[0]["response"]["functionResponse"]["responseBody"]["TEXT"]["body"] == "10"
    assert output[1] == {"name": "add", "response": {"result": 13}}
    assert output[2:] == (11, 14)


def test_databricks_mosaic_ai_message_adapter() -> None:
    from agent_roi.adapters import DatabricksMosaicAIAdapter

    registry, runner = _platform_runner()
    adapter = DatabricksMosaicAIAdapter(registry)
    result = runner.run(
        lambda ctx, _: adapter.execute_message(
            ctx,
            {
                "tool_calls": [
                    {
                        "id": "call-1",
                        "function": {
                            "name": "add",
                            "arguments": '{"a": 20, "b": 22}',
                        },
                    }
                ]
            },
        ),
        None,
    )
    assert result.output == [
        {"role": "tool", "tool_call_id": "call-1", "content": "42"}
    ]
