from __future__ import annotations

import asyncio
import base64
from dataclasses import dataclass
from datetime import date, datetime, time
from decimal import Decimal
from enum import Enum
import io
import json
from pathlib import Path
from types import SimpleNamespace
from urllib import error as urlerror

import pytest

import agent_roi
from agent_roi._serialization import canonical_json, csv_safe, digest_value, markdown_escape, to_jsonable
from agent_roi.adapters import (
    BedrockAgentsAdapter,
    ControlledHTTPAdapter,
    DatabricksMosaicAIAdapter,
    FunctionCallAdapter,
    LangChainAdapter,
    LangGraphAdapter,
    MCPAdapter,
    OpenAIAgentsAdapter,
    SemanticKernelAdapter,
    VertexAIAdapter,
    bind_context,
    controlled_tool,
)
from agent_roi.audit.event import AuditEvent
from agent_roi.audit.redact import redact
from agent_roi.control.decision import ConfidenceInputs, DecisionOutcome, DecisionPolicy
from agent_roi.control.guardrails import GuardrailViolation, Guardrails
from agent_roi.runtime.tools import ToolRegistry


class FakeContext:
    def __init__(self):
        self.calls = []

    def call_tool(self, name, *args, **kwargs):
        self.calls.append((name, args, kwargs))
        return {"name": name, "args": args, "kwargs": kwargs}

    async def acall_tool(self, name, *args, **kwargs):
        self.calls.append((name, args, kwargs))
        return {"name": name, "args": args, "kwargs": kwargs}


class Color(Enum):
    RED = "red"


@dataclass
class Payload:
    count: int
    when: datetime


class BadRepr:
    def __repr__(self):
        raise RuntimeError("no repr")


class LongRepr:
    def __repr__(self):
        return "x" * 50


def test_serialization_all_supported_types_and_fallbacks(tmp_path: Path) -> None:
    value = {
        "none": None,
        "float": 1.5,
        "nan": float("nan"),
        "pos_inf": float("inf"),
        "neg_inf": float("-inf"),
        "decimal": Decimal("1.25"),
        "enum": Color.RED,
        "datetime": datetime(2026, 1, 2, 3, 4, 5),
        "date": date(2026, 1, 2),
        "time": time(3, 4, 5),
        "path": tmp_path / "x",
        "bytes": b"abc",
        "dataclass": Payload(2, datetime(2026, 1, 1)),
        "mapping": {2: "b", 1: "a"},
        "tuple": (1, 2),
        "set": {"b", "a"},
        "bad": BadRepr(),
        "long": LongRepr(),
    }
    converted = to_jsonable(value, max_repr=20)
    assert converted["nan"] == "nan"
    assert converted["pos_inf"] == "inf"
    assert converted["neg_inf"] == "-inf"
    assert converted["decimal"] == "1.25"
    assert converted["enum"] == "red"
    assert converted["bytes"]["base64"] == base64.b64encode(b"abc").decode()
    assert converted["bad"]["repr"] == "<unreprable>"
    assert converted["long"]["repr"].endswith("...")
    assert canonical_json({"b": 1, "a": 2}) == '{"a":2,"b":1}'
    assert len(digest_value(value)) == 64
    assert csv_safe(123) == 123
    assert csv_safe("  =SUM(A1:A2)").startswith("'")
    assert csv_safe("safe") == "safe"
    assert markdown_escape(" a|b`c\\d\r\ne ") == "a\\|b\\`c\\\\d  e"


def test_lazy_enterprise_exports_and_unknown_attribute() -> None:
    assert agent_roi.RetryPolicy.__name__ == "RetryPolicy"
    assert agent_roi.PostgresROILedger.__name__ == "PostgresROILedger"
    with pytest.raises(AttributeError):
        agent_roi.__getattr__("does_not_exist")


def test_guardrails_validation_and_limit_failures() -> None:
    invalid = [
        {"max_steps": True},
        {"max_steps": 0},
        {"max_tool_calls": True},
        {"max_tool_calls": -1},
        {"deterministic": 1},
        {"require_registered_tools": 1},
        {"require_bound_approval_grants": 1},
        {"max_cost_usd": float("inf")},
        {"max_cost_usd": -1},
        {"allowed_tools": "lookup"},
        {"allowed_tools": [""]},
        {"allowed_tools": [1]},
    ]
    for kwargs in invalid:
        with pytest.raises(ValueError):
            Guardrails(**kwargs)

    g = Guardrails(max_steps=1, max_tool_calls=1, max_cost_usd=1, allowed_tools=frozenset({"x"}))
    with pytest.raises(GuardrailViolation, match="numeric"):
        g.validate_cost_amount(object())
    with pytest.raises(GuardrailViolation, match="finite"):
        g.validate_cost_amount(float("nan"))
    with pytest.raises(GuardrailViolation, match="non-empty"):
        g.validate_tool_allowed("")
    with pytest.raises(GuardrailViolation, match="allowlisted"):
        g.validate_tool_allowed("y")
    with pytest.raises(GuardrailViolation, match="negative"):
        g.validate_limits(-1, 0, 0)
    with pytest.raises(GuardrailViolation, match="steps"):
        g.validate_limits(2, 0, 0)
    with pytest.raises(GuardrailViolation, match="tool calls"):
        g.validate_limits(1, 2, 0)
    with pytest.raises(GuardrailViolation, match="cost"):
        g.validate_limits(1, 1, 2)


def test_decision_policy_all_validation_and_scoring_branches() -> None:
    for kwargs in [
        {"min_confidence": "x"},
        {"min_confidence": 2},
        {"abstain_action": "bad"},
        {"w_prob": "x"},
        {"w_prob": float("inf")},
        {"w_prob": -1},
        {"w_prob": 0, "w_margin": 0, "w_z": 0, "w_entropy": 0, "w_llm": 0},
    ]:
        with pytest.raises(ValueError):
            DecisionPolicy(**kwargs)
    p = DecisionPolicy(min_confidence=0.4, abstain_action="retry")
    assert p._stable_sigmoid(-1000) == pytest.approx(0.0)
    score = p.score(ConfidenceInputs(prob=2, margin=-1, z_score=-2, entropy=10, llm_self_score=2))
    assert 0 <= score <= 1
    assert p.decide(ConfidenceInputs(prob=1, margin=1, z_score=10, entropy=0, llm_self_score=1)) is DecisionOutcome.ACCEPT
    assert DecisionPolicy(min_confidence=1).decide(ConfidenceInputs()) is DecisionOutcome.HUMAN_REVIEW
    for field in ["prob", "margin", "z_score", "entropy", "llm_self_score"]:
        with pytest.raises(ValueError):
            p.score(ConfidenceInputs(**{field: float("nan")}))


def test_redaction_and_audit_event_non_mapping_payload(monkeypatch) -> None:
    assert redact({"TOKEN": "x", "items": [{"password": "y"}], "tuple": ({"ssn": "z"},), "set": {2, 1}}) == {
        "TOKEN": "[REDACTED]",
        "items": [{"password": "[REDACTED]"}],
        "tuple": ({"ssn": "[REDACTED]"},),
        "set": [1, 2],
    }
    monkeypatch.setattr("agent_roi.audit.event.to_jsonable", lambda value: [1, 2])
    event = AuditEvent.create("c", "r", "x", {"a": 1}, None, True)
    assert event.payload == {"value": [1, 2]}
    assert event.hash and len(event.hash) == 64
    unchained = AuditEvent.create("c", "r", "x", {}, None, False)
    assert unchained.hash is None
    assert unchained.to_dict()["event_type"] == "x"


def test_adapter_parse_error_paths_and_sync_execution() -> None:
    ctx = FakeContext()
    with pytest.raises(ValueError):
        BedrockAgentsAdapter.parse({})
    assert BedrockAgentsAdapter.parse({"function": "x", "parameters": {"a": 1}}) == ("x", {"a": 1})
    with pytest.raises(ValueError):
        BedrockAgentsAdapter.parse({"function": "x", "parameters": [{}]})
    with pytest.raises(ValueError):
        BedrockAgentsAdapter.parse({"function": "x", "parameters": "bad"})

    with pytest.raises(ValueError):
        FunctionCallAdapter().parse({})
    with pytest.raises(ValueError):
        FunctionCallAdapter().parse({"name": "x", "arguments": []})
    assert FunctionCallAdapter().execute(ctx, {"function": "x", "input": {"a": 1}})["kwargs"] == {"a": 1}

    with pytest.raises(ValueError):
        LangChainAdapter._parse_action({})
    action = SimpleNamespace(tool="x", tool_input=7)
    assert LangChainAdapter._parse_action(action) == ("x", 7)
    assert LangChainAdapter._invoke(ctx, "x", 7)["args"] == (7,)

    with pytest.raises(ValueError):
        LangGraphAdapter(ctx).tool_node()({"name": "x", "arguments": []})

    with pytest.raises(TypeError):
        MCPAdapter(object())

    with pytest.raises(ValueError):
        OpenAIAgentsAdapter._parse_call({})
    with pytest.raises(ValueError, match="valid JSON"):
        OpenAIAgentsAdapter._parse_call({"name": "x", "arguments": "{"})
    with pytest.raises(ValueError, match="object"):
        OpenAIAgentsAdapter._parse_call({"name": "x", "arguments": []})
    obj_call = SimpleNamespace(function=SimpleNamespace(name="x", arguments='{"a": 1}'))
    assert OpenAIAgentsAdapter._parse_call(obj_call) == ("x", {"a": 1})

    with pytest.raises(ValueError):
        SemanticKernelAdapter.parse({})
    with pytest.raises(ValueError, match="mapping-compatible"):
        SemanticKernelAdapter.parse({"name": "x", "arguments": object()})
    invocation = SimpleNamespace(plugin_name="p", function_name="f", arguments={"a": 1})
    assert SemanticKernelAdapter.parse(invocation) == ("p.f", {"a": 1})

    with pytest.raises(ValueError):
        VertexAIAdapter.parse({})
    with pytest.raises(ValueError, match="mapping"):
        VertexAIAdapter.parse({"name": "x", "args": []})
    assert VertexAIAdapter.parse(SimpleNamespace(name="x", args={"a": 1})) == ("x", {"a": 1})


def test_async_adapter_paths() -> None:
    async def run():
        ctx = FakeContext()
        assert (await BedrockAgentsAdapter().aexecute(ctx, {"function": "x", "parameters": {"a": 1}}))["response"]
        assert (await FunctionCallAdapter().aexecute(ctx, {"name": "x", "args": {"a": 1}}))["kwargs"] == {"a": 1}
        langchain = LangChainAdapter(ToolRegistry())
        assert (await langchain.aexecute_action(ctx, {"tool": "x", "tool_input": {"a": 1}}))["kwargs"] == {"a": 1}
        assert (await langchain.aexecute_action(ctx, {"tool": "x", "tool_input": 3}))["args"] == (3,)
        node = LangGraphAdapter(ctx).async_tool_node(result_field="out")
        assert (await node({"name": "x", "arguments": {"a": 1}}))["out"]["kwargs"] == {"a": 1}
        with pytest.raises(ValueError):
            await LangGraphAdapter(ctx).async_tool_node()({"name": "x", "arguments": []})
        assert (await OpenAIAgentsAdapter(ToolRegistry()).aexecute(ctx, {"name": "x", "arguments": {"a": 1}}))["kwargs"] == {"a": 1}
        assert (await SemanticKernelAdapter().aexecute(ctx, {"name": "x", "arguments": {"a": 1}}))["kwargs"] == {"a": 1}
        assert (await VertexAIAdapter().aexecute(ctx, {"name": "x", "args": {"a": 1}}))["response"]["result"]["kwargs"] == {"a": 1}
        db = DatabricksMosaicAIAdapter(ToolRegistry())
        message = {"tool_calls": [SimpleNamespace(id="c1", function=SimpleNamespace(name="x", arguments='{"a": 1}'))]}
        assert (await db.aexecute_message(ctx, message))[0]["tool_call_id"] == "c1"

        class AsyncClient:
            async def call_tool(self, name, arguments):
                return name, arguments
        registry = ToolRegistry()
        mcp = MCPAdapter(AsyncClient())
        mcp.register_tool(registry, "local", remote_name="remote")
        spec = registry.require("local")
        assert await spec.handler({"a": 1}) == ("remote", {"a": 1})
        assert (await mcp.aexecute(ctx, "local", {"a": 2}))["args"] == ({"a": 2},)

    asyncio.run(run())


def test_registry_definitions_function_map_and_bound_executor() -> None:
    registry = ToolRegistry()

    @controlled_tool(registry, name="typed", description="typed")
    def typed(a: int, b: float, c: bool, d: list, e: dict, optional: str = "x", *args, **kwargs):
        return a

    assert typed.__agent_roi_tool_name__ == "typed"
    definition = OpenAIAgentsAdapter(registry).tool_definitions()[0]["function"]["parameters"]
    assert definition["properties"]["a"]["type"] == "integer"
    assert definition["properties"]["b"]["type"] == "number"
    assert definition["properties"]["c"]["type"] == "boolean"
    assert definition["properties"]["d"]["type"] == "array"
    assert definition["properties"]["e"]["type"] == "object"
    assert "optional" not in definition["required"]
    ctx = FakeContext()
    fm = LangChainAdapter(registry).function_map(ctx)
    assert fm["typed"].__name__ == "typed"
    fm["typed"](1, b=2)
    executor = bind_context(ctx)
    executor.invoke("typed", 1, cost_usd=0.2)
    asyncio.run(executor.ainvoke("typed", 1, cost_usd=0.3))
    assert len(ctx.calls) == 3


def test_controlled_http_remaining_paths(monkeypatch) -> None:
    with pytest.raises(ValueError, match="cannot be empty"):
        ControlledHTTPAdapter(allowed_hosts=[])
    adapter = ControlledHTTPAdapter(allowed_hosts={"api.example.com"}, max_request_bytes=2, max_response_bytes=3)
    with pytest.raises(ValueError, match="request body"):
        adapter.request("https://api.example.com", method="POST", json_body={"x": 1})

    class TextResponse:
        status = 201
        headers = {"Content-Type": "text/plain", "X": "y"}
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def read(self, size): return b"abc"
    monkeypatch.setattr("agent_roi.adapters.http.urlrequest.urlopen", lambda *a, **k: TextResponse())
    result = ControlledHTTPAdapter(allowed_hosts={"api.example.com"}, max_response_bytes=3).request("https://api.example.com")
    assert result == {"status": 201, "headers": {"Content-Type": "text/plain", "X": "y"}, "body": "abc"}

    class LargeResponse(TextResponse):
        def read(self, size): return b"abcd"
    monkeypatch.setattr("agent_roi.adapters.http.urlrequest.urlopen", lambda *a, **k: LargeResponse())
    with pytest.raises(ValueError, match="response"):
        adapter.request("https://api.example.com")

    exc = urlerror.HTTPError("https://api.example.com", 500, "bad", {}, io.BytesIO(b"failure"))
    monkeypatch.setattr("agent_roi.adapters.http.urlrequest.urlopen", lambda *a, **k: (_ for _ in ()).throw(exc))
    with pytest.raises(RuntimeError, match="HTTP 500"):
        ControlledHTTPAdapter(allowed_hosts={"api.example.com"}).request("https://api.example.com")

    registry = ToolRegistry()
    spec = adapter.register(registry, name="request", requires_approval=True, default_cost_usd=1)
    assert spec.name == "request" and spec.requires_approval
