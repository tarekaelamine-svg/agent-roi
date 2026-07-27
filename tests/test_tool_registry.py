import pytest

from agent_roi import (
    DecisionOutcome,
    GuardrailViolation,
    Guardrails,
    SentinelRunner,
    ToolRegistry,
)


def test_registered_tool_executes_without_callable_from_agent():
    registry = ToolRegistry()
    registry.add("double", lambda value: value * 2)
    runner = SentinelRunner(
        guardrails=Guardrails(
            allowed_tools=frozenset({"double"}), require_registered_tools=True
        ),
        tool_registry=registry,
    )

    result = runner.run(lambda ctx, payload: ctx.call_tool("double", payload), 4)
    assert result.output == 8
    assert result.outcome is DecisionOutcome.HUMAN_REVIEW
    assert result.ctx_snapshot["state"]["tool_calls"] == 1


def test_registered_tool_rejects_callable_substitution():
    trusted = lambda: "safe"
    registry = ToolRegistry()
    registry.add("operation", trusted)
    runner = SentinelRunner(
        guardrails=Guardrails(
            allowed_tools=frozenset({"operation"}), require_registered_tools=True
        ),
        tool_registry=registry,
    )

    with pytest.raises(GuardrailViolation, match="does not match"):
        runner.run(
            lambda ctx, payload: ctx.call_tool("operation", lambda: "unsafe"), None
        )


def test_unregistered_tool_is_blocked_in_strict_mode():
    runner = SentinelRunner(
        guardrails=Guardrails(
            allowed_tools=frozenset({"missing"}), require_registered_tools=True
        ),
        tool_registry=ToolRegistry(),
    )
    with pytest.raises(GuardrailViolation, match="not registered"):
        runner.run(lambda ctx, payload: ctx.call_tool("missing", lambda: 1), None)


def test_approval_requirement_stops_before_execution():
    executed = []
    registry = ToolRegistry()
    registry.add(
        "delete_record",
        lambda record_id: executed.append(record_id),
        risk="high",
        requires_approval=True,
    )
    runner = SentinelRunner(
        guardrails=Guardrails(
            allowed_tools=frozenset({"delete_record"}), require_registered_tools=True
        ),
        tool_registry=registry,
    )

    result = runner.run(
        lambda ctx, payload: ctx.call_tool("delete_record", payload), "R-1"
    )
    assert result.outcome is DecisionOutcome.HUMAN_REVIEW
    assert executed == []
    assert result.ctx_snapshot["state"]["tool_calls"] == 0
    assert result.output["approval_checkpoint"]["tool_name"] == "delete_record"


def test_approval_callback_allows_execution():
    executed = []
    registry = ToolRegistry()
    registry.add(
        "delete_record",
        lambda record_id: executed.append(record_id) or "deleted",
        risk="high",
        requires_approval=True,
    )
    runner = SentinelRunner(
        guardrails=Guardrails(
            allowed_tools=frozenset({"delete_record"}), require_registered_tools=True
        ),
        tool_registry=registry,
        approval_callback=lambda spec, args, kwargs: spec.name == "delete_record",
    )

    result = runner.run(
        lambda ctx, payload: ctx.call_tool("delete_record", payload), "R-1"
    )
    assert result.output == "deleted"
    assert executed == ["R-1"]
