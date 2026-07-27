from __future__ import annotations

import pytest

from agent_roi import ConfidenceInputs, GuardrailViolation, Guardrails, SentinelRunner, ToolRegistry
from agent_roi.enterprise.identity import Principal, RBACAuthorizer, RoleDefinition
from agent_roi.enterprise.telemetry import InMemoryEventSink


def _registry() -> ToolRegistry:
    registry = ToolRegistry()
    registry.add("lookup_invoice", lambda invoice_id: {"invoice_id": invoice_id}, version="1")
    return registry


def test_runner_enforces_rbac_before_tool_execution() -> None:
    called = []
    registry = ToolRegistry()
    registry.add("delete_invoice", lambda invoice_id: called.append(invoice_id), risk="high")
    principal = Principal("user-1", "acme", roles=frozenset({"reader"}))
    authorizer = RBACAuthorizer(
        [RoleDefinition("reader", frozenset({"tool.execute:lookup_*"}))]
    )
    runner = SentinelRunner(
        guardrails=Guardrails(
            allowed_tools=frozenset({"delete_invoice"}), require_registered_tools=True
        ),
        tool_registry=registry,
        principal=principal,
        authorizer=authorizer,
        organization_id="acme",
        environment="prod",
        agent_id="invoice-agent",
    )
    with pytest.raises(GuardrailViolation, match="not authorized"):
        runner.run(lambda ctx, _: ctx.call_tool("delete_invoice", "INV-1"), None)
    assert called == []


def test_runner_emits_cloudevents_with_enterprise_context() -> None:
    sink = InMemoryEventSink()
    principal = Principal("user-1", "acme", roles=frozenset({"owner"}))
    authorizer = RBACAuthorizer(
        [RoleDefinition("owner", frozenset({"tool.execute:*"}))]
    )
    runner = SentinelRunner(
        guardrails=Guardrails(
            allowed_tools=frozenset({"lookup_invoice"}), require_registered_tools=True
        ),
        tool_registry=_registry(),
        principal=principal,
        authorizer=authorizer,
        organization_id="acme",
        environment="prod",
        agent_id="invoice-agent",
        event_sinks=[sink],
    )
    result = runner.run(
        lambda ctx, _: (
            ctx.call_tool("lookup_invoice", "INV-1"),
            ConfidenceInputs(prob=1, margin=1, z_score=5, entropy=0, llm_self_score=1),
        ),
        None,
    )
    assert result.output["invoice_id"] == "INV-1"
    assert any(event.type == "com.agentroi.authorization.decision" for event in sink.events)
    completed = [event for event in sink.events if event.type == "com.agentroi.run.completed"][-1]
    assert completed.data["organization_id"] == "acme"
    assert completed.data["agent_id"] == "invoice-agent"


def test_event_sink_can_be_fail_open_or_fail_closed() -> None:
    class Broken:
        def emit(self, event):
            raise RuntimeError("siem unavailable")

    open_runner = SentinelRunner(event_sinks=[Broken()])
    assert open_runner.run(lambda ctx, _: "ok", None).output == "ok"
    assert open_runner.event_sink_errors

    closed_runner = SentinelRunner(event_sinks=[Broken()], fail_on_event_sink_error=True)
    with pytest.raises(RuntimeError, match="siem unavailable"):
        closed_runner.run(lambda ctx, _: "ok", None)
