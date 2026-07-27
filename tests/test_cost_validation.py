import pytest

from agent_roi import GuardrailViolation, Guardrails
from agent_roi.runtime.context import SentinelContext


@pytest.mark.parametrize("bad_cost", [-1.0, float("nan"), float("inf")])
def test_add_cost_rejects_invalid_values(bad_cost):
    context = SentinelContext(guardrails=Guardrails())
    with pytest.raises(GuardrailViolation):
        context.add_cost(bad_cost)
    assert context.state.cost_usd == 0.0


def test_limit_violation_does_not_mutate_state_or_execute_tool():
    context = SentinelContext(
        guardrails=Guardrails(
            max_tool_calls=1,
            max_cost_usd=0.01,
            allowed_tools=frozenset({"tool"}),
        )
    )
    calls = []

    def tool():
        calls.append("called")
        return "ok"

    assert context.call_tool("tool", tool, cost_usd=0.009) == "ok"
    with pytest.raises(GuardrailViolation):
        context.call_tool("tool", tool, cost_usd=0.005)

    assert calls == ["called"]
    assert context.state.tool_calls == 1
    assert context.state.cost_usd == pytest.approx(0.009)
