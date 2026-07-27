import pytest

from agent_roi.runtime.context import SentinelContext
from agent_roi.control.guardrails import Guardrails, GuardrailViolation


def test_tool_allowlist_blocks_unknown_tool():
    ctx = SentinelContext(guardrails=Guardrails(allowed_tools={"ok"}))

    def dummy():
        return "x"

    # allowed tool passes
    assert ctx.call_tool("ok", dummy) == "x"

    # unknown tool blocked
    with pytest.raises(GuardrailViolation):
        ctx.call_tool("nope", dummy)


def test_max_cost_usd_enforced():
    ctx = SentinelContext(guardrails=Guardrails(max_cost_usd=0.01, allowed_tools={"t"}))

    def dummy():
        return "x"

    # First call consumes 0.009 => OK
    ctx.call_tool("t", dummy, cost_usd=0.009)

    # Next call consumes 0.005 => exceeds 0.01 => violation
    with pytest.raises(GuardrailViolation):
        ctx.call_tool("t", dummy, cost_usd=0.005)


def test_max_tool_calls_enforced():
    ctx = SentinelContext(guardrails=Guardrails(max_tool_calls=1, allowed_tools={"t"}))

    def dummy():
        return "x"

    ctx.call_tool("t", dummy)  # tool_calls = 1, OK

    with pytest.raises(GuardrailViolation):
        ctx.call_tool("t", dummy)  # tool_calls = 2, should violate


def test_max_steps_enforced():
    ctx = SentinelContext(guardrails=Guardrails(max_steps=1))

    ctx.bump_step()  # steps = 1, OK
    with pytest.raises(GuardrailViolation):
        ctx.bump_step()  # steps = 2, should violate
