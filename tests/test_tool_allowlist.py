import pytest
from agent_roi.runtime.context import SentinelContext
from agent_roi.control.guardrails import Guardrails, GuardrailViolation

def test_ctx_call_tool_respects_allowlist():
    ctx = SentinelContext(guardrails=Guardrails(allowed_tools={"ok_tool"}))

    def tool():
        return "x"

    assert ctx.call_tool("ok_tool", tool) == "x"
    with pytest.raises(GuardrailViolation):
        ctx.call_tool("bad_tool", tool)
