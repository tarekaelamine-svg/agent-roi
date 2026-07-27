import pytest

from agent_roi.policies.validate import validate_policy, PolicyValidationError


def test_validate_policy_requires_keys():
    with pytest.raises(PolicyValidationError) as e:
        validate_policy({"guardrails": {}, "decision_policy": {}})
    msg = str(e.value)
    assert "max_steps is required" in msg
    assert "min_confidence is required" in msg


def test_validate_policy_rejects_bad_types():
    bad = {
        "guardrails": {"max_steps": "oops", "max_tool_calls": 5, "max_cost_usd": 0.1},
        "decision_policy": {"min_confidence": 0.8},
    }
    with pytest.raises(PolicyValidationError):
        validate_policy(bad)
