from pathlib import Path

import pytest

from agent_roi import DecisionOutcome
from agent_roi.policies import PolicyValidationError, load_policy, validate_policy


def test_policy_root_must_be_mapping():
    with pytest.raises(PolicyValidationError, match="root must be"):
        validate_policy([])


def test_policy_rejects_nonfinite_cost():
    with pytest.raises(PolicyValidationError, match="must be finite"):
        validate_policy(
            {
                "guardrails": {
                    "max_steps": 1,
                    "max_tool_calls": 1,
                    "max_cost_usd": float("nan"),
                },
                "decision_policy": {"min_confidence": 0.8},
            }
        )


def test_loaded_policy_constructs_runtime_objects():
    policy = load_policy("finops_policy.yaml")
    assert policy.guardrails().require_registered_tools is True
    assert policy.decision_policy().abstain_action is DecisionOutcome.HUMAN_REVIEW


def test_invalid_abstain_action_in_yaml_is_rejected(tmp_path: Path):
    path = tmp_path / "bad.yaml"
    path.write_text(
        """
guardrails:
  max_steps: 1
  max_tool_calls: 1
  max_cost_usd: 1

decision_policy:
  min_confidence: 0.8
  abstain_action: explode
""",
        encoding="utf-8",
    )
    with pytest.raises(PolicyValidationError, match="must be one of"):
        load_policy("unused.yaml", override_path=path)
