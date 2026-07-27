import math
import pytest

from agent_roi import ConfidenceInputs, DecisionOutcome, DecisionPolicy


def test_missing_signals_reduce_confidence():
    policy = DecisionPolicy()
    assert policy.score(ConfidenceInputs(llm_self_score=0.8)) < 0.1


def test_extreme_negative_z_score_is_stable():
    policy = DecisionPolicy()
    score = policy.score(ConfidenceInputs(z_score=-1000))
    assert math.isfinite(score)
    assert score == 0.0


def test_abstain_action_string_is_converted_to_enum():
    policy = DecisionPolicy(abstain_action="retry")
    assert policy.abstain_action is DecisionOutcome.RETRY
    assert policy.decide(ConfidenceInputs()) is DecisionOutcome.RETRY


def test_invalid_abstain_action_is_rejected():
    with pytest.raises(ValueError, match="abstain_action"):
        DecisionPolicy(abstain_action="not-a-real-action")


def test_nonfinite_confidence_input_is_rejected():
    with pytest.raises(ValueError, match="prob must be finite"):
        DecisionPolicy().score(ConfidenceInputs(prob=float("nan")))
