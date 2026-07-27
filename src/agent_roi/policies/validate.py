from __future__ import annotations

import math
from typing import Any, Dict, List

from agent_roi.control.decision import DecisionOutcome


class PolicyValidationError(ValueError):
    pass


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _is_finite_number(value: Any) -> bool:
    return _is_number(value) and math.isfinite(float(value))


def _require_mapping(data: Dict[str, Any], key: str, errors: List[str], *, required: bool = True) -> Dict[str, Any]:
    if key not in data and not required:
        return {}
    value = data.get(key)
    if not isinstance(value, dict):
        errors.append(f"policy.{key} must be a mapping/object")
        return {}
    return value


def _require_number(
    obj: Dict[str, Any],
    path: str,
    key: str,
    errors: List[str],
    *,
    min_value: float | None = None,
    max_value: float | None = None,
    required: bool = False,
) -> None:
    if key not in obj:
        if required:
            errors.append(f"{path}.{key} is required")
        return
    value = obj.get(key)
    if not _is_number(value):
        errors.append(f"{path}.{key} must be a number")
        return
    if not math.isfinite(float(value)):
        errors.append(f"{path}.{key} must be finite")
        return
    number = float(value)
    if min_value is not None and number < min_value:
        errors.append(f"{path}.{key} must be >= {min_value}")
    if max_value is not None and number > max_value:
        errors.append(f"{path}.{key} must be <= {max_value}")


def _require_int_like(
    obj: Dict[str, Any],
    path: str,
    key: str,
    errors: List[str],
    *,
    min_value: int | None = None,
    required: bool = False,
) -> None:
    if key not in obj:
        if required:
            errors.append(f"{path}.{key} is required")
        return
    value = obj.get(key)
    if not _is_finite_number(value) or float(value) != int(float(value)):
        errors.append(f"{path}.{key} must be an integer")
        return
    integer = int(value)
    if min_value is not None and integer < min_value:
        errors.append(f"{path}.{key} must be >= {min_value}")


def _validate_allowed_tools(guardrails: Dict[str, Any], errors: List[str]) -> None:
    allowed = guardrails.get("allowed_tools")
    if allowed is None:
        return
    if not isinstance(allowed, (list, set, tuple, frozenset)):
        errors.append("policy.guardrails.allowed_tools must be a list or set of strings")
        return
    if any(not isinstance(item, str) or not item.strip() for item in allowed):
        errors.append("policy.guardrails.allowed_tools must contain only non-empty strings")


def _validate_decision_weights(policy: Dict[str, Any], errors: List[str]) -> None:
    total = 0.0
    present = False
    for key in ("w_prob", "w_margin", "w_z", "w_entropy", "w_llm"):
        if key not in policy:
            continue
        present = True
        value = policy[key]
        if not _is_number(value):
            errors.append(f"policy.decision_policy.{key} must be a number")
            continue
        if not math.isfinite(float(value)):
            errors.append(f"policy.decision_policy.{key} must be finite")
            continue
        if float(value) < 0:
            errors.append(f"policy.decision_policy.{key} must be >= 0")
            continue
        total += float(value)
    if present and total == 0:
        errors.append("policy.decision_policy confidence weights cannot all be zero")


def _validate_nested_numeric_mapping(
    parent: Dict[str, Any], path: str, errors: List[str]
) -> None:
    for section_name, section in parent.items():
        section_path = f"{path}.{section_name}"
        if not isinstance(section, dict):
            errors.append(f"{section_path} must be a mapping/object")
            continue
        for key, value in section.items():
            item_path = f"{section_path}.{key}"
            if key == "always_flag":
                if not isinstance(value, bool):
                    errors.append(f"{item_path} must be a boolean")
                continue
            if isinstance(value, bool):
                errors.append(f"{item_path} must be a finite number")
            elif not _is_finite_number(value):
                errors.append(f"{item_path} must be a finite number")
            elif float(value) < 0:
                errors.append(f"{item_path} must be >= 0")


def validate_policy(data: Any) -> None:
    errors: List[str] = []
    if not isinstance(data, dict):
        raise PolicyValidationError("Invalid policy:\n- policy root must be a mapping/object")

    if "policy_name" in data and (
        not isinstance(data["policy_name"], str) or not data["policy_name"].strip()
    ):
        errors.append("policy.policy_name must be a non-empty string")

    guardrails = _require_mapping(data, "guardrails", errors)
    _require_int_like(guardrails, "policy.guardrails", "max_steps", errors, min_value=1, required=True)
    _require_int_like(guardrails, "policy.guardrails", "max_tool_calls", errors, min_value=0, required=True)
    _require_number(guardrails, "policy.guardrails", "max_cost_usd", errors, min_value=0.0, required=True)
    for key in (
        "deterministic",
        "require_registered_tools",
        "require_bound_approval_grants",
    ):
        if key in guardrails and not isinstance(guardrails[key], bool):
            errors.append(f"policy.guardrails.{key} must be a boolean")
    _validate_allowed_tools(guardrails, errors)

    decision_policy = _require_mapping(data, "decision_policy", errors)
    _require_number(
        decision_policy,
        "policy.decision_policy",
        "min_confidence",
        errors,
        min_value=0.0,
        max_value=1.0,
        required=True,
    )
    if "abstain_action" in decision_policy:
        action = decision_policy["abstain_action"]
        if not isinstance(action, str):
            errors.append("policy.decision_policy.abstain_action must be a string")
        else:
            try:
                DecisionOutcome(action)
            except ValueError:
                allowed = ", ".join(outcome.value for outcome in DecisionOutcome)
                errors.append(
                    f"policy.decision_policy.abstain_action must be one of: {allowed}"
                )
    _validate_decision_weights(decision_policy, errors)

    thresholds = _require_mapping(data, "thresholds", errors, required=False)
    if thresholds:
        _validate_nested_numeric_mapping(thresholds, "policy.thresholds", errors)

    scoring = _require_mapping(data, "scoring", errors, required=False)
    if scoring:
        multipliers = scoring.get("savings_multipliers", {})
        if not isinstance(multipliers, dict):
            errors.append("policy.scoring.savings_multipliers must be a mapping/object")
        else:
            for name, value in multipliers.items():
                path = f"policy.scoring.savings_multipliers.{name}"
                if not _is_finite_number(value):
                    errors.append(f"{path} must be a finite number")
                elif not 0.0 <= float(value) <= 1.0:
                    errors.append(f"{path} must be between 0 and 1")

    routing = _require_mapping(data, "approval_routing", errors, required=False)
    if routing:
        allowed_risks = {"low", "med", "medium", "high"}
        for key in (
            "requires_approval_for_risk",
            "production_requires_approval_for_risk",
        ):
            risks = routing.get(key, [])
            if not isinstance(risks, (list, tuple, set, frozenset)):
                errors.append(f"policy.approval_routing.{key} must be a list")
                continue
            for risk in risks:
                if not isinstance(risk, str) or risk.strip().lower() not in allowed_risks:
                    errors.append(
                        f"policy.approval_routing.{key} must contain only "
                        "low, med, medium, or high"
                    )

    if errors:
        raise PolicyValidationError("Invalid policy:\n- " + "\n- ".join(errors))
