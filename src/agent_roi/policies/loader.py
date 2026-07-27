from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
from types import MappingProxyType
from typing import Any, Dict, Mapping, Optional

from agent_roi.control.decision import DecisionPolicy
from agent_roi.control.guardrails import Guardrails
from .validate import validate_policy


@dataclass(frozen=True)
class Policy:
    name: str
    data: Mapping[str, Any]

    def guardrails(self) -> Guardrails:
        return Guardrails(**dict(self.data.get("guardrails", {})))

    def decision_policy(self) -> DecisionPolicy:
        return DecisionPolicy(**dict(self.data.get("decision_policy", {})))



def _freeze(value: Any) -> Any:
    """Recursively freeze validated policy data against accidental mutation."""
    if isinstance(value, dict):
        return MappingProxyType({str(key): _freeze(child) for key, child in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(child) for child in value)
    if isinstance(value, tuple):
        return tuple(_freeze(child) for child in value)
    if isinstance(value, set):
        return frozenset(_freeze(child) for child in value)
    return value

def _normalize_policy(data: Dict[str, Any]) -> Dict[str, Any]:
    normalized = deepcopy(data)
    guardrails = normalized.get("guardrails")
    if isinstance(guardrails, dict):
        allowed = guardrails.get("allowed_tools")
        if isinstance(allowed, (list, tuple, set, frozenset)):
            guardrails["allowed_tools"] = frozenset(str(item).strip() for item in allowed)
    return normalized




def policy_from_mapping(name: str, data: Mapping[str, Any]) -> Policy:
    """Validate and freeze policy data supplied by a control plane or API."""
    if not isinstance(name, str) or not name.strip():
        raise ValueError("name must be a non-empty string")
    copied = deepcopy(dict(data))
    validate_policy(copied)
    normalized = _normalize_policy(copied)
    Guardrails(**dict(normalized["guardrails"]))
    DecisionPolicy(**dict(normalized["decision_policy"]))
    return Policy(name=name.strip(), data=_freeze(normalized))

def load_policy(
    package_yaml_name: str,
    *,
    override_path: Optional[str | Path] = None,
) -> Policy:
    """Load and validate a bundled or enterprise override YAML policy."""
    try:
        import yaml  # type: ignore
    except Exception as exc:  # pragma: no cover - dependency is declared
        raise RuntimeError(
            "PyYAML is required to load policy YAML. Install with: pip install PyYAML"
        ) from exc

    if not isinstance(package_yaml_name, str) or not package_yaml_name.strip():
        raise ValueError("package_yaml_name must be a non-empty string")

    if override_path is not None:
        path = Path(override_path)
        if not path.is_file():
            raise FileNotFoundError(f"Policy override not found: {path}")
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    else:
        policy_path = files("agent_roi.policies").joinpath(package_yaml_name)
        if not policy_path.is_file():
            raise FileNotFoundError(f"Bundled policy not found: {package_yaml_name}")
        raw = yaml.safe_load(policy_path.read_text(encoding="utf-8"))

    data = {} if raw is None else raw
    validate_policy(data)
    normalized = _normalize_policy(data)

    # Constructor validation provides a second line of defense and guarantees
    # consumers can construct runtime controls from a successfully loaded policy.
    Guardrails(**dict(normalized["guardrails"]))
    DecisionPolicy(**dict(normalized["decision_policy"]))

    return Policy(name=package_yaml_name, data=_freeze(normalized))
