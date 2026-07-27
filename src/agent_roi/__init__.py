from __future__ import annotations

try:
    from importlib.metadata import version
    __version__ = version("agent-roi")
except Exception:  # Source checkout before installation
    __version__ = "2.0.0"

from .audit.store import AuditIntegrityError, AuditStore, InMemoryAuditStore, JsonlAuditStore, SqliteAuditStore
from .audit.postgres import PostgresAuditStore
from .audit.remote import RemoteAuditStore
from .control.decision import ConfidenceInputs, DecisionOutcome, DecisionPolicy
from .control.guardrails import GuardrailViolation, Guardrails
from .runtime.executor import SentinelResult, SentinelRunner
from .runtime.tools import (
    ApprovalGrant,
    HumanApprovalRequired,
    ToolRegistry,
    ToolRegistrationError,
    ToolSpec,
)

__all__ = [
    "__version__",
    "SentinelRunner",
    "SentinelResult",
    "DecisionPolicy",
    "ConfidenceInputs",
    "DecisionOutcome",
    "Guardrails",
    "GuardrailViolation",
    "AuditStore",
    "JsonlAuditStore",
    "SqliteAuditStore",
    "InMemoryAuditStore",
    "AuditIntegrityError",
    "PostgresAuditStore",
    "RemoteAuditStore",
    "ToolRegistry",
    "ToolSpec",
    "ToolRegistrationError",
    "ApprovalGrant",
    "HumanApprovalRequired",
]


_ENTERPRISE_EXPORTS = {
    "EnterpriseSentinelRunner": ("agent_roi.enterprise.runtime", "EnterpriseSentinelRunner"),
    "Principal": ("agent_roi.enterprise.identity", "Principal"),
    "RBACAuthorizer": ("agent_roi.enterprise.identity", "RBACAuthorizer"),
    "DynamicRBACAuthorizer": ("agent_roi.enterprise.identity", "DynamicRBACAuthorizer"),
    "ControlPlaneClient": ("agent_roi.enterprise.control_plane", "ControlPlaneClient"),
    "ControlPlaneService": ("agent_roi.enterprise.control_plane", "ControlPlaneService"),
    "RealizedROILedger": ("agent_roi.roi.ledger", "RealizedROILedger"),
    "PostgresControlPlaneStore": ("agent_roi.enterprise.postgres", "PostgresControlPlaneStore"),
    "PostgresIdentityStore": ("agent_roi.enterprise.postgres", "PostgresIdentityStore"),
    "PostgresApprovalRepository": ("agent_roi.approvals.postgres", "PostgresApprovalRepository"),
    "PostgresROILedger": ("agent_roi.roi.postgres", "PostgresROILedger"),
    "RetryPolicy": ("agent_roi.runtime.resilience", "RetryPolicy"),
    "CircuitBreaker": ("agent_roi.runtime.resilience", "CircuitBreaker"),
    "IdempotencyPolicy": ("agent_roi.runtime.resilience", "IdempotencyPolicy"),
}


def __getattr__(name: str):
    target = _ENTERPRISE_EXPORTS.get(name)
    if target is None:
        raise AttributeError(name)
    from importlib import import_module
    module = import_module(target[0])
    value = getattr(module, target[1])
    globals()[name] = value
    return value

__all__.extend(_ENTERPRISE_EXPORTS)
