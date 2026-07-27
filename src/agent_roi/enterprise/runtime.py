from __future__ import annotations

from typing import Any, Iterable, Optional

from agent_roi import __version__
from agent_roi.audit.store import AuditStore
from agent_roi.runtime.executor import SentinelResult, SentinelRunner
from agent_roi.runtime.tools import ApprovalCallback, ToolRegistry
from agent_roi.policies.loader import policy_from_mapping

from .control_plane import ControlPlaneClient, PolicyBundle
from .telemetry import EventSink


class EnterpriseSentinelRunner(SentinelRunner):
    """Sentinel runner configured from a signed central policy bundle."""

    def __init__(
        self,
        *,
        control_plane_client: ControlPlaneClient,
        policy_bundle: PolicyBundle,
        organization_id: str,
        environment: str,
        agent_id: str,
        heartbeat_fail_closed: bool = False,
        **kwargs: Any,
    ) -> None:
        policy = policy_from_mapping(
            f"{policy_bundle.name}@{policy_bundle.version}", policy_bundle.policy
        )
        super().__init__(
            guardrails=policy.guardrails(),
            decision_policy=policy.decision_policy(),
            organization_id=organization_id,
            environment=environment,
            agent_id=agent_id,
            **kwargs,
        )
        self.control_plane_client = control_plane_client
        self.policy_bundle = policy_bundle
        self.heartbeat_fail_closed = bool(heartbeat_fail_closed)
        self.heartbeat_errors: list[str] = []

    @classmethod
    def from_control_plane(
        cls,
        *,
        control_plane_client: ControlPlaneClient,
        organization_id: str,
        environment: str,
        agent_id: str,
        policy_name: str,
        name: str = "enterprise_agent",
        audit_store: Optional[AuditStore] = None,
        tool_registry: Optional[ToolRegistry] = None,
        approval_callback: Optional[ApprovalCallback] = None,
        principal: Any = None,
        authorizer: Any = None,
        event_sinks: Optional[Iterable[EventSink]] = None,
        metadata: Optional[dict[str, Any]] = None,
        heartbeat_fail_closed: bool = False,
        **kwargs: Any,
    ) -> "EnterpriseSentinelRunner":
        get_for_agent = getattr(control_plane_client, "get_policy_for_agent", None)
        if callable(get_for_agent):
            bundle = get_for_agent(organization_id, policy_name, environment, agent_id)
        else:
            bundle = control_plane_client.get_active_policy(
                organization_id, policy_name, environment
            )
        return cls(
            control_plane_client=control_plane_client,
            policy_bundle=bundle,
            organization_id=organization_id,
            environment=environment,
            agent_id=agent_id,
            heartbeat_fail_closed=heartbeat_fail_closed,
            name=name,
            audit_store=audit_store,
            tool_registry=tool_registry,
            approval_callback=approval_callback,
            principal=principal,
            authorizer=authorizer,
            event_sinks=event_sinks,
            metadata={"policy_version": bundle.version, **dict(metadata or {})},
            **kwargs,
        )

    def heartbeat(self, status: str) -> None:
        try:
            self.control_plane_client.heartbeat(
                organization_id=self.organization_id,
                agent_id=self.agent_id,
                environment=self.environment,
                policy_digest=self.policy_digest,
                version=__version__,
                status=status,
            )
        except Exception as exc:
            self.heartbeat_errors.append(str(exc))
            if self.heartbeat_fail_closed:
                raise

    def run(self, *args: Any, **kwargs: Any) -> SentinelResult:
        self.heartbeat("running")
        try:
            result = super().run(*args, **kwargs)
        except Exception:
            self.heartbeat("error")
            raise
        self.heartbeat("production")
        return result

    async def arun(self, *args: Any, **kwargs: Any) -> SentinelResult:
        self.heartbeat("running")
        try:
            result = await super().arun(*args, **kwargs)
        except Exception:
            self.heartbeat("error")
            raise
        self.heartbeat("production")
        return result
