from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import tempfile

try:
    import agent_roi  # noqa: F401
except ModuleNotFoundError:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from agent_roi import ConfidenceInputs, SqliteAuditStore, ToolRegistry
from agent_roi.enterprise import (
    ControlPlaneService,
    HMACPolicySigner,
    InMemoryEventSink,
    Principal,
    RBACAuthorizer,
    RoleDefinition,
    SqliteControlPlaneStore,
)
from agent_roi.enterprise.runtime import EnterpriseSentinelRunner
from agent_roi.policies import load_policy
from agent_roi.roi import RealizedROILedger


def run_demo(outdir: str | Path | None = None) -> dict[str, object]:
    output = Path(outdir) if outdir else Path(tempfile.mkdtemp(prefix="agent-roi-enterprise-"))
    output.mkdir(parents=True, exist_ok=True)

    signer = HMACPolicySigner(b"enterprise-demo-signing-key-32-bytes!", key_id="demo-key")
    control_plane = ControlPlaneService(
        SqliteControlPlaneStore(output / "control-plane.sqlite3"),
        signers={signer.key_id: signer},
        default_signer_key_id=signer.key_id,
    )
    policy = load_policy("finops_policy.yaml")
    bundle = control_plane.publish_policy(
        organization_id="acme",
        name="finops",
        environment="prod",
        version="2.0.0",
        policy=policy.data,
        created_by="policy-admin",
    )
    control_plane.activate_policy(
        organization_id="acme",
        name="finops",
        environment="prod",
        version=bundle.version,
        activated_by="policy-admin",
    )
    control_plane.register_agent(
        organization_id="acme",
        agent_id="finops-agent",
        environment="prod",
        owner="cloud-platform",
        purpose="Governed cloud cost analysis",
        version="2.0.0",
    )

    registry = ToolRegistry()
    registry.add(
        "finops_analyze",
        lambda monthly_cost_usd: {
            "monthly_cost_usd": monthly_cost_usd,
            "estimated_monthly_savings_usd": round(monthly_cost_usd * 0.15, 2),
        },
        description="Estimate governed FinOps savings",
        version="2",
        risk="low",
        default_cost_usd=0.01,
    )
    principal = Principal(
        "analyst-1", "acme", roles=frozenset({"agent_owner"})
    )
    authorizer = RBACAuthorizer(
        [RoleDefinition("agent_owner", frozenset({"tool.execute:finops_analyze"}))]
    )
    events = InMemoryEventSink()
    audit = SqliteAuditStore(output / "audit.sqlite3")
    runner = EnterpriseSentinelRunner.from_control_plane(
        control_plane_client=control_plane,
        organization_id="acme",
        environment="prod",
        agent_id="finops-agent",
        policy_name="finops",
        name="enterprise-finops-demo",
        audit_store=audit,
        tool_registry=registry,
        principal=principal,
        authorizer=authorizer,
        event_sinks=[events],
        heartbeat_fail_closed=True,
    )

    result = runner.run(
        lambda ctx, payload: (
            ctx.call_tool("finops_analyze", payload["monthly_cost_usd"]),
            ConfidenceInputs(
                prob=0.99,
                margin=0.95,
                z_score=3.0,
                entropy=0.05,
                llm_self_score=0.95,
            ),
        ),
        {"monthly_cost_usd": 10000.0},
    )

    ledger = RealizedROILedger(output / "roi-ledger.sqlite3")
    opportunity = ledger.create_opportunity(
        organization_id="acme",
        agent_id="finops-agent",
        business_unit="Technology",
        business_owner="CIO",
        title="Cloud optimization",
        value_type="cost_savings",
        value_period="monthly",
        baseline_usd=10000,
        forecast_value_usd=result.output["estimated_monthly_savings_usd"],
        confidence=result.confidence,
        source_key=f"run:{result.run_id}",
        created_by=principal.subject,
    )

    summary = {
        "output_directory": str(output),
        "decision_outcome": result.outcome.value,
        "confidence": result.confidence,
        "policy_version": bundle.version,
        "policy_signature_verified": True,
        "audit_events_verified": audit.verify(),
        "enterprise_events": len(events.events),
        "agent_status": control_plane.store.get_agent(
            "acme", "finops-agent", "prod"
        )["status"],
        "roi_opportunity_id": opportunity.opportunity_id,
        "forecast_monthly_value_usd": opportunity.forecast_value_usd,
    }
    (output / "enterprise-summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the Agent-ROI P0 enterprise demo")
    parser.add_argument("--outdir", default="")
    args = parser.parse_args(argv)
    print(json.dumps(run_demo(args.outdir or None), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
