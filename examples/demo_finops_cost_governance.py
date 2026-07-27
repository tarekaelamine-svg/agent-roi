from __future__ import annotations

import argparse
from pathlib import Path
import sys

try:
    import agent_roi  # noqa: F401
except ModuleNotFoundError:  # Run directly from an unpacked source distribution.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from agent_roi import ConfidenceInputs, SqliteAuditStore, SentinelRunner, ToolRegistry
from agent_roi.finops import FinOpsAnalyzer
from agent_roi.policies import Policy, load_policy
from agent_roi.roi.executive import build_executive_brief
from agent_roi.roi.report import build_finops_roi_report
from agent_roi.runtime.artifacts import atomic_write_text, create_artifact_dir, write_manifest


BUSINESS_CONTEXT = {
    "program": "Cloud Cost Governance",
    "business_unit": "Enterprise Infrastructure",
    "reporting_period": "2026-01",
    "currency": "USD",
    "assumptions": [
        "Savings estimates are conservative",
        "No production changes are executed automatically",
        "High-risk actions require owner approval",
        "All controlled tool decisions are audited",
    ],
}


def analyze_finops(policy: Policy, payload: dict) -> dict:
    return FinOpsAnalyzer(policy, BUSINESS_CONTEXT).analyze(payload)


def finops_agent(ctx, payload):
    policy = ctx.call_tool(
        "policy_load",
        "finops_policy.yaml",
        override_path=payload.get("policy_path"),
    )
    output = ctx.call_tool(
        "finops_analyze",
        policy,
        payload,
    )
    confidence = ConfidenceInputs(
        prob=0.99,
        margin=0.80,
        z_score=3.0,
        entropy=0.05,
        llm_self_score=0.95,
    )
    return output, confidence


def main(
    policy_path: str | None = None,
    outdir: str | Path | None = None,
    *,
    overwrite: bool = False,
) -> Path:
    policy = load_policy("finops_policy.yaml", override_path=policy_path)
    artifacts = create_artifact_dir(
        "finops", outdir, clean_known_artifacts=overwrite
    )
    audit_store = SqliteAuditStore(artifacts / "audit.sqlite3")

    registry = ToolRegistry()
    registry.add("policy_load", load_policy, risk="low", version="1.0")
    registry.add(
        "finops_analyze", analyze_finops, risk="low", version="1.0", default_cost_usd=0.02
    )

    runner = SentinelRunner(
        name="cloud_cost_governance",
        guardrails=policy.guardrails(),
        decision_policy=policy.decision_policy(),
        audit_store=audit_store,
        metadata=BUSINESS_CONTEXT,
        tool_registry=registry,
    )
    payload = {
        "policy_path": policy_path,
        "resources": [
            {
                "id": "ec2-prod-payments-01",
                "type": "ec2_instance",
                "owner": "payments",
                "environment": "production",
                "monthly_cost_usd": 520,
                "utilization_pct": 6.2,
            },
            {
                "id": "rds-prod-orders",
                "type": "rds_instance",
                "owner": "orders",
                "environment": "production",
                "monthly_cost_usd": 860,
                "utilization_pct": 2.0,
            },
            {
                "id": "s3-central-logs",
                "type": "s3_bucket",
                "owner": "security",
                "environment": "shared",
                "monthly_cost_usd": 310,
                "storage_gb": 9200,
            },
        ],
    }
    result = runner.run(finops_agent, payload)

    report = build_finops_roi_report(
        sentinel_result=result,
        agent_output=result.output,
        title="Cloud Cost Governance ROI Report",
    )
    brief = build_executive_brief(
        title="Cloud Cost Governance — Executive Brief",
        business_context=BUSINESS_CONTEXT,
        sentinel_result=result,
        agent_output=result.output,
    )
    analyzer = FinOpsAnalyzer(policy, BUSINESS_CONTEXT)
    analyzer.export_recommendations_csv(result.output, artifacts / "recommendations.csv")
    atomic_write_text(artifacts / "roi_report.md", report.to_markdown())
    atomic_write_text(artifacts / "executive_brief.md", brief)
    verified = audit_store.verify()
    audit_store.export_jsonl(artifacts / "audit.jsonl")
    write_manifest(
        artifacts,
        demo_name="finops",
        business_context=BUSINESS_CONTEXT,
        decision_outcome=result.outcome.value,
        confidence=result.confidence,
        extra={
            "audit_events_verified": verified,
            "policy_digest": runner.policy_digest,
            "tool_calls": result.ctx_snapshot["state"]["tool_calls"],
            "cost_usd": result.ctx_snapshot["state"]["cost_usd"],
        },
    )

    print("\nRun summary")
    print(f"  outcome:     {result.outcome.value}")
    print(f"  confidence:  {result.confidence:.3f}")
    print(f"  steps:       {result.ctx_snapshot['state']['steps']}")
    print(f"  tool_calls:  {result.ctx_snapshot['state']['tool_calls']}")
    print(f"  cost_usd:    {result.ctx_snapshot['state']['cost_usd']:.4f}")
    print(f"  audit_events:{verified:>4}")
    print(f"\nArtifacts written to: {artifacts}\n")
    return artifacts


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run the Agent-ROI finops example")
    parser.add_argument("--policy", default=None, help="Optional policy override YAML")
    parser.add_argument("--outdir", default=None, help="Exact artifact directory")
    parser.add_argument("--overwrite", action="store_true", help="Replace known Agent-ROI artifacts")
    arguments = parser.parse_args()
    main(arguments.policy, arguments.outdir, overwrite=arguments.overwrite)
