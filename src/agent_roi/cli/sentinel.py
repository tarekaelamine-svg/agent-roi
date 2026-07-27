from __future__ import annotations

import argparse
from pathlib import Path
from typing import Optional

from agent_roi import (
    ConfidenceInputs,
    SqliteAuditStore,
    SentinelRunner,
    ToolRegistry,
    __version__,
)
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


def _confidence_for_mode(mode: str) -> ConfidenceInputs:
    normalized = (mode or "review").strip().lower()
    if normalized == "accept":
        return ConfidenceInputs(
            prob=0.99,
            margin=0.80,
            z_score=3.0,
            entropy=0.05,
            llm_self_score=0.95,
        )
    if normalized == "review":
        return ConfidenceInputs(
            prob=0.80,
            margin=0.18,
            z_score=1.2,
            entropy=0.60,
            llm_self_score=0.70,
        )
    raise ValueError("Invalid mode. Use: accept or review")


def _build_demo_payload(policy_path: Optional[str]) -> dict:
    return {
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


def _analyze_finops(policy: Policy, payload: dict) -> dict:
    return FinOpsAnalyzer(policy=policy, business_context=BUSINESS_CONTEXT).analyze(payload)


def _make_finops_agent(confidence: ConfidenceInputs):
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
        return output, confidence

    return finops_agent


def _build_registry() -> ToolRegistry:
    registry = ToolRegistry()
    registry.add("policy_load", load_policy, risk="low", version="1.0")
    registry.add(
        "finops_analyze",
        _analyze_finops,
        risk="low",
        version="1.0",
        default_cost_usd=0.02,
    )
    return registry


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="agent-roi",
        description="Guarded FinOps demo with registered tools, audit logging, decision routing, and ROI artifacts.",
    )
    parser.add_argument(
        "--policy",
        dest="policy_path",
        default=None,
        help="Path to an enterprise override policy YAML file.",
    )
    parser.add_argument(
        "--outdir",
        dest="outdir",
        default=None,
        help="Exact output directory. Default: a unique directory under artifacts/finops/.",
    )
    parser.add_argument(
        "--mode",
        dest="mode",
        default="review",
        choices=["accept", "review"],
        help="Drive the demo to an accept or human-review confidence result.",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Replace only known Agent-ROI artifacts in an existing output directory.",
    )
    parser.add_argument("--version", action="version", version=f"agent-roi {__version__}")
    args = parser.parse_args(argv)

    if args.policy_path is not None and not Path(args.policy_path).is_file():
        parser.error(f"--policy file not found: {args.policy_path}")

    policy = load_policy("finops_policy.yaml", override_path=args.policy_path)
    try:
        artifacts = create_artifact_dir(
            "finops", args.outdir, clean_known_artifacts=args.overwrite
        )
    except FileExistsError as exc:
        parser.error(str(exc))
    audit_store = SqliteAuditStore(artifacts / "audit.sqlite3", hash_chain=True)

    runner = SentinelRunner(
        name="cli_finops_demo",
        guardrails=policy.guardrails(),
        decision_policy=policy.decision_policy(),
        audit_store=audit_store,
        metadata=BUSINESS_CONTEXT,
        tool_registry=_build_registry(),
    )

    result = runner.run(
        _make_finops_agent(_confidence_for_mode(args.mode)),
        _build_demo_payload(args.policy_path),
    )

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

    analyzer = FinOpsAnalyzer(policy=policy, business_context=BUSINESS_CONTEXT)
    analyzer.export_recommendations_csv(result.output, artifacts / "recommendations.csv")
    atomic_write_text(artifacts / "roi_report.md", report.to_markdown())
    atomic_write_text(artifacts / "executive_brief.md", brief)
    audit_events = audit_store.verify()
    audit_store.export_jsonl(artifacts / "audit.jsonl")

    write_manifest(
        artifact_dir=artifacts,
        demo_name="finops",
        business_context=BUSINESS_CONTEXT,
        decision_outcome=result.outcome.value,
        confidence=result.confidence,
        extra={
            "agent_roi_version": __version__,
            "audit_events_verified": audit_events,
            "tool_calls": result.ctx_snapshot["state"]["tool_calls"],
            "cost_usd": result.ctx_snapshot["state"]["cost_usd"],
            "policy_digest": runner.policy_digest,
        },
    )

    print("\nRun summary")
    print(f"  mode:        {args.mode}")
    print(f"  outcome:     {result.outcome.value}")
    print(f"  confidence:  {result.confidence:.3f}")
    print(f"  steps:       {result.ctx_snapshot['state']['steps']}")
    print(f"  tool_calls:  {result.ctx_snapshot['state']['tool_calls']}")
    print(f"  cost_usd:    {result.ctx_snapshot['state']['cost_usd']:.4f}")
    print(f"  audit_events:{audit_events:>4}")
    print(f"\nArtifacts written to: {artifacts}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
