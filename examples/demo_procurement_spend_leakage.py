from __future__ import annotations

import argparse
from pathlib import Path
import sys

try:
    import agent_roi  # noqa: F401
except ModuleNotFoundError:  # Run directly from an unpacked source distribution.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from agent_roi import ConfidenceInputs, SqliteAuditStore, SentinelRunner, ToolRegistry
from agent_roi.policies import Policy, load_policy
from agent_roi.procurement import ProcurementLeakageAnalyzer
from agent_roi.roi.executive import build_executive_brief
from agent_roi.roi.report import build_procurement_roi_report
from agent_roi.runtime.artifacts import atomic_write_text, create_artifact_dir, write_manifest


BUSINESS_CONTEXT = {
    "program": "Procurement Spend Leakage",
    "business_unit": "Shared Services",
    "reporting_period": "2026-01",
    "currency": "USD",
    "assumptions": [
        "Recoverable value is an estimate",
        "No payment is halted automatically",
        "Findings require accounts-payable approval",
    ],
}


def analyze_procurement(policy: Policy, payload: dict) -> dict:
    return ProcurementLeakageAnalyzer(policy, BUSINESS_CONTEXT).analyze(payload)


def procurement_agent(ctx, payload):
    policy = ctx.call_tool(
        "policy_load",
        "procurement_policy.yaml",
        override_path=payload.get("policy_path"),
    )
    output = ctx.call_tool(
        "procurement_analyze",
        policy,
        payload,
    )
    confidence = ConfidenceInputs(
        prob=0.86,
        margin=0.20,
        z_score=1.8,
        entropy=0.32,
        llm_self_score=0.82,
    )
    return output, confidence


def main(
    policy_path: str | None = None,
    outdir: str | Path | None = None,
    *,
    overwrite: bool = False,
) -> Path:
    policy = load_policy("procurement_policy.yaml", override_path=policy_path)
    artifacts = create_artifact_dir(
        "procurement", outdir, clean_known_artifacts=overwrite
    )
    audit_store = SqliteAuditStore(artifacts / "audit.sqlite3")

    registry = ToolRegistry()
    registry.add("policy_load", load_policy, risk="low", version="1.0")
    registry.add(
        "procurement_analyze", analyze_procurement, risk="low", version="1.0", default_cost_usd=0.02
    )

    runner = SentinelRunner(
        name="procurement_spend_leakage",
        guardrails=policy.guardrails(),
        decision_policy=policy.decision_policy(),
        audit_store=audit_store,
        metadata=BUSINESS_CONTEXT,
        tool_registry=registry,
    )
    payload = {
        "policy_path": policy_path,
        "approved_vendors": ["ACME_SUPPLY"],
        "baseline_unit_prices": {"SKU-123": 10.0},
        "invoices": [
            {
                "record_id": "1",
                "vendor": "ACME_SUPPLY",
                "invoice_id": "INV-1",
                "amount_usd": 5200,
                "sku": "SKU-123",
                "qty": 500,
                "unit_price_usd": 10.4,
            },
            {
                "record_id": "2",
                "vendor": "ACME_SUPPLY",
                "invoice_id": "INV-1",
                "amount_usd": 5200,
                "sku": "SKU-123",
                "qty": 500,
                "unit_price_usd": 10.4,
            },
        ],
    }
    result = runner.run(procurement_agent, payload)

    report = build_procurement_roi_report(
        sentinel_result=result,
        agent_output=result.output,
        title="Procurement Spend Leakage ROI Report",
    )
    brief = build_executive_brief(
        title="Procurement Spend Leakage — Executive Brief",
        business_context=BUSINESS_CONTEXT,
        sentinel_result=result,
        agent_output=result.output,
        summary_value_field="est_total_recoverable_value_usd",
        recommendation_value_field="est_recoverable_value_usd",
        value_label="Estimated recoverable value",
        value_period_label="one-time",
        item_id_fields=("record_id", "invoice_id"),
    )
    analyzer = ProcurementLeakageAnalyzer(policy, BUSINESS_CONTEXT)
    analyzer.export_recommendations_csv(result.output, artifacts / "recommendations.csv")
    atomic_write_text(artifacts / "roi_report.md", report.to_markdown())
    atomic_write_text(artifacts / "executive_brief.md", brief)
    verified = audit_store.verify()
    audit_store.export_jsonl(artifacts / "audit.jsonl")
    write_manifest(
        artifacts,
        demo_name="procurement",
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
    parser = argparse.ArgumentParser(description="Run the Agent-ROI procurement example")
    parser.add_argument("--policy", default=None, help="Optional policy override YAML")
    parser.add_argument("--outdir", default=None, help="Exact artifact directory")
    parser.add_argument("--overwrite", action="store_true", help="Replace known Agent-ROI artifacts")
    arguments = parser.parse_args()
    main(arguments.policy, arguments.outdir, overwrite=arguments.overwrite)
