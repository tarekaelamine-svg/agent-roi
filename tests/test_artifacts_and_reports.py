from pathlib import Path

from agent_roi import DecisionOutcome
from agent_roi.roi.report import build_procurement_roi_report
from agent_roi.runtime.artifacts import create_artifact_dir, write_manifest


class Result:
    outcome = DecisionOutcome.HUMAN_REVIEW
    confidence = 0.65
    correlation_id = "corr"
    run_id = "run"
    ctx_snapshot = {"state": {"cost_usd": 0.02}}


def test_custom_artifact_directory_is_used_exactly(tmp_path: Path):
    requested = tmp_path / "custom"
    created = create_artifact_dir("demo", requested)
    assert created == requested
    assert created.is_dir()
    manifest = write_manifest(
        created,
        demo_name="demo",
        business_context={"currency": "USD"},
        decision_outcome="human_review",
        confidence=0.5,
    )
    assert manifest.is_file()


def test_procurement_report_uses_one_time_language():
    output = {
        "summary": {
            "num_records_scanned": 2,
            "num_recommendations": 1,
            "est_total_recoverable_value_usd": 5200,
        },
        "recommendations": [
            {
                "record_id": "2",
                "invoice_id": "INV-1",
                "vendor": "ACME",
                "action": "duplicate_invoice",
                "risk": "high",
                "est_recoverable_value_usd": 5200,
                "rationale": "Duplicate invoice.",
            }
        ],
    }
    markdown = build_procurement_roi_report(
        sentinel_result=Result(), agent_output=output
    ).to_markdown()
    assert "Invoice records scanned" in markdown
    assert "one-time" in markdown
    assert "cloud cost-optimization" not in markdown
    assert "Resources scanned" not in markdown
