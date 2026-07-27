from __future__ import annotations

import os
from pathlib import Path
import sqlite3
from types import SimpleNamespace

import pytest

from agent_roi.finops.analyzer import FinOpsAnalyzer, _nonnegative_float as finops_number
from agent_roi.policies import load_policy
from agent_roi.procurement.analyzer import (
    ProcurementLeakageAnalyzer,
    _nonnegative_float as procurement_number,
)
from agent_roi.roi.executive import build_executive_brief
from agent_roi.roi.ledger import RealizedROILedger, _money_to_cents
from agent_roi.roi.report import (
    ROIReport,
    _compute_payback_display,
    _compute_roi_multiple,
    _fmt_money,
    _safe_float,
    _summarize_risks,
    build_roi_report,
)
from agent_roi.runtime.artifacts import atomic_write_text, create_artifact_dir, write_manifest


def _result(cost: float = 2.0):
    return SimpleNamespace(
        ctx_snapshot={"state": {"cost_usd": cost}},
        outcome=SimpleNamespace(value="accept"),
        confidence=0.75,
        correlation_id="corr",
        run_id="run",
    )


def _create_opportunity(ledger: RealizedROILedger, **overrides):
    values = dict(
        organization_id="acme",
        agent_id="agent",
        business_unit="Finance",
        business_owner="Owner",
        title="Value",
        value_type="cost_savings",
        value_period="one_time",
        baseline_usd=100,
        forecast_value_usd=20,
        confidence=0.8,
        source_key="source",
        created_by="tester",
    )
    values.update(overrides)
    return ledger.create_opportunity(**values)


def test_finops_validation_idle_storage_and_export_edges(tmp_path: Path, monkeypatch) -> None:
    analyzer = FinOpsAnalyzer(load_policy("finops_policy.yaml"), {})
    for value in (object(), "bad"):
        with pytest.raises(ValueError, match="numeric"):
            finops_number(value, "x")
    for value in (-1, float("inf"), float("nan")):
        with pytest.raises(ValueError, match="finite and nonnegative"):
            finops_number(value, "x")
    with pytest.raises(TypeError, match="mapping"):
        analyzer.analyze([])  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="must be a list"):
        analyzer.analyze({"resources": {}})
    with pytest.raises(TypeError, match=r"resources\[0\]"):
        analyzer.analyze({"resources": ["bad"]})

    output = analyzer.analyze(
        {
            "resources": [
                {
                    "id": "idle",
                    "type": "ec2_instance",
                    "monthly_cost_usd": 100,
                    "utilization_pct": 50,
                    "days_idle": 20,
                },
                {
                    "id": "disk",
                    "type": "ebs_volume",
                    "monthly_cost_usd": 20,
                    "days_idle": 8,
                    "attached": False,
                },
            ]
        }
    )
    assert {item["action"] for item in output["recommendations"]} == {
        "scheduled_stop",
        "snapshot_then_delete",
    }
    with pytest.raises(TypeError, match="must be a list"):
        analyzer.export_recommendations_csv({"recommendations": {"x": 1}}, tmp_path / "a.csv")
    with pytest.raises(TypeError, match="contain mappings"):
        analyzer.export_recommendations_csv({"recommendations": [1]}, tmp_path / "b.csv")
    monkeypatch.setattr(os, "chmod", lambda *_: (_ for _ in ()).throw(OSError("no")))
    assert analyzer.export_recommendations_csv(output, tmp_path / "ok.csv").exists()


def test_procurement_validation_routing_and_export_edges(tmp_path: Path, monkeypatch) -> None:
    analyzer = ProcurementLeakageAnalyzer(
        load_policy("procurement_policy.yaml"), {"environment": "production"}
    )
    for value in (object(), "bad"):
        with pytest.raises(ValueError, match="numeric"):
            procurement_number(value, "x")
    for value in (-1, float("inf")):
        with pytest.raises(ValueError, match="finite and nonnegative"):
            procurement_number(value, "x")
    assert analyzer.approval_status({}, "medium") == "procurement_approval_required"
    assert analyzer._approved_vendor_set(None) == set()
    with pytest.raises(TypeError, match="list or set"):
        analyzer._approved_vendor_set("ACME")
    with pytest.raises(TypeError, match="only strings"):
        analyzer._approved_vendor_set([1])
    with pytest.raises(TypeError, match="mapping"):
        analyzer.analyze([])  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="must be a list"):
        analyzer.analyze({"invoices": {}})
    with pytest.raises(TypeError, match="must be a mapping"):
        analyzer.analyze({"baseline_unit_prices": []})
    with pytest.raises(TypeError, match=r"invoices\[0\]"):
        analyzer.analyze({"invoices": [1]})
    with pytest.raises(TypeError, match="must be a list"):
        analyzer.export_recommendations_csv({"recommendations": {"x": 1}}, tmp_path / "a.csv")
    with pytest.raises(TypeError, match="contain mappings"):
        analyzer.export_recommendations_csv({"recommendations": [1]}, tmp_path / "b.csv")
    monkeypatch.setattr(os, "chmod", lambda *_: (_ for _ in ()).throw(OSError("no")))
    assert analyzer.export_recommendations_csv({"recommendations": []}, tmp_path / "ok.csv").exists()


def test_roi_ledger_validation_filters_and_duplicate_costs(tmp_path: Path) -> None:
    for value in (object(), "bad"):
        with pytest.raises(ValueError, match="numeric"):
            _money_to_cents(value)
    for value in (-1, float("inf"), float("nan")):
        with pytest.raises(ValueError, match="finite and nonnegative"):
            _money_to_cents(value)

    ledger = RealizedROILedger(tmp_path / "roi.sqlite3")
    with pytest.raises(ValueError, match="organization_id"):
        _create_opportunity(ledger, organization_id="")
    with pytest.raises(ValueError, match="confidence"):
        _create_opportunity(ledger, source_key="bad-confidence", confidence=2)
    with pytest.raises(ValueError, match="currency_code"):
        _create_opportunity(ledger, source_key="bad-currency", currency_code="US")
    with pytest.raises(ValueError, match="Invalid value_type"):
        _create_opportunity(ledger, source_key="bad-type", value_type="nope")

    opportunity = _create_opportunity(ledger)
    assert ledger.list_opportunities(
        organization_id="acme", agent_id="agent", status="proposed"
    )[0].opportunity_id == opportunity.opportunity_id
    with pytest.raises(ValueError, match="in-progress"):
        ledger.record_value(
            opportunity.opportunity_id,
            stage="realized",
            amount_usd=1,
            evidence_key="e",
            recorded_by="r",
        )
    with pytest.raises(ValueError, match="required"):
        ledger.record_value(
            opportunity.opportunity_id,
            stage="potential",
            amount_usd=1,
            evidence_key="",
            recorded_by="r",
        )
    with pytest.raises(ValueError, match="does not match"):
        ledger.record_cost(
            organization_id="other",
            agent_id="agent",
            opportunity_id=opportunity.opportunity_id,
            cost_type="model",
            amount_usd=1,
            currency_code="USD",
            evidence_key="c",
            recorded_by="r",
        )
    with pytest.raises(ValueError, match="required"):
        ledger.record_cost(
            organization_id="acme",
            agent_id="agent",
            cost_type="model",
            amount_usd=1,
            currency_code="USD",
            evidence_key="",
            recorded_by="r",
        )
    ledger.record_cost(
        organization_id="acme",
        agent_id="agent",
        cost_type="model",
        amount_usd=1,
        currency_code="USD",
        evidence_key="cost-1",
        recorded_by="r",
    )
    with pytest.raises(ValueError, match="already been counted"):
        ledger.record_cost(
            organization_id="acme",
            agent_id="agent",
            cost_type="model",
            amount_usd=1,
            currency_code="USD",
            evidence_key="cost-1",
            recorded_by="r",
        )


def test_roi_ledger_upgrades_legacy_revision_schema(tmp_path: Path) -> None:
    path = tmp_path / "legacy.sqlite3"
    conn = sqlite3.connect(path)
    try:
        conn.execute(
            """CREATE TABLE roi_opportunities (
            opportunity_id TEXT PRIMARY KEY, organization_id TEXT NOT NULL, agent_id TEXT NOT NULL,
            business_unit TEXT NOT NULL, business_owner TEXT NOT NULL, title TEXT NOT NULL,
            value_type TEXT NOT NULL, value_period TEXT NOT NULL, status TEXT NOT NULL,
            currency_code TEXT NOT NULL, baseline_cents INTEGER NOT NULL, forecast_cents INTEGER NOT NULL,
            confidence REAL NOT NULL, source_key TEXT NOT NULL, measurement_start TEXT NOT NULL,
            measurement_end TEXT NOT NULL, created_at_utc TEXT NOT NULL, created_by TEXT NOT NULL,
            metadata_json TEXT NOT NULL, UNIQUE (organization_id, source_key))"""
        )
        conn.commit()
    finally:
        conn.close()
    RealizedROILedger(path)
    conn = sqlite3.connect(path)
    try:
        assert "revision" in {row[1] for row in conn.execute("PRAGMA table_info(roi_opportunities)")}
    finally:
        conn.close()


def test_report_helpers_and_empty_unknown_rendering() -> None:
    assert _fmt_money(1, "CAD") == "CAD 1.00"
    assert _safe_float("bad", 7) == 7
    assert _summarize_risks([{"risk": "medium"}, {"risk": "mystery"}]) == {
        "low": 0,
        "med": 1,
        "high": 0,
        "unknown": 1,
    }
    assert _compute_payback_display(1, 0, 30)[1] == "N/A"
    assert _compute_payback_display(0, 100, 30)[1] == "< 1 minute"
    assert "minutes" in _compute_payback_display(0.01, 1000, 30)[1]
    assert "hours" in _compute_payback_display(1, 100, 30)[1]
    assert "days" in _compute_payback_display(10, 100, 30)[1]
    assert "months" in _compute_payback_display(200, 100, 30)[1]
    assert _compute_roi_multiple(0, 100)[1] == "N/A"

    report = build_roi_report(
        sentinel_result=_result(),
        agent_output={"summary": "bad", "recommendations": "bad"},
        title="T",
        summary_value_field="value",
        recommendation_value_field="value",
        scope_summary_fields=("count",),
        value_period_label="month",
        value_period_days=30,
        scope_label="Items",
        item_label="Item",
        item_type_label="Type",
        item_id_fields=("id",),
        item_type_fields=("type",),
        executive_summary_subject="opportunities",
    )
    markdown = report.to_markdown()
    assert "No actions recommended" in markdown
    assert "No recommendations generated" in markdown

    custom = ROIReport(
        title="T", generated_at_utc="now", correlation_id="c", run_id="r",
        decision_outcome="accept", decision_confidence=1, estimated_monthly_savings_usd=1,
        estimated_run_cost_usd=1, roi_multiple_monthly=1, roi_multiple_display="1×",
        payback_days=1, payback_display="1 day", num_resources_scanned=1,
        num_recommendations=1, risk_counts={"low": 0, "med": 0, "high": 0, "unknown": 1},
        top_recommendations=[{"id": "x", "risk": "mystery", "value": 1, "rationale": "note"}],
        notes=["note"], recommendation_value_field="value",
    )
    rendered = custom.to_markdown()
    assert "Unknown risk" in rendered and "## Notes" in rendered


def test_executive_brief_invalid_structures_empty_and_scalar_assumption() -> None:
    brief = build_executive_brief(
        title="Brief",
        business_context={"program": "P", "assumptions": "single"},
        sentinel_result=_result(),
        agent_output={"summary": "bad", "recommendations": "bad"},
    )
    assert "No recommendations generated" in brief
    assert "- single" in brief


def test_artifact_validation_cleanup_and_permission_failures(tmp_path: Path, monkeypatch) -> None:
    with pytest.raises(ValueError, match="demo_name"):
        create_artifact_dir("")
    generated = create_artifact_dir("demo", None)
    assert generated.exists()

    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "link"
    link.symlink_to(target, target_is_directory=True)
    with pytest.raises(ValueError, match="symbolic"):
        create_artifact_dir("demo", link)

    dirty = tmp_path / "dirty"
    dirty.mkdir()
    (dirty / "unknown.txt").write_text("x")
    with pytest.raises(FileExistsError, match="non-Agent-ROI"):
        create_artifact_dir("demo", dirty, clean_known_artifacts=True)

    known = tmp_path / "known"
    known.mkdir()
    (known / "audit.jsonl").write_text("x")
    sub = known / "audit.sqlite3"
    sub.mkdir()
    assert create_artifact_dir("demo", known, clean_known_artifacts=True) == known
    assert list(known.iterdir()) == []

    monkeypatch.setattr(os, "chmod", lambda *_: (_ for _ in ()).throw(OSError("no")))
    assert create_artifact_dir("demo", tmp_path / "chmod").exists()
    output = atomic_write_text(tmp_path / "atomic.txt", "hello")
    assert output.read_text() == "hello"
    manifest = write_manifest(
        tmp_path / "manifest", demo_name="d", business_context={},
        decision_outcome="accept", confidence=1, extra={"extra": True},
    )
    assert '"extra": true' in manifest.read_text()
