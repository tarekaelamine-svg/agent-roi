from __future__ import annotations

from pathlib import Path

import pytest

from agent_roi.roi.ledger import (
    CostType,
    OpportunityStatus,
    RealizedROILedger,
    ValueStage,
)


def _create(ledger: RealizedROILedger, **overrides):
    values = {
        "organization_id": "acme",
        "agent_id": "invoice-agent",
        "business_unit": "Finance",
        "business_owner": "CFO",
        "title": "Duplicate invoice recovery",
        "value_type": "cost_savings",
        "value_period": "one_time",
        "baseline_usd": 100000,
        "forecast_value_usd": 20000,
        "confidence": 0.85,
        "source_key": "assessment-1",
        "created_by": "analyst",
    }
    values.update(overrides)
    return ledger.create_opportunity(**values)


def test_roi_lifecycle_realized_validated_cost_and_net_value(tmp_path: Path) -> None:
    ledger = RealizedROILedger(tmp_path / "roi.sqlite3")
    opportunity = _create(ledger)
    opportunity = ledger.transition(
        opportunity.opportunity_id, OpportunityStatus.APPROVED, changed_by="cfo"
    )
    opportunity = ledger.transition(
        opportunity.opportunity_id, OpportunityStatus.IN_PROGRESS, changed_by="owner"
    )
    ledger.record_value(
        opportunity.opportunity_id,
        stage=ValueStage.REALIZED,
        amount_usd=12000,
        evidence_key="credit-memo-1",
        evidence_uri="erp://credit/1",
        recorded_by="analyst",
    )
    ledger.record_value(
        opportunity.opportunity_id,
        stage=ValueStage.VALIDATED,
        amount_usd=10000,
        evidence_key="finance-validation-1",
        recorded_by="finance",
    )
    ledger.record_cost(
        organization_id="acme",
        agent_id="invoice-agent",
        opportunity_id=opportunity.opportunity_id,
        cost_type=CostType.MODEL,
        amount_usd=1000,
        currency_code="USD",
        evidence_key="model-bill-1",
        recorded_by="platform",
    )
    summary = ledger.portfolio_summary(organization_id="acme")
    assert summary["forecast_value_usd"] == 20000.0
    assert summary["realized_value_usd"] == 12000.0
    assert summary["validated_value_usd"] == 10000.0
    assert summary["total_cost_usd"] == 1000.0
    assert summary["net_validated_value_usd"] == 9000.0
    assert summary["validated_roi_multiple"] == 10.0


def test_roi_ledger_prevents_duplicate_sources_and_evidence(tmp_path: Path) -> None:
    ledger = RealizedROILedger(tmp_path / "roi.sqlite3")
    opportunity = _create(ledger)
    with pytest.raises(ValueError, match="source_key"):
        _create(ledger, title="Other")
    ledger.transition(opportunity.opportunity_id, "approved", changed_by="cfo")
    ledger.transition(opportunity.opportunity_id, "in_progress", changed_by="owner")
    ledger.record_value(
        opportunity.opportunity_id,
        stage="realized",
        amount_usd=100,
        evidence_key="erp-1",
        recorded_by="analyst",
    )
    with pytest.raises(ValueError, match="already been counted"):
        ledger.record_value(
            opportunity.opportunity_id,
            stage="realized",
            amount_usd=100,
            evidence_key="erp-1",
            recorded_by="analyst",
        )


def test_roi_ledger_rejects_invalid_status_transition(tmp_path: Path) -> None:
    ledger = RealizedROILedger(tmp_path / "roi.sqlite3")
    opportunity = _create(ledger)
    with pytest.raises(ValueError, match="Invalid ROI status transition"):
        ledger.transition(opportunity.opportunity_id, "validated", changed_by="cfo")


def test_roi_ledger_requires_currency_selection_for_mixed_portfolio(tmp_path: Path) -> None:
    ledger = RealizedROILedger(tmp_path / "roi.sqlite3")
    _create(ledger)
    _create(
        ledger,
        source_key="assessment-eur",
        title="European savings",
        currency_code="EUR",
    )
    with pytest.raises(ValueError, match="multiple currencies"):
        ledger.portfolio_summary(organization_id="acme")
    usd = ledger.portfolio_summary(organization_id="acme", currency_code="USD")
    assert usd["opportunity_count"] == 1
