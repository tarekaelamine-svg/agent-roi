from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import math
from typing import Any, Dict, List, Optional, Sequence, Tuple

from agent_roi._serialization import markdown_escape


def _fmt_money(value: float, currency_code: str = "USD", decimals: int = 2) -> str:
    code = str(currency_code or "USD").strip().upper()
    symbols = {"USD": "$", "EUR": "€", "GBP": "£", "JPY": "¥"}
    symbol = symbols.get(code)
    if symbol is not None:
        return f"{symbol}{value:,.{decimals}f}"
    return f"{code} {value:,.{decimals}f}"


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return default
    return number if math.isfinite(number) else default


def _risk_rank(risk: str) -> int:
    return {"low": 1, "med": 2, "medium": 2, "high": 3}.get(
        (risk or "").strip().lower(), 4
    )


def _summarize_risks(recommendations: List[Dict[str, Any]]) -> Dict[str, int]:
    counts = {"low": 0, "med": 0, "high": 0, "unknown": 0}
    for recommendation in recommendations:
        risk = str(recommendation.get("risk") or "").strip().lower()
        if risk == "medium":
            risk = "med"
        counts[risk if risk in counts else "unknown"] += 1
    return counts


def _compute_payback_display(
    run_cost_usd: float, value_usd: float, period_days: Optional[float]
) -> Tuple[Optional[float], str]:
    if value_usd <= 0 or period_days is None or period_days <= 0:
        return None, "N/A"
    daily_value = value_usd / period_days
    days = run_cost_usd / daily_value if run_cost_usd > 0 else 0.0
    if run_cost_usd <= 0:
        return 0.0, "< 1 minute"
    if days < 1.0 / 24.0:
        return days, f"~{max(1.0, days * 1440.0):,.0f} minutes"
    if days < 1.0:
        return days, f"~{days * 24.0:,.1f} hours"
    if days < 30.0:
        return days, f"~{days:,.1f} days"
    return days, f"~{days / 30.0:,.1f} months"


def _compute_roi_multiple(run_cost_usd: float, value_usd: float) -> Tuple[Optional[float], str]:
    if run_cost_usd <= 0:
        return None, "N/A"
    multiple = value_usd / run_cost_usd
    if multiple >= 1000:
        return multiple, f"{multiple:,.0f}×"
    if multiple >= 100:
        return multiple, f"{multiple:,.1f}×"
    return multiple, f"{multiple:,.2f}×"


def _first_value(mapping: Dict[str, Any], keys: Sequence[str], default: Any = "") -> Any:
    for key in keys:
        value = mapping.get(key)
        if value not in (None, ""):
            return value
    return default


@dataclass(frozen=True)
class ROIReport:
    title: str
    generated_at_utc: str
    correlation_id: str
    run_id: str
    decision_outcome: str
    decision_confidence: float
    estimated_monthly_savings_usd: float  # Legacy field; see estimated_value_usd.
    estimated_run_cost_usd: float
    roi_multiple_monthly: Optional[float]  # Legacy field; applies to configured value period.
    roi_multiple_display: str
    payback_days: Optional[float]
    payback_display: str
    num_resources_scanned: int  # Legacy field; may represent records/items.
    num_recommendations: int
    risk_counts: Dict[str, int]
    top_recommendations: List[Dict[str, Any]]
    notes: List[str]
    value_period_label: str = "month"
    scope_label: str = "Resources scanned"
    item_label: str = "Resource"
    item_type_label: str = "Type"
    recommendation_value_field: str = "est_monthly_savings_usd"
    item_id_fields: Tuple[str, ...] = ("resource_id", "record_id", "id")
    item_type_fields: Tuple[str, ...] = ("resource_type", "item_type", "type")
    executive_summary_subject: str = "cost-optimization recommendations"
    currency_code: str = "USD"

    @property
    def estimated_value_usd(self) -> float:
        return self.estimated_monthly_savings_usd

    def to_markdown(self) -> str:
        low = self.risk_counts.get("low", 0)
        medium = self.risk_counts.get("med", 0)
        high = self.risk_counts.get("high", 0)
        period_suffix = (
            "" if self.value_period_label == "one-time" else f" / {self.value_period_label}"
        )

        lines: List[str] = [f"# {self.title}", ""]
        lines.append(
            f"> **Executive Summary:** This run generated actionable {self.executive_summary_subject} with"
        )
        lines.append(
            f"> estimated value of **{_fmt_money(self.estimated_value_usd, self.currency_code)}{period_suffix}**."
        )
        lines.extend(
            [
                "",
                "## Overview",
                f"- Generated (UTC): **{self.generated_at_utc}**",
                f"- Correlation ID: `{self.correlation_id}`",
                f"- Run ID: `{self.run_id}`",
                "",
                "## Governance Decision",
                f"- Outcome: **{self.decision_outcome}**",
                f"- Confidence score: **{self.decision_confidence:.3f}**",
                "",
                "## ROI Summary",
                f"- Estimated value ({self.value_period_label}): **{_fmt_money(self.estimated_value_usd, self.currency_code)}**",
                f"- Estimated run cost: **{_fmt_money(self.estimated_run_cost_usd, self.currency_code, decimals=4)}**",
                f"- Value / run-cost multiple: **{self.roi_multiple_display}**",
                f"- Payback period: **{self.payback_display}**",
                "",
                "## Scope and Risk Breakdown",
                "",
                "| Metric | Value |",
                "|---|---:|",
                f"| {markdown_escape(self.scope_label)} | {self.num_resources_scanned:,} |",
                f"| Recommendations generated | {self.num_recommendations:,} |",
                f"| Low risk | {low:,} |",
                f"| Medium risk | {medium:,} |",
                f"| High risk | {high:,} |",
            ]
        )
        if self.risk_counts.get("unknown", 0):
            lines.append(f"| Unknown risk | {self.risk_counts['unknown']:,} |")

        lines.extend(["", "## Recommended Next Actions"])
        if high:
            lines.append(f"- **Explicit approval required:** {high} high-risk recommendation(s).")
        if medium:
            lines.append(f"- **Validate before action:** {medium} medium-risk recommendation(s).")
        if low:
            lines.append(f"- **Fast-track candidate:** {low} low-risk recommendation(s), after standard checks.")
        if self.num_recommendations == 0:
            lines.append("- No actions recommended in this run.")

        lines.extend(["", f"## Top Recommendations (by estimated value / {self.value_period_label})", ""])
        if not self.top_recommendations:
            lines.extend(["_No recommendations generated._", ""])
        else:
            lines.append(
                f"| Rank | {self.item_label} | {self.item_type_label} | Action | Risk | Est. value | Rationale |"
            )
            lines.append("|---:|---|---|---|---|---:|---|")
            for index, recommendation in enumerate(self.top_recommendations, start=1):
                item_id = markdown_escape(_first_value(recommendation, self.item_id_fields, "item"))
                item_type = markdown_escape(_first_value(recommendation, self.item_type_fields, ""))
                action = markdown_escape(recommendation.get("action", ""))
                risk = markdown_escape(recommendation.get("risk", ""))
                value = _safe_float(recommendation.get(self.recommendation_value_field, 0.0))
                rationale = markdown_escape(recommendation.get("rationale", ""))
                lines.append(
                    f"| {index} | `{item_id}` | {item_type} | {action} | {risk} | {_fmt_money(value, self.currency_code)} | {rationale} |"
                )
            lines.append("")

        if self.notes:
            lines.append("## Notes")
            lines.extend(f"- {markdown_escape(note)}" for note in self.notes)
            lines.append("")
        return "\n".join(lines)


def build_roi_report(
    *,
    sentinel_result: Any,
    agent_output: Dict[str, Any],
    title: str,
    summary_value_field: str,
    recommendation_value_field: str,
    scope_summary_fields: Sequence[str],
    value_period_label: str,
    value_period_days: Optional[float],
    scope_label: str,
    item_label: str,
    item_type_label: str,
    item_id_fields: Sequence[str],
    item_type_fields: Sequence[str],
    executive_summary_subject: str,
    notes: Optional[List[str]] = None,
    top_n: int = 5,
) -> ROIReport:
    summary = agent_output.get("summary", {}) if isinstance(agent_output, dict) else {}
    recommendations = agent_output.get("recommendations", []) if isinstance(agent_output, dict) else []
    if not isinstance(summary, dict):
        summary = {}
    if not isinstance(recommendations, list):
        recommendations = []

    value = _safe_float(summary.get(summary_value_field, 0.0))
    currency_code = str(summary.get("currency", "USD") or "USD").upper()
    scope_count = int(_safe_float(_first_value(summary, scope_summary_fields, 0)))
    recommendation_count = int(
        _safe_float(summary.get("num_recommendations", len(recommendations)), len(recommendations))
    )

    snapshot = getattr(sentinel_result, "ctx_snapshot", {}) or {}
    run_cost = _safe_float(snapshot.get("state", {}).get("cost_usd", 0.0))
    outcome_object = getattr(sentinel_result, "outcome", "")
    outcome = getattr(outcome_object, "value", str(outcome_object))
    confidence = _safe_float(getattr(sentinel_result, "confidence", 0.0))

    sorted_recommendations = sorted(
        recommendations,
        key=lambda recommendation: (
            -_safe_float(recommendation.get(recommendation_value_field, 0.0)),
            _risk_rank(str(recommendation.get("risk", ""))),
        ),
    )
    top = sorted_recommendations[: max(0, int(top_n))]
    roi_multiple, roi_display = _compute_roi_multiple(run_cost, value)
    payback_days, payback_display = _compute_payback_display(
        run_cost, value, value_period_days
    )

    return ROIReport(
        title=title,
        generated_at_utc=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
        correlation_id=str(getattr(sentinel_result, "correlation_id", "")),
        run_id=str(getattr(sentinel_result, "run_id", "")),
        decision_outcome=outcome,
        decision_confidence=confidence,
        estimated_monthly_savings_usd=value,
        estimated_run_cost_usd=run_cost,
        roi_multiple_monthly=roi_multiple,
        roi_multiple_display=roi_display,
        payback_days=payback_days,
        payback_display=payback_display,
        num_resources_scanned=scope_count,
        num_recommendations=recommendation_count,
        risk_counts=_summarize_risks(recommendations),
        top_recommendations=top,
        notes=list(notes or []),
        value_period_label=value_period_label,
        scope_label=scope_label,
        item_label=item_label,
        item_type_label=item_type_label,
        recommendation_value_field=recommendation_value_field,
        item_id_fields=tuple(item_id_fields),
        item_type_fields=tuple(item_type_fields),
        executive_summary_subject=executive_summary_subject,
        currency_code=currency_code,
    )


def build_finops_roi_report(
    *,
    sentinel_result: Any,
    agent_output: Dict[str, Any],
    title: str = "Agent-ROI Report (FinOps)",
    top_n: int = 5,
) -> ROIReport:
    return build_roi_report(
        sentinel_result=sentinel_result,
        agent_output=agent_output,
        title=title,
        summary_value_field="est_total_monthly_savings_usd",
        recommendation_value_field="est_monthly_savings_usd",
        scope_summary_fields=("num_resources_scanned",),
        value_period_label="month",
        value_period_days=30.0,
        scope_label="Resources scanned",
        item_label="Resource",
        item_type_label="Type",
        item_id_fields=("resource_id", "id"),
        item_type_fields=("resource_type", "type"),
        executive_summary_subject="cloud cost-optimization recommendations",
        notes=[
            "Savings are estimates based on deterministic heuristics; validate them against current utilization and pricing data.",
            "High-risk infrastructure changes require explicit owner approval and a rollback plan.",
            "Audit events are stored in a tamper-evident append-only log for governance review.",
        ],
        top_n=top_n,
    )


def build_procurement_roi_report(
    *,
    sentinel_result: Any,
    agent_output: Dict[str, Any],
    title: str = "Agent-ROI Report (Procurement)",
    top_n: int = 5,
) -> ROIReport:
    return build_roi_report(
        sentinel_result=sentinel_result,
        agent_output=agent_output,
        title=title,
        summary_value_field="est_total_recoverable_value_usd",
        recommendation_value_field="est_recoverable_value_usd",
        scope_summary_fields=("num_records_scanned",),
        value_period_label="one-time",
        value_period_days=None,
        scope_label="Invoice records scanned",
        item_label="Invoice",
        item_type_label="Vendor",
        item_id_fields=("record_id", "invoice_id"),
        item_type_fields=("vendor",),
        executive_summary_subject="procurement leakage findings",
        notes=[
            "Recoverable value is an estimate and should be validated against contracts, payment status, and supporting evidence.",
            "No payment hold or vendor action should occur without accounts-payable approval.",
            "Audit events are stored in a tamper-evident append-only log for governance review.",
        ],
        top_n=top_n,
    )
