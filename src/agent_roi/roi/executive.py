from __future__ import annotations

from datetime import datetime, timezone
import math
from typing import Any, Dict, List, Sequence

from agent_roi._serialization import markdown_escape


def _safe_float(value: Any) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0.0
    return number if math.isfinite(number) else 0.0


def _fmt_money(value: float, currency_code: str) -> str:
    code = str(currency_code or "USD").strip().upper()
    symbols = {"USD": "$", "EUR": "€", "GBP": "£", "JPY": "¥"}
    symbol = symbols.get(code)
    return f"{symbol}{value:,.2f}" if symbol else f"{code} {value:,.2f}"


def build_executive_brief(
    *,
    title: str,
    business_context: Dict[str, Any],
    sentinel_result: Any,
    agent_output: Dict[str, Any],
    top_n: int = 5,
    summary_value_field: str = "est_total_monthly_savings_usd",
    recommendation_value_field: str = "est_monthly_savings_usd",
    value_label: str = "Estimated savings identified",
    value_period_label: str = "month",
    item_id_fields: Sequence[str] = ("resource_id", "record_id", "id"),
) -> str:
    summary = agent_output.get("summary", {}) if isinstance(agent_output, dict) else {}
    recommendations = agent_output.get("recommendations", []) if isinstance(agent_output, dict) else []
    if not isinstance(summary, dict):
        summary = {}
    if not isinstance(recommendations, list):
        recommendations = []

    recommendations = sorted(
        [item for item in recommendations if isinstance(item, dict)],
        key=lambda item: _safe_float(item.get(recommendation_value_field, 0.0)),
        reverse=True,
    )
    top = recommendations[: max(0, int(top_n))]
    outcome_object = getattr(sentinel_result, "outcome", "")
    outcome = getattr(outcome_object, "value", str(outcome_object))
    confidence = _safe_float(getattr(sentinel_result, "confidence", 0.0))
    value = _safe_float(summary.get(summary_value_field, 0.0))
    currency = str(
        summary.get("currency", business_context.get("currency", "USD")) or "USD"
    ).upper()
    period_suffix = "" if value_period_label == "one-time" else f"/{value_period_label}"

    lines: List[str] = [
        f"# {markdown_escape(title)}",
        "",
        f"**Generated (UTC):** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}",
        f"**Program:** {markdown_escape(business_context.get('program', ''))}",
        f"**Reporting Period:** {markdown_escape(business_context.get('reporting_period', ''))}",
        "",
        "## Key Takeaways",
        f"- {markdown_escape(value_label)}: **{_fmt_money(value, currency)}{period_suffix}**",
        f"- Governance decision: **{markdown_escape(outcome)}** (confidence **{confidence:.3f}**)",
        f"- Recommendations produced: **{int(_safe_float(summary.get('num_recommendations', len(recommendations))))}**",
        "",
        "## Top Opportunities",
    ]

    if not top:
        lines.append("_No recommendations generated._")
    else:
        for recommendation in top:
            item_id: Any = "item"
            for field in item_id_fields:
                if recommendation.get(field) not in (None, ""):
                    item_id = recommendation[field]
                    break
            action = markdown_escape(recommendation.get("action", ""))
            risk = markdown_escape(recommendation.get("risk", ""))
            item_value = _safe_float(recommendation.get(recommendation_value_field, 0.0))
            lines.append(
                f"- **{action}** on `{markdown_escape(item_id)}` — "
                f"**{_fmt_money(item_value, currency)}{period_suffix}** (risk: `{risk}`)"
            )

    lines.extend(
        [
            "",
            "## Controls Applied",
            "- Pre-execution tool allowlisting and registered-handler binding",
            "- Step, tool-call, and cost ceilings",
            "- Payload-bound approval checkpoints",
            "- Confidence-based output routing",
            "- Cross-process-safe tamper-evident audit logging with sensitive-field redaction",
            "",
            "## Assumptions",
        ]
    )
    assumptions = business_context.get("assumptions", [])
    if not isinstance(assumptions, (list, tuple)):
        assumptions = [assumptions]
    lines.extend(f"- {markdown_escape(assumption)}" for assumption in assumptions)
    lines.append("")
    return "\n".join(lines)
