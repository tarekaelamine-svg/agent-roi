from __future__ import annotations

import csv
from dataclasses import dataclass
import math
import os
from pathlib import Path
from typing import Any, Dict, List, Tuple

from agent_roi.policies.loader import Policy
from agent_roi._serialization import csv_safe


def _nonnegative_float(value: Any, field_name: str) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field_name} must be numeric") from exc
    if not math.isfinite(number) or number < 0:
        raise ValueError(f"{field_name} must be finite and nonnegative")
    return number


@dataclass(frozen=True)
class Finding:
    finding_type: str
    severity: str
    evidence: Dict[str, Any]
    recommendation: Dict[str, Any]
    record: Dict[str, Any]
    record_index: int


class ProcurementLeakageAnalyzer:
    """Deterministic procurement leakage analyzer with deduplicated recovery."""

    _PRIORITY = {
        "duplicate_invoice": 0,
        "price_variance": 1,
        "unapproved_vendor": 2,
        "missing_invoice_id": 3,
    }

    def __init__(self, policy: Policy, business_context: Dict[str, Any]) -> None:
        self.policy = policy
        self.ctx = dict(business_context)
        self.thresholds = policy.data.get("thresholds", {})
        self.multipliers = policy.data.get("scoring", {}).get("savings_multipliers", {})
        self.routing = policy.data.get("approval_routing", {})

    def approval_status(self, invoice: Dict[str, Any], risk: str) -> str:
        risk_value = str(risk or "").strip().lower()
        if risk_value == "medium":
            risk_value = "med"
        general = {
            str(value).strip().lower()
            for value in self.routing.get("requires_approval_for_risk", [])
        }
        production = {
            str(value).strip().lower()
            for value in self.routing.get("production_requires_approval_for_risk", [])
        }
        environment = str(
            invoice.get("environment", self.ctx.get("environment", ""))
        ).strip().lower()
        if risk_value in general or (
            environment == "production" and risk_value in production
        ):
            return "procurement_approval_required"
        return "auto_approve_candidate"

    @staticmethod
    def _approved_vendor_set(value: Any) -> set[str]:
        if value is None:
            return set()
        if isinstance(value, str) or not isinstance(
            value, (list, tuple, set, frozenset)
        ):
            raise TypeError("payload.approved_vendors must be a list or set of vendor names")
        approved: set[str] = set()
        for vendor in value:
            if not isinstance(vendor, str):
                raise TypeError("payload.approved_vendors must contain only strings")
            if vendor.strip():
                approved.add(vendor.strip().casefold())
        return approved

    def analyze(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(payload, dict):
            raise TypeError("payload must be a mapping")
        invoices = payload.get("invoices", [])
        if not isinstance(invoices, list):
            raise TypeError("payload.invoices must be a list")

        approved_vendors = self._approved_vendor_set(payload.get("approved_vendors", []))
        baseline_prices = payload.get("baseline_unit_prices", {})
        if not isinstance(baseline_prices, dict):
            raise TypeError("payload.baseline_unit_prices must be a mapping")

        findings: List[Finding] = []
        seen: set[Tuple[str, str, float]] = set()
        duplicate_threshold = self.thresholds.get("duplicate_invoice", {})
        duplicate_amount = float(duplicate_threshold.get("amount_usd_gt", 1000.0))

        invoice_amounts: Dict[int, float] = {}
        for index, invoice in enumerate(invoices):
            if not isinstance(invoice, dict):
                raise TypeError(f"invoices[{index}] must be a mapping")

            vendor = str(invoice.get("vendor", "unknown")).strip()
            invoice_id = str(invoice.get("invoice_id", "")).strip()
            amount = _nonnegative_float(
                invoice.get("amount_usd", 0.0), f"invoices[{index}].amount_usd"
            )
            invoice_amounts[index] = amount

            if not invoice_id:
                findings.append(
                    Finding(
                        finding_type="invoice_data_quality",
                        severity="medium",
                        evidence={"missing_field": "invoice_id", "vendor": vendor},
                        recommendation={
                            "action": "missing_invoice_id",
                            "est_recoverable_value_usd": 0.0,
                            "risk": "med",
                            "rationale": "Invoice ID is missing. Resolve the data-quality issue before duplicate-payment analysis.",
                        },
                        record=invoice,
                        record_index=index,
                    )
                )
            else:
                signature = (vendor.casefold(), invoice_id.casefold(), amount)
                if signature in seen and amount > duplicate_amount:
                    action = "duplicate_invoice"
                    gross = round(amount * float(self.multipliers.get(action, 1.0)), 2)
                    findings.append(
                        Finding(
                            finding_type="duplicate_payment_risk",
                            severity="high",
                            evidence={
                                "vendor": vendor,
                                "invoice_id": invoice_id,
                                "amount_usd": amount,
                            },
                            recommendation={
                                "action": action,
                                "est_recoverable_value_usd": gross,
                                "risk": "high",
                                "rationale": "Duplicate invoice signature detected. Validate payment status before placing any hold.",
                            },
                            record=invoice,
                            record_index=index,
                        )
                    )
                else:
                    seen.add(signature)

            if self.thresholds.get("unapproved_vendor", {}).get("always_flag", True):
                if vendor.casefold() not in approved_vendors and vendor.casefold() != "unknown":
                    action = "unapproved_vendor"
                    gross = round(amount * float(self.multipliers.get(action, 0.40)), 2)
                    findings.append(
                        Finding(
                            finding_type="vendor_compliance_risk",
                            severity="medium",
                            evidence={"vendor": vendor},
                            recommendation={
                                "action": action,
                                "est_recoverable_value_usd": gross,
                                "risk": "med",
                                "rationale": "Vendor is not on the approved list. Validate onboarding and contract status.",
                            },
                            record=invoice,
                            record_index=index,
                        )
                    )

            sku = invoice.get("sku")
            quantity = _nonnegative_float(invoice.get("qty", 0), f"invoices[{index}].qty")
            if sku in baseline_prices and quantity > 0:
                baseline = _nonnegative_float(
                    baseline_prices[sku], f"baseline_unit_prices[{sku!r}]"
                )
                unit_price = _nonnegative_float(
                    invoice.get("unit_price_usd", 0), f"invoices[{index}].unit_price_usd"
                )
                percent_over = ((unit_price - baseline) / baseline) * 100.0 if baseline > 0 else 0.0
                variance_threshold = self.thresholds.get("price_variance", {})
                if percent_over > float(variance_threshold.get("pct_gt", 15.0)):
                    action = "price_variance"
                    delta_total = max(0.0, (unit_price - baseline) * quantity)
                    gross = round(delta_total * float(self.multipliers.get(action, 0.60)), 2)
                    findings.append(
                        Finding(
                            finding_type="price_variance",
                            severity="high",
                            evidence={
                                "sku": sku,
                                "baseline_unit_price": baseline,
                                "unit_price": unit_price,
                                "pct_over": round(percent_over, 1),
                            },
                            recommendation={
                                "action": action,
                                "est_recoverable_value_usd": gross,
                                "risk": "high",
                                "rationale": f"Unit price is {percent_over:.1f}% above baseline. Validate contract terms before initiating a dispute.",
                            },
                            record=invoice,
                            record_index=index,
                        )
                    )

        # Allocate recoverable value once per invoice. Multiple categories remain
        # visible, but their deduplicated values cannot exceed the invoice amount.
        grouped: Dict[int, List[Finding]] = {}
        for finding in findings:
            grouped.setdefault(finding.record_index, []).append(finding)

        recommendations: List[Dict[str, Any]] = []
        for record_index, record_findings in grouped.items():
            remaining = invoice_amounts.get(record_index, 0.0)
            ordered = sorted(
                record_findings,
                key=lambda item: self._PRIORITY.get(
                    str(item.recommendation.get("action", "")), 99
                ),
            )
            for finding in ordered:
                invoice = finding.record
                recommendation = dict(finding.recommendation)
                gross = _nonnegative_float(
                    recommendation.get("est_recoverable_value_usd", 0.0),
                    "recommendation.est_recoverable_value_usd",
                )
                allocated = round(min(gross, remaining), 2)
                remaining = round(max(0.0, remaining - allocated), 2)
                recommendation.update(
                    {
                        "record_id": invoice.get("record_id"),
                        "vendor": invoice.get("vendor"),
                        "invoice_id": invoice.get("invoice_id"),
                        "business_unit": invoice.get("business_unit", "unknown"),
                        "finding_type": finding.finding_type,
                        "approval_status": self.approval_status(
                            invoice, recommendation.get("risk", "")
                        ),
                        "gross_est_recoverable_value_usd": round(gross, 2),
                        "est_recoverable_value_usd": allocated,
                        "overlap_adjustment_usd": round(gross - allocated, 2),
                    }
                )
                recommendations.append(recommendation)

        total_recoverable = round(
            sum(
                _nonnegative_float(
                    recommendation.get("est_recoverable_value_usd", 0.0),
                    "recommendation.est_recoverable_value_usd",
                )
                for recommendation in recommendations
            ),
            2,
        )
        total_invoice_value = round(sum(invoice_amounts.values()), 2)
        return {
            "summary": {
                "program": self.ctx.get("program", "Procurement Spend Leakage"),
                "reporting_period": self.ctx.get("reporting_period"),
                "currency": self.ctx.get("currency", "USD"),
                "num_records_scanned": len(invoices),
                "num_findings": len(findings),
                "num_recommendations": len(recommendations),
                "total_invoice_value_usd": total_invoice_value,
                "est_total_recoverable_value_usd": min(total_recoverable, total_invoice_value),
                "value_period": "one_time",
            },
            "recommendations": recommendations,
            "assumptions": self.ctx.get("assumptions", []),
        }

    def export_recommendations_csv(
        self, agent_output: Dict[str, Any], out_path: str | Path
    ) -> Path:
        path = Path(out_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        recommendations = agent_output.get("recommendations", []) or []
        if not isinstance(recommendations, list):
            raise TypeError("agent_output.recommendations must be a list")
        fieldnames = [
            "record_id",
            "vendor",
            "invoice_id",
            "business_unit",
            "finding_type",
            "action",
            "risk",
            "approval_status",
            "gross_est_recoverable_value_usd",
            "overlap_adjustment_usd",
            "est_recoverable_value_usd",
            "rationale",
        ]
        temporary = path.with_name(path.name + ".tmp")
        with temporary.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            writer.writeheader()
            for recommendation in recommendations:
                if not isinstance(recommendation, dict):
                    raise TypeError("recommendations must contain mappings")
                writer.writerow(
                    {key: csv_safe(recommendation.get(key, "")) for key in fieldnames}
                )
        temporary.replace(path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        return path
