from __future__ import annotations

import csv
from dataclasses import dataclass
import math
import os
from pathlib import Path
from typing import Any, Dict, List

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
    resource: Dict[str, Any]


class FinOpsAnalyzer:
    """Deterministic cloud-cost opportunity analyzer."""

    def __init__(self, policy: Policy, business_context: Dict[str, Any]) -> None:
        self.policy = policy
        self.ctx = dict(business_context)
        self.multipliers = policy.data.get("scoring", {}).get("savings_multipliers", {})
        self.thresholds = policy.data.get("thresholds", {})
        self.routing = policy.data.get("approval_routing", {})

    def approval_status(self, resource: Dict[str, Any], risk: str) -> str:
        environment = str(resource.get("environment") or "").lower()
        risk_value = str(risk or "").lower()
        production_risks = set(
            self.routing.get("production_requires_approval_for_risk") or []
        )
        if environment == "production" and risk_value in production_risks:
            return "owner_approval_required"
        return "auto_approve_candidate"

    def analyze(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(payload, dict):
            raise TypeError("payload must be a mapping")
        resources = payload.get("resources", [])
        if not isinstance(resources, list):
            raise TypeError("payload.resources must be a list")

        findings: List[Finding] = []
        for index, resource in enumerate(resources):
            if not isinstance(resource, dict):
                raise TypeError(f"resources[{index}] must be a mapping")

            resource_type = resource.get("type")
            cost = _nonnegative_float(
                resource.get("monthly_cost_usd", 0.0),
                f"resources[{index}].monthly_cost_usd",
            )
            utilization = _nonnegative_float(
                resource.get("utilization_pct", 0.0),
                f"resources[{index}].utilization_pct",
            )
            idle_days = int(
                _nonnegative_float(
                    resource.get("days_idle", 0), f"resources[{index}].days_idle"
                )
            )

            if resource_type == "ec2_instance":
                threshold = self.thresholds.get("underutilized_compute", {})
                if utilization < float(
                    threshold.get("utilization_pct_lt", 10.0)
                ) and cost > float(threshold.get("monthly_cost_usd_gt", 200.0)):
                    action = "rightsizing_recommendation"
                    savings = round(cost * float(self.multipliers.get(action, 0.35)), 2)
                    risk = (
                        "med"
                        if str(resource.get("environment", "")).lower() == "production"
                        else "low"
                    )
                    findings.append(
                        Finding(
                            finding_type="underutilized_compute",
                            severity="high",
                            evidence={
                                "utilization_pct": utilization,
                                "monthly_cost_usd": cost,
                            },
                            recommendation={
                                "action": action,
                                "est_monthly_savings_usd": savings,
                                "risk": risk,
                                "rationale": f"Low utilization ({utilization:.1f}%). Recommend downsizing.",
                            },
                            resource=resource,
                        )
                    )
                    continue

                threshold = self.thresholds.get("idle_compute", {})
                if idle_days >= int(threshold.get("idle_days_gte", 14)) and cost > float(
                    threshold.get("monthly_cost_usd_gt", 50.0)
                ):
                    action = "scheduled_stop"
                    savings = round(cost * float(self.multipliers.get(action, 0.65)), 2)
                    findings.append(
                        Finding(
                            finding_type="idle_compute",
                            severity="medium",
                            evidence={"days_idle": idle_days, "monthly_cost_usd": cost},
                            recommendation={
                                "action": action,
                                "est_monthly_savings_usd": savings,
                                "risk": "low",
                                "rationale": f"Idle for {idle_days} days. Recommend a stop schedule.",
                            },
                            resource=resource,
                        )
                    )
                    continue

            if resource_type == "ebs_volume":
                attached = bool(resource.get("attached", True))
                if not attached and idle_days >= 7 and cost > 10:
                    action = "snapshot_then_delete"
                    savings = round(cost * float(self.multipliers.get(action, 0.90)), 2)
                    findings.append(
                        Finding(
                            finding_type="orphaned_storage",
                            severity="medium",
                            evidence={"attached": False, "days_idle": idle_days},
                            recommendation={
                                "action": action,
                                "est_monthly_savings_usd": savings,
                                "risk": "low",
                                "rationale": "Unattached volume. Snapshot, validate, then delete.",
                            },
                            resource=resource,
                        )
                    )
                    continue

            if resource_type == "rds_instance":
                threshold = self.thresholds.get("underutilized_database", {})
                if utilization < float(
                    threshold.get("utilization_pct_lt", 5.0)
                ) and cost > float(threshold.get("monthly_cost_usd_gt", 300.0)):
                    action = "rightsizing_recommendation"
                    savings = round(cost * float(self.multipliers.get(action, 0.30)), 2)
                    findings.append(
                        Finding(
                            finding_type="underutilized_database",
                            severity="high",
                            evidence={
                                "utilization_pct": utilization,
                                "monthly_cost_usd": cost,
                            },
                            recommendation={
                                "action": action,
                                "est_monthly_savings_usd": savings,
                                "risk": "high",
                                "rationale": f"Very low utilization ({utilization:.1f}%). Owner validation required.",
                            },
                            resource=resource,
                        )
                    )
                    continue

            if resource_type == "s3_bucket":
                threshold = self.thresholds.get("large_bucket", {})
                storage_gb = _nonnegative_float(
                    resource.get("storage_gb", 0), f"resources[{index}].storage_gb"
                )
                if storage_gb > float(threshold.get("storage_gb_gt", 5000)):
                    action = "lifecycle_policy_to_infrequent_access"
                    savings = round(cost * float(self.multipliers.get(action, 0.20)), 2)
                    findings.append(
                        Finding(
                            finding_type="storage_tiering_opportunity",
                            severity="low",
                            evidence={
                                "storage_gb": storage_gb,
                                "monthly_cost_usd": cost,
                            },
                            recommendation={
                                "action": action,
                                "est_monthly_savings_usd": savings,
                                "risk": "low",
                                "rationale": "Large bucket. Add a lifecycle policy for lower-cost storage tiers.",
                            },
                            resource=resource,
                        )
                    )

        recommendations: List[Dict[str, Any]] = []
        for finding in findings:
            resource = finding.resource
            recommendation = dict(finding.recommendation)
            recommendation.update(
                {
                    "resource_id": resource.get("id"),
                    "resource_type": resource.get("type"),
                    "environment": resource.get("environment"),
                    "owner": resource.get("owner", "unknown"),
                    "approval_status": self.approval_status(
                        resource, recommendation.get("risk", "")
                    ),
                }
            )
            recommendations.append(recommendation)

        total_savings = round(
            sum(
                _nonnegative_float(
                    recommendation.get("est_monthly_savings_usd", 0.0),
                    "recommendation.est_monthly_savings_usd",
                )
                for recommendation in recommendations
            ),
            2,
        )
        return {
            "summary": {
                "program": self.ctx.get("program", "Cloud Cost Governance"),
                "reporting_period": self.ctx.get("reporting_period"),
                "currency": self.ctx.get("currency", "USD"),
                "num_resources_scanned": len(resources),
                "num_findings": len(findings),
                "num_recommendations": len(recommendations),
                "est_total_monthly_savings_usd": total_savings,
                "value_period": "monthly",
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
        fieldnames = [
            "resource_id",
            "resource_type",
            "environment",
            "owner",
            "action",
            "risk",
            "approval_status",
            "est_monthly_savings_usd",
            "rationale",
        ]
        if not isinstance(recommendations, list):
            raise TypeError("agent_output.recommendations must be a list")
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
