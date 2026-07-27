from agent_roi.roi.report import build_finops_roi_report


class DummyOutcome:
    value = "accept"


class DummyResult:
    outcome = DummyOutcome()
    confidence = 0.9
    correlation_id = "c"
    run_id = "r"
    ctx_snapshot = {"state": {"cost_usd": 1.0}}


def test_roi_sort_prefers_low_risk_on_tie():
    output = {
        "summary": {
            "num_resources_scanned": 2,
            "num_recommendations": 2,
            "est_total_monthly_savings_usd": 200,
        },
        "recommendations": [
            {
                "est_monthly_savings_usd": 100,
                "risk": "high",
                "resource_id": "A",
            },
            {
                "est_monthly_savings_usd": 100,
                "risk": "low",
                "resource_id": "B",
            },
        ],
    }
    report = build_finops_roi_report(
        sentinel_result=DummyResult(), agent_output=output, top_n=2
    )
    assert report.top_recommendations[0]["resource_id"] == "B"
