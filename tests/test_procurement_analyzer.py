from agent_roi.procurement import ProcurementLeakageAnalyzer
from agent_roi.policies import load_policy

def test_procurement_duplicate_detected():
    policy = load_policy("procurement_policy.yaml")
    analyzer = ProcurementLeakageAnalyzer(policy, {"program": "test"})
    payload = {
        "approved_vendors": ["A"],
        "baseline_unit_prices": {},
        "invoices": [
            {"record_id": "1", "vendor": "A", "invoice_id": "X", "amount_usd": 2000},
            {"record_id": "2", "vendor": "A", "invoice_id": "X", "amount_usd": 2000},
        ],
    }
    out = analyzer.analyze(payload)
    assert out["summary"]["num_recommendations"] >= 1
