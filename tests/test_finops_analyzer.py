from agent_roi.finops import FinOpsAnalyzer
from agent_roi.policies import load_policy

def test_finops_generates_recommendations():
    policy = load_policy("finops_policy.yaml")
    analyzer = FinOpsAnalyzer(policy, {"program": "test"})
    payload = {
        "resources": [
            {"id": "i1", "type": "ec2_instance", "monthly_cost_usd": 500,
             "utilization_pct": 5, "environment": "production"}
        ]
    }
    out = analyzer.analyze(payload)
    assert out["summary"]["num_recommendations"] >= 1
