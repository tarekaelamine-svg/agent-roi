import importlib.util
from pathlib import Path

from agent_roi.cli.sentinel import main as cli_main


ROOT = Path(__file__).resolve().parents[1]


def _load_example(filename: str):
    path = ROOT / "examples" / filename
    spec = importlib.util.spec_from_file_location(path.stem, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _assert_artifacts(path: Path):
    expected = {
        "audit.jsonl",
        "executive_brief.md",
        "manifest.json",
        "recommendations.csv",
        "roi_report.md",
    }
    assert expected <= {item.name for item in path.iterdir()}


def test_cli_runs_with_custom_outdir(tmp_path: Path):
    outdir = tmp_path / "cli"
    assert cli_main(["--mode", "accept", "--outdir", str(outdir)]) == 0
    _assert_artifacts(outdir)


def test_finops_demo_runs(tmp_path: Path):
    module = _load_example("demo_finops_cost_governance.py")
    outdir = tmp_path / "finops"
    assert module.main(outdir=outdir) == outdir
    _assert_artifacts(outdir)


def test_procurement_demo_runs_and_uses_procurement_report(tmp_path: Path):
    module = _load_example("demo_procurement_spend_leakage.py")
    outdir = tmp_path / "procurement"
    assert module.main(outdir=outdir) == outdir
    _assert_artifacts(outdir)
    report = (outdir / "roi_report.md").read_text(encoding="utf-8")
    assert "procurement leakage findings" in report
    assert "one-time" in report


def test_enterprise_p0_demo_runs(tmp_path: Path):
    module = _load_example("demo_enterprise_p0.py")
    outdir = tmp_path / "enterprise"
    summary = module.run_demo(outdir)
    assert summary["decision_outcome"] == "accept"
    assert summary["policy_signature_verified"] is True
    assert summary["audit_events_verified"] >= 9
    assert (outdir / "enterprise-summary.json").is_file()
    assert (outdir / "control-plane.sqlite3").is_file()
    assert (outdir / "roi-ledger.sqlite3").is_file()
