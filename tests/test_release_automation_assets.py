from __future__ import annotations

from pathlib import Path
import subprocess
import sys

import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_release_workflows_are_present_and_parse() -> None:
    workflows = ROOT / ".github" / "workflows"
    expected = {"ci.yml", "testpypi.yml", "release.yml", "container.yml", "codeql.yml"}
    assert expected <= {path.name for path in workflows.glob("*.yml")}
    for path in workflows.glob("*.yml"):
        parsed = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert isinstance(parsed, dict)
        assert "jobs" in parsed
        assert "permissions" in parsed
    release = (workflows / "release.yml").read_text()
    assert "pypa/gh-action-pypi-publish@release/v1" in release
    assert "id-token: write" in release
    container = (workflows / "container.yml").read_text()
    assert "actions/attest@v4" in container
    assert "sbom: true" in container


def test_helm_chart_supports_immutable_images_and_production_controls() -> None:
    chart = ROOT / "deployment" / "helm" / "agent-roi"
    helpers = (chart / "templates" / "_helpers.tpl").read_text()
    deployment = (chart / "templates" / "deployment.yaml").read_text()
    values = yaml.safe_load((chart / "values.yaml").read_text())
    assert "repository@" not in helpers  # rendered through printf rather than hard-coded text
    assert 'printf "%s@%s"' in helpers
    assert 'include "agent-roi.image"' in deployment
    assert "AGENT_ROI_SIGNING_PROVIDER" in deployment
    assert values["image"]["digest"] == ""
    assert (chart / "templates" / "networkpolicy.yaml").is_file()
    assert (chart / "templates" / "hpa.yaml").is_file()
    assert (chart / "templates" / "ingress.yaml").is_file()
    production = yaml.safe_load((chart / "values-production.example.yaml").read_text())
    assert production["image"]["digest"].startswith("sha256:")
    assert production["networkPolicy"]["enabled"] is True


def test_container_installs_enterprise_runtime_and_release_script_validates() -> None:
    dockerfile = (ROOT / "deployment" / "docker" / "Dockerfile").read_text()
    assert '${WHEEL}[enterprise]' in dockerfile
    result = subprocess.run(
        [sys.executable, "scripts/verify_release.py"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=True,
    )
    assert "release validation passed" in result.stdout


def test_vscode_release_assets_and_runbook_are_packaged() -> None:
    assert (ROOT / ".vscode" / "tasks.json").is_file()
    assert (ROOT / "scripts" / "prepare_release.ps1").is_file()
    runbook = (ROOT / "docs" / "VS_CODE_PRODUCTION_RELEASE.md").read_text()
    assert "Trusted Publishing" in runbook
    assert "helm upgrade --install" in runbook
    assert "v2.0.1" in runbook
