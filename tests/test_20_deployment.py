from __future__ import annotations

from pathlib import Path


def test_deployment_assets_cover_supported_clouds_and_kubernetes() -> None:
    root = Path(__file__).resolve().parents[1] / "deployment"
    required = [
        root / "docker" / "Dockerfile",
        root / "docker" / "docker-compose.yml",
        root / "helm" / "agent-roi" / "Chart.yaml",
        root / "helm" / "agent-roi" / "values.yaml",
        root / "helm" / "agent-roi" / "templates" / "deployment.yaml",
        root / "helm" / "agent-roi" / "templates" / "migration-job.yaml",
        root / "terraform" / "aws" / "main.tf",
        root / "terraform" / "azure" / "main.tf",
        root / "terraform" / "gcp" / "main.tf",
    ]
    missing = [str(path) for path in required if not path.is_file()]
    assert missing == []


def test_container_and_helm_defaults_are_non_root_and_health_aware() -> None:
    root = Path(__file__).resolve().parents[1] / "deployment"
    dockerfile = (root / "docker" / "Dockerfile").read_text()
    deployment = (root / "helm" / "agent-roi" / "templates" / "deployment.yaml").read_text()
    values = (root / "helm" / "agent-roi" / "values.yaml").read_text()
    assert "USER agentroi" in dockerfile
    assert "runAsNonRoot: true" in deployment
    assert "readOnlyRootFilesystem: true" in deployment
    assert "readinessProbe:" in deployment
    assert "livenessProbe:" in deployment
    assert "postgres:" in values.lower()
    assert "oidc:" in values.lower()


def test_manifest_includes_migrations_and_deployment_assets() -> None:
    root = Path(__file__).resolve().parents[1]
    manifest = (root / "MANIFEST.in").read_text()
    assert "recursive-include src/agent_roi/migrations *.sql" in manifest
    assert "recursive-include deployment" in manifest


def test_terraform_assets_use_canonical_hcl_without_semicolon_compaction() -> None:
    root = Path(__file__).resolve().parents[1] / "deployment" / "terraform"
    for path in root.rglob("*.tf"):
        text = path.read_text()
        assert ";" not in text, path
        assert text.count("{") == text.count("}"), path
        assert 'required_version = ">= 1.6.0"' in (path.parent / "main.tf").read_text()


def test_helm_service_account_supports_cloud_workload_identity() -> None:
    root = Path(__file__).resolve().parents[1] / "deployment" / "helm" / "agent-roi"
    values = (root / "values.yaml").read_text()
    service_account = (root / "templates" / "serviceaccount.yaml").read_text()
    assert "serviceAccount:" in values
    assert "annotations: {}" in values
    assert "automountServiceAccountToken: false" in values
    assert ".Values.serviceAccount.annotations" in service_account
    assert ".Values.serviceAccount.automountServiceAccountToken" in service_account
