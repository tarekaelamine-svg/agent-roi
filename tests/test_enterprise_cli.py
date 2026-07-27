from __future__ import annotations

import argparse
from pathlib import Path

import pytest

from agent_roi.cli.control_plane import build_app


def test_control_plane_cli_builds_durable_app(tmp_path: Path, monkeypatch) -> None:
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    monkeypatch.setenv("AGENT_ROI_POLICY_SIGNING_KEY", "x" * 32)
    args = argparse.Namespace(
        data_dir=str(tmp_path / "data"),
        signing_key_file="",
        signing_key_id="test-key",
        allow_unauthenticated=True,
        oidc_issuer="",
        oidc_audience="",
        oidc_jwks_url="",
        oidc_organization_claim="org_id",
        oidc_roles_claim="roles",
        oidc_groups_claim="groups",
    )
    app = build_app(args)
    assert TestClient(app).get("/healthz").json() == {"status": "ok"}
    assert (tmp_path / "data" / "control-plane.sqlite3").exists()
    assert (tmp_path / "data" / "identity.sqlite3").exists()
    assert (tmp_path / "data" / "roi-ledger.sqlite3").exists()
    assert (tmp_path / "data" / "audit.sqlite3").exists()


def test_control_plane_cli_requires_oidc_by_default(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("AGENT_ROI_POLICY_SIGNING_KEY", "x" * 32)
    args = argparse.Namespace(
        data_dir=str(tmp_path),
        signing_key_file="",
        signing_key_id="test-key",
        allow_unauthenticated=False,
        oidc_issuer="",
        oidc_audience="",
        oidc_jwks_url="",
        oidc_organization_claim="org_id",
        oidc_roles_claim="roles",
        oidc_groups_claim="groups",
    )
    with pytest.raises(ValueError, match="OIDC"):
        build_app(args)
