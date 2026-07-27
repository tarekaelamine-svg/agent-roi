from __future__ import annotations

import argparse
import json

import pytest

from agent_roi.cli import outbox as outbox_cli
from agent_roi.cli import control_plane as control_plane_cli


def test_outbox_cli_rejects_missing_and_invalid_configuration(monkeypatch) -> None:
    monkeypatch.delenv("AGENT_ROI_POSTGRES_DSN", raising=False)
    with pytest.raises(SystemExit, match="AGENT_ROI_POSTGRES_DSN"):
        outbox_cli.main(["--once"])
    with pytest.raises(SystemExit, match="JSON object"):
        outbox_cli.main(["--dsn", "postgresql://test", "--destinations-json", "["])
    with pytest.raises(SystemExit, match="At least one"):
        outbox_cli.main(["--dsn", "postgresql://test", "--destinations-json", "{}"])


def test_outbox_cli_runs_one_batch(monkeypatch, capsys) -> None:
    captured: dict[str, object] = {}

    class FakeStore:
        def __init__(self, dsn: str, *, schema: str) -> None:
            captured["store"] = (dsn, schema)

    class FakeHandler:
        def __init__(self, endpoint: str) -> None:
            captured.setdefault("endpoints", []).append(endpoint)

    class FakeWorker:
        def __init__(self, store, handlers, *, retry_policy) -> None:
            captured["handlers"] = sorted(handlers)
            captured["attempts"] = retry_policy.max_attempts

        def run_once(self, *, limit: int):
            captured["limit"] = limit
            return {"claimed": 1, "delivered": 1, "retried": 0, "dead_lettered": 0}

    monkeypatch.setattr(outbox_cli, "PostgresOutboxStore", FakeStore)
    monkeypatch.setattr(outbox_cli, "JsonHttpOutboxHandler", FakeHandler)
    monkeypatch.setattr(outbox_cli, "OutboxWorker", FakeWorker)
    assert outbox_cli.main(
        [
            "--dsn",
            "postgresql://test",
            "--schema",
            "enterprise",
            "--destinations-json",
            json.dumps({"siem": "https://siem.example/events"}),
            "--batch-size",
            "7",
            "--once",
        ]
    ) == 0
    assert captured["store"] == ("postgresql://test", "enterprise")
    assert captured["handlers"] == ["siem"]
    assert captured["limit"] == 7
    assert json.loads(capsys.readouterr().out)["delivered"] == 1


def test_control_plane_postgres_build_uses_explicit_migration_mode(monkeypatch, tmp_path) -> None:
    pytest.importorskip("fastapi")
    events: list[tuple] = []

    class Factory:
        def __init__(self, dsn: str, *, schema: str) -> None:
            events.append(("factory", dsn, schema))

    class Migrator:
        def __init__(self, factory) -> None:
            events.append(("manager", factory))

        def migrate(self):
            events.append(("migrate",))
            return (1, 2, 3, 4, 5)

    class Store:
        def __init__(self, dsn: str, *, schema: str, auto_migrate: bool) -> None:
            events.append((type(self).__name__, dsn, schema, auto_migrate))

    class Identity(Store):
        def save_role(self, role) -> None:
            events.append(("role", role.name))

        def list_roles(self):
            return ()

        def list_bindings(self, organization_id=""):
            return ()

    class Audit:
        def __init__(self, dsn: str, *, schema: str, initialize: bool) -> None:
            events.append(("audit", dsn, schema, initialize))

    monkeypatch.setattr(control_plane_cli, "PostgresConnectionFactory", Factory)
    monkeypatch.setattr(control_plane_cli, "PostgresMigrationManager", Migrator)
    monkeypatch.setattr(control_plane_cli, "PostgresControlPlaneStore", Store)
    monkeypatch.setattr(control_plane_cli, "PostgresIdentityStore", Identity)
    monkeypatch.setattr(control_plane_cli, "PostgresROILedger", Store)
    monkeypatch.setattr(control_plane_cli, "PostgresAuditStore", Audit)
    monkeypatch.setenv("AGENT_ROI_POLICY_SIGNING_KEY", "x" * 32)
    args = argparse.Namespace(
        data_dir=str(tmp_path),
        signing_key_file="",
        signing_key_id="test",
        postgres_dsn="postgresql://test",
        postgres_schema="enterprise",
        auto_migrate=True,
        allow_unauthenticated=True,
        oidc_issuer="",
        oidc_audience="",
        oidc_jwks_url="",
        oidc_organization_claim="org_id",
        oidc_roles_claim="roles",
        oidc_groups_claim="groups",
    )
    app = control_plane_cli.build_app(args)
    assert app.state.agent_roi["database_backend"] == "postgres"
    assert ("migrate",) in events
    assert ("audit", "postgresql://test", "enterprise", False) in events
