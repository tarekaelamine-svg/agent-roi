from __future__ import annotations

import argparse
import base64
import builtins
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from agent_roi.cli import control_plane, database, outbox, sentinel


class Identity:
    def __init__(self,*a,**k): self.roles=[]
    def save_role(self,role): self.roles.append(role)


class App:
    def __init__(self): self.state=SimpleNamespace()


def ns(tmp_path,**overrides):
    data=dict(data_dir=str(tmp_path),signing_key_file="",signing_key_id="key",postgres_dsn="",postgres_schema="agent_roi",auto_migrate=False,allow_unauthenticated=True,oidc_issuer="",oidc_audience="",oidc_jwks_url="",oidc_organization_claim="org",oidc_roles_claim="roles",oidc_groups_claim="groups")
    data.update(overrides); return argparse.Namespace(**data)


def test_control_plane_signing_roles_build_backends_and_auth(tmp_path: Path,monkeypatch):
    monkeypatch.delenv("AGENT_ROI_POLICY_SIGNING_KEY",raising=False)
    with pytest.raises(ValueError,match="Set"): control_plane._signing_key()
    monkeypatch.setenv("AGENT_ROI_POLICY_SIGNING_KEY","short")
    with pytest.raises(ValueError,match="32"): control_plane._signing_key()
    monkeypatch.setenv("AGENT_ROI_POLICY_SIGNING_KEY","base64:not-valid")
    with pytest.raises(ValueError,match="base64"): control_plane._signing_key()
    raw=b"x"*32; monkeypatch.setenv("AGENT_ROI_POLICY_SIGNING_KEY","base64:"+base64.b64encode(raw).decode())
    assert control_plane._signing_key()==raw
    keyfile=tmp_path/"key"; keyfile.write_bytes(b"y"*32); assert control_plane._signing_key(str(keyfile))==b"y"*32
    ident=Identity(); control_plane._install_default_roles(ident); assert len(ident.roles)==6

    monkeypatch.setattr(control_plane,"SqliteControlPlaneStore",lambda *a:"store")
    monkeypatch.setattr(control_plane,"SqliteIdentityStore",Identity)
    monkeypatch.setattr(control_plane,"RealizedROILedger",lambda *a:"ledger")
    monkeypatch.setattr(control_plane,"SqliteAuditStore",lambda *a:"audit")
    monkeypatch.setattr(control_plane,"create_fastapi_app",lambda *a,**k:App())
    app=control_plane.build_app(ns(tmp_path))
    assert app.state.agent_roi["database_backend"]=="sqlite"
    with pytest.raises(ValueError,match="OIDC"):
        control_plane.build_app(ns(tmp_path,allow_unauthenticated=False))
    monkeypatch.setattr(control_plane,"OIDCVerifier",lambda config:"verifier")
    monkeypatch.setattr(control_plane,"DynamicRBACAuthorizer",lambda identity:"auth")
    app=control_plane.build_app(ns(tmp_path,allow_unauthenticated=False,oidc_issuer="https://i",oidc_audience="a"))
    assert app.state.agent_roi["authenticated"]

    migrated=[]
    monkeypatch.setattr(control_plane,"PostgresMigrationManager",lambda f:SimpleNamespace(migrate=lambda:migrated.append(1)))
    monkeypatch.setattr(control_plane,"PostgresConnectionFactory",lambda *a,**k:"factory")
    monkeypatch.setattr(control_plane,"PostgresControlPlaneStore",lambda *a,**k:"store")
    monkeypatch.setattr(control_plane,"PostgresIdentityStore",Identity)
    monkeypatch.setattr(control_plane,"PostgresROILedger",lambda *a,**k:"ledger")
    monkeypatch.setattr(control_plane,"PostgresAuditStore",lambda *a,**k:"audit")
    app=control_plane.build_app(ns(tmp_path,postgres_dsn="dsn",auto_migrate=True))
    assert app.state.agent_roi["database_backend"]=="postgres" and migrated==[1]


def test_control_plane_main_and_parser_errors(tmp_path: Path,monkeypatch):
    monkeypatch.setenv("AGENT_ROI_POLICY_SIGNING_KEY","x"*32)
    app=App(); monkeypatch.setattr(control_plane,"build_app",lambda args:app)
    called=[]; monkeypatch.setitem(sys.modules,"uvicorn",SimpleNamespace(run=lambda *a,**k:called.append((a,k))))
    assert control_plane.main(["--allow-unauthenticated","--data-dir",str(tmp_path)])==0 and called
    monkeypatch.setattr(control_plane,"build_app",lambda args:(_ for _ in ()).throw(ValueError("bad")))
    with pytest.raises(SystemExit): control_plane.main(["--allow-unauthenticated"])
    original=builtins.__import__
    def block(name,*a,**k):
        if name=="uvicorn": raise ImportError()
        return original(name,*a,**k)
    monkeypatch.delitem(sys.modules,"uvicorn",raising=False); monkeypatch.setattr(builtins,"__import__",block); monkeypatch.setattr(control_plane,"build_app",lambda args:app)
    with pytest.raises(RuntimeError,match="control-plane"): control_plane.main(["--allow-unauthenticated"])


def test_database_cli_all_commands(monkeypatch,capsys):
    migrations=[SimpleNamespace(version=1,name="one")]
    monkeypatch.setattr(database,"load_postgres_migrations",lambda:migrations)
    assert database.main(["list"])==0 and '"one"' in capsys.readouterr().out
    with pytest.raises(SystemExit,match="dsn"): database.main(["status"])
    class Manager:
        def __init__(self,*a): self.calls=[]
        def current_version(self): return 3
        def migrate(self,target_version=None): self.calls.append(target_version); return (1,2)
    manager=Manager(); monkeypatch.setattr(database,"PostgresMigrationManager",lambda f:manager); monkeypatch.setattr(database,"PostgresConnectionFactory",lambda *a,**k:"f")
    assert database.main(["status","--dsn","d","--schema","s"])==0 and '"current_version": 3' in capsys.readouterr().out
    assert database.main(["migrate","--dsn","d","--target-version","2"])==0 and manager.calls==[2]


def test_outbox_cli_validation_once_and_loop(monkeypatch,capsys):
    with pytest.raises(SystemExit,match="dsn"): outbox.main([])
    with pytest.raises(SystemExit,match="JSON object"): outbox.main(["--dsn","d","--destinations-json","{"])
    with pytest.raises(SystemExit,match="At least"): outbox.main(["--dsn","d","--destinations-json","{}"])
    monkeypatch.setattr(outbox,"PostgresOutboxStore",lambda *a,**k:"store")
    monkeypatch.setattr(outbox,"JsonHttpOutboxHandler",lambda endpoint:endpoint)
    class Worker:
        calls=0
        def __init__(self,*a,**k): pass
        def run_once(self,**k): self.calls+=1; return {"claimed":0,"delivered":0,"retried":0,"dead_lettered":0}
    monkeypatch.setattr(outbox,"OutboxWorker",Worker)
    assert outbox.main(["--dsn","d","--destinations-json",'{"x":"https://e"}',"--once"])==0
    slept=[]; monkeypatch.setattr(outbox.time,"sleep",lambda n:slept.append(n) or (_ for _ in ()).throw(KeyboardInterrupt()))
    with pytest.raises(KeyboardInterrupt): outbox.main(["--dsn","d","--destinations-json",'{"x":"https://e"}'])
    assert slept


def test_sentinel_cli_edge_paths(tmp_path: Path,monkeypatch):
    with pytest.raises(ValueError): sentinel._confidence_for_mode("bad")
    assert sentinel._build_demo_payload(None)["resources"]
    assert sentinel._build_registry().names()==frozenset({"policy_load","finops_analyze"})
    with pytest.raises(SystemExit): sentinel.main(["--policy",str(tmp_path/"missing")])
    existing=tmp_path/"existing"; existing.mkdir(); (existing/"other.txt").write_text("x")
    with pytest.raises(SystemExit): sentinel.main(["--outdir",str(existing)])
