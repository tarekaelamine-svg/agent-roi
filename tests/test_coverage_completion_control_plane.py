from __future__ import annotations

import io
import json
import os
import sqlite3
import time
from pathlib import Path
from urllib import error as urlerror

import pytest
import yaml

from agent_roi.audit import InMemoryAuditStore
from agent_roi.enterprise.control_plane import (
    CachedControlPlaneClient,
    ControlPlaneClient,
    ControlPlaneError,
    ControlPlaneService,
    HMACPolicySigner,
    PolicyBundle,
    PolicyBundleCache,
    PolicySignatureError,
    SqliteControlPlaneStore,
    create_fastapi_app,
)
from agent_roi.enterprise.identity import Principal, RBACAuthorizer, RoleDefinition, SqliteIdentityStore
from agent_roi.roi.ledger import RealizedROILedger


def policy() -> dict:
    path = Path(__file__).parents[1] / "src" / "agent_roi" / "policies" / "finops_policy.yaml"
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def service(tmp_path: Path, *, signed: bool = True, sink=None) -> ControlPlaneService:
    signer = HMACPolicySigner(b"k" * 32, key_id="key-1")
    return ControlPlaneService(
        SqliteControlPlaneStore(tmp_path / "control.sqlite3"),
        signers={signer.key_id: signer},
        default_signer_key_id=signer.key_id,
        require_signed_bundles=signed,
        event_sink=sink,
    )


def publish(svc: ControlPlaneService, env="prod", version="1") -> PolicyBundle:
    return svc.publish_policy(
        organization_id="acme", name="finops", environment=env, version=version,
        policy=policy(), created_by="admin",
    )


def test_signer_bundle_and_service_validation_errors(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        HMACPolicySigner(b"short")
    with pytest.raises(ValueError):
        HMACPolicySigner(b"x" * 32, key_id=" ")
    signer = HMACPolicySigner(b"a" * 32, key_id="a")
    bundle = PolicyBundle.create(
        organization_id="acme", name="finops", environment="prod", version="1",
        policy=policy(), signer=signer, created_by="admin",
    )
    with pytest.raises(PolicySignatureError, match="digest"):
        PolicyBundle.from_dict({**bundle.to_dict(), "digest": "bad"}).verify(signer)
    with pytest.raises(PolicySignatureError, match="signature"):
        bundle.verify(HMACPolicySigner(b"b" * 32, key_id="b"))
    with pytest.raises(ValueError):
        ControlPlaneService(object(), signers={"a": signer}, default_signer_key_id="missing")
    svc = ControlPlaneService(object(), signers={"a": signer}, default_signer_key_id="a")
    with pytest.raises(PolicySignatureError, match="Unknown"):
        svc.verify_bundle(PolicyBundle.from_dict({**bundle.to_dict(), "signer_key_id": "unknown"}))


def test_sqlite_store_errors_revisions_filters_and_legacy_upgrade(tmp_path: Path) -> None:
    legacy = tmp_path / "legacy.sqlite3"
    conn = sqlite3.connect(legacy)
    conn.executescript("""
      CREATE TABLE policy_bundles (organization_id TEXT,name TEXT,environment TEXT,version TEXT,payload_json TEXT,digest TEXT,signature TEXT,signer_key_id TEXT,status TEXT,created_at_utc TEXT,created_by TEXT,PRIMARY KEY(organization_id,name,environment,version));
      CREATE TABLE active_policies (organization_id TEXT,name TEXT,environment TEXT,version TEXT,activated_at_utc TEXT,activated_by TEXT,PRIMARY KEY(organization_id,name,environment));
      CREATE TABLE policy_rollouts (organization_id TEXT,name TEXT,environment TEXT,primary_version TEXT,candidate_version TEXT,candidate_percentage INTEGER,seed TEXT,updated_at_utc TEXT,updated_by TEXT,PRIMARY KEY(organization_id,name,environment));
      CREATE TABLE agents (organization_id TEXT,agent_id TEXT,environment TEXT,owner TEXT,purpose TEXT,status TEXT,metadata_json TEXT,registered_at_utc TEXT,last_heartbeat_utc TEXT,policy_digest TEXT,version TEXT,PRIMARY KEY(organization_id,agent_id,environment));
    """)
    conn.close()
    upgraded = SqliteControlPlaneStore(legacy)
    with upgraded._connection() as c:
        for table in ("active_policies", "policy_rollouts", "agents"):
            assert "revision" in {r[1] for r in c.execute(f"PRAGMA table_info({table})")}

    svc = service(tmp_path)
    first = publish(svc, "prod", "1")
    with pytest.raises(ControlPlaneError, match="already exists"):
        svc.store.save_bundle(first)
    with pytest.raises(KeyError):
        svc.store.get_bundle("acme", "missing", "prod", "1")
    with pytest.raises(KeyError):
        svc.store.get_active("acme", "finops", "prod")
    with pytest.raises(KeyError):
        svc.store.get_active_revision("acme", "finops", "prod")
    svc.activate_policy(organization_id="acme", name="finops", environment="prod", version="1", activated_by="a")
    with pytest.raises(ControlPlaneError, match="revision conflict"):
        svc.activate_policy(organization_id="acme", name="finops", environment="prod", version="1", activated_by="a", expected_revision=99)
    publish(svc, "prod", "2")
    for bad in (0, 100, True):
        with pytest.raises(ValueError):
            svc.start_rollout(organization_id="acme", name="finops", environment="prod", candidate_version="2", candidate_percentage=bad, updated_by="a")
    with pytest.raises(ValueError, match="differ"):
        svc.start_rollout(organization_id="acme", name="finops", environment="prod", candidate_version="1", candidate_percentage=10, updated_by="a")
    rollout = svc.start_rollout(organization_id="acme", name="finops", environment="prod", candidate_version="2", candidate_percentage=10, updated_by="a")
    assert rollout["seed"]
    with pytest.raises(ControlPlaneError, match="revision conflict"):
        svc.start_rollout(organization_id="acme", name="finops", environment="prod", candidate_version="2", candidate_percentage=20, updated_by="a", expected_revision=99)
    assert svc.start_rollout(organization_id="acme", name="finops", environment="prod", candidate_version="2", candidate_percentage=20, updated_by="a", expected_revision=rollout["revision"])["revision"] == 2
    svc.cancel_rollout("acme", "finops", "prod")
    with pytest.raises(KeyError):
        svc.store.get_rollout("acme", "finops", "prod")
    assert svc.store.resolve_active("acme", "finops", "prod", agent_id="a").version == "1"
    assert len(svc.store.list_bundles("acme", name="finops", environment="prod")) == 2

    with pytest.raises(KeyError):
        svc.store.get_agent("acme", "no", "prod")
    with pytest.raises(KeyError):
        svc.heartbeat(organization_id="acme", agent_id="no", environment="prod", policy_digest="", version="")
    agent = svc.register_agent(organization_id="acme", agent_id="a", environment="prod", owner="o", purpose="p", status="approved")
    with pytest.raises(ControlPlaneError):
        svc.register_agent(organization_id="acme", agent_id="a", environment="prod", owner="o", purpose="p", expected_revision=99)
    agent = svc.register_agent(organization_id="acme", agent_id="a", environment="prod", owner="o2", purpose="p", status="approved", expected_revision=agent["revision"])
    with pytest.raises(ControlPlaneError):
        svc.heartbeat(organization_id="acme", agent_id="a", environment="prod", policy_digest="d", version="2", expected_revision=99)
    svc.heartbeat(organization_id="acme", agent_id="a", environment="prod", policy_digest="d", version="2", expected_revision=agent["revision"])
    assert len(svc.store.list_agents("acme", environment="prod", status="production", limit=1000, offset=-1)) == 1


def test_service_events_unsigned_paths_and_promotion(tmp_path: Path) -> None:
    class Sink:
        def __init__(self): self.events = []
        def emit(self, event): self.events.append(event)
    sink = Sink()
    svc = service(tmp_path, signed=False, sink=sink)
    publish(svc, "dev", "1")
    promoted = svc.promote_policy(
        organization_id="acme", name="finops", source_environment="dev", target_environment="prod",
        source_version="1", target_version="2", promoted_by="admin", activate=False,
    )
    assert promoted.version == "2"
    svc.activate_policy(organization_id="acme", name="finops", environment="prod", version="2", activated_by="admin")
    assert svc.policy_for_agent("acme", "finops", "prod", "a").version == "2"
    assert svc.active_policy("acme", "finops", "prod").version == "2"
    publish(svc, "prod", "3")
    svc.rollback_policy(organization_id="acme", name="finops", environment="prod", version="2", rolled_back_by="admin")
    assert {e.type.rsplit(".", 1)[-1] for e in sink.events} >= {"published", "promoted", "activated", "rolled_back", "rollout_cancelled"}


def test_http_client_request_and_all_management_wrappers(monkeypatch, tmp_path: Path) -> None:
    signer = HMACPolicySigner(b"z" * 32)
    bundle = PolicyBundle.create(organization_id="o", name="p", environment="e", version="1", policy=policy(), signer=signer, created_by="a")
    client = ControlPlaneClient("https://cp/", bearer_token="token", signer=signer)

    class Response:
        def __init__(self, data: bytes): self.data = data
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def read(self): return self.data
    seen = []
    def ok(req, timeout):
        seen.append(req)
        return Response(json.dumps(bundle.to_dict()).encode())
    monkeypatch.setattr("agent_roi.enterprise.control_plane.urlrequest.urlopen", ok)
    assert client._request("POST", "/x", {"a": 1}, extra_headers={"If-Match": "2"})["version"] == "1"
    assert seen[-1].headers["Authorization"] == "Bearer token"
    monkeypatch.setattr("agent_roi.enterprise.control_plane.urlrequest.urlopen", lambda *a, **k: Response(b""))
    assert client._request("GET", "/x") is None
    err = urlerror.HTTPError("u", 409, "conflict", {}, io.BytesIO(b"detail"))
    monkeypatch.setattr("agent_roi.enterprise.control_plane.urlrequest.urlopen", lambda *a, **k: (_ for _ in ()).throw(err))
    with pytest.raises(ControlPlaneError, match="409"):
        client._request("GET", "/x")
    monkeypatch.setattr("agent_roi.enterprise.control_plane.urlrequest.urlopen", lambda *a, **k: (_ for _ in ()).throw(OSError("down")))
    with pytest.raises(ControlPlaneError, match="unavailable"):
        client._request("GET", "/x")

    calls = []
    def fake(method, path, payload=None, **kwargs):
        calls.append((method, path, payload, kwargs))
        if path.endswith("/agents") or "/heartbeat" in path:
            return {"agent_id": "a", "revision": 1}
        return bundle.to_dict()
    monkeypatch.setattr(client, "_request", fake)
    assert client.publish_policy(organization_id="o", name="p", environment="e", version="1", policy=policy()).version == "1"
    assert client.activate_policy("o", "p", "e", "1", expected_revision=2).version == "1"
    assert client.promote_policy(organization_id="o", name="p", source_environment="e", source_version="1", target_environment="p", target_version="2", activate=True).version == "1"
    assert client.get_active_policy("o", "p", "e").version == "1"
    assert client.get_policy_for_agent("o", "p", "e", "a").version == "1"
    assert client.runtime_policy("o", "p", "e").guardrails().max_steps
    assert client.register_agent(organization_id="o", agent_id="a", environment="e", owner="x", purpose="y", expected_revision=1)["agent_id"] == "a"
    assert client.heartbeat(organization_id="o", agent_id="a", environment="e", policy_digest="d", version="1", expected_revision=1)["agent_id"] == "a"
    assert any(c[3].get("extra_headers") for c in calls)


def test_policy_cache_stale_chmod_and_agent_fallback(monkeypatch, tmp_path: Path) -> None:
    signer = HMACPolicySigner(b"q" * 32)
    bundle = PolicyBundle.create(organization_id="o", name="p", environment="e", version="1", policy=policy(), signer=signer, created_by="a")
    with pytest.raises(ValueError):
        PolicyBundleCache(tmp_path / "bad", signer=signer, max_stale_seconds=-1)
    cache = PolicyBundleCache(tmp_path / "cache", signer=signer, max_stale_seconds=0)
    monkeypatch.setattr(os, "chmod", lambda *a: (_ for _ in ()).throw(OSError()))
    cache.save(bundle, agent_id="a")
    with pytest.raises(KeyError):
        cache.load("x", "y", "z")
    time.sleep(0.002)
    with pytest.raises(ControlPlaneError, match="stale"):
        cache.load("o", "p", "e", agent_id="a")
    assert cache.load("o", "p", "e", agent_id="a", allow_stale=True).version == "1"

    class Client:
        def __init__(self, fail=False): self.fail = fail
        def get_policy_for_agent(self, *args):
            if self.fail: raise RuntimeError("offline")
            return bundle
        def heartbeat(self, **kwargs): return kwargs
    good = CachedControlPlaneClient(Client(), cache, allow_stale_on_error=True)
    assert good.get_policy_for_agent("o", "p", "e", "a").version == "1"
    bad = CachedControlPlaneClient(Client(True), cache, allow_stale_on_error=True)
    assert bad.get_policy_for_agent("o", "p", "e", "a").version == "1"
    assert bad.heartbeat(x=1) == {"x": 1}


def test_fastapi_error_surfaces_and_optional_services(tmp_path: Path) -> None:
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    svc = service(tmp_path)
    identity = SqliteIdentityStore(tmp_path / "identity.sqlite3")
    ledger = RealizedROILedger(tmp_path / "roi.sqlite3")
    audit = InMemoryAuditStore()
    client = TestClient(create_fastapi_app(svc, scim_directory=identity, roi_ledger=ledger, audit_store=audit))
    assert client.get("/healthz").json() == {"status": "ok"}
    assert client.get("/v1/organizations/acme/policies/prod/missing/active").status_code == 404
    assert client.get("/v1/organizations/acme/policies/prod/missing/resolve?agent_id=a").status_code == 404
    assert client.post("/v1/organizations/acme/policies/prod/finops/1", json={}).status_code == 400
    assert client.post("/v1/organizations/acme/policies/prod/finops/1/activate").status_code == 404
    assert client.post("/v1/organizations/acme/policies/dev/finops/1/promote/prod", json={}).status_code == 400
    assert client.post("/v1/organizations/acme/policies/prod/finops/1/rollback").status_code == 404
    assert client.post("/v1/organizations/acme/policies/prod/finops/2/rollout", json={}).status_code == 400
    assert client.delete("/v1/organizations/acme/policies/prod/finops/rollout").status_code == 200
    assert client.post("/v1/organizations/acme/agents", json={}, headers={"If-Match": "abc"}).status_code == 400
    assert client.post("/v1/organizations/acme/agents/a/prod/heartbeat", json={}).status_code == 404

    assert client.post("/v1/audit/events", json={}).status_code == 400
    event = client.post("/v1/audit/events", json={"correlation_id":"c","run_id":"r","event_type":"e","payload":{}})
    assert event.status_code == 201
    body = event.json()
    assert client.post("/v1/audit/events/append", json=body).status_code == 409
    assert client.get("/v1/audit/chains/c/tail").json()["last_hash"]
    assert client.get("/v1/audit/verify?correlation_id=c").json()["events_verified"] == 1

    assert client.get("/scim/v2/Users/no").status_code == 404
    assert client.put("/scim/v2/Users/no", json={"userName":"x"}).status_code == 404
    assert client.delete("/scim/v2/Users/no").status_code == 404
    assert client.get("/scim/v2/Groups/no").status_code == 404
    assert client.put("/scim/v2/Groups/no", json={"displayName":"x"}).status_code == 404
    assert client.delete("/scim/v2/Groups/no").status_code == 404
    u = client.post("/scim/v2/Users", json={"userName":"x@example.com"})
    assert client.post("/scim/v2/Users", json={"userName":"x@example.com"}).status_code == 409
    g = client.post("/scim/v2/Groups", json={"displayName":"g"})
    assert client.post("/scim/v2/Groups", json={"displayName":"g"}).status_code == 409
    assert client.put(f"/scim/v2/Users/{u.json()['id']}", json={"userName":""}).status_code == 409
    assert client.put(f"/scim/v2/Groups/{g.json()['id']}", json={"displayName":""}).status_code == 409
    assert client.put("/v1/identity/roles/", json={}).status_code in {404, 405}
    assert client.delete("/v1/identity/roles/no").status_code == 404
    assert client.post("/v1/identity/bindings", json={}).status_code == 400
    assert client.delete("/v1/identity/bindings/no").status_code == 404

    assert client.post("/v1/organizations/acme/roi/opportunities", json={}).status_code == 400
    assert client.get("/v1/organizations/acme/roi/opportunities/no").status_code == 404
    assert client.post("/v1/organizations/acme/roi/opportunities/no/transition", json={"status":"approved"}).status_code == 404
    assert client.post("/v1/organizations/acme/roi/opportunities/no/values", json={}).status_code == 404
    assert client.post("/v1/organizations/acme/roi/costs", json={}).status_code == 400


def test_fastapi_authentication_and_authorization_failures(tmp_path: Path) -> None:
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient
    class BadVerifier:
        def verify_authorization_header(self, header): raise ValueError("bad")
    app = create_fastapi_app(service(tmp_path), oidc_verifier=BadVerifier())
    assert TestClient(app).get("/v1/organizations/acme/agents").status_code == 401

    class Verifier:
        def verify_authorization_header(self, header): return Principal("u", "acme", roles=frozenset())
    auth = RBACAuthorizer([RoleDefinition("none", frozenset())])
    client = TestClient(create_fastapi_app(service(tmp_path / "two"), oidc_verifier=Verifier(), authorizer=auth))
    assert client.get("/v1/organizations/acme/agents", headers={"Authorization":"Bearer x"}).status_code == 403
