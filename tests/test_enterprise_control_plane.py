from __future__ import annotations

import socket
import threading
import time
from pathlib import Path

import pytest
import yaml

from agent_roi.enterprise.control_plane import (
    ControlPlaneClient,
    ControlPlaneService,
    HMACPolicySigner,
    PolicyBundle,
    PolicySignatureError,
    SqliteControlPlaneStore,
    create_fastapi_app,
)
from agent_roi.enterprise.identity import SCIMDirectory
from agent_roi.roi.ledger import RealizedROILedger


def _policy() -> dict:
    path = Path(__file__).parents[1] / "src" / "agent_roi" / "policies" / "finops_policy.yaml"
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _service(tmp_path: Path) -> ControlPlaneService:
    signer = HMACPolicySigner(b"x" * 32, key_id="test-key")
    return ControlPlaneService(
        SqliteControlPlaneStore(tmp_path / "control.sqlite3"),
        signers={signer.key_id: signer},
        default_signer_key_id=signer.key_id,
    )


def test_signed_policy_publish_activate_and_runtime(tmp_path: Path) -> None:
    service = _service(tmp_path)
    bundle = service.publish_policy(
        organization_id="acme",
        name="finops",
        environment="prod",
        version="1.2.3",
        policy=_policy(),
        created_by="policy-admin",
    )
    service.verify_bundle(bundle)
    service.activate_policy(
        organization_id="acme",
        name="finops",
        environment="prod",
        version="1.2.3",
        activated_by="policy-admin",
    )
    runtime = service.runtime_policy("acme", "finops", "prod")
    assert runtime.guardrails().require_registered_tools is True
    assert service.active_policy("acme", "finops", "prod").version == "1.2.3"


def test_policy_signature_detects_payload_tampering(tmp_path: Path) -> None:
    service = _service(tmp_path)
    bundle = service.publish_policy(
        organization_id="acme",
        name="finops",
        environment="prod",
        version="1",
        policy=_policy(),
        created_by="admin",
    )
    tampered = PolicyBundle.from_dict(
        {**bundle.to_dict(), "policy": {**dict(bundle.policy), "policy_name": "tampered"}}
    )
    with pytest.raises(PolicySignatureError):
        service.verify_bundle(tampered)


def test_agent_inventory_and_heartbeat(tmp_path: Path) -> None:
    store = _service(tmp_path).store
    store.register_agent(
        organization_id="acme",
        agent_id="invoice-agent",
        environment="prod",
        owner="finance",
        purpose="Invoice validation",
        version="2.0.0",
        metadata={"data_classification": "confidential"},
    )
    heartbeat = store.heartbeat(
        organization_id="acme",
        agent_id="invoice-agent",
        environment="prod",
        policy_digest="abc",
        version="2.0.0",
    )
    assert heartbeat["policy_digest"] == "abc"
    assert heartbeat["last_heartbeat_utc"]
    assert store.list_agents("acme")[0]["metadata"]["data_classification"] == "confidential"


def test_fastapi_control_plane_policy_scim_and_roi(tmp_path: Path) -> None:
    fastapi = pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    service = _service(tmp_path)
    directory = SCIMDirectory()
    ledger = RealizedROILedger(tmp_path / "roi.sqlite3")
    app = create_fastapi_app(service, scim_directory=directory, roi_ledger=ledger)
    client = TestClient(app)

    published = client.post(
        "/v1/organizations/acme/policies/prod/finops/1",
        json={"policy": _policy(), "created_by": "admin"},
    )
    assert published.status_code == 200, published.text
    activated = client.post("/v1/organizations/acme/policies/prod/finops/1/activate")
    assert activated.status_code == 200
    active = client.get("/v1/organizations/acme/policies/prod/finops/active")
    assert active.json()["version"] == "1"

    user = client.post(
        "/scim/v2/Users",
        json={"userName": "user@example.com", "displayName": "User"},
    )
    assert user.status_code == 201
    users = client.get("/scim/v2/Users").json()
    assert users["totalResults"] == 1

    roi = client.post(
        "/v1/organizations/acme/roi/opportunities",
        json={
            "agent_id": "invoice-agent",
            "business_unit": "Finance",
            "business_owner": "CFO",
            "title": "Duplicate invoice recovery",
            "value_type": "cost_savings",
            "value_period": "one_time",
            "baseline_usd": 100000,
            "forecast_value_usd": 20000,
            "confidence": 0.8,
            "source_key": "assessment-1",
            "created_by": "analyst",
        },
    )
    assert roi.status_code == 201, roi.text
    summary = client.get("/v1/organizations/acme/roi/summary").json()
    assert summary["forecast_value_usd"] == 20000.0


def _run_uvicorn(app):
    uvicorn = pytest.importorskip("uvicorn")
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="critical")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 5
    while not server.started and time.time() < deadline:
        time.sleep(0.02)
    if not server.started:
        raise RuntimeError("uvicorn did not start")
    return server, thread, port


def test_control_plane_http_client_fetches_and_verifies_policy(tmp_path: Path) -> None:
    service = _service(tmp_path)
    signer = service.signers[service.default_signer_key_id]
    service.publish_policy(
        organization_id="acme",
        name="finops",
        environment="prod",
        version="1",
        policy=_policy(),
        created_by="admin",
    )
    service.activate_policy(
        organization_id="acme",
        name="finops",
        environment="prod",
        version="1",
        activated_by="admin",
    )
    service.store.register_agent(
        organization_id="acme",
        agent_id="finops-agent",
        environment="prod",
        owner="platform",
        purpose="FinOps",
    )
    app = create_fastapi_app(service)
    server, thread, port = _run_uvicorn(app)
    try:
        client = ControlPlaneClient(f"http://127.0.0.1:{port}", signer=signer)
        bundle = client.get_active_policy("acme", "finops", "prod")
        assert bundle.version == "1"
        assert client.runtime_policy("acme", "finops", "prod").guardrails().max_steps == 8
        heartbeat = client.heartbeat(
            organization_id="acme",
            agent_id="finops-agent",
            environment="prod",
            policy_digest="digest",
            version="2.0.0",
        )
        assert heartbeat["policy_digest"] == "digest"
    finally:
        server.should_exit = True
        thread.join(timeout=5)

@pytest.mark.filterwarnings("ignore:websockets.*:DeprecationWarning")
@pytest.mark.filterwarnings("ignore:websockets.server.*:DeprecationWarning")
def test_enterprise_runner_loads_central_policy_and_heartbeats(tmp_path: Path) -> None:
    from agent_roi.enterprise.runtime import EnterpriseSentinelRunner

    service = _service(tmp_path)
    signer = service.signers[service.default_signer_key_id]
    service.publish_policy(
        organization_id="acme",
        name="finops",
        environment="prod",
        version="1",
        policy=_policy(),
        created_by="admin",
    )
    service.activate_policy(
        organization_id="acme",
        name="finops",
        environment="prod",
        version="1",
        activated_by="admin",
    )
    service.store.register_agent(
        organization_id="acme",
        agent_id="finops-agent",
        environment="prod",
        owner="platform",
        purpose="FinOps",
    )
    app = create_fastapi_app(service)
    server, thread, port = _run_uvicorn(app)
    try:
        client = ControlPlaneClient(f"http://127.0.0.1:{port}", signer=signer)
        from agent_roi import ToolRegistry
        registry = ToolRegistry()
        registry.add("policy_load", lambda: None)
        registry.add("finops_analyze", lambda: None)
        runner = EnterpriseSentinelRunner.from_control_plane(
            control_plane_client=client,
            organization_id="acme",
            environment="prod",
            agent_id="finops-agent",
            policy_name="finops",
            tool_registry=registry,
        )
        result = runner.run(lambda ctx, _: "ok", None)
        assert result.output == "ok"
        inventory = service.store.get_agent("acme", "finops-agent", "prod")
        assert inventory["last_heartbeat_utc"]
        assert inventory["version"] == "2.0.0"
        assert runner.heartbeat_errors == []
    finally:
        server.should_exit = True
        thread.join(timeout=5)

def test_policy_rollout_is_deterministic_and_cancellable(tmp_path: Path) -> None:
    service = _service(tmp_path)
    for version, confidence in (("1", 0.80), ("2", 0.90)):
        policy = _policy()
        policy["decision_policy"]["min_confidence"] = confidence
        service.publish_policy(
            organization_id="acme",
            name="finops",
            environment="prod",
            version=version,
            policy=policy,
            created_by="admin",
        )
    service.activate_policy(
        organization_id="acme",
        name="finops",
        environment="prod",
        version="1",
        activated_by="admin",
    )
    rollout = service.start_rollout(
        organization_id="acme",
        name="finops",
        environment="prod",
        candidate_version="2",
        candidate_percentage=50,
        updated_by="admin",
        seed="fixed-seed",
    )
    assert rollout["primary_version"] == "1"
    assignments = {
        agent_id: service.policy_for_agent("acme", "finops", "prod", agent_id).version
        for agent_id in [f"agent-{index}" for index in range(30)]
    }
    assert set(assignments.values()) == {"1", "2"}
    assert assignments == {
        agent_id: service.policy_for_agent("acme", "finops", "prod", agent_id).version
        for agent_id in assignments
    }
    service.cancel_rollout("acme", "finops", "prod")
    assert service.policy_for_agent("acme", "finops", "prod", "agent-1").version == "1"


def test_verified_policy_cache_supports_offline_operation(tmp_path: Path) -> None:
    from agent_roi.enterprise.control_plane import (
        CachedControlPlaneClient,
        PolicyBundleCache,
    )

    service = _service(tmp_path)
    signer = service.signers[service.default_signer_key_id]
    bundle = service.publish_policy(
        organization_id="acme",
        name="finops",
        environment="prod",
        version="1",
        policy=_policy(),
        created_by="admin",
    )

    class WorkingClient:
        def get_active_policy(self, organization_id, name, environment):
            return bundle

    cache = PolicyBundleCache(tmp_path / "cache", signer=signer, max_stale_seconds=60)
    cached = CachedControlPlaneClient(WorkingClient(), cache)
    assert cached.get_active_policy("acme", "finops", "prod").version == "1"

    class BrokenClient:
        def get_active_policy(self, *args):
            raise RuntimeError("offline")

    offline = CachedControlPlaneClient(BrokenClient(), cache)
    assert offline.get_active_policy("acme", "finops", "prod").version == "1"


def test_fastapi_scim_crud_and_rbac_administration(tmp_path: Path) -> None:
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient
    from agent_roi.enterprise.identity import SqliteIdentityStore

    directory = SqliteIdentityStore(tmp_path / "identity.sqlite3")
    app = create_fastapi_app(_service(tmp_path), scim_directory=directory)
    client = TestClient(app)

    created = client.post(
        "/scim/v2/Users",
        json={"userName": "user@example.com", "displayName": "Original"},
    )
    user_id = created.json()["id"]
    assert client.get(f"/scim/v2/Users/{user_id}").status_code == 200
    replaced = client.put(
        f"/scim/v2/Users/{user_id}",
        json={"userName": "user@example.com", "displayName": "Updated"},
    )
    assert replaced.json()["displayName"] == "Updated"

    group = client.post(
        "/scim/v2/Groups",
        json={"displayName": "Approvers", "members": [{"value": user_id}]},
    )
    group_id = group.json()["id"]
    assert client.get(f"/scim/v2/Groups/{group_id}").status_code == 200

    role = client.put(
        "/v1/identity/roles/approver",
        json={"permissions": ["approval.decide:*"]},
    )
    assert role.status_code == 200
    binding = client.post(
        "/v1/identity/bindings",
        json={"role": "approver", "organization_id": "acme", "group": "Approvers"},
    )
    assert binding.status_code == 201
    assert len(client.get("/v1/identity/bindings").json()) == 1

    assert client.delete(f"/v1/identity/bindings/{binding.json()['binding_id']}").status_code == 204
    assert client.delete(f"/scim/v2/Groups/{group_id}").status_code == 204
    assert client.delete(f"/scim/v2/Users/{user_id}").status_code == 204


def test_control_plane_rejects_cross_organization_paths(tmp_path: Path) -> None:
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient
    from agent_roi.enterprise.identity import Principal, RBACAuthorizer, RoleDefinition

    class Verifier:
        def verify_authorization_header(self, header):
            return Principal("admin", "acme", roles=frozenset({"admin"}))

    authorizer = RBACAuthorizer(
        [RoleDefinition("admin", frozenset({"policy.*"}))]
    )
    app = create_fastapi_app(
        _service(tmp_path), oidc_verifier=Verifier(), authorizer=authorizer
    )
    client = TestClient(app)
    response = client.post(
        "/v1/organizations/other/policies/prod/finops/1",
        headers={"Authorization": "Bearer token"},
        json={"policy": _policy()},
    )
    assert response.status_code == 403
    assert response.json()["detail"] == "Cross-organization access denied"


def test_policy_promotion_rollback_and_direct_service_resolution(tmp_path: Path) -> None:
    service = _service(tmp_path)
    policy = _policy()
    service.publish_policy(
        organization_id="acme",
        name="finops",
        environment="dev",
        version="1",
        policy=policy,
        created_by="admin",
    )
    promoted = service.promote_policy(
        organization_id="acme",
        name="finops",
        source_environment="dev",
        target_environment="prod",
        source_version="1",
        promoted_by="admin",
        activate=True,
    )
    assert promoted.environment == "prod"
    assert service.get_policy_for_agent("acme", "finops", "prod", "agent-1").version == "1"

    policy2 = _policy()
    policy2["decision_policy"]["min_confidence"] = 0.95
    service.publish_policy(
        organization_id="acme",
        name="finops",
        environment="prod",
        version="2",
        policy=policy2,
        created_by="admin",
    )
    service.activate_policy(
        organization_id="acme",
        name="finops",
        environment="prod",
        version="2",
        activated_by="admin",
    )
    rolled_back = service.rollback_policy(
        organization_id="acme",
        name="finops",
        environment="prod",
        version="1",
        rolled_back_by="admin",
    )
    assert rolled_back.version == "1"
    assert service.active_policy("acme", "finops", "prod").version == "1"


def test_control_plane_roi_lifecycle_api(tmp_path: Path) -> None:
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    ledger = RealizedROILedger(tmp_path / "roi-api.sqlite3")
    client = TestClient(create_fastapi_app(_service(tmp_path), roi_ledger=ledger))
    created = client.post(
        "/v1/organizations/acme/roi/opportunities",
        json={
            "agent_id": "invoice-agent",
            "business_unit": "Finance",
            "business_owner": "CFO",
            "title": "Recovered duplicate payments",
            "value_type": "cost_savings",
            "value_period": "one_time",
            "baseline_usd": 100000,
            "forecast_value_usd": 25000,
            "confidence": 0.9,
            "source_key": "roi-api-1",
            "created_by": "analyst",
        },
    )
    opportunity_id = created.json()["opportunity_id"]
    assert client.get(
        f"/v1/organizations/acme/roi/opportunities/{opportunity_id}"
    ).status_code == 200
    assert len(client.get("/v1/organizations/acme/roi/opportunities").json()) == 1

    for status in ("approved", "in_progress", "realizing"):
        response = client.post(
            f"/v1/organizations/acme/roi/opportunities/{opportunity_id}/transition",
            json={"status": status, "changed_by": "owner"},
        )
        assert response.status_code == 200, response.text

    realized = client.post(
        f"/v1/organizations/acme/roi/opportunities/{opportunity_id}/values",
        json={
            "stage": "realized",
            "amount_usd": 20000,
            "evidence_key": "credit-memo-1",
            "recorded_by": "analyst",
        },
    )
    assert realized.status_code == 201, realized.text
    validated = client.post(
        f"/v1/organizations/acme/roi/opportunities/{opportunity_id}/values",
        json={
            "stage": "validated",
            "amount_usd": 18000,
            "evidence_key": "finance-validation-1",
            "recorded_by": "controller",
        },
    )
    assert validated.status_code == 201, validated.text
    cost = client.post(
        "/v1/organizations/acme/roi/costs",
        json={
            "agent_id": "invoice-agent",
            "opportunity_id": opportunity_id,
            "cost_type": "model",
            "amount_usd": 1000,
            "currency_code": "USD",
            "evidence_key": "cloud-bill-1",
            "recorded_by": "finops",
        },
    )
    assert cost.status_code == 201, cost.text
    summary = client.get("/v1/organizations/acme/roi/summary").json()
    assert summary["validated_value_usd"] == 18000.0
    assert summary["net_validated_value_usd"] == 17000.0


def test_control_plane_http_client_management_operations(tmp_path: Path) -> None:
    service = _service(tmp_path)
    signer = service.signers[service.default_signer_key_id]
    app = create_fastapi_app(service)
    server, thread, port = _run_uvicorn(app)
    try:
        client = ControlPlaneClient(f"http://127.0.0.1:{port}", signer=signer)
        published = client.publish_policy(
            organization_id="acme",
            name="finops",
            environment="dev",
            version="1",
            policy=_policy(),
            created_by="admin",
        )
        assert published.version == "1"
        client.activate_policy("acme", "finops", "dev", "1")
        promoted = client.promote_policy(
            organization_id="acme",
            name="finops",
            source_environment="dev",
            source_version="1",
            target_environment="prod",
            activate=True,
        )
        assert promoted.environment == "prod"
        registered = client.register_agent(
            organization_id="acme",
            agent_id="agent-1",
            environment="prod",
            owner="platform",
            purpose="Governed execution",
        )
        assert registered["agent_id"] == "agent-1"
    finally:
        server.should_exit = True
        thread.join(timeout=5)


def test_control_plane_oidc_and_rbac_end_to_end(tmp_path: Path) -> None:
    jwt = pytest.importorskip("jwt")
    pytest.importorskip("fastapi")
    from datetime import datetime, timedelta, timezone
    from fastapi.testclient import TestClient
    from agent_roi.enterprise.identity import (
        OIDCConfig,
        OIDCVerifier,
        RBACAuthorizer,
        RoleDefinition,
    )

    key = "control-plane-test-secret-at-least-32-bytes"
    now = datetime.now(timezone.utc)
    token = jwt.encode(
        {
            "iss": "https://issuer.example",
            "aud": "agent-roi",
            "sub": "policy-admin",
            "org_id": "acme",
            "roles": ["policy_admin"],
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(minutes=5)).timestamp()),
        },
        key,
        algorithm="HS256",
    )
    verifier = OIDCVerifier(
        OIDCConfig(
            issuer="https://issuer.example",
            audience="agent-roi",
            algorithms=("HS256",),
        ),
        verification_key=key,
    )
    authorizer = RBACAuthorizer(
        [RoleDefinition("policy_admin", frozenset({"policy.*"}))]
    )
    client = TestClient(
        create_fastapi_app(
            _service(tmp_path), oidc_verifier=verifier, authorizer=authorizer
        )
    )
    path = "/v1/organizations/acme/policies/prod/finops/1"
    assert client.post(path, json={"policy": _policy()}).status_code == 401
    response = client.post(
        path,
        headers={"Authorization": f"Bearer {token}"},
        json={"policy": _policy()},
    )
    assert response.status_code == 200, response.text
    assert response.json()["created_by"] == "policy-admin"


def test_control_plane_client_escapes_path_and_query_segments(monkeypatch) -> None:
    signer = HMACPolicySigner(b"client-path-test-key-at-least-32-bytes")
    bundle = PolicyBundle.create(
        organization_id="acme/division",
        name="policy name",
        environment="prod west",
        version="1",
        policy=_policy(),
        signer=signer,
        created_by="admin",
    )
    client = ControlPlaneClient("https://control.example", signer=signer)
    captured = []

    def fake_request(method, path, payload=None):
        captured.append((method, path, payload))
        return bundle.to_dict()

    monkeypatch.setattr(client, "_request", fake_request)
    client.get_active_policy("acme/division", "policy name", "prod west")
    client.get_policy_for_agent(
        "acme/division", "policy name", "prod west", "agent/one & two"
    )
    client.heartbeat(
        organization_id="acme/division",
        agent_id="agent/one",
        environment="prod west",
        policy_digest="digest",
        version="2",
    )

    assert captured[0][1] == (
        "/v1/organizations/acme%2Fdivision/policies/prod%20west/"
        "policy%20name/active"
    )
    assert captured[1][1].endswith("resolve?agent_id=agent%2Fone+%26+two")
    assert captured[2][1] == (
        "/v1/organizations/acme%2Fdivision/agents/agent%2Fone/"
        "prod%20west/heartbeat"
    )
