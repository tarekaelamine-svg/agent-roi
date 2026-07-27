from __future__ import annotations

from pathlib import Path

import pytest

from agent_roi.enterprise.control_plane import (
    ControlPlaneService,
    HMACPolicySigner,
    SqliteControlPlaneStore,
    create_fastapi_app,
)
from agent_roi.enterprise.identity import SqliteIdentityStore
from agent_roi.roi.ledger import RealizedROILedger


def _service(tmp_path: Path):
    signer = HMACPolicySigner(b"x" * 32)
    store = SqliteControlPlaneStore(tmp_path / "control.sqlite3")
    service = ControlPlaneService(
        store,
        signers={signer.key_id: signer},
        default_signer_key_id=signer.key_id,
    )
    return service


def test_agent_api_paginates_and_returns_correlation_headers(tmp_path: Path) -> None:
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    service = _service(tmp_path)
    for index in range(4):
        service.register_agent(
            organization_id="acme",
            agent_id=f"agent-{index}",
            environment="prod",
            owner="owner",
            purpose="test",
        )
    app = create_fastapi_app(service)
    response = TestClient(app).get(
        "/v1/organizations/acme/agents?limit=2&offset=1",
        headers={"X-Correlation-ID": "corr-1"},
    )
    assert response.status_code == 200
    assert [item["agent_id"] for item in response.json()] == ["agent-1", "agent-2"]
    assert response.headers["X-Correlation-ID"] == "corr-1"
    assert response.headers["X-Agent-ROI-API-Version"] == "2.0"


def test_agent_api_if_match_prevents_lost_update(tmp_path: Path) -> None:
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    service = _service(tmp_path)
    service.register_agent(
        organization_id="acme",
        agent_id="agent-1",
        environment="prod",
        owner="owner",
        purpose="test",
    )
    client = TestClient(create_fastapi_app(service))
    body = {
        "agent_id": "agent-1",
        "environment": "prod",
        "owner": "new-owner",
        "purpose": "updated",
    }
    ok = client.post("/v1/organizations/acme/agents", json=body, headers={"If-Match": '"1"'})
    assert ok.status_code == 200
    assert ok.json()["revision"] == 2
    conflict = client.post("/v1/organizations/acme/agents", json=body, headers={"If-Match": '"1"'})
    assert conflict.status_code == 409


def test_policy_activation_if_match_is_optimistic(tmp_path: Path) -> None:
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    service = _service(tmp_path)
    for version in ("1", "2"):
        service.publish_policy(
            organization_id="acme",
            name="finance",
            environment="prod",
            version=version,
            policy={
                "policy_name": "finance",
                "guardrails": {
                    "max_steps": 10,
                    "max_tool_calls": 5,
                    "max_cost_usd": 10.0,
                    "allowed_tools": ["lookup"],
                    "require_registered_tools": False,
                    "require_bound_approval_grants": False,
                },
                "decision_policy": {
                    "min_confidence": 0.7,
                    "abstain_action": "human_review",
                },
            },
            created_by="admin",
        )
    service.activate_policy(
        organization_id="acme", name="finance", environment="prod", version="1", activated_by="admin"
    )
    client = TestClient(create_fastapi_app(service))
    path = "/v1/organizations/acme/policies/prod/finance/2/activate"
    activated = client.post(path, headers={"If-Match": 'W/"1"'})
    assert activated.status_code == 200
    assert activated.json()["revision"] == 2
    active = client.get("/v1/organizations/acme/policies/prod/finance/active")
    assert active.json()["revision"] == 2
    assert client.post(path, headers={"If-Match": "1"}).status_code == 409


def test_roi_api_paginates_and_enforces_revision(tmp_path: Path) -> None:
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    service = _service(tmp_path)
    ledger = RealizedROILedger(tmp_path / "roi.sqlite3")
    for index in range(3):
        ledger.create_opportunity(
            organization_id="acme",
            agent_id="agent",
            business_unit="finance",
            business_owner="owner",
            title=f"Opportunity {index}",
            value_type="cost_savings",
            value_period="one_time",
            baseline_usd=1000,
            forecast_value_usd=100,
            confidence=0.8,
            source_key=f"source-{index}",
            created_by="owner",
            opportunity_id=f"roi-{index}",
        )
    client = TestClient(create_fastapi_app(service, roi_ledger=ledger))
    page = client.get("/v1/organizations/acme/roi/opportunities?limit=1&offset=1")
    assert page.status_code == 200
    assert [item["opportunity_id"] for item in page.json()] == ["roi-1"]
    transition = client.post(
        "/v1/organizations/acme/roi/opportunities/roi-1/transition",
        json={"status": "approved", "changed_by": "owner"},
        headers={"If-Match": "1"},
    )
    assert transition.status_code == 200
    assert transition.json()["revision"] == 2
    conflict = client.post(
        "/v1/organizations/acme/roi/opportunities/roi-1/transition",
        json={"status": "in_progress", "changed_by": "owner"},
        headers={"If-Match": "1"},
    )
    assert conflict.status_code == 400


def test_scim_api_paginates_postgres_compatible_directory(tmp_path: Path) -> None:
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    service = _service(tmp_path)
    identity = SqliteIdentityStore(tmp_path / "identity.sqlite3")
    for index in range(3):
        identity.create_user({"userName": f"user-{index}@example.com"})
    client = TestClient(create_fastapi_app(service, scim_directory=identity))
    response = client.get("/scim/v2/Users?startIndex=2&count=1")
    # SQLite directory is the single-node reference backend. The API still
    # slices consistently when the repository itself lacks pagination args.
    assert response.status_code == 200
    payload = response.json()
    assert payload["startIndex"] == 2
    assert payload["itemsPerPage"] == 1
    assert payload["totalResults"] == 3
    assert payload["Resources"][0]["userName"] == "user-1@example.com"


def test_scim_group_page_reports_total_results(tmp_path: Path) -> None:
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    service = _service(tmp_path)
    identity = SqliteIdentityStore(tmp_path / "identity-groups.sqlite3")
    for index in range(3):
        identity.create_group({"displayName": f"group-{index}"})
    client = TestClient(create_fastapi_app(service, scim_directory=identity))
    response = client.get("/scim/v2/Groups?startIndex=3&count=1")
    assert response.status_code == 200
    payload = response.json()
    assert payload["totalResults"] == 3
    assert payload["itemsPerPage"] == 1
    assert payload["Resources"][0]["displayName"] == "group-2"
