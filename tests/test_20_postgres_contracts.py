from __future__ import annotations

from dataclasses import dataclass
import json
import time
from typing import Any, Mapping

import pytest

from agent_roi.approvals import ApprovalRecord, ApprovalRequest, ApprovalStatus
from agent_roi.approvals.postgres import PostgresApprovalRepository
from agent_roi.enterprise.outbox import PostgresOutboxStore
from agent_roi.enterprise.postgres import PostgresControlPlaneStore, PostgresIdentityStore
from agent_roi.roi.postgres import PostgresROILedger
from agent_roi.runtime.resilience import PostgresIdempotencyStore


@dataclass
class Step:
    contains: str
    rows: list[Any]
    rowcount: int = 0


class ScriptedDB:
    def __init__(self, steps: list[Step]) -> None:
        self.steps = list(steps)
        self.calls: list[tuple[str, tuple[Any, ...]]] = []
        self.commits = 0
        self.rollbacks = 0

    def connect(self, dsn: str, **kwargs):
        assert dsn == "postgresql://contract"
        return ScriptedConnection(self)

    def assert_complete(self) -> None:
        assert self.steps == []


class ScriptedConnection:
    def __init__(self, db: ScriptedDB) -> None:
        self.db = db

    def cursor(self):
        return ScriptedCursor(self.db)

    def commit(self):
        self.db.commits += 1

    def rollback(self):
        self.db.rollbacks += 1

    def close(self):
        return None


class ScriptedCursor:
    description = None

    def __init__(self, db: ScriptedDB) -> None:
        self.db = db
        self.rows: list[Any] = []
        self.rowcount = 0

    def execute(self, sql, params=None):
        normalized = " ".join(str(sql).split())
        params = tuple(params or ())
        self.db.calls.append((normalized, params))
        if normalized.startswith("CREATE SCHEMA") or normalized.startswith("SET search_path"):
            self.rows = []
            self.rowcount = 0
            return
        if not self.db.steps:
            raise AssertionError(f"Unexpected SQL: {normalized}")
        step = self.db.steps.pop(0)
        assert step.contains.lower() in normalized.lower(), (step.contains, normalized)
        self.rows = list(step.rows)
        self.rowcount = step.rowcount

    def fetchone(self):
        return self.rows[0] if self.rows else None

    def fetchall(self):
        return list(self.rows)

    def close(self):
        return None


def _agent_row() -> dict[str, Any]:
    return {
        "organization_id": "acme",
        "agent_id": "invoice-agent",
        "environment": "prod",
        "owner": "platform",
        "purpose": "invoices",
        "status": "production",
        "metadata_json": {"tier": "critical"},
        "registered_at_utc": "2026-01-01T00:00:00+00:00",
        "last_heartbeat_utc": "2026-01-02T00:00:00+00:00",
        "policy_digest": "digest",
        "version": "2.0.0",
        "revision": 4,
    }


def _roi_row() -> dict[str, Any]:
    return {
        "opportunity_id": "roi-1",
        "organization_id": "acme",
        "agent_id": "invoice-agent",
        "business_unit": "finance",
        "business_owner": "controller",
        "title": "Duplicate recovery",
        "value_type": "cost_savings",
        "value_period": "one_time",
        "status": "proposed",
        "currency_code": "USD",
        "baseline_cents": 100000,
        "forecast_cents": 25000,
        "confidence": 0.8,
        "source_key": "source-1",
        "measurement_start": "2026-01-01",
        "measurement_end": "2026-03-31",
        "created_at_utc": "2026-01-01T00:00:00+00:00",
        "created_by": "owner",
        "metadata_json": {"system": "erp"},
        "revision": 7,
    }


def test_postgres_control_plane_agent_pagination_contract() -> None:
    db = ScriptedDB([Step("SELECT * FROM agents", [_agent_row()])])
    store = PostgresControlPlaneStore(
        "postgresql://contract", connect_factory=db.connect, auto_migrate=False
    )
    agents = store.list_agents("acme", environment="prod", status="production", limit=25, offset=5)
    assert agents[0]["metadata"] == {"tier": "critical"}
    assert agents[0]["revision"] == 4
    sql, params = db.calls[-1]
    assert "LIMIT %s OFFSET %s" in sql
    assert params[-2:] == (25, 5)
    db.assert_complete()


def test_postgres_identity_preserves_custom_scim_attributes() -> None:
    row = {
        "user_id": "u-1",
        "user_name": "owner@example.com",
        "display_name": "Owner",
        "active": True,
        "emails_json": ["owner@example.com"],
        "attributes_json": {"urn:example:department": {"name": "Finance"}},
        "organization_id": "acme",
        "external_id": "external",
        "revision": 3,
    }
    db = ScriptedDB([Step("SELECT * FROM scim_users", [row])])
    store = PostgresIdentityStore(
        "postgresql://contract", connect_factory=db.connect, auto_migrate=False
    )
    user = store.get_user("u-1")
    assert user.attributes["urn:example:department"]["name"] == "Finance"
    assert user.attributes["organization_id"] == "acme"
    assert user.attributes["revision"] == 3
    db.assert_complete()


def test_postgres_approval_preserves_decision_timestamp() -> None:
    now = int(time.time() * 1000)
    request = ApprovalRequest(
        request_id="request-1",
        checkpoint_id="checkpoint-1",
        action_digest="a" * 64,
        organization_id="acme",
        environment="prod",
        agent_id="invoice-agent",
        correlation_id="corr",
        run_id="run",
        tool_name="pay_invoice",
        tool_version="2",
        risk="high",
        estimated_cost_usd=1.0,
        arguments_digest="b" * 64,
        policy_digest="c" * 64,
        created_at_epoch_ms=now,
        expires_at_epoch_ms=now + 60000,
    )
    record = ApprovalRecord(
        request=request,
        status=ApprovalStatus.APPROVED,
        external_id="ticket-1",
        decided_by="approver",
        reason="validated",
        decided_at_epoch_ms=now + 100,
    )
    row = {
        "checkpoint_id": request.checkpoint_id,
        "request_json": request.to_dict(),
        "status": "approved",
        "external_id": "ticket-1",
        "decided_by": "approver",
        "decision_reason": "validated",
        "decided_at_epoch_ms": now + 100,
    }
    db = ScriptedDB(
        [
            Step("INSERT INTO approval_records", [(2,)], rowcount=1),
            Step("SELECT * FROM approval_records", [row]),
        ]
    )
    repository = PostgresApprovalRepository(
        "postgresql://contract", connect_factory=db.connect, auto_migrate=False
    )
    assert repository.save_record(record) == 2
    restored = repository.get_record(request.checkpoint_id)
    assert restored.decided_at_epoch_ms == now + 100
    approval_insert = next(call for call in db.calls if "INSERT INTO approval_records" in call[0])
    assert approval_insert[1][-1] == now + 100
    db.assert_complete()


def test_postgres_roi_exposes_revision_and_page_parameters() -> None:
    db = ScriptedDB([Step("SELECT * FROM roi_opportunities", [_roi_row()])])
    ledger = PostgresROILedger(
        "postgresql://contract", connect_factory=db.connect, auto_migrate=False
    )
    opportunities = ledger.list_opportunities(
        organization_id="acme", agent_id="invoice-agent", limit=10, offset=20
    )
    assert opportunities[0].revision == 7
    assert opportunities[0].forecast_value_usd == 250.0
    assert db.calls[-1][1][-2:] == (10, 20)
    db.assert_complete()


def test_postgres_outbox_claim_uses_skip_locked() -> None:
    row = {
        "event_id": "evt-1",
        "topic": "audit",
        "destination": "splunk",
        "payload_json": {"x": 1},
        "idempotency_key": "idem-1",
        "status": "leased",
        "attempts": 1,
        "available_at_utc": "2026-01-01T00:00:00+00:00",
        "lease_owner": "worker",
        "lease_expires_at_utc": "2026-01-01T00:01:00+00:00",
        "last_error": "",
        "created_at_utc": "2026-01-01T00:00:00+00:00",
        "delivered_at_utc": None,
    }
    db = ScriptedDB([Step("FOR UPDATE SKIP LOCKED", [row], rowcount=1)])
    store = PostgresOutboxStore(
        "postgresql://contract", connect_factory=db.connect, auto_migrate=False
    )
    events = store.claim(worker_id="worker", destination="splunk", limit=5, lease_seconds=30)
    assert events[0].event_id == "evt-1"
    assert "FOR UPDATE SKIP LOCKED" in db.calls[-1][0]
    assert db.calls[-1][1] == ("splunk", 5, "worker", 30)
    db.assert_complete()


def test_postgres_idempotency_contract_returns_cached_response() -> None:
    cached = {
        "namespace": "payments",
        "idempotency_key": "key-1",
        "request_digest": "digest",
        "status": "completed",
        "response_json": {"payment": "P-1"},
        "error_text": "",
    }
    db = ScriptedDB(
        [
            Step("DELETE FROM idempotency_records", [], rowcount=0),
            Step("INSERT INTO idempotency_records", [], rowcount=0),
            Step("SELECT * FROM idempotency_records", [cached]),
        ]
    )
    store = PostgresIdempotencyStore(
        "postgresql://contract", connect_factory=db.connect, auto_migrate=False
    )
    result = store.begin("payments", "key-1", "digest", ttl_seconds=60)
    assert result.status == "completed"
    assert result.response == {"payment": "P-1"}
    db.assert_complete()


def _policy_bundle():
    from agent_roi.enterprise.control_plane import HMACPolicySigner, PolicyBundle

    return PolicyBundle.create(
        organization_id="acme",
        name="finance",
        environment="prod",
        version="2.0.0",
        policy={
            "policy_name": "finance",
            "guardrails": {
                "max_steps": 5,
                "max_tool_calls": 3,
                "max_cost_usd": 1.0,
                "allowed_tools": ["lookup"],
            },
            "decision_policy": {"min_confidence": 0.7, "abstain_action": "human_review"},
        },
        signer=HMACPolicySigner(b"x" * 32),
        created_by="admin",
    )


def _bundle_row(bundle):
    return {
        "organization_id": bundle.organization_id,
        "name": bundle.name,
        "environment": bundle.environment,
        "version": bundle.version,
        "payload_json": dict(bundle.policy),
        "digest": bundle.digest,
        "signature": bundle.signature,
        "signer_key_id": bundle.signer_key_id,
        "status": bundle.status,
        "created_at_utc": bundle.created_at_utc,
        "created_by": bundle.created_by,
    }


def test_postgres_control_plane_policy_crud_and_revision_contract() -> None:
    bundle = _policy_bundle()
    row = _bundle_row(bundle)
    db = ScriptedDB(
        [
            Step("INSERT INTO policy_bundles", [], rowcount=1),
            Step("SELECT * FROM policy_bundles", [row]),
            Step("SELECT * FROM policy_bundles", [row]),
            Step("INSERT INTO active_policies", [], rowcount=1),
            Step("DELETE FROM policy_rollouts", [], rowcount=0),
            Step("SELECT revision FROM active_policies", [{"revision": 2}]),
            Step("SELECT version FROM active_policies", [{"version": bundle.version}]),
            Step("SELECT * FROM policy_bundles", [row]),
        ]
    )
    store = PostgresControlPlaneStore(
        "postgresql://contract", connect_factory=db.connect, auto_migrate=False
    )
    store.save_bundle(bundle)
    assert store.get_bundle("acme", "finance", "prod", "2.0.0").digest == bundle.digest
    assert store.activate(
        "acme", "finance", "prod", "2.0.0", activated_by="admin"
    ).version == "2.0.0"
    assert store.get_active_revision("acme", "finance", "prod") == 2
    assert store.get_active("acme", "finance", "prod").version == "2.0.0"
    db.assert_complete()


def test_postgres_identity_create_list_count_and_group_contract() -> None:
    user_row = {
        "user_id": "u-1",
        "user_name": "owner@example.com",
        "display_name": "Owner",
        "active": True,
        "emails_json": ["owner@example.com"],
        "attributes_json": {"department": "Finance"},
        "organization_id": "acme",
        "external_id": "ext-1",
        "revision": 1,
    }
    group_row = {
        "group_id": "g-1",
        "display_name": "Approvers",
        "organization_id": "acme",
        "external_id": "ext-g",
        "revision": 1,
    }
    db = ScriptedDB(
        [
            Step("INSERT INTO scim_users", [], rowcount=1),
            Step("SELECT * FROM scim_users", [user_row]),
            Step("SELECT COUNT(*) AS count FROM scim_users", [{"count": 1}]),
            Step("SELECT * FROM scim_users", [user_row]),
            Step("INSERT INTO scim_groups", [], rowcount=1),
            Step("INSERT INTO scim_group_members", [], rowcount=1),
            Step("SELECT COUNT(*) AS count FROM scim_groups", [{"count": 1}]),
        ]
    )
    store = PostgresIdentityStore(
        "postgresql://contract", connect_factory=db.connect, auto_migrate=False
    )
    created = store.create_user(
        {
            "id": "u-1",
            "userName": "owner@example.com",
            "displayName": "Owner",
            "emails": [{"value": "owner@example.com"}],
            "externalId": "ext-1",
            "department": "Finance",
        },
        organization_id="acme",
    )
    assert created.user_name == "owner@example.com"
    assert store.list_users(organization_id="acme", limit=10)[0].id == "u-1"
    assert store.count_users(organization_id="acme") == 1
    group = store.create_group(
        {
            "id": "g-1",
            "displayName": "Approvers",
            "externalId": "ext-g",
            "members": [{"value": "u-1"}],
        },
        organization_id="acme",
    )
    assert group.members == frozenset({"u-1"})
    assert store.count_groups(organization_id="acme") == 1
    db.assert_complete()


def test_postgres_approval_grant_lifecycle_contract() -> None:
    from agent_roi.runtime.tools import ApprovalGrant

    grant = ApprovalGrant(
        action_digest="a" * 64,
        approved_by="approver",
        expires_at_epoch_ms=int(time.time() * 1000) + 60000,
        checkpoint_id="checkpoint-1",
        reason="approved",
    )
    row = {
        "action_digest": grant.action_digest,
        "checkpoint_id": grant.checkpoint_id,
        "approved_by": grant.approved_by,
        "expires_at_epoch_ms": grant.expires_at_epoch_ms,
        "reason": grant.reason,
        "consumed_at_utc": None,
    }
    db = ScriptedDB(
        [
            Step("INSERT INTO approval_grants", [(1,)], rowcount=1),
            Step("SELECT * FROM approval_grants", [row]),
            Step("UPDATE approval_grants SET consumed_at_utc", [{**row, "consumed_at_utc": "2026-01-01"}], rowcount=1),
            Step("SELECT * FROM approval_grants", []),
        ]
    )
    repository = PostgresApprovalRepository(
        "postgresql://contract", connect_factory=db.connect, auto_migrate=False
    )
    repository.save_grant(grant)
    assert repository.get_grant(grant.action_digest).approved_by == "approver"
    repository.consume_grant(grant.action_digest)
    with pytest.raises(KeyError):
        repository.get_grant(grant.action_digest)
    db.assert_complete()


def test_postgres_roi_create_transition_value_cost_and_summary_contract() -> None:
    proposed = _roi_row()
    proposed["value_type"] = "cost_savings"
    in_progress = {**proposed, "status": "in_progress", "revision": 3}
    db = ScriptedDB(
        [
            Step("INSERT INTO roi_opportunities", [], rowcount=1),
            Step("SELECT * FROM roi_opportunities", [proposed]),
            Step("SELECT * FROM roi_opportunities", [proposed]),
            Step("UPDATE roi_opportunities", [], rowcount=1),
            Step("INSERT INTO roi_status_history", [], rowcount=1),
            Step("SELECT * FROM roi_opportunities", [in_progress]),
            Step("SELECT * FROM roi_opportunities", [in_progress]),
            Step("INSERT INTO roi_values", [], rowcount=1),
            Step("SELECT * FROM roi_opportunities", [in_progress]),
            Step("INSERT INTO roi_costs", [], rowcount=1),
            Step("SELECT * FROM roi_opportunities", [in_progress]),
            Step("SELECT opportunity_id,stage,amount_cents FROM roi_values", [
                {"opportunity_id": "roi-1", "stage": "validated", "amount_cents": 20000}
            ]),
            Step("SELECT agent_id,opportunity_id,amount_cents FROM roi_costs", [
                {"agent_id": "invoice-agent", "opportunity_id": "roi-1", "amount_cents": 5000}
            ]),
        ]
    )
    ledger = PostgresROILedger(
        "postgresql://contract", connect_factory=db.connect, auto_migrate=False
    )
    created = ledger.create_opportunity(
        opportunity_id="roi-1",
        organization_id="acme",
        agent_id="invoice-agent",
        business_unit="finance",
        business_owner="controller",
        title="Duplicate recovery",
        value_type="cost_savings",
        value_period="one_time",
        baseline_usd=1000,
        forecast_value_usd=250,
        confidence=0.8,
        source_key="source-1",
        created_by="owner",
        measurement_start="2026-01-01",
        measurement_end="2026-03-31",
        metadata={"system": "erp"},
    )
    assert created.opportunity_id == "roi-1"
    transitioned = ledger.transition(
        "roi-1", "approved", changed_by="controller", expected_revision=7
    )
    assert transitioned.status.value == "in_progress"
    value = ledger.record_value(
        "roi-1", stage="validated", amount_usd=200, evidence_key="evidence-1", recorded_by="finance"
    )
    assert value["amount_usd"] == 200.0
    cost = ledger.record_cost(
        organization_id="acme",
        agent_id="invoice-agent",
        opportunity_id="roi-1",
        cost_type="model",
        amount_usd=50,
        currency_code="USD",
        evidence_key="cost-1",
        recorded_by="platform",
    )
    assert cost["amount_usd"] == 50.0
    summary = ledger.portfolio_summary(
        organization_id="acme", agent_id="invoice-agent", currency_code="USD"
    )
    assert summary["net_validated_value_usd"] == 150.0
    assert summary["validated_roi_multiple"] == 4.0
    db.assert_complete()
