from __future__ import annotations

import time

import pytest

from agent_roi import Guardrails, SentinelRunner, ToolRegistry
from agent_roi.approvals import (
    ApprovalBroker,
    InMemoryApprovalProvider,
    JiraServiceManagementApprovalProvider,
    ServiceNowApprovalProvider,
    SlackApprovalProvider,
    TeamsApprovalProvider,
)
from agent_roi.enterprise.identity import Principal, RBACAuthorizer, RoleDefinition


def _runner(broker: ApprovalBroker, called: list[str]) -> SentinelRunner:
    registry = ToolRegistry()
    registry.add(
        "pay_invoice",
        lambda invoice_id: called.append(invoice_id) or "paid",
        risk="high",
        requires_approval=True,
        version="2",
    )
    return SentinelRunner(
        guardrails=Guardrails(
            allowed_tools=frozenset({"pay_invoice"}),
            require_registered_tools=True,
            require_bound_approval_grants=True,
        ),
        tool_registry=registry,
        approval_callback=broker,
        organization_id="acme",
        environment="prod",
        agent_id="invoice-agent",
    )


def test_approval_broker_submits_once_then_returns_bound_grant() -> None:
    provider = InMemoryApprovalProvider()
    authorizer = RBACAuthorizer(
        [RoleDefinition("approver", frozenset({"approval.decide:*"}))]
    )
    broker = ApprovalBroker(
        provider,
        organization_id="acme",
        environment="prod",
        agent_id="invoice-agent",
        requested_by="requester",
        authorizer=authorizer,
    )
    called: list[str] = []
    first = _runner(broker, called).run(
        lambda ctx, _: ctx.call_tool("pay_invoice", "INV-1"), None
    )
    assert first.outcome.value == "human_review"
    assert called == []
    checkpoint = first.output["approval_checkpoint"]
    assert len(provider.records) == 1

    approver = Principal("approver-1", "acme", roles=frozenset({"approver"}))
    record = broker.decide(
        checkpoint["checkpoint_id"],
        approved=True,
        principal=approver,
        reason="Validated against PO",
    )
    assert record.status.value == "approved"
    second = _runner(broker, called).run(
        lambda ctx, _: ctx.call_tool("pay_invoice", "INV-1"), None
    )
    assert second.output == "paid"
    assert called == ["INV-1"]


def test_approval_broker_enforces_separation_of_duties() -> None:
    broker = ApprovalBroker(
        InMemoryApprovalProvider(),
        requested_by="same-user",
    )
    first = _runner(broker, []).run(
        lambda ctx, _: ctx.call_tool("pay_invoice", "INV-1"), None
    )
    checkpoint_id = first.output["approval_checkpoint"]["checkpoint_id"]
    with pytest.raises(PermissionError, match="own actions"):
        broker.decide(
            checkpoint_id,
            approved=True,
            principal=Principal("same-user", "acme"),
        )


def test_approval_integration_payloads_include_action_details() -> None:
    broker = ApprovalBroker(InMemoryApprovalProvider(), agent_id="agent", environment="prod")
    first = _runner(broker, []).run(
        lambda ctx, _: ctx.call_tool("pay_invoice", "INV-1"), None
    )
    request = broker.pending()[0].request

    service_now = ServiceNowApprovalProvider(
        "https://example.service-now.com", bearer_token="token"
    )
    jira = JiraServiceManagementApprovalProvider(
        "https://jira.example",
        bearer_token="token",
        service_desk_id="1",
        request_type_id="2",
    )
    slack = SlackApprovalProvider("https://hooks.slack.com/test")
    teams = TeamsApprovalProvider("https://example.webhook.office.com/test")

    assert request.action_digest in service_now.build_payload(request)["description"]
    assert request.action_digest in jira.build_payload(request)["requestFieldValues"]["description"]
    assert slack.build_payload(request)["blocks"][1]["fields"]
    assert teams.build_payload(request)["attachments"][0]["content"]["body"]


def test_sqlite_approval_repository_survives_broker_restart(tmp_path) -> None:
    from agent_roi.approvals import SqliteApprovalRepository

    repository = SqliteApprovalRepository(tmp_path / "approvals.sqlite3")
    provider = InMemoryApprovalProvider()
    broker = ApprovalBroker(
        provider,
        organization_id="acme",
        environment="prod",
        agent_id="invoice-agent",
        requested_by="requester",
        repository=repository,
    )
    called: list[str] = []
    first = _runner(broker, called).run(
        lambda ctx, _: ctx.call_tool("pay_invoice", "INV-2"), None
    )
    checkpoint = first.output["approval_checkpoint"]
    broker.decide(
        checkpoint["checkpoint_id"],
        approved=True,
        principal=Principal("approver", "acme"),
    )

    restarted = ApprovalBroker(
        InMemoryApprovalProvider(),
        organization_id="acme",
        environment="prod",
        agent_id="invoice-agent",
        requested_by="requester",
        repository=SqliteApprovalRepository(tmp_path / "approvals.sqlite3"),
    )
    second = _runner(restarted, called).run(
        lambda ctx, _: ctx.call_tool("pay_invoice", "INV-2"), None
    )
    assert second.output == "paid"
    assert called == ["INV-2"]


def test_pagerduty_and_email_approval_integrations(monkeypatch) -> None:
    from agent_roi.approvals import PagerDutyApprovalProvider, SMTPApprovalProvider

    broker = ApprovalBroker(InMemoryApprovalProvider(), agent_id="agent", environment="prod")
    _runner(broker, []).run(
        lambda ctx, _: ctx.call_tool("pay_invoice", "INV-3"), None
    )
    request = broker.pending()[0].request

    pagerduty = PagerDutyApprovalProvider("routing-key")
    payload = pagerduty.build_payload(request)
    assert payload["dedup_key"] == request.checkpoint_id
    assert payload["payload"]["custom_details"]["action_digest"] == request.action_digest

    sent = {}

    class FakeSMTP:
        def __init__(self, host, port, timeout):
            sent["connection"] = (host, port, timeout)
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return False
        def starttls(self):
            sent["tls"] = True
        def login(self, username, password):
            sent["login"] = (username, password)
        def send_message(self, message):
            sent["message"] = message

    monkeypatch.setattr("smtplib.SMTP", FakeSMTP)
    provider = SMTPApprovalProvider(
        "smtp.example.com",
        sender="agentroi@example.com",
        recipients=["approvers@example.com"],
        username="user",
        password="secret",
    )
    assert provider.submit(request) == request.request_id
    assert sent["tls"] is True
    assert request.checkpoint_id in sent["message"].get_content()
