from __future__ import annotations

from typing import Any, Mapping, Optional
from urllib.parse import quote

from .base import ApprovalRecord, ApprovalRequest, JsonHttpApprovalProvider


class WebhookApprovalProvider(JsonHttpApprovalProvider):
    name = "webhook"


class ServiceNowApprovalProvider(JsonHttpApprovalProvider):
    name = "servicenow"

    def __init__(
        self,
        instance_url: str,
        *,
        bearer_token: str,
        table: str = "sc_request",
        timeout_seconds: float = 10.0,
        require_https: bool = True,
    ) -> None:
        endpoint = instance_url.rstrip("/") + f"/api/now/table/{quote(table)}"
        super().__init__(
            endpoint,
            headers={"Authorization": f"Bearer {bearer_token}"},
            timeout_seconds=timeout_seconds,
            require_https=require_https,
        )

    def build_payload(self, request: ApprovalRequest) -> Mapping[str, Any]:
        return {
            "short_description": request.summary,
            "description": (
                f"Agent: {request.agent_id}\nEnvironment: {request.environment}\n"
                f"Tool: {request.tool_name} {request.tool_version}\nRisk: {request.risk}\n"
                f"Estimated cost: ${request.estimated_cost_usd:.4f}\n"
                f"Action digest: {request.action_digest}\nCheckpoint: {request.checkpoint_id}"
            ),
            "correlation_id": request.correlation_id,
        }

    def extract_external_id(self, response: Any, request: ApprovalRequest) -> str:
        if isinstance(response, Mapping) and isinstance(response.get("result"), Mapping):
            return str(response["result"].get("sys_id") or response["result"].get("number") or request.request_id)
        return super().extract_external_id(response, request)


class JiraServiceManagementApprovalProvider(JsonHttpApprovalProvider):
    name = "jira_service_management"

    def __init__(
        self,
        base_url: str,
        *,
        bearer_token: str,
        service_desk_id: str,
        request_type_id: str,
        timeout_seconds: float = 10.0,
        require_https: bool = True,
    ) -> None:
        endpoint = base_url.rstrip("/") + "/rest/servicedeskapi/request"
        super().__init__(
            endpoint,
            headers={"Authorization": f"Bearer {bearer_token}"},
            timeout_seconds=timeout_seconds,
            require_https=require_https,
        )
        self.service_desk_id = service_desk_id
        self.request_type_id = request_type_id

    def build_payload(self, request: ApprovalRequest) -> Mapping[str, Any]:
        return {
            "serviceDeskId": self.service_desk_id,
            "requestTypeId": self.request_type_id,
            "requestFieldValues": {
                "summary": request.summary,
                "description": (
                    f"Tool: {request.tool_name}\nRisk: {request.risk}\n"
                    f"Environment: {request.environment}\nAction digest: {request.action_digest}\n"
                    f"Checkpoint: {request.checkpoint_id}"
                ),
            },
        }

    def extract_external_id(self, response: Any, request: ApprovalRequest) -> str:
        if isinstance(response, Mapping):
            return str(response.get("issueKey") or response.get("requestId") or request.request_id)
        return request.request_id


class SlackApprovalProvider(JsonHttpApprovalProvider):
    name = "slack"

    def build_payload(self, request: ApprovalRequest) -> Mapping[str, Any]:
        return {
            "text": request.summary,
            "blocks": [
                {"type": "header", "text": {"type": "plain_text", "text": "Agent-ROI approval required"}},
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Agent*\n{request.agent_id or 'unknown'}"},
                        {"type": "mrkdwn", "text": f"*Tool*\n{request.tool_name}"},
                        {"type": "mrkdwn", "text": f"*Environment*\n{request.environment or 'unknown'}"},
                        {"type": "mrkdwn", "text": f"*Risk*\n{request.risk}"},
                        {"type": "mrkdwn", "text": f"*Estimated cost*\n${request.estimated_cost_usd:.4f}"},
                        {"type": "mrkdwn", "text": f"*Checkpoint*\n`{request.checkpoint_id}`"},
                    ],
                },
            ],
        }


class TeamsApprovalProvider(JsonHttpApprovalProvider):
    name = "microsoft_teams"

    def build_payload(self, request: ApprovalRequest) -> Mapping[str, Any]:
        return {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": {
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "type": "AdaptiveCard",
                        "version": "1.4",
                        "body": [
                            {"type": "TextBlock", "size": "Large", "weight": "Bolder", "text": "Agent-ROI approval required"},
                            {"type": "TextBlock", "wrap": True, "text": request.summary},
                            {
                                "type": "FactSet",
                                "facts": [
                                    {"title": "Agent", "value": request.agent_id or "unknown"},
                                    {"title": "Tool", "value": request.tool_name},
                                    {"title": "Environment", "value": request.environment or "unknown"},
                                    {"title": "Risk", "value": request.risk},
                                    {"title": "Estimated cost", "value": f"${request.estimated_cost_usd:.4f}"},
                                    {"title": "Checkpoint", "value": request.checkpoint_id},
                                ],
                            },
                        ],
                    },
                }
            ],
        }


class PagerDutyApprovalProvider(JsonHttpApprovalProvider):
    """Create a PagerDuty Events API v2 alert for a pending approval."""

    name = "pagerduty"

    def __init__(
        self,
        routing_key: str,
        *,
        endpoint: str = "https://events.pagerduty.com/v2/enqueue",
        timeout_seconds: float = 10.0,
        require_https: bool = True,
    ) -> None:
        if not routing_key.strip():
            raise ValueError("PagerDuty routing_key is required")
        super().__init__(
            endpoint,
            timeout_seconds=timeout_seconds,
            require_https=require_https,
        )
        self.routing_key = routing_key.strip()

    def build_payload(self, request: ApprovalRequest) -> Mapping[str, Any]:
        return {
            "routing_key": self.routing_key,
            "event_action": "trigger",
            "dedup_key": request.checkpoint_id,
            "payload": {
                "summary": request.summary,
                "source": request.agent_id or "agent-roi",
                "severity": "critical" if request.risk in {"critical", "high"} else "warning",
                "component": request.tool_name,
                "group": request.environment or "default",
                "class": "agent_action_approval",
                "custom_details": request.to_dict(),
            },
        }

    def extract_external_id(self, response: Any, request: ApprovalRequest) -> str:
        if isinstance(response, Mapping):
            return str(response.get("dedup_key") or request.checkpoint_id)
        return request.checkpoint_id


class SMTPApprovalProvider:
    """Send reviewable approval notifications through an enterprise SMTP relay."""

    name = "smtp"

    def __init__(
        self,
        host: str,
        *,
        sender: str,
        recipients: list[str] | tuple[str, ...],
        port: int = 587,
        username: str = "",
        password: str = "",
        use_starttls: bool = True,
        timeout_seconds: float = 10.0,
    ) -> None:
        if not host.strip() or not sender.strip() or not recipients:
            raise ValueError("SMTP host, sender, and at least one recipient are required")
        self.host = host.strip()
        self.port = int(port)
        self.sender = sender.strip()
        self.recipients = tuple(str(value).strip() for value in recipients if str(value).strip())
        if not self.recipients:
            raise ValueError("At least one non-empty SMTP recipient is required")
        self.username = username
        self.password = password
        self.use_starttls = bool(use_starttls)
        self.timeout_seconds = float(timeout_seconds)

    def submit(self, request: ApprovalRequest) -> str:
        from email.message import EmailMessage
        import smtplib

        message = EmailMessage()
        message["Subject"] = f"Agent-ROI approval required: {request.tool_name}"
        message["From"] = self.sender
        message["To"] = ", ".join(self.recipients)
        message.set_content(
            "\n".join(
                [
                    request.summary,
                    "",
                    f"Agent: {request.agent_id or 'unknown'}",
                    f"Environment: {request.environment or 'unknown'}",
                    f"Tool: {request.tool_name} {request.tool_version}",
                    f"Risk: {request.risk}",
                    f"Estimated cost: ${request.estimated_cost_usd:.4f}",
                    f"Checkpoint: {request.checkpoint_id}",
                    f"Action digest: {request.action_digest}",
                    f"Expires: {request.expires_at_epoch_ms}",
                ]
            )
        )
        with smtplib.SMTP(self.host, self.port, timeout=self.timeout_seconds) as client:
            if self.use_starttls:
                client.starttls()
            if self.username:
                client.login(self.username, self.password)
            client.send_message(message)
        return request.request_id

    def update(self, record: ApprovalRecord) -> None:
        return None
