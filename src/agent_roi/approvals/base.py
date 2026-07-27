from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import json
import threading
import time
from typing import Any, Mapping, Optional, Protocol
from urllib import error as urlerror
from urllib import request as urlrequest
import uuid

from agent_roi._serialization import canonical_json
from agent_roi.runtime.tools import ApprovalGrant, ToolSpec


class ApprovalStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"
    CANCELLED = "cancelled"


@dataclass(frozen=True)
class ApprovalRequest:
    request_id: str
    checkpoint_id: str
    action_digest: str
    organization_id: str
    environment: str
    agent_id: str
    correlation_id: str
    run_id: str
    tool_name: str
    tool_version: str
    risk: str
    estimated_cost_usd: float
    arguments_digest: str
    policy_digest: str
    created_at_epoch_ms: int
    expires_at_epoch_ms: int
    requested_by: str = ""
    summary: str = ""
    metadata: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_checkpoint(
        cls,
        checkpoint: Mapping[str, Any],
        *,
        organization_id: str = "",
        environment: str = "",
        agent_id: str = "",
        requested_by: str = "",
        summary: str = "",
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> "ApprovalRequest":
        return cls(
            request_id=str(uuid.uuid4()),
            checkpoint_id=str(checkpoint["checkpoint_id"]),
            action_digest=str(checkpoint["action_digest"]),
            organization_id=organization_id,
            environment=environment,
            agent_id=agent_id,
            correlation_id=str(checkpoint.get("correlation_id", "")),
            run_id=str(checkpoint.get("run_id", "")),
            tool_name=str(checkpoint["tool_name"]),
            tool_version=str(checkpoint.get("tool_version", "")),
            risk=str(checkpoint.get("risk", "unknown")),
            estimated_cost_usd=float(checkpoint.get("estimated_cost_usd", 0.0)),
            arguments_digest=str(checkpoint.get("arguments_digest", "")),
            policy_digest=str(checkpoint.get("policy_digest", "")),
            created_at_epoch_ms=int(checkpoint.get("created_at_epoch_ms", int(time.time() * 1000))),
            expires_at_epoch_ms=int(checkpoint["expires_at_epoch_ms"]),
            requested_by=requested_by,
            summary=summary or f"Approve {checkpoint['tool_name']} execution",
            metadata=dict(metadata or {}),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "checkpoint_id": self.checkpoint_id,
            "action_digest": self.action_digest,
            "organization_id": self.organization_id,
            "environment": self.environment,
            "agent_id": self.agent_id,
            "correlation_id": self.correlation_id,
            "run_id": self.run_id,
            "tool_name": self.tool_name,
            "tool_version": self.tool_version,
            "risk": self.risk,
            "estimated_cost_usd": self.estimated_cost_usd,
            "arguments_digest": self.arguments_digest,
            "policy_digest": self.policy_digest,
            "created_at_epoch_ms": self.created_at_epoch_ms,
            "expires_at_epoch_ms": self.expires_at_epoch_ms,
            "requested_by": self.requested_by,
            "summary": self.summary,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class ApprovalRecord:
    request: ApprovalRequest
    status: ApprovalStatus
    external_id: str = ""
    decided_by: str = ""
    reason: str = ""
    decided_at_epoch_ms: int = 0


class ApprovalProvider(Protocol):
    name: str
    def submit(self, request: ApprovalRequest) -> str: ...
    def update(self, record: ApprovalRecord) -> None: ...


class InMemoryApprovalProvider:
    name = "memory"

    def __init__(self) -> None:
        self.records: dict[str, ApprovalRecord] = {}

    def submit(self, request: ApprovalRequest) -> str:
        self.records[request.request_id] = ApprovalRecord(request, ApprovalStatus.PENDING)
        return request.request_id

    def update(self, record: ApprovalRecord) -> None:
        self.records[record.request.request_id] = record


class JsonHttpApprovalProvider:
    """Base provider for ticketing, chat, and webhook integrations."""

    name = "http"

    def __init__(
        self,
        endpoint: str,
        *,
        headers: Optional[Mapping[str, str]] = None,
        timeout_seconds: float = 10.0,
        require_https: bool = True,
    ) -> None:
        if require_https and not endpoint.lower().startswith("https://"):
            raise ValueError("Approval integration endpoints must use HTTPS")
        self.endpoint = endpoint
        self.headers = dict(headers or {})
        self.timeout_seconds = float(timeout_seconds)

    def build_payload(self, request: ApprovalRequest) -> Mapping[str, Any]:
        return request.to_dict()

    def extract_external_id(self, response: Any, request: ApprovalRequest) -> str:
        if isinstance(response, Mapping):
            for key in ("id", "key", "sys_id", "request_id"):
                if response.get(key):
                    return str(response[key])
        return request.request_id

    def _post(self, payload: Mapping[str, Any]) -> Any:
        req = urlrequest.Request(
            self.endpoint,
            data=canonical_json(dict(payload)).encode("utf-8"),
            method="POST",
            headers={"Content-Type": "application/json", "Accept": "application/json", **self.headers},
        )
        try:
            with urlrequest.urlopen(req, timeout=self.timeout_seconds) as response:
                body = response.read()
                if response.status < 200 or response.status >= 300:
                    raise RuntimeError(f"Approval integration returned HTTP {response.status}")
                return json.loads(body) if body else {}
        except urlerror.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Approval integration returned HTTP {exc.code}: {detail}") from exc
        except OSError as exc:
            raise RuntimeError("Approval integration is unavailable") from exc

    def submit(self, request: ApprovalRequest) -> str:
        response = self._post(self.build_payload(request))
        return self.extract_external_id(response, request)

    def update(self, record: ApprovalRecord) -> None:
        # Not every inbound webhook/ticket API supports updates. Subclasses may
        # override this; a submitted record remains auditable in the broker.
        return None


class ApprovalBroker:
    """Thread-safe approval workflow and Sentinel approval callback.

    A first tool attempt submits exactly one external request and returns
    ``False``, causing a human-review result. An authorized approver can then
    issue a payload-bound grant; a retried run receives that grant.
    """

    def __init__(
        self,
        provider: ApprovalProvider,
        *,
        organization_id: str = "",
        environment: str = "",
        agent_id: str = "",
        requested_by: str = "",
        authorizer: Any = None,
        repository: Any = None,
    ) -> None:
        self.provider = provider
        self.organization_id = organization_id
        self.environment = environment
        self.agent_id = agent_id
        self.requested_by = requested_by
        self.authorizer = authorizer
        self.repository = repository
        self._records: dict[str, ApprovalRecord] = {}
        self._grants: dict[str, ApprovalGrant] = {}
        self._approved_actions: dict[str, ApprovalGrant] = {}
        self._lock = threading.RLock()

    def __call__(
        self,
        spec: ToolSpec[Any],
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
        checkpoint: Mapping[str, Any],
    ) -> ApprovalGrant | bool:
        checkpoint_id = str(checkpoint["checkpoint_id"])
        with self._lock:
            grant = self._grants.get(checkpoint_id)
            if grant is not None:
                try:
                    grant.validate(dict(checkpoint))
                except ValueError:
                    self._grants.pop(checkpoint_id, None)
                else:
                    return grant
            action_digest = str(checkpoint["action_digest"])
            approved_action = self._approved_actions.get(action_digest)
            if approved_action is None and self.repository is not None:
                try:
                    approved_action = self.repository.get_grant(action_digest)
                except KeyError:
                    approved_action = None
            if approved_action is not None:
                now_ms = int(time.time() * 1000)
                if now_ms <= approved_action.expires_at_epoch_ms:
                    replay = ApprovalGrant(
                        action_digest=action_digest,
                        approved_by=approved_action.approved_by,
                        expires_at_epoch_ms=min(
                            approved_action.expires_at_epoch_ms,
                            int(checkpoint["expires_at_epoch_ms"]),
                        ),
                        checkpoint_id=checkpoint_id,
                        reason=approved_action.reason,
                    )
                    self._grants[checkpoint_id] = replay
                    return replay
                self._approved_actions.pop(action_digest, None)
            if checkpoint_id not in self._records and self.repository is not None:
                try:
                    self._records[checkpoint_id] = self.repository.get_record(checkpoint_id)
                except KeyError:
                    pass
            if checkpoint_id not in self._records:
                request = ApprovalRequest.from_checkpoint(
                    checkpoint,
                    organization_id=self.organization_id,
                    environment=self.environment,
                    agent_id=self.agent_id,
                    requested_by=self.requested_by,
                    summary=f"Approve {spec.name} ({spec.risk} risk)",
                    metadata={"argument_count": len(args), "keyword_names": sorted(kwargs)},
                )
                external_id = self.provider.submit(request)
                self._records[checkpoint_id] = ApprovalRecord(
                    request=request,
                    status=ApprovalStatus.PENDING,
                    external_id=external_id,
                )
                if self.repository is not None:
                    self.repository.save_record(self._records[checkpoint_id])
            return False

    def decide(
        self,
        checkpoint_id: str,
        *,
        approved: bool,
        principal: Any,
        reason: str = "",
        ttl_seconds: Optional[int] = None,
    ) -> ApprovalRecord:
        with self._lock:
            try:
                current = self._records[checkpoint_id]
            except KeyError:
                if self.repository is not None:
                    try:
                        current = self.repository.get_record(checkpoint_id)
                        self._records[checkpoint_id] = current
                    except KeyError as exc:
                        raise KeyError(f"Approval checkpoint not found: {checkpoint_id}") from exc
                else:
                    raise KeyError(f"Approval checkpoint not found: {checkpoint_id}")
            if current.status is not ApprovalStatus.PENDING:
                raise ValueError("Approval request has already been decided")
            now_ms = int(time.time() * 1000)
            if now_ms > current.request.expires_at_epoch_ms:
                expired = ApprovalRecord(
                    request=current.request,
                    status=ApprovalStatus.EXPIRED,
                    external_id=current.external_id,
                    decided_at_epoch_ms=now_ms,
                )
                self._records[checkpoint_id] = expired
                if self.repository is not None:
                    self.repository.save_record(expired)
                self.provider.update(expired)
                raise ValueError("Approval request has expired")
            if self.authorizer is not None:
                self.authorizer.require(
                    principal,
                    "approval.decide",
                    current.request.tool_name,
                    context={"environment": current.request.environment},
                )
            decided_by = str(getattr(principal, "subject", principal)).strip()
            if not decided_by:
                raise ValueError("Approver identity is required")
            if current.request.requested_by and decided_by == current.request.requested_by:
                raise PermissionError("Requesters cannot approve their own actions")
            status = ApprovalStatus.APPROVED if approved else ApprovalStatus.DENIED
            record = ApprovalRecord(
                request=current.request,
                status=status,
                external_id=current.external_id,
                decided_by=decided_by,
                reason=reason,
                decided_at_epoch_ms=now_ms,
            )
            self._records[checkpoint_id] = record
            if self.repository is not None:
                self.repository.save_record(record)
            if approved:
                requested_expiry = now_ms + int(ttl_seconds or 900) * 1000
                expiry = min(requested_expiry, current.request.expires_at_epoch_ms)
                grant = ApprovalGrant(
                    action_digest=current.request.action_digest,
                    approved_by=decided_by,
                    expires_at_epoch_ms=expiry,
                    checkpoint_id=checkpoint_id,
                    reason=reason,
                )
                self._grants[checkpoint_id] = grant
                self._approved_actions[current.request.action_digest] = grant
                if self.repository is not None:
                    self.repository.save_grant(grant)
            self.provider.update(record)
            return record

    def record(self, checkpoint_id: str) -> ApprovalRecord:
        with self._lock:
            if checkpoint_id in self._records:
                return self._records[checkpoint_id]
            if self.repository is not None:
                return self.repository.get_record(checkpoint_id)
            raise KeyError(checkpoint_id)

    def pending(self) -> tuple[ApprovalRecord, ...]:
        with self._lock:
            if self.repository is not None:
                return self.repository.pending()
            return tuple(
                record for record in self._records.values() if record.status is ApprovalStatus.PENDING
            )

class SqliteApprovalRepository:
    """Durable approval records and payload-bound grants."""

    def __init__(self, path: str | "Path") -> None:
        from pathlib import Path
        import sqlite3

        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._sqlite3 = sqlite3
        self._lock = threading.RLock()
        with self._connection() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS approval_records (
                    checkpoint_id TEXT PRIMARY KEY,
                    action_digest TEXT NOT NULL,
                    request_json TEXT NOT NULL,
                    status TEXT NOT NULL,
                    external_id TEXT NOT NULL,
                    decided_by TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    decided_at_epoch_ms INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_approval_action ON approval_records(action_digest);
                CREATE TABLE IF NOT EXISTS approval_grants (
                    action_digest TEXT PRIMARY KEY,
                    grant_json TEXT NOT NULL,
                    updated_at_epoch_ms INTEGER NOT NULL
                );
                """
            )

    def _connect(self):
        conn = self._sqlite3.connect(self.path, timeout=30.0)
        conn.row_factory = self._sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _connection(self):
        from contextlib import contextmanager

        @contextmanager
        def managed():
            conn = self._connect()
            try:
                with conn:
                    yield conn
            finally:
                conn.close()

        return managed()

    @staticmethod
    def _request_from_dict(data: Mapping[str, Any]) -> ApprovalRequest:
        return ApprovalRequest(
            request_id=str(data["request_id"]),
            checkpoint_id=str(data["checkpoint_id"]),
            action_digest=str(data["action_digest"]),
            organization_id=str(data.get("organization_id", "")),
            environment=str(data.get("environment", "")),
            agent_id=str(data.get("agent_id", "")),
            correlation_id=str(data.get("correlation_id", "")),
            run_id=str(data.get("run_id", "")),
            tool_name=str(data["tool_name"]),
            tool_version=str(data.get("tool_version", "")),
            risk=str(data.get("risk", "unknown")),
            estimated_cost_usd=float(data.get("estimated_cost_usd", 0.0)),
            arguments_digest=str(data.get("arguments_digest", "")),
            policy_digest=str(data.get("policy_digest", "")),
            created_at_epoch_ms=int(data["created_at_epoch_ms"]),
            expires_at_epoch_ms=int(data["expires_at_epoch_ms"]),
            requested_by=str(data.get("requested_by", "")),
            summary=str(data.get("summary", "")),
            metadata=dict(data.get("metadata", {})),
        )

    def save_record(self, record: ApprovalRecord) -> None:
        with self._lock, self._connection() as conn:
            conn.execute(
                """INSERT INTO approval_records VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(checkpoint_id) DO UPDATE SET
                     status=excluded.status,
                     external_id=excluded.external_id,
                     decided_by=excluded.decided_by,
                     reason=excluded.reason,
                     decided_at_epoch_ms=excluded.decided_at_epoch_ms""",
                (
                    record.request.checkpoint_id,
                    record.request.action_digest,
                    canonical_json(record.request.to_dict()),
                    record.status.value,
                    record.external_id,
                    record.decided_by,
                    record.reason,
                    record.decided_at_epoch_ms,
                ),
            )

    def get_record(self, checkpoint_id: str) -> ApprovalRecord:
        with self._connection() as conn:
            row = conn.execute(
                "SELECT * FROM approval_records WHERE checkpoint_id=?", (checkpoint_id,)
            ).fetchone()
        if row is None:
            raise KeyError(checkpoint_id)
        request = self._request_from_dict(json.loads(row["request_json"]))
        return ApprovalRecord(
            request=request,
            status=ApprovalStatus(row["status"]),
            external_id=row["external_id"],
            decided_by=row["decided_by"],
            reason=row["reason"],
            decided_at_epoch_ms=int(row["decided_at_epoch_ms"]),
        )

    def pending(self) -> tuple[ApprovalRecord, ...]:
        with self._connection() as conn:
            rows = conn.execute(
                "SELECT checkpoint_id FROM approval_records WHERE status=? ORDER BY rowid",
                (ApprovalStatus.PENDING.value,),
            ).fetchall()
        return tuple(self.get_record(row["checkpoint_id"]) for row in rows)

    def save_grant(self, grant: ApprovalGrant) -> None:
        with self._lock, self._connection() as conn:
            conn.execute(
                """INSERT INTO approval_grants VALUES (?, ?, ?)
                   ON CONFLICT(action_digest) DO UPDATE SET grant_json=excluded.grant_json,
                   updated_at_epoch_ms=excluded.updated_at_epoch_ms""",
                (
                    grant.action_digest,
                    canonical_json(
                        {
                            "action_digest": grant.action_digest,
                            "approved_by": grant.approved_by,
                            "expires_at_epoch_ms": grant.expires_at_epoch_ms,
                            "checkpoint_id": grant.checkpoint_id,
                            "reason": grant.reason,
                        }
                    ),
                    int(time.time() * 1000),
                ),
            )

    def get_grant(self, action_digest: str) -> ApprovalGrant:
        with self._connection() as conn:
            row = conn.execute(
                "SELECT grant_json FROM approval_grants WHERE action_digest=?",
                (action_digest,),
            ).fetchone()
        if row is None:
            raise KeyError(action_digest)
        data = json.loads(row["grant_json"])
        return ApprovalGrant(
            action_digest=data["action_digest"],
            approved_by=data["approved_by"],
            expires_at_epoch_ms=int(data["expires_at_epoch_ms"]),
            checkpoint_id=data.get("checkpoint_id"),
            reason=data.get("reason", ""),
        )
