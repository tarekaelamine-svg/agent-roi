from __future__ import annotations

import json
from typing import Any, Dict, Optional
from urllib import error as urlerror
from urllib import parse as urlparse
from urllib import request as urlrequest

from agent_roi._serialization import canonical_json
from .event import AuditEvent
from .store import AuditIntegrityError


class RemoteAuditStore:
    """Synchronous client for a centralized Agent-ROI audit ingestion service."""

    def __init__(
        self,
        base_url: str,
        *,
        bearer_token: str = "",
        timeout_seconds: float = 10.0,
        hash_chain: bool = True,
        require_https: bool = True,
    ) -> None:
        if require_https and not base_url.lower().startswith("https://"):
            raise ValueError("Remote audit services must use HTTPS")
        self.base_url = base_url.rstrip("/")
        self.bearer_token = bearer_token
        self.timeout_seconds = float(timeout_seconds)
        self.hash_chain = bool(hash_chain)

    def _request(self, method: str, path: str, payload: Optional[dict[str, Any]] = None) -> Any:
        body = None if payload is None else canonical_json(payload).encode("utf-8")
        headers = {"Accept": "application/json"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        if self.bearer_token:
            headers["Authorization"] = f"Bearer {self.bearer_token}"
        req = urlrequest.Request(self.base_url + path, data=body, method=method, headers=headers)
        try:
            with urlrequest.urlopen(req, timeout=self.timeout_seconds) as response:
                raw = response.read()
                return json.loads(raw) if raw else None
        except urlerror.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Remote audit service returned HTTP {exc.code}: {detail}") from exc
        except OSError as exc:
            raise RuntimeError("Remote audit service is unavailable") from exc

    @staticmethod
    def _event_from_dict(value: dict[str, Any]) -> AuditEvent:
        return AuditEvent(
            event_id=str(value["event_id"]),
            correlation_id=str(value["correlation_id"]),
            run_id=str(value["run_id"]),
            ts_epoch_ms=int(value["ts_epoch_ms"]),
            event_type=str(value["event_type"]),
            payload=dict(value["payload"]),
            prev_hash=value.get("prev_hash"),
            hash=value.get("hash"),
        )

    def record(
        self,
        *,
        correlation_id: str,
        run_id: str,
        event_type: str,
        payload: Dict[str, Any],
    ) -> AuditEvent:
        data = self._request(
            "POST",
            "/v1/audit/events",
            {
                "correlation_id": correlation_id,
                "run_id": run_id,
                "event_type": event_type,
                "payload": payload,
            },
        )
        return self._event_from_dict(data)

    def append(self, event: AuditEvent) -> None:
        data = self._request("POST", "/v1/audit/events/append", event.to_dict())
        returned = self._event_from_dict(data)
        if returned.to_dict() != event.to_dict():
            raise AuditIntegrityError("Remote audit service altered the appended event")

    def last_hash(self, correlation_id: str) -> Optional[str]:
        encoded = urlparse.quote(correlation_id, safe="")
        data = self._request("GET", f"/v1/audit/chains/{encoded}/tail")
        return data.get("last_hash") if isinstance(data, dict) else None

    def verify(self, correlation_id: str = "") -> int:
        query = "" if not correlation_id else "?correlation_id=" + urlparse.quote(correlation_id, safe="")
        data = self._request("GET", "/v1/audit/verify" + query)
        return int(data["events_verified"])
