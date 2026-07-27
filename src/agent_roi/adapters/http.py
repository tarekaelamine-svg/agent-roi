from __future__ import annotations

import json
from typing import Any, Iterable, Mapping, Optional
from urllib import error as urlerror
from urllib import parse as urlparse
from urllib import request as urlrequest

from agent_roi._serialization import canonical_json
from agent_roi.runtime.tools import ToolRegistry, ToolSpec


class ControlledHTTPAdapter:
    """Allowlisted HTTPS transport suitable for registration as a controlled tool."""

    def __init__(
        self,
        *,
        allowed_hosts: Iterable[str],
        allowed_methods: Iterable[str] = ("GET", "POST"),
        timeout_seconds: float = 10.0,
        max_request_bytes: int = 1_000_000,
        max_response_bytes: int = 5_000_000,
        default_headers: Optional[Mapping[str, str]] = None,
    ) -> None:
        self.allowed_hosts = frozenset(host.lower().strip() for host in allowed_hosts if host.strip())
        self.allowed_methods = frozenset(method.upper().strip() for method in allowed_methods)
        if not self.allowed_hosts:
            raise ValueError("allowed_hosts cannot be empty")
        self.timeout_seconds = float(timeout_seconds)
        self.max_request_bytes = int(max_request_bytes)
        self.max_response_bytes = int(max_response_bytes)
        self.default_headers = dict(default_headers or {})

    def request(
        self,
        url: str,
        *,
        method: str = "GET",
        json_body: Any = None,
        headers: Optional[Mapping[str, str]] = None,
    ) -> dict[str, Any]:
        parsed = urlparse.urlsplit(url)
        if parsed.scheme.lower() != "https":
            raise ValueError("Controlled HTTP requests must use HTTPS")
        if (parsed.hostname or "").lower() not in self.allowed_hosts:
            raise PermissionError(f"HTTP host is not allowlisted: {parsed.hostname}")
        method = method.upper()
        if method not in self.allowed_methods:
            raise PermissionError(f"HTTP method is not allowlisted: {method}")
        body = None if json_body is None else canonical_json(json_body).encode("utf-8")
        if body is not None and len(body) > self.max_request_bytes:
            raise ValueError("HTTP request body exceeds max_request_bytes")
        req = urlrequest.Request(
            url,
            data=body,
            method=method,
            headers={
                **self.default_headers,
                **dict(headers or {}),
                **({"Content-Type": "application/json"} if body is not None else {}),
            },
        )
        try:
            with urlrequest.urlopen(req, timeout=self.timeout_seconds) as response:
                content = response.read(self.max_response_bytes + 1)
                if len(content) > self.max_response_bytes:
                    raise ValueError("HTTP response exceeds max_response_bytes")
                content_type = response.headers.get("Content-Type", "")
                parsed_body: Any
                if "json" in content_type.lower() and content:
                    parsed_body = json.loads(content)
                else:
                    parsed_body = content.decode("utf-8", errors="replace")
                return {
                    "status": response.status,
                    "headers": dict(response.headers.items()),
                    "body": parsed_body,
                }
        except urlerror.HTTPError as exc:
            content = exc.read(self.max_response_bytes + 1)
            raise RuntimeError(
                f"Controlled HTTP request returned HTTP {exc.code}: "
                + content.decode("utf-8", errors="replace")
            ) from exc

    def register(
        self,
        registry: ToolRegistry,
        *,
        name: str = "http_request",
        risk: str = "medium",
        requires_approval: bool = False,
        version: str = "1",
        default_cost_usd: float = 0.0,
    ) -> ToolSpec[Any]:
        return registry.add(
            name,
            self.request,
            description="Allowlisted enterprise HTTPS request",
            risk=risk,
            requires_approval=requires_approval,
            default_cost_usd=default_cost_usd,
            version=version,
        )
