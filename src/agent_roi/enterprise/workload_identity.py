from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatchcase
import json
import time
from typing import Any, Mapping, Optional, Protocol
from urllib import parse as urlparse
from urllib import request as urlrequest

from .identity import AuthenticationError, OIDCVerifier, Principal


class AccessTokenProvider(Protocol):
    def token(self) -> str: ...


@dataclass(frozen=True)
class WorkloadIdentityPolicy:
    allowed_subjects: tuple[str, ...] = ("*",)
    allowed_identity_types: tuple[str, ...] = ("workload", "service_account")
    required_attributes: Mapping[str, str] = field(default_factory=dict)

    def validate(self, principal: Principal) -> Principal:
        identity_type = str(principal.attributes.get("identity_type", "workload"))
        if identity_type not in self.allowed_identity_types:
            raise AuthenticationError(f"Identity type is not allowed: {identity_type}")
        if not any(fnmatchcase(principal.subject, pattern) for pattern in self.allowed_subjects):
            raise AuthenticationError("Workload subject is not allowlisted")
        for name, expected in self.required_attributes.items():
            if str(principal.attributes.get(name, "")) != str(expected):
                raise AuthenticationError(f"Workload identity attribute mismatch: {name}")
        return principal


class WorkloadOIDCVerifier:
    """Enforces workload-specific policy on a validated OIDC token."""

    def __init__(
        self,
        verifier: OIDCVerifier,
        *,
        policy: WorkloadIdentityPolicy = WorkloadIdentityPolicy(),
        client_id_claim: str = "client_id",
    ) -> None:
        self.verifier = verifier
        self.policy = policy
        self.client_id_claim = client_id_claim

    def verify(self, token: str) -> Principal:
        principal = self.verifier.verify(token)
        attributes = dict(principal.attributes)
        attributes.setdefault("identity_type", "workload")
        attributes.setdefault("client_id", attributes.get(self.client_id_claim, principal.subject))
        workload = Principal(
            subject=principal.subject,
            organization_id=principal.organization_id,
            display_name=principal.display_name,
            email=principal.email,
            roles=principal.roles,
            groups=principal.groups,
            attributes=attributes,
            token_id=principal.token_id,
        )
        return self.policy.validate(workload)

    def verify_authorization_header(self, header: str) -> Principal:
        scheme, _, token = str(header or "").partition(" ")
        if scheme.lower() != "bearer" or not token.strip():
            raise AuthenticationError("Authorization header must use Bearer authentication")
        return self.verify(token)


class OAuthClientCredentialsProvider:
    """OAuth 2.0 client-credentials provider with in-memory token caching."""

    def __init__(
        self,
        token_url: str,
        client_id: str,
        client_secret: str,
        *,
        scope: str = "",
        audience: str = "",
        timeout_seconds: float = 10.0,
        refresh_skew_seconds: int = 60,
        extra_fields: Optional[Mapping[str, str]] = None,
    ) -> None:
        if not token_url.lower().startswith("https://"):
            raise ValueError("token_url must use HTTPS")
        if not client_id.strip() or not client_secret:
            raise ValueError("client_id and client_secret are required")
        self.token_url = token_url
        self.client_id = client_id
        self._client_secret = client_secret
        self.scope = scope
        self.audience = audience
        self.timeout_seconds = float(timeout_seconds)
        self.refresh_skew_seconds = max(0, int(refresh_skew_seconds))
        self.extra_fields = dict(extra_fields or {})
        self._cached_token = ""
        self._expires_at = 0.0

    def token(self) -> str:
        now = time.time()
        if self._cached_token and now < self._expires_at - self.refresh_skew_seconds:
            return self._cached_token
        fields = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self._client_secret,
            **self.extra_fields,
        }
        if self.scope:
            fields["scope"] = self.scope
        if self.audience:
            fields["audience"] = self.audience
        req = urlrequest.Request(
            self.token_url,
            method="POST",
            data=urlparse.urlencode(fields).encode("utf-8"),
            headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
        )
        try:
            with urlrequest.urlopen(req, timeout=self.timeout_seconds) as response:
                payload = json.loads(response.read())
        except Exception as exc:
            raise AuthenticationError("OAuth client-credentials token request failed") from exc
        token = str(payload.get("access_token", "")).strip()
        if not token:
            raise AuthenticationError("OAuth token endpoint returned no access_token")
        expires_in = max(1, int(payload.get("expires_in", 300)))
        self._cached_token = token
        self._expires_at = now + expires_in
        return token


class AzureManagedIdentityProvider:
    """Azure Instance Metadata Service managed-identity token provider."""

    def __init__(
        self,
        resource: str,
        *,
        client_id: str = "",
        endpoint: str = "http://169.254.169.254/metadata/identity/oauth2/token",
        api_version: str = "2018-02-01",
        timeout_seconds: float = 2.0,
    ) -> None:
        if not resource.strip():
            raise ValueError("resource is required")
        self.resource = resource
        self.client_id = client_id
        self.endpoint = endpoint
        self.api_version = api_version
        self.timeout_seconds = float(timeout_seconds)

    def token(self) -> str:
        query = {"api-version": self.api_version, "resource": self.resource}
        if self.client_id:
            query["client_id"] = self.client_id
        req = urlrequest.Request(
            self.endpoint + "?" + urlparse.urlencode(query),
            headers={"Metadata": "true"},
        )
        try:
            with urlrequest.urlopen(req, timeout=self.timeout_seconds) as response:
                payload = json.loads(response.read())
        except Exception as exc:
            raise AuthenticationError("Azure managed-identity token request failed") from exc
        token = str(payload.get("access_token", "")).strip()
        if not token:
            raise AuthenticationError("Azure managed identity returned no access_token")
        return token


class GCPMetadataIdentityProvider:
    """Google metadata-server identity-token provider."""

    def __init__(
        self,
        audience: str,
        *,
        endpoint: str = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity",
        timeout_seconds: float = 2.0,
    ) -> None:
        if not audience.strip():
            raise ValueError("audience is required")
        self.audience = audience
        self.endpoint = endpoint
        self.timeout_seconds = float(timeout_seconds)

    def token(self) -> str:
        req = urlrequest.Request(
            self.endpoint
            + "?"
            + urlparse.urlencode({"audience": self.audience, "format": "full"}),
            headers={"Metadata-Flavor": "Google"},
        )
        try:
            with urlrequest.urlopen(req, timeout=self.timeout_seconds) as response:
                token = response.read().decode("utf-8").strip()
        except Exception as exc:
            raise AuthenticationError("GCP metadata identity-token request failed") from exc
        if not token:
            raise AuthenticationError("GCP metadata server returned no token")
        return token


class SPIFFEIdentityVerifier:
    """Map a verified mTLS SPIFFE ID to an Agent-ROI workload principal."""

    def __init__(
        self,
        *,
        trust_domain: str,
        organization_id: str,
        allowed_paths: tuple[str, ...] = ("/*",),
        roles: tuple[str, ...] = (),
    ) -> None:
        if not trust_domain.strip() or not organization_id.strip():
            raise ValueError("trust_domain and organization_id are required")
        self.trust_domain = trust_domain.strip().lower()
        self.organization_id = organization_id.strip()
        self.allowed_paths = allowed_paths
        self.roles = frozenset(roles)

    def verify(self, spiffe_id: str) -> Principal:
        parsed = urlparse.urlparse(spiffe_id)
        if parsed.scheme != "spiffe" or parsed.netloc.lower() != self.trust_domain:
            raise AuthenticationError("SPIFFE trust domain is not allowed")
        path = parsed.path or "/"
        if not any(fnmatchcase(path, pattern) for pattern in self.allowed_paths):
            raise AuthenticationError("SPIFFE workload path is not allowed")
        return Principal(
            subject=spiffe_id,
            organization_id=self.organization_id,
            roles=self.roles,
            attributes={
                "identity_type": "workload",
                "spiffe_trust_domain": self.trust_domain,
                "spiffe_path": path,
            },
        )
