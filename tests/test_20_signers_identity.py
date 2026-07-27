from __future__ import annotations

import base64
import hashlib
import json

import pytest

from agent_roi.enterprise.identity import AuthenticationError, OIDCConfig, OIDCVerifier
from agent_roi.enterprise.signers import (
    AWSKMSPolicySigner,
    AzureKeyVaultPolicySigner,
    ExternalSignerError,
    GCPKMSPolicySigner,
    PKCS11PolicySigner,
    VaultTransitPolicySigner,
)
from agent_roi.enterprise.workload_identity import (
    AzureManagedIdentityProvider,
    GCPMetadataIdentityProvider,
    OAuthClientCredentialsProvider,
    SPIFFEIdentityVerifier,
    WorkloadIdentityPolicy,
    WorkloadOIDCVerifier,
)


class AWSClient:
    def sign(self, **kwargs):
        return {"Signature": b"aws-signature"}

    def verify(self, **kwargs):
        return {"SignatureValid": kwargs["Signature"] == b"aws-signature"}


class AzureResult:
    def __init__(self, *, signature=b"azure-signature", is_valid=True):
        self.signature = signature
        self.is_valid = is_valid


class AzureClient:
    def sign(self, algorithm, digest):
        assert len(digest) == 32
        return AzureResult()

    def verify(self, algorithm, digest, signature):
        return AzureResult(is_valid=signature == b"azure-signature")


class GCPClient:
    def asymmetric_sign(self, request):
        assert len(request["digest"]["sha256"]) == 32
        return type("Response", (), {"signature": b"gcp-signature"})()


class FakeHTTPResponse:
    def __init__(self, payload, status=200):
        self.payload = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self):
        return self.payload


def test_external_kms_and_hsm_signers_round_trip() -> None:
    payload = b"policy-bundle"
    aws = AWSKMSPolicySigner("key", client=AWSClient())
    aws_signature = aws.sign(payload)
    assert aws.verify(payload, aws_signature)

    azure = AzureKeyVaultPolicySigner("key", client=AzureClient())
    azure_signature = azure.sign(payload)
    assert azure.verify(payload, azure_signature)

    gcp = GCPKMSPolicySigner(
        "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
        client=GCPClient(),
        verify_callback=lambda value, signature: value == payload and signature == b"gcp-signature",
    )
    gcp_signature = gcp.sign(payload)
    assert gcp.verify(payload, gcp_signature)

    pkcs11 = PKCS11PolicySigner(
        "slot:key",
        sign_callback=lambda value: hashlib.sha256(value).digest(),
        verify_callback=lambda value, signature: signature == hashlib.sha256(value).digest(),
    )
    signature = pkcs11.sign(payload)
    assert pkcs11.verify(payload, signature)


def test_external_signer_wraps_provider_failures() -> None:
    class Broken:
        def sign(self, **kwargs):
            raise RuntimeError("down")

    signer = AWSKMSPolicySigner("key", client=Broken())
    with pytest.raises(ExternalSignerError, match="AWS KMS"):
        signer.sign(b"payload")


def test_vault_transit_signer_uses_https_api(monkeypatch) -> None:
    requests = []

    def fake_urlopen(request, timeout):
        requests.append(request)
        if "/sign/" in request.full_url:
            return FakeHTTPResponse({"data": {"signature": "vault:v1:sig"}})
        return FakeHTTPResponse({"data": {"valid": True}})

    monkeypatch.setattr("agent_roi.enterprise.signers.urlrequest.urlopen", fake_urlopen)
    signer = VaultTransitPolicySigner("https://vault.example", "agent-roi", token="token")
    assert signer.sign(b"payload") == "vault:v1:sig"
    assert signer.verify(b"payload", "vault:v1:sig")
    assert all(request.headers["X-vault-token"] == "token" for request in requests)


def test_oauth_client_credentials_caches_token(monkeypatch) -> None:
    calls = []

    def fake_urlopen(request, timeout):
        calls.append(request.data)
        return FakeHTTPResponse({"access_token": "token-1", "expires_in": 3600})

    monkeypatch.setattr("agent_roi.enterprise.workload_identity.urlrequest.urlopen", fake_urlopen)
    provider = OAuthClientCredentialsProvider(
        "https://id.example/token", "client", "secret", scope="agent.execute"
    )
    assert provider.token() == "token-1"
    assert provider.token() == "token-1"
    assert len(calls) == 1
    assert b"client_secret=secret" in calls[0]


def test_cloud_metadata_identity_providers_send_required_headers(monkeypatch) -> None:
    requests = []

    def fake_urlopen(request, timeout):
        requests.append(request)
        if request.headers.get("Metadata") == "true":
            return FakeHTTPResponse({"access_token": "azure-token"})
        return FakeHTTPResponse(b"gcp-token")

    monkeypatch.setattr("agent_roi.enterprise.workload_identity.urlrequest.urlopen", fake_urlopen)
    assert AzureManagedIdentityProvider("api://agent-roi").token() == "azure-token"
    assert GCPMetadataIdentityProvider("agent-roi").token() == "gcp-token"
    assert requests[0].headers["Metadata"] == "true"
    assert requests[1].headers["Metadata-flavor"] == "Google"


def test_spiffe_identity_enforces_trust_domain_and_path() -> None:
    verifier = SPIFFEIdentityVerifier(
        trust_domain="example.org",
        organization_id="acme",
        allowed_paths=("/prod/*",),
        roles=("agent_owner",),
    )
    principal = verifier.verify("spiffe://example.org/prod/invoice-agent")
    assert principal.organization_id == "acme"
    assert principal.roles == frozenset({"agent_owner"})
    with pytest.raises(AuthenticationError):
        verifier.verify("spiffe://other.org/prod/invoice-agent")
    with pytest.raises(AuthenticationError):
        verifier.verify("spiffe://example.org/dev/invoice-agent")


def test_workload_oidc_policy_restricts_subjects() -> None:
    jwt = pytest.importorskip("jwt")
    import time

    key = "secret-key-with-at-least-32-bytes!!"
    claims = {
        "iss": "https://issuer.example",
        "aud": "agent-roi",
        "sub": "service:invoice-agent",
        "org_id": "acme",
        "iat": int(time.time()),
        "exp": int(time.time()) + 300,
        "identity_type": "workload",
        "region": "us-east",
    }
    token = jwt.encode(claims, key, algorithm="HS256")
    oidc = OIDCVerifier(
        OIDCConfig(
            issuer="https://issuer.example",
            audience="agent-roi",
            algorithms=("HS256",),
        ),
        verification_key=key,
    )
    verifier = WorkloadOIDCVerifier(
        oidc,
        policy=WorkloadIdentityPolicy(
            allowed_subjects=("service:*",), required_attributes={"region": "us-east"}
        ),
    )
    assert verifier.verify(token).subject == "service:invoice-agent"
