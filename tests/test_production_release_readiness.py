from __future__ import annotations

import argparse
import base64
from types import ModuleType, SimpleNamespace
import sys

import pytest

from agent_roi.cli import control_plane
from agent_roi.enterprise.control_plane import HMACPolicySigner


def _args(**overrides):
    values = dict(
        signing_provider="hmac",
        signing_key_file="",
        signing_key_id="",
        aws_kms_key_id="",
        aws_kms_signing_algorithm="RSASSA_PSS_SHA_256",
        azure_key_id="",
        azure_signing_algorithm="PS256",
        gcp_kms_key_id="",
        vault_url="",
        vault_key_name="",
        vault_token="",
        vault_key_version=0,
    )
    values.update(overrides)
    return argparse.Namespace(**values)


def test_required_signing_settings_and_hmac(monkeypatch) -> None:
    assert control_plane._required_setting(" value ", "setting") == "value"
    with pytest.raises(ValueError, match="setting is required"):
        control_plane._required_setting("", "setting")
    monkeypatch.setenv("AGENT_ROI_POLICY_SIGNING_KEY", "x" * 32)
    signer = control_plane._policy_signer(_args(signing_provider="HMAC", signing_key_id="key"))
    assert isinstance(signer, HMACPolicySigner)
    assert signer.key_id == "key"


def test_aws_and_vault_signer_factories(monkeypatch) -> None:
    calls = []

    class AWS:
        def __init__(self, key_id, *, signing_algorithm):
            calls.append(("aws", key_id, signing_algorithm))
            self.key_id = key_id

    class Vault:
        def __init__(self, url, key_name, *, token, key_version):
            calls.append(("vault", url, key_name, token, key_version))
            self.key_id = "vault-key"

    monkeypatch.setattr(control_plane, "AWSKMSPolicySigner", AWS)
    monkeypatch.setattr(control_plane, "VaultTransitPolicySigner", Vault)
    assert control_plane._policy_signer(
        _args(signing_provider="aws_kms", aws_kms_key_id="arn:key")
    ).key_id == "arn:key"
    assert control_plane._policy_signer(
        _args(
            signing_provider="vault-transit",
            vault_url="https://vault.example",
            vault_key_name="policy",
            vault_token="token",
            vault_key_version=3,
        )
    ).key_id == "vault-key"
    assert calls == [
        ("aws", "arn:key", "RSASSA_PSS_SHA_256"),
        ("vault", "https://vault.example", "policy", "token", 3),
    ]
    with pytest.raises(ValueError, match="AWS KMS key ID"):
        control_plane._policy_signer(_args(signing_provider="aws-kms"))


def test_azure_signer_factory(monkeypatch) -> None:
    credential = object()
    crypto_client = object()
    azure = ModuleType("azure")
    identity = ModuleType("azure.identity")
    keyvault = ModuleType("azure.keyvault")
    keys = ModuleType("azure.keyvault.keys")
    crypto = ModuleType("azure.keyvault.keys.crypto")
    identity.DefaultAzureCredential = lambda: credential
    crypto.CryptographyClient = lambda key_id, cred: (key_id, cred, crypto_client)
    monkeypatch.setitem(sys.modules, "azure", azure)
    monkeypatch.setitem(sys.modules, "azure.identity", identity)
    monkeypatch.setitem(sys.modules, "azure.keyvault", keyvault)
    monkeypatch.setitem(sys.modules, "azure.keyvault.keys", keys)
    monkeypatch.setitem(sys.modules, "azure.keyvault.keys.crypto", crypto)

    captured = {}

    class Signer:
        def __init__(self, key_id, *, client, algorithm):
            captured.update(key_id=key_id, client=client, algorithm=algorithm)
            self.key_id = key_id

    monkeypatch.setattr(control_plane, "AzureKeyVaultPolicySigner", Signer)
    signer = control_plane._policy_signer(
        _args(
            signing_provider="azure-key-vault",
            signing_key_id="logical-key",
            azure_key_id="https://vault/keys/policy/version",
        )
    )
    assert signer.key_id == "logical-key"
    assert captured["client"] == (
        "https://vault/keys/policy/version",
        credential,
        crypto_client,
    )
    assert captured["algorithm"] == "PS256"


def test_gcp_signer_factory(monkeypatch) -> None:
    client = object()
    google = ModuleType("google")
    cloud = ModuleType("google.cloud")
    kms = ModuleType("google.cloud.kms_v1")
    kms.KeyManagementServiceClient = lambda: client
    cloud.kms_v1 = kms
    monkeypatch.setitem(sys.modules, "google", google)
    monkeypatch.setitem(sys.modules, "google.cloud", cloud)
    monkeypatch.setitem(sys.modules, "google.cloud.kms_v1", kms)
    monkeypatch.setattr(control_plane, "_gcp_verify_callback", lambda c, k: (c, k))

    captured = {}

    class Signer:
        def __init__(self, key_id, *, client, verify_callback):
            captured.update(key_id=key_id, client=client, callback=verify_callback)
            self.key_id = key_id

    monkeypatch.setattr(control_plane, "GCPKMSPolicySigner", Signer)
    signer = control_plane._policy_signer(
        _args(signing_provider="gcp-kms", gcp_kms_key_id="projects/p/keyVersions/1")
    )
    assert signer.key_id == "projects/p/keyVersions/1"
    assert captured["callback"] == (client, "projects/p/keyVersions/1")


def test_gcp_public_key_verifiers() -> None:
    cryptography = pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

    payload = b"policy payload"

    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = rsa_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    class Client:
        def __init__(self, algorithm):
            self.algorithm = algorithm

        def get_public_key(self, *, request):
            assert request["name"] == "key"
            return SimpleNamespace(pem=pem, algorithm=self.algorithm)

    pss = control_plane._gcp_verify_callback(Client("RSA_SIGN_PSS_2048_SHA256"), "key")
    signature = rsa_key.sign(
        payload,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=hashes.SHA256().digest_size),
        hashes.SHA256(),
    )
    assert pss(payload, signature)
    assert not pss(payload + b"x", signature)

    pkcs = control_plane._gcp_verify_callback(Client("RSA_SIGN_PKCS1_2048_SHA256"), "key")
    signature = rsa_key.sign(payload, padding.PKCS1v15(), hashes.SHA256())
    assert pkcs(payload, signature)

    ec_key = ec.generate_private_key(ec.SECP256R1())
    ec_pem = ec_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    ec_client = SimpleNamespace(
        get_public_key=lambda **_: {"pem": ec_pem, "algorithm": "EC_SIGN_P256_SHA256"}
    )
    ec_verify = control_plane._gcp_verify_callback(ec_client, "key")
    assert ec_verify(payload, ec_key.sign(payload, ec.ECDSA(hashes.SHA256())))

    with pytest.raises(ValueError, match="Unsupported GCP"):
        control_plane._gcp_verify_callback(Client("UNKNOWN"), "key")


def test_signer_rejects_unknown_provider_and_parser_reads_env(monkeypatch) -> None:
    with pytest.raises(ValueError, match="Unsupported signing provider"):
        control_plane._policy_signer(_args(signing_provider="unknown"))
    monkeypatch.setenv("AGENT_ROI_SIGNING_PROVIDER", "aws-kms")
    monkeypatch.setenv("AGENT_ROI_AWS_KMS_KEY_ID", "arn:test")
    args = control_plane._parser().parse_args(["--allow-unauthenticated"])
    assert args.signing_provider == "aws-kms"
    assert args.aws_kms_key_id == "arn:test"
