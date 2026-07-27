from __future__ import annotations

import base64
import hashlib
import json
from typing import Any, Callable, Mapping, Optional
from urllib import request as urlrequest


class ExternalSignerError(RuntimeError):
    """Raised when a KMS, HSM, or Vault signing operation fails."""


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _unb64(value: str) -> bytes:
    try:
        return base64.b64decode(str(value), validate=True)
    except Exception as exc:
        raise ExternalSignerError("Signature is not valid base64") from exc


class AWSKMSPolicySigner:
    """AWS KMS asymmetric RSA/ECC signer.

    The injected client must implement ``sign`` and ``verify`` like boto3 KMS.
    """

    def __init__(
        self,
        key_id: str,
        *,
        client: Any = None,
        signing_algorithm: str = "RSASSA_PSS_SHA_256",
    ) -> None:
        if not str(key_id).strip():
            raise ValueError("AWS KMS key_id is required")
        self.key_id = str(key_id).strip()
        self.signing_algorithm = str(signing_algorithm).strip()
        if client is None:
            try:
                import boto3  # type: ignore
            except ImportError as exc:  # pragma: no cover
                raise RuntimeError("AWS KMS signing requires boto3; install agent-roi[aws]") from exc
            client = boto3.client("kms")
        self.client = client

    def sign(self, payload: bytes) -> str:
        try:
            response = self.client.sign(
                KeyId=self.key_id,
                Message=payload,
                MessageType="RAW",
                SigningAlgorithm=self.signing_algorithm,
            )
            return _b64(bytes(response["Signature"]))
        except Exception as exc:
            raise ExternalSignerError("AWS KMS signing failed") from exc

    def verify(self, payload: bytes, signature: str) -> bool:
        try:
            response = self.client.verify(
                KeyId=self.key_id,
                Message=payload,
                MessageType="RAW",
                Signature=_unb64(signature),
                SigningAlgorithm=self.signing_algorithm,
            )
            return bool(response.get("SignatureValid", False))
        except Exception as exc:
            raise ExternalSignerError("AWS KMS verification failed") from exc


class AzureKeyVaultPolicySigner:
    """Azure Key Vault/Managed HSM signer using an injected CryptographyClient."""

    def __init__(self, key_id: str, *, client: Any, algorithm: str = "PS256") -> None:
        if not str(key_id).strip() or client is None:
            raise ValueError("Azure key_id and cryptography client are required")
        self.key_id = str(key_id).strip()
        self.client = client
        self.algorithm = algorithm

    def sign(self, payload: bytes) -> str:
        digest = hashlib.sha256(payload).digest()
        try:
            result = self.client.sign(self.algorithm, digest)
            signature = getattr(result, "signature", result)
            return _b64(bytes(signature))
        except Exception as exc:
            raise ExternalSignerError("Azure Key Vault signing failed") from exc

    def verify(self, payload: bytes, signature: str) -> bool:
        digest = hashlib.sha256(payload).digest()
        try:
            result = self.client.verify(self.algorithm, digest, _unb64(signature))
            return bool(getattr(result, "is_valid", result))
        except Exception as exc:
            raise ExternalSignerError("Azure Key Vault verification failed") from exc


class GCPKMSPolicySigner:
    """Google Cloud KMS asymmetric signer.

    Cloud KMS signs digests but verification is normally performed with the
    public key. Supply ``verify_callback(payload, signature_bytes)`` using the
    configured public key verifier.
    """

    def __init__(
        self,
        key_id: str,
        *,
        client: Any,
        verify_callback: Callable[[bytes, bytes], bool],
    ) -> None:
        if not str(key_id).strip() or client is None or not callable(verify_callback):
            raise ValueError("GCP key_id, client, and verify_callback are required")
        self.key_id = str(key_id).strip()
        self.client = client
        self.verify_callback = verify_callback

    def sign(self, payload: bytes) -> str:
        digest = hashlib.sha256(payload).digest()
        try:
            response = self.client.asymmetric_sign(
                request={"name": self.key_id, "digest": {"sha256": digest}}
            )
            signature = getattr(response, "signature", None)
            if signature is None:
                signature = response["signature"]
            return _b64(bytes(signature))
        except Exception as exc:
            raise ExternalSignerError("Google Cloud KMS signing failed") from exc

    def verify(self, payload: bytes, signature: str) -> bool:
        try:
            return bool(self.verify_callback(payload, _unb64(signature)))
        except Exception as exc:
            raise ExternalSignerError("Google Cloud KMS verification failed") from exc


class VaultTransitPolicySigner:
    """HashiCorp Vault Transit signer over its HTTPS API."""

    def __init__(
        self,
        base_url: str,
        key_name: str,
        *,
        token: str,
        key_version: int = 0,
        timeout_seconds: float = 10.0,
    ) -> None:
        if not base_url.lower().startswith("https://"):
            raise ValueError("Vault base_url must use HTTPS")
        if not key_name.strip() or not token.strip():
            raise ValueError("Vault key_name and token are required")
        self.base_url = base_url.rstrip("/")
        self.key_name = key_name.strip()
        self.token = token.strip()
        self.key_version = int(key_version)
        self.timeout_seconds = float(timeout_seconds)
        self.key_id = f"vault:{self.key_name}:{self.key_version or 'latest'}"

    def _post(self, operation: str, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        req = urlrequest.Request(
            f"{self.base_url}/v1/transit/{operation}/{self.key_name}",
            method="POST",
            data=json.dumps(dict(payload)).encode("utf-8"),
            headers={"X-Vault-Token": self.token, "Content-Type": "application/json"},
        )
        try:
            with urlrequest.urlopen(req, timeout=self.timeout_seconds) as response:
                return json.loads(response.read())
        except Exception as exc:
            raise ExternalSignerError(f"Vault Transit {operation} failed") from exc

    def sign(self, payload: bytes) -> str:
        body: dict[str, Any] = {
            "input": _b64(payload),
            "hash_algorithm": "sha2-256",
            "signature_algorithm": "pss",
        }
        if self.key_version:
            body["key_version"] = self.key_version
        response = self._post("sign", body)
        return str(response["data"]["signature"])

    def verify(self, payload: bytes, signature: str) -> bool:
        response = self._post(
            "verify",
            {
                "input": _b64(payload),
                "signature": signature,
                "hash_algorithm": "sha2-256",
                "signature_algorithm": "pss",
            },
        )
        return bool(response.get("data", {}).get("valid", False))


class PKCS11PolicySigner:
    """PKCS#11 HSM signer using injected sign and verify callbacks.

    This dependency-neutral adapter allows applications to use python-pkcs11,
    PyKCS11, or a vendor SDK without forcing one binding on all installations.
    """

    def __init__(
        self,
        key_id: str,
        *,
        sign_callback: Callable[[bytes], bytes],
        verify_callback: Callable[[bytes, bytes], bool],
    ) -> None:
        if not str(key_id).strip() or not callable(sign_callback) or not callable(verify_callback):
            raise ValueError("PKCS#11 key_id, sign_callback, and verify_callback are required")
        self.key_id = str(key_id).strip()
        self.sign_callback = sign_callback
        self.verify_callback = verify_callback

    def sign(self, payload: bytes) -> str:
        try:
            return _b64(bytes(self.sign_callback(payload)))
        except Exception as exc:
            raise ExternalSignerError("PKCS#11 signing failed") from exc

    def verify(self, payload: bytes, signature: str) -> bool:
        try:
            return bool(self.verify_callback(payload, _unb64(signature)))
        except Exception as exc:
            raise ExternalSignerError("PKCS#11 verification failed") from exc
