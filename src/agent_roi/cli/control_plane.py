from __future__ import annotations

import argparse
import base64
import os
from pathlib import Path
from typing import Any, Optional

from agent_roi import PostgresAuditStore, SqliteAuditStore, __version__
from agent_roi.db import PostgresConnectionFactory, PostgresMigrationManager
from agent_roi.enterprise.control_plane import (
    ControlPlaneService,
    HMACPolicySigner,
    PolicySigner,
    SqliteControlPlaneStore,
    create_fastapi_app,
)
from agent_roi.enterprise.signers import (
    AWSKMSPolicySigner,
    AzureKeyVaultPolicySigner,
    GCPKMSPolicySigner,
    VaultTransitPolicySigner,
)
from agent_roi.enterprise.postgres import PostgresControlPlaneStore, PostgresIdentityStore
from agent_roi.enterprise.identity import (
    OIDCConfig,
    DynamicRBACAuthorizer,
    OIDCVerifier,
    RoleDefinition,
    SqliteIdentityStore,
)
from agent_roi.roi.ledger import RealizedROILedger
from agent_roi.roi.postgres import PostgresROILedger


def _signing_key(path: str = "") -> bytes:
    raw: bytes
    if path:
        raw = Path(path).read_bytes().strip()
    else:
        value = os.environ.get("AGENT_ROI_POLICY_SIGNING_KEY", "").strip()
        if not value:
            raise ValueError(
                "Set AGENT_ROI_POLICY_SIGNING_KEY or provide --signing-key-file"
            )
        if value.startswith("base64:"):
            try:
                raw = base64.b64decode(value.removeprefix("base64:"), validate=True)
            except Exception as exc:
                raise ValueError("Invalid base64 policy signing key") from exc
        else:
            raw = value.encode("utf-8")
    if len(raw) < 32:
        raise ValueError("Policy signing key must contain at least 32 bytes")
    return raw


def _required_setting(value: str, name: str) -> str:
    normalized = str(value or "").strip()
    if not normalized:
        raise ValueError(f"{name} is required for the selected signing provider")
    return normalized


def _gcp_verify_callback(client: Any, key_name: str):
    """Build a verifier from the public key associated with a Cloud KMS key version."""
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec, padding
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise RuntimeError(
            "GCP KMS verification requires cryptography; install agent-roi[gcp]."
        ) from exc

    response = client.get_public_key(request={"name": key_name})
    pem = getattr(response, "pem", None) or response["pem"]
    algorithm = str(getattr(response, "algorithm", None) or response["algorithm"])
    public_key = serialization.load_pem_public_key(str(pem).encode("utf-8"))

    if "RSA_SIGN_PSS" in algorithm:
        verifier = padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=hashes.SHA256().digest_size,
        )
        mode = "rsa"
    elif "RSA_SIGN_PKCS1" in algorithm:
        verifier = padding.PKCS1v15()
        mode = "rsa"
    elif "EC_SIGN" in algorithm:
        verifier = ec.ECDSA(hashes.SHA256())
        mode = "ec"
    else:
        raise ValueError(f"Unsupported GCP KMS signing algorithm: {algorithm}")

    def verify(payload: bytes, signature: bytes) -> bool:
        try:
            if mode == "rsa":
                public_key.verify(signature, payload, verifier, hashes.SHA256())
            else:
                public_key.verify(signature, payload, verifier)
            return True
        except InvalidSignature:
            return False

    return verify


def _policy_signer(args: argparse.Namespace) -> PolicySigner:
    provider = str(
        getattr(args, "signing_provider", "")
        or os.environ.get("AGENT_ROI_SIGNING_PROVIDER", "hmac")
    ).strip().lower().replace("_", "-")
    configured_key_id = str(
        getattr(args, "signing_key_id", "")
        or os.environ.get("AGENT_ROI_SIGNING_KEY_ID", "")
    ).strip()

    if provider == "hmac":
        return HMACPolicySigner(
            _signing_key(getattr(args, "signing_key_file", "")),
            key_id=configured_key_id or "control-plane-hmac",
        )

    if provider in {"aws", "aws-kms"}:
        key_id = _required_setting(
            getattr(args, "aws_kms_key_id", "")
            or os.environ.get("AGENT_ROI_AWS_KMS_KEY_ID", ""),
            "AWS KMS key ID",
        )
        algorithm = str(
            getattr(args, "aws_kms_signing_algorithm", "")
            or os.environ.get(
                "AGENT_ROI_AWS_KMS_SIGNING_ALGORITHM", "RSASSA_PSS_SHA_256"
            )
        )
        return AWSKMSPolicySigner(key_id, signing_algorithm=algorithm)

    if provider in {"azure", "azure-key-vault", "azure-managed-hsm"}:
        key_id = _required_setting(
            getattr(args, "azure_key_id", "")
            or os.environ.get("AGENT_ROI_AZURE_KEY_ID", ""),
            "Azure Key Vault key ID",
        )
        try:
            from azure.identity import DefaultAzureCredential  # type: ignore
            from azure.keyvault.keys.crypto import CryptographyClient  # type: ignore
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise RuntimeError(
                "Azure signing requires agent-roi[azure]."
            ) from exc
        client = CryptographyClient(key_id, DefaultAzureCredential())
        algorithm = str(
            getattr(args, "azure_signing_algorithm", "")
            or os.environ.get("AGENT_ROI_AZURE_SIGNING_ALGORITHM", "PS256")
        )
        return AzureKeyVaultPolicySigner(
            configured_key_id or key_id, client=client, algorithm=algorithm
        )

    if provider in {"gcp", "gcp-kms", "google-kms"}:
        key_id = _required_setting(
            getattr(args, "gcp_kms_key_id", "")
            or os.environ.get("AGENT_ROI_GCP_KMS_KEY_ID", ""),
            "GCP KMS key-version ID",
        )
        try:
            from google.cloud import kms_v1  # type: ignore
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise RuntimeError("GCP signing requires agent-roi[gcp].") from exc
        client = kms_v1.KeyManagementServiceClient()
        return GCPKMSPolicySigner(
            configured_key_id or key_id,
            client=client,
            verify_callback=_gcp_verify_callback(client, key_id),
        )

    if provider in {"vault", "vault-transit"}:
        base_url = _required_setting(
            getattr(args, "vault_url", "")
            or os.environ.get("AGENT_ROI_VAULT_URL", ""),
            "Vault URL",
        )
        key_name = _required_setting(
            getattr(args, "vault_key_name", "")
            or os.environ.get("AGENT_ROI_VAULT_KEY_NAME", ""),
            "Vault Transit key name",
        )
        token = _required_setting(
            getattr(args, "vault_token", "")
            or os.environ.get("AGENT_ROI_VAULT_TOKEN", ""),
            "Vault token",
        )
        version = int(
            getattr(args, "vault_key_version", 0)
            or os.environ.get("AGENT_ROI_VAULT_KEY_VERSION", "0")
        )
        return VaultTransitPolicySigner(
            base_url, key_name, token=token, key_version=version
        )

    raise ValueError(
        "Unsupported signing provider. Choose hmac, aws-kms, azure-key-vault, "
        "gcp-kms, or vault-transit."
    )


def _install_default_roles(identity: Any) -> None:
    roles = [
        RoleDefinition("platform_admin", frozenset({"*"})),
        RoleDefinition(
            "policy_admin",
            frozenset(
                {
                    "policy.*",
                    "agent.read",
                    "agent.register",
                    "agent.heartbeat",
                    "audit.read:*",
                    "approval.read:*",
                }
            ),
        ),
        RoleDefinition(
            "agent_owner",
            frozenset({"agent.read", "agent.execute", "tool.execute:*", "roi.*"}),
        ),
        RoleDefinition(
            "approver",
            frozenset({"approval.read:*", "approval.decide:*", "audit.read:*"}),
        ),
        RoleDefinition(
            "auditor", frozenset({"audit.read:*", "policy.read:*", "roi.read:*"})
        ),
        RoleDefinition(
            "finance_reviewer", frozenset({"roi.read:*", "roi.validate:*"})
        ),
    ]
    for role in roles:
        identity.save_role(role)


def build_app(args: argparse.Namespace) -> Any:
    data_dir = Path(args.data_dir)
    data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    signer = _policy_signer(args)
    postgres_dsn = getattr(args, "postgres_dsn", "") or os.environ.get("AGENT_ROI_POSTGRES_DSN", "")
    postgres_schema = getattr(args, "postgres_schema", "agent_roi")
    auto_migrate = bool(getattr(args, "auto_migrate", False))
    if postgres_dsn:
        if auto_migrate:
            PostgresMigrationManager(
                PostgresConnectionFactory(postgres_dsn, schema=postgres_schema)
            ).migrate()
        store = PostgresControlPlaneStore(
            postgres_dsn, schema=postgres_schema, auto_migrate=False
        )
        identity = PostgresIdentityStore(
            postgres_dsn, schema=postgres_schema, auto_migrate=False
        )
        ledger = PostgresROILedger(
            postgres_dsn, schema=postgres_schema, auto_migrate=False
        )
        audit = PostgresAuditStore(
            postgres_dsn, schema=postgres_schema, initialize=False
        )
    else:
        store = SqliteControlPlaneStore(data_dir / "control-plane.sqlite3")
        identity = SqliteIdentityStore(data_dir / "identity.sqlite3")
        ledger = RealizedROILedger(data_dir / "roi-ledger.sqlite3")
        audit = SqliteAuditStore(data_dir / "audit.sqlite3")
    _install_default_roles(identity)
    service = ControlPlaneService(
        store,
        signers={signer.key_id: signer},
        default_signer_key_id=signer.key_id,
    )

    oidc_verifier = None
    authorizer = None
    if not args.allow_unauthenticated:
        if not args.oidc_issuer or not args.oidc_audience:
            raise ValueError(
                "OIDC issuer and audience are required unless --allow-unauthenticated is set"
            )
        oidc_verifier = OIDCVerifier(
            OIDCConfig(
                issuer=args.oidc_issuer,
                audience=args.oidc_audience,
                jwks_url=args.oidc_jwks_url,
                organization_claim=args.oidc_organization_claim,
                roles_claim=args.oidc_roles_claim,
                groups_claim=args.oidc_groups_claim,
            )
        )
        authorizer = DynamicRBACAuthorizer(identity)

    app = create_fastapi_app(
        service,
        oidc_verifier=oidc_verifier,
        authorizer=authorizer,
        scim_directory=identity,
        roi_ledger=ledger,
        audit_store=audit,
    )
    app.state.agent_roi = {
        "version": __version__,
        "data_dir": str(data_dir),
        "database_backend": "postgres" if postgres_dsn else "sqlite",
        "authenticated": not args.allow_unauthenticated,
        "signing_key_id": signer.key_id,
        "signing_provider": type(signer).__name__,
    }
    return app


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agent-roi-control-plane",
        description="Run the self-hosted Agent-ROI enterprise control plane.",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--data-dir", default="./agent-roi-data")
    parser.add_argument("--postgres-dsn", default=os.environ.get("AGENT_ROI_POSTGRES_DSN", ""))
    parser.add_argument("--postgres-schema", default=os.environ.get("AGENT_ROI_POSTGRES_SCHEMA", "agent_roi"))
    parser.add_argument(
        "--auto-migrate",
        action="store_true",
        help="Apply packaged PostgreSQL migrations before startup; use a dedicated migration job in production.",
    )
    parser.add_argument(
        "--signing-provider",
        default=os.environ.get("AGENT_ROI_SIGNING_PROVIDER", "hmac"),
        help="Policy signing provider: hmac, aws-kms, azure-key-vault, gcp-kms, or vault-transit.",
    )
    parser.add_argument("--signing-key-file", default="")
    parser.add_argument(
        "--signing-key-id", default=os.environ.get("AGENT_ROI_SIGNING_KEY_ID", "")
    )
    parser.add_argument(
        "--aws-kms-key-id", default=os.environ.get("AGENT_ROI_AWS_KMS_KEY_ID", "")
    )
    parser.add_argument(
        "--aws-kms-signing-algorithm",
        default=os.environ.get(
            "AGENT_ROI_AWS_KMS_SIGNING_ALGORITHM", "RSASSA_PSS_SHA_256"
        ),
    )
    parser.add_argument(
        "--azure-key-id", default=os.environ.get("AGENT_ROI_AZURE_KEY_ID", "")
    )
    parser.add_argument(
        "--azure-signing-algorithm",
        default=os.environ.get("AGENT_ROI_AZURE_SIGNING_ALGORITHM", "PS256"),
    )
    parser.add_argument(
        "--gcp-kms-key-id", default=os.environ.get("AGENT_ROI_GCP_KMS_KEY_ID", "")
    )
    parser.add_argument("--vault-url", default=os.environ.get("AGENT_ROI_VAULT_URL", ""))
    parser.add_argument(
        "--vault-key-name", default=os.environ.get("AGENT_ROI_VAULT_KEY_NAME", "")
    )
    parser.add_argument(
        "--vault-token", default=os.environ.get("AGENT_ROI_VAULT_TOKEN", "")
    )
    parser.add_argument(
        "--vault-key-version",
        type=int,
        default=int(os.environ.get("AGENT_ROI_VAULT_KEY_VERSION", "0")),
    )
    parser.add_argument("--allow-unauthenticated", action="store_true")
    parser.add_argument("--oidc-issuer", default=os.environ.get("AGENT_ROI_OIDC_ISSUER", ""))
    parser.add_argument("--oidc-audience", default=os.environ.get("AGENT_ROI_OIDC_AUDIENCE", ""))
    parser.add_argument("--oidc-jwks-url", default=os.environ.get("AGENT_ROI_OIDC_JWKS_URL", ""))
    parser.add_argument("--oidc-organization-claim", default="org_id")
    parser.add_argument("--oidc-roles-claim", default="roles")
    parser.add_argument("--oidc-groups-claim", default="groups")
    parser.add_argument("--version", action="version", version=f"agent-roi {__version__}")
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        app = build_app(args)
    except ValueError as exc:
        parser.error(str(exc))
    try:
        import uvicorn  # type: ignore
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise RuntimeError(
            "Control-plane hosting requires agent-roi[control-plane]."
        ) from exc
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
