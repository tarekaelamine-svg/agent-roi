from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import sqlite3
import threading
import time
from typing import Any, Iterable, Mapping, Optional, Protocol
from urllib import error as urlerror
from urllib import parse as urlparse
from urllib import request as urlrequest
import uuid

from agent_roi._serialization import canonical_json, digest_value, to_jsonable
from agent_roi.policies.loader import Policy, policy_from_mapping


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class ControlPlaneError(RuntimeError):
    """Raised when the enterprise control plane rejects or cannot serve a request."""


class PolicySignatureError(ControlPlaneError):
    """Raised when a policy bundle signature is absent or invalid."""


class PolicySigner(Protocol):
    key_id: str

    def sign(self, payload: bytes) -> str: ...
    def verify(self, payload: bytes, signature: str) -> bool: ...


@dataclass(frozen=True)
class HMACPolicySigner:
    """HMAC-SHA256 policy signer for private control-plane deployments.

    For cross-organization distribution, use a custom ``PolicySigner`` backed by
    an asymmetric KMS/HSM key. The service intentionally depends on the signer
    protocol rather than a single key-management product.
    """

    secret: bytes
    key_id: str = "hmac-default"

    def __post_init__(self) -> None:
        if not isinstance(self.secret, bytes) or len(self.secret) < 32:
            raise ValueError("HMAC policy signing keys must contain at least 32 bytes")
        if not self.key_id.strip():
            raise ValueError("key_id must be a non-empty string")

    def sign(self, payload: bytes) -> str:
        return hmac.new(self.secret, payload, hashlib.sha256).hexdigest()

    def verify(self, payload: bytes, signature: str) -> bool:
        return hmac.compare_digest(self.sign(payload), str(signature))


@dataclass(frozen=True)
class PolicyBundle:
    organization_id: str
    name: str
    environment: str
    version: str
    policy: Mapping[str, Any]
    digest: str
    signature: str
    signer_key_id: str
    status: str = "published"
    created_at_utc: str = field(default_factory=_utc_now)
    created_by: str = "system"

    @classmethod
    def create(
        cls,
        *,
        organization_id: str,
        name: str,
        environment: str,
        version: str,
        policy: Mapping[str, Any],
        signer: PolicySigner,
        created_by: str,
    ) -> "PolicyBundle":
        normalized = to_jsonable(dict(policy))
        policy_from_mapping(name, normalized)
        envelope = {
            "organization_id": organization_id,
            "name": name,
            "environment": environment,
            "version": version,
            "policy": normalized,
        }
        payload = canonical_json(envelope).encode("utf-8")
        return cls(
            organization_id=organization_id,
            name=name,
            environment=environment,
            version=version,
            policy=normalized,
            digest=hashlib.sha256(payload).hexdigest(),
            signature=signer.sign(payload),
            signer_key_id=signer.key_id,
            created_by=created_by,
        )

    def signing_payload(self) -> bytes:
        return canonical_json(
            {
                "organization_id": self.organization_id,
                "name": self.name,
                "environment": self.environment,
                "version": self.version,
                "policy": dict(self.policy),
            }
        ).encode("utf-8")

    def verify(self, signer: PolicySigner) -> None:
        payload = self.signing_payload()
        if hashlib.sha256(payload).hexdigest() != self.digest:
            raise PolicySignatureError("Policy bundle digest is invalid")
        if signer.key_id != self.signer_key_id or not signer.verify(payload, self.signature):
            raise PolicySignatureError("Policy bundle signature is invalid")
        policy_from_mapping(self.name, self.policy)

    def to_dict(self) -> dict[str, Any]:
        return {
            "organization_id": self.organization_id,
            "name": self.name,
            "environment": self.environment,
            "version": self.version,
            "policy": dict(self.policy),
            "digest": self.digest,
            "signature": self.signature,
            "signer_key_id": self.signer_key_id,
            "status": self.status,
            "created_at_utc": self.created_at_utc,
            "created_by": self.created_by,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "PolicyBundle":
        return cls(
            organization_id=str(value["organization_id"]),
            name=str(value["name"]),
            environment=str(value["environment"]),
            version=str(value["version"]),
            policy=dict(value["policy"]),
            digest=str(value["digest"]),
            signature=str(value["signature"]),
            signer_key_id=str(value["signer_key_id"]),
            status=str(value.get("status", "published")),
            created_at_utc=str(value.get("created_at_utc", _utc_now())),
            created_by=str(value.get("created_by", "system")),
        )


class SqliteControlPlaneStore:
    """Transactional local store for a self-hosted control plane.

    SQLite is appropriate for a single control-plane node. Multi-node
    deployments should provide a repository with equivalent transactional
    semantics backed by PostgreSQL or another HA database.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
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

    def _initialize(self) -> None:
        with self._connection() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS policy_bundles (
                    organization_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    environment TEXT NOT NULL,
                    version TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    digest TEXT NOT NULL,
                    signature TEXT NOT NULL,
                    signer_key_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at_utc TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    PRIMARY KEY (organization_id, name, environment, version)
                );
                CREATE TABLE IF NOT EXISTS active_policies (
                    organization_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    environment TEXT NOT NULL,
                    version TEXT NOT NULL,
                    activated_at_utc TEXT NOT NULL,
                    activated_by TEXT NOT NULL,
                    revision INTEGER NOT NULL DEFAULT 1,
                    PRIMARY KEY (organization_id, name, environment),
                    FOREIGN KEY (organization_id, name, environment, version)
                      REFERENCES policy_bundles(organization_id, name, environment, version)
                );
                CREATE TABLE IF NOT EXISTS policy_rollouts (
                    organization_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    environment TEXT NOT NULL,
                    primary_version TEXT NOT NULL,
                    candidate_version TEXT NOT NULL,
                    candidate_percentage INTEGER NOT NULL,
                    seed TEXT NOT NULL,
                    updated_at_utc TEXT NOT NULL,
                    updated_by TEXT NOT NULL,
                    revision INTEGER NOT NULL DEFAULT 1,
                    PRIMARY KEY (organization_id, name, environment),
                    FOREIGN KEY (organization_id, name, environment, primary_version)
                      REFERENCES policy_bundles(organization_id, name, environment, version),
                    FOREIGN KEY (organization_id, name, environment, candidate_version)
                      REFERENCES policy_bundles(organization_id, name, environment, version)
                );
                CREATE TABLE IF NOT EXISTS agents (
                    organization_id TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    environment TEXT NOT NULL,
                    owner TEXT NOT NULL,
                    purpose TEXT NOT NULL,
                    status TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    registered_at_utc TEXT NOT NULL,
                    last_heartbeat_utc TEXT,
                    policy_digest TEXT,
                    version TEXT,
                    revision INTEGER NOT NULL DEFAULT 1,
                    PRIMARY KEY (organization_id, agent_id, environment)
                );
                """
            )
            for table in ("active_policies", "policy_rollouts", "agents"):
                columns = {row[1] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
                if "revision" not in columns:
                    conn.execute(f"ALTER TABLE {table} ADD COLUMN revision INTEGER NOT NULL DEFAULT 1")

    def save_bundle(self, bundle: PolicyBundle) -> None:
        with self._lock, self._connection() as conn:
            try:
                conn.execute(
                    """INSERT INTO policy_bundles VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        bundle.organization_id,
                        bundle.name,
                        bundle.environment,
                        bundle.version,
                        canonical_json(bundle.policy),
                        bundle.digest,
                        bundle.signature,
                        bundle.signer_key_id,
                        bundle.status,
                        bundle.created_at_utc,
                        bundle.created_by,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise ControlPlaneError("Policy version already exists") from exc

    def get_bundle(
        self, organization_id: str, name: str, environment: str, version: str
    ) -> PolicyBundle:
        with self._connection() as conn:
            row = conn.execute(
                """SELECT * FROM policy_bundles
                   WHERE organization_id=? AND name=? AND environment=? AND version=?""",
                (organization_id, name, environment, version),
            ).fetchone()
        if row is None:
            raise KeyError(f"Policy bundle not found: {organization_id}/{environment}/{name}/{version}")
        return PolicyBundle(
            organization_id=row["organization_id"],
            name=row["name"],
            environment=row["environment"],
            version=row["version"],
            policy=json.loads(row["payload_json"]),
            digest=row["digest"],
            signature=row["signature"],
            signer_key_id=row["signer_key_id"],
            status=row["status"],
            created_at_utc=row["created_at_utc"],
            created_by=row["created_by"],
        )

    def activate(
        self,
        organization_id: str,
        name: str,
        environment: str,
        version: str,
        *,
        activated_by: str,
        expected_revision: Optional[int] = None,
    ) -> PolicyBundle:
        bundle = self.get_bundle(organization_id, name, environment, version)
        with self._lock, self._connection() as conn:
            if expected_revision is None:
                conn.execute(
                    """INSERT INTO active_policies(
                           organization_id,name,environment,version,activated_at_utc,activated_by,revision
                       ) VALUES (?, ?, ?, ?, ?, ?, 1)
                       ON CONFLICT(organization_id, name, environment) DO UPDATE SET
                         version=excluded.version,
                         activated_at_utc=excluded.activated_at_utc,
                         activated_by=excluded.activated_by,
                         revision=active_policies.revision+1""",
                    (organization_id, name, environment, version, _utc_now(), activated_by),
                )
            else:
                cursor = conn.execute(
                    """UPDATE active_policies SET version=?,activated_at_utc=?,activated_by=?,
                           revision=revision+1
                       WHERE organization_id=? AND name=? AND environment=? AND revision=?""",
                    (version, _utc_now(), activated_by, organization_id, name, environment, int(expected_revision)),
                )
                if cursor.rowcount != 1:
                    raise ControlPlaneError("Active policy revision conflict")
            conn.execute(
                "DELETE FROM policy_rollouts WHERE organization_id=? AND name=? AND environment=?",
                (organization_id, name, environment),
            )
        return bundle

    def get_active(self, organization_id: str, name: str, environment: str) -> PolicyBundle:
        with self._connection() as conn:
            row = conn.execute(
                """SELECT version FROM active_policies
                   WHERE organization_id=? AND name=? AND environment=?""",
                (organization_id, name, environment),
            ).fetchone()
        if row is None:
            raise KeyError(f"No active policy: {organization_id}/{environment}/{name}")
        return self.get_bundle(organization_id, name, environment, row["version"])

    def get_active_revision(self, organization_id: str, name: str, environment: str) -> int:
        with self._connection() as conn:
            row = conn.execute(
                """SELECT revision FROM active_policies
                   WHERE organization_id=? AND name=? AND environment=?""",
                (organization_id, name, environment),
            ).fetchone()
        if row is None:
            raise KeyError(f"No active policy: {organization_id}/{environment}/{name}")
        return int(row["revision"])

    def start_rollout(
        self,
        organization_id: str,
        name: str,
        environment: str,
        candidate_version: str,
        *,
        candidate_percentage: int,
        updated_by: str,
        seed: str = "",
        expected_revision: Optional[int] = None,
    ) -> dict[str, Any]:
        if isinstance(candidate_percentage, bool) or not 1 <= int(candidate_percentage) <= 99:
            raise ValueError("candidate_percentage must be between 1 and 99")
        primary = self.get_active(organization_id, name, environment)
        self.get_bundle(organization_id, name, environment, candidate_version)
        if primary.version == candidate_version:
            raise ValueError("candidate_version must differ from the active version")
        seed_value = seed or digest_value(
            {"organization_id": organization_id, "name": name, "environment": environment, "candidate": candidate_version}
        )[:16]
        with self._lock, self._connection() as conn:
            if expected_revision is None:
                conn.execute(
                    """INSERT INTO policy_rollouts(
                           organization_id,name,environment,primary_version,candidate_version,
                           candidate_percentage,seed,updated_at_utc,updated_by,revision
                       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
                       ON CONFLICT(organization_id, name, environment) DO UPDATE SET
                         primary_version=excluded.primary_version,
                         candidate_version=excluded.candidate_version,
                         candidate_percentage=excluded.candidate_percentage,
                         seed=excluded.seed,
                         updated_at_utc=excluded.updated_at_utc,
                         updated_by=excluded.updated_by,
                         revision=policy_rollouts.revision+1""",
                    (organization_id, name, environment, primary.version, candidate_version, int(candidate_percentage), seed_value, _utc_now(), updated_by),
                )
            else:
                cursor = conn.execute(
                    """UPDATE policy_rollouts SET primary_version=?,candidate_version=?,
                           candidate_percentage=?,seed=?,updated_at_utc=?,updated_by=?,revision=revision+1
                       WHERE organization_id=? AND name=? AND environment=? AND revision=?""",
                    (primary.version, candidate_version, int(candidate_percentage), seed_value, _utc_now(), updated_by,
                     organization_id, name, environment, int(expected_revision)),
                )
                if cursor.rowcount != 1:
                    raise ControlPlaneError("Policy rollout revision conflict")
        return self.get_rollout(organization_id, name, environment)

    def get_rollout(self, organization_id: str, name: str, environment: str) -> dict[str, Any]:
        with self._connection() as conn:
            row = conn.execute(
                "SELECT * FROM policy_rollouts WHERE organization_id=? AND name=? AND environment=?",
                (organization_id, name, environment),
            ).fetchone()
        if row is None:
            raise KeyError("No active policy rollout")
        return dict(row)

    def cancel_rollout(self, organization_id: str, name: str, environment: str) -> None:
        with self._lock, self._connection() as conn:
            conn.execute(
                "DELETE FROM policy_rollouts WHERE organization_id=? AND name=? AND environment=?",
                (organization_id, name, environment),
            )

    def resolve_active(
        self, organization_id: str, name: str, environment: str, *, agent_id: str
    ) -> PolicyBundle:
        primary = self.get_active(organization_id, name, environment)
        try:
            rollout = self.get_rollout(organization_id, name, environment)
        except KeyError:
            return primary
        bucket = int(
            hashlib.sha256(
                f"{rollout['seed']}:{organization_id}:{environment}:{agent_id}".encode("utf-8")
            ).hexdigest()[:8],
            16,
        ) % 100
        version = (
            rollout["candidate_version"]
            if bucket < int(rollout["candidate_percentage"])
            else rollout["primary_version"]
        )
        return self.get_bundle(organization_id, name, environment, version)

    def list_bundles(
        self, organization_id: str, *, name: str = "", environment: str = ""
    ) -> tuple[PolicyBundle, ...]:
        clauses = ["organization_id=?"]
        params: list[Any] = [organization_id]
        if name:
            clauses.append("name=?")
            params.append(name)
        if environment:
            clauses.append("environment=?")
            params.append(environment)
        query = "SELECT version, name, environment FROM policy_bundles WHERE " + " AND ".join(clauses) + " ORDER BY created_at_utc"
        with self._connection() as conn:
            rows = conn.execute(query, params).fetchall()
        return tuple(
            self.get_bundle(organization_id, row["name"], row["environment"], row["version"])
            for row in rows
        )

    def register_agent(
        self,
        *,
        organization_id: str,
        agent_id: str,
        environment: str,
        owner: str,
        purpose: str,
        status: str = "approved",
        metadata: Optional[Mapping[str, Any]] = None,
        version: str = "",
        expected_revision: Optional[int] = None,
    ) -> dict[str, Any]:
        now = _utc_now()
        with self._lock, self._connection() as conn:
            if expected_revision is None:
                conn.execute(
                    """INSERT INTO agents(
                           organization_id,agent_id,environment,owner,purpose,status,metadata_json,
                           registered_at_utc,last_heartbeat_utc,policy_digest,version,revision
                       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
                       ON CONFLICT(organization_id, agent_id, environment) DO UPDATE SET
                         owner=excluded.owner,
                         purpose=excluded.purpose,
                         status=excluded.status,
                         metadata_json=excluded.metadata_json,
                         version=excluded.version,
                         revision=agents.revision+1""",
                    (
                        organization_id, agent_id, environment, owner, purpose, status,
                        canonical_json(dict(metadata or {})), now, None, None, version,
                    ),
                )
            else:
                cursor = conn.execute(
                    """UPDATE agents SET owner=?,purpose=?,status=?,metadata_json=?,version=?,
                           revision=revision+1
                       WHERE organization_id=? AND agent_id=? AND environment=? AND revision=?""",
                    (owner, purpose, status, canonical_json(dict(metadata or {})), version,
                     organization_id, agent_id, environment, int(expected_revision)),
                )
                if cursor.rowcount != 1:
                    raise ControlPlaneError("Agent revision conflict")
        return self.get_agent(organization_id, agent_id, environment)

    def heartbeat(
        self,
        *,
        organization_id: str,
        agent_id: str,
        environment: str,
        policy_digest: str,
        version: str,
        status: str = "production",
        expected_revision: Optional[int] = None,
    ) -> dict[str, Any]:
        with self._lock, self._connection() as conn:
            query = """UPDATE agents SET last_heartbeat_utc=?,policy_digest=?,version=?,status=?,
                       revision=revision+1 WHERE organization_id=? AND agent_id=? AND environment=?"""
            params: list[Any] = [_utc_now(), policy_digest, version, status, organization_id, agent_id, environment]
            if expected_revision is not None:
                query += " AND revision=?"
                params.append(int(expected_revision))
            cursor = conn.execute(query, params)
            if cursor.rowcount != 1:
                if expected_revision is not None:
                    raise ControlPlaneError("Agent heartbeat revision conflict")
                raise KeyError(f"Agent not registered: {agent_id}")
        return self.get_agent(organization_id, agent_id, environment)

    def get_agent(self, organization_id: str, agent_id: str, environment: str) -> dict[str, Any]:
        with self._connection() as conn:
            row = conn.execute(
                "SELECT * FROM agents WHERE organization_id=? AND agent_id=? AND environment=?",
                (organization_id, agent_id, environment),
            ).fetchone()
        if row is None:
            raise KeyError(agent_id)
        return {
            **dict(row),
            "metadata": json.loads(row["metadata_json"]),
        }

    def list_agents(
        self,
        organization_id: str,
        *,
        environment: str = "",
        status: str = "",
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[dict[str, Any], ...]:
        clauses = ["organization_id=?"]
        params: list[Any] = [organization_id]
        if environment:
            clauses.append("environment=?")
            params.append(environment)
        if status:
            clauses.append("status=?")
            params.append(status)
        params.extend([max(1, min(int(limit), 500)), max(0, int(offset))])
        with self._connection() as conn:
            rows = conn.execute(
                "SELECT * FROM agents WHERE " + " AND ".join(clauses)
                + " ORDER BY agent_id, environment LIMIT ? OFFSET ?",
                params,
            ).fetchall()
        return tuple({**dict(row), "metadata": json.loads(row["metadata_json"])} for row in rows)


class ControlPlaneService:
    def __init__(
        self,
        store: Any,
        *,
        signers: Mapping[str, PolicySigner],
        default_signer_key_id: str,
        require_signed_bundles: bool = True,
        event_sink: Any = None,
    ) -> None:
        if default_signer_key_id not in signers:
            raise ValueError("default_signer_key_id is not configured")
        self.store = store
        self.signers = dict(signers)
        self.default_signer_key_id = default_signer_key_id
        self.require_signed_bundles = bool(require_signed_bundles)
        self.event_sink = event_sink

    def _emit(self, event_type: str, data: Mapping[str, Any]) -> None:
        if self.event_sink is None:
            return
        from .telemetry import CloudEvent
        self.event_sink.emit(
            CloudEvent(
                type=f"com.agentroi.policy.{event_type}",
                source="/agent-roi/control-plane",
                subject=str(data.get("name", "policy")),
                data=dict(data),
            )
        )

    def publish_policy(
        self,
        *,
        organization_id: str,
        name: str,
        environment: str,
        version: str,
        policy: Mapping[str, Any],
        created_by: str,
        signer_key_id: str = "",
    ) -> PolicyBundle:
        signer = self.signers[signer_key_id or self.default_signer_key_id]
        bundle = PolicyBundle.create(
            organization_id=organization_id,
            name=name,
            environment=environment,
            version=version,
            policy=policy,
            signer=signer,
            created_by=created_by,
        )
        self.store.save_bundle(bundle)
        self._emit("published", bundle.to_dict())
        return bundle

    def verify_bundle(self, bundle: PolicyBundle) -> None:
        signer = self.signers.get(bundle.signer_key_id)
        if signer is None:
            raise PolicySignatureError(f"Unknown policy signing key: {bundle.signer_key_id}")
        bundle.verify(signer)

    def activate_policy(
        self, *, expected_revision: Optional[int] = None, **kwargs: Any
    ) -> PolicyBundle:
        if expected_revision is not None:
            kwargs["expected_revision"] = int(expected_revision)
        bundle = self.store.activate(**kwargs)
        self.verify_bundle(bundle)
        self._emit("activated", bundle.to_dict())
        return bundle

    def start_rollout(
        self, *, expected_revision: Optional[int] = None, **kwargs: Any
    ) -> dict[str, Any]:
        if expected_revision is not None:
            kwargs["expected_revision"] = int(expected_revision)
        rollout = self.store.start_rollout(**kwargs)
        self._emit("rollout_started", rollout)
        return rollout

    def cancel_rollout(self, organization_id: str, name: str, environment: str) -> None:
        self.store.cancel_rollout(organization_id, name, environment)
        self._emit(
            "rollout_cancelled",
            {"organization_id": organization_id, "name": name, "environment": environment},
        )

    def policy_for_agent(
        self, organization_id: str, name: str, environment: str, agent_id: str
    ) -> PolicyBundle:
        bundle = self.store.resolve_active(
            organization_id, name, environment, agent_id=agent_id
        )
        if self.require_signed_bundles:
            self.verify_bundle(bundle)
        return bundle

    def active_policy(self, organization_id: str, name: str, environment: str) -> PolicyBundle:
        bundle = self.store.get_active(organization_id, name, environment)
        if self.require_signed_bundles:
            self.verify_bundle(bundle)
        return bundle

    def get_policy_for_agent(
        self, organization_id: str, name: str, environment: str, agent_id: str
    ) -> PolicyBundle:
        return self.policy_for_agent(organization_id, name, environment, agent_id)

    def promote_policy(
        self,
        *,
        organization_id: str,
        name: str,
        source_environment: str,
        target_environment: str,
        source_version: str,
        target_version: str = "",
        promoted_by: str,
        activate: bool = False,
        signer_key_id: str = "",
    ) -> PolicyBundle:
        source = self.store.get_bundle(
            organization_id, name, source_environment, source_version
        )
        if self.require_signed_bundles:
            self.verify_bundle(source)
        promoted = self.publish_policy(
            organization_id=organization_id,
            name=name,
            environment=target_environment,
            version=target_version or source.version,
            policy=source.policy,
            created_by=promoted_by,
            signer_key_id=signer_key_id,
        )
        self._emit(
            "promoted",
            {
                **promoted.to_dict(),
                "source_environment": source_environment,
                "source_version": source_version,
            },
        )
        if activate:
            return self.activate_policy(
                organization_id=organization_id,
                name=name,
                environment=target_environment,
                version=promoted.version,
                activated_by=promoted_by,
            )
        return promoted

    def rollback_policy(
        self,
        *,
        organization_id: str,
        name: str,
        environment: str,
        version: str,
        rolled_back_by: str,
    ) -> PolicyBundle:
        bundle = self.activate_policy(
            organization_id=organization_id,
            name=name,
            environment=environment,
            version=version,
            activated_by=rolled_back_by,
        )
        self.cancel_rollout(organization_id, name, environment)
        self._emit(
            "rolled_back",
            {**bundle.to_dict(), "rolled_back_by": rolled_back_by},
        )
        return bundle

    def runtime_policy(self, organization_id: str, name: str, environment: str) -> Policy:
        bundle = self.active_policy(organization_id, name, environment)
        return policy_from_mapping(f"{name}@{bundle.version}", bundle.policy)

    def register_agent(
        self, *, expected_revision: Optional[int] = None, **kwargs: Any
    ) -> dict[str, Any]:
        if expected_revision is not None:
            kwargs["expected_revision"] = int(expected_revision)
        return self.store.register_agent(**kwargs)

    def heartbeat(
        self, *, expected_revision: Optional[int] = None, **kwargs: Any
    ) -> dict[str, Any]:
        if expected_revision is not None:
            kwargs["expected_revision"] = int(expected_revision)
        return self.store.heartbeat(**kwargs)


class ControlPlaneClient:
    """Small dependency-free HTTP client for the central control plane."""

    def __init__(
        self,
        base_url: str,
        *,
        bearer_token: str = "",
        timeout_seconds: float = 10.0,
        signer: Optional[PolicySigner] = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.bearer_token = bearer_token
        self.timeout_seconds = float(timeout_seconds)
        self.signer = signer

    def _request(
        self,
        method: str,
        path: str,
        payload: Optional[Mapping[str, Any]] = None,
        *,
        extra_headers: Optional[Mapping[str, str]] = None,
    ) -> Any:
        body = None if payload is None else canonical_json(dict(payload)).encode("utf-8")
        headers = {"Accept": "application/json"}
        if extra_headers:
            headers.update({str(key): str(value) for key, value in extra_headers.items()})
        if body is not None:
            headers["Content-Type"] = "application/json"
        if self.bearer_token:
            headers["Authorization"] = f"Bearer {self.bearer_token}"
        req = urlrequest.Request(self.base_url + path, data=body, method=method, headers=headers)
        try:
            with urlrequest.urlopen(req, timeout=self.timeout_seconds) as response:
                content = response.read()
                return json.loads(content) if content else None
        except urlerror.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise ControlPlaneError(f"Control plane returned HTTP {exc.code}: {detail}") from exc
        except OSError as exc:
            raise ControlPlaneError("Control plane is unavailable") from exc

    @staticmethod
    def _segment(value: str) -> str:
        return urlparse.quote(str(value), safe="")

    def publish_policy(
        self,
        *,
        organization_id: str,
        name: str,
        environment: str,
        version: str,
        policy: Mapping[str, Any],
        created_by: str = "api",
        signer_key_id: str = "",
    ) -> PolicyBundle:
        org, env, policy_name, ver = map(
            self._segment, (organization_id, environment, name, version)
        )
        data = self._request(
            "POST",
            f"/v1/organizations/{org}/policies/{env}/{policy_name}/{ver}",
            {
                "policy": dict(policy),
                "created_by": created_by,
                "signer_key_id": signer_key_id,
            },
        )
        bundle = PolicyBundle.from_dict(data)
        if self.signer is not None:
            bundle.verify(self.signer)
        return bundle

    def activate_policy(
        self,
        organization_id: str,
        name: str,
        environment: str,
        version: str,
        *,
        expected_revision: Optional[int] = None,
    ) -> PolicyBundle:
        org, env, policy_name, ver = map(
            self._segment, (organization_id, environment, name, version)
        )
        data = self._request(
            "POST",
            f"/v1/organizations/{org}/policies/{env}/{policy_name}/{ver}/activate",
            {},
            extra_headers={"If-Match": str(expected_revision)} if expected_revision is not None else None,
        )
        bundle = PolicyBundle.from_dict(data)
        if self.signer is not None:
            bundle.verify(self.signer)
        return bundle

    def promote_policy(
        self,
        *,
        organization_id: str,
        name: str,
        source_environment: str,
        source_version: str,
        target_environment: str,
        target_version: str = "",
        activate: bool = False,
    ) -> PolicyBundle:
        org, source_env, policy_name, source_ver, target_env = map(
            self._segment,
            (organization_id, source_environment, name, source_version, target_environment),
        )
        data = self._request(
            "POST",
            f"/v1/organizations/{org}/policies/{source_env}/{policy_name}/{source_ver}/promote/{target_env}",
            {"target_version": target_version, "activate": activate},
        )
        bundle = PolicyBundle.from_dict(data)
        if self.signer is not None:
            bundle.verify(self.signer)
        return bundle

    def start_rollout(
        self,
        *,
        organization_id: str,
        name: str,
        environment: str,
        candidate_version: str,
        candidate_percentage: int,
        seed: str = "",
    ) -> dict[str, Any]:
        org, env, policy_name, candidate = map(
            self._segment, (organization_id, environment, name, candidate_version)
        )
        return self._request(
            "POST",
            f"/v1/organizations/{org}/policies/{env}/{policy_name}/{candidate}/rollout",
            {"candidate_percentage": candidate_percentage, "seed": seed},
        )

    def cancel_rollout(self, organization_id: str, name: str, environment: str) -> None:
        org, env, policy_name = map(
            self._segment, (organization_id, environment, name)
        )
        self._request(
            "DELETE",
            f"/v1/organizations/{org}/policies/{env}/{policy_name}/rollout",
        )

    def register_agent(
        self,
        *,
        organization_id: str,
        agent_id: str,
        environment: str,
        owner: str,
        purpose: str,
        status: str = "approved",
        version: str = "",
        metadata: Optional[Mapping[str, Any]] = None,
        expected_revision: Optional[int] = None,
    ) -> dict[str, Any]:
        org = self._segment(organization_id)
        kwargs: dict[str, Any] = {}
        if expected_revision is not None:
            kwargs["extra_headers"] = {"If-Match": str(expected_revision)}
        return self._request(
            "POST",
            f"/v1/organizations/{org}/agents",
            {
                "agent_id": agent_id,
                "environment": environment,
                "owner": owner,
                "purpose": purpose,
                "status": status,
                "version": version,
                "metadata": dict(metadata or {}),
            },
            **kwargs,
        )

    def get_active_policy(self, organization_id: str, name: str, environment: str) -> PolicyBundle:
        org, env, policy_name = map(
            self._segment, (organization_id, environment, name)
        )
        data = self._request(
            "GET", f"/v1/organizations/{org}/policies/{env}/{policy_name}/active"
        )
        bundle = PolicyBundle.from_dict(data)
        if self.signer is not None:
            bundle.verify(self.signer)
        return bundle

    def get_policy_for_agent(
        self, organization_id: str, name: str, environment: str, agent_id: str
    ) -> PolicyBundle:
        org, env, policy_name = map(
            self._segment, (organization_id, environment, name)
        )
        query = urlparse.urlencode({"agent_id": str(agent_id)})
        data = self._request(
            "GET",
            f"/v1/organizations/{org}/policies/{env}/{policy_name}/resolve?{query}",
        )
        bundle = PolicyBundle.from_dict(data)
        if self.signer is not None:
            bundle.verify(self.signer)
        return bundle

    def runtime_policy(self, organization_id: str, name: str, environment: str) -> Policy:
        bundle = self.get_active_policy(organization_id, name, environment)
        return policy_from_mapping(f"{name}@{bundle.version}", bundle.policy)

    def heartbeat(
        self,
        *,
        organization_id: str,
        agent_id: str,
        environment: str,
        policy_digest: str,
        version: str,
        status: str = "production",
        expected_revision: Optional[int] = None,
    ) -> dict[str, Any]:
        org, agent, env = map(
            self._segment, (organization_id, agent_id, environment)
        )
        kwargs: dict[str, Any] = {}
        if expected_revision is not None:
            kwargs["extra_headers"] = {"If-Match": str(expected_revision)}
        return self._request(
            "POST",
            f"/v1/organizations/{org}/agents/{agent}/{env}/heartbeat",
            {"policy_digest": policy_digest, "version": version, "status": status},
            **kwargs,
        )


class PolicyBundleCache:
    """Verified on-disk cache for offline policy operation."""

    def __init__(
        self,
        directory: str | Path,
        *,
        signer: PolicySigner,
        max_stale_seconds: int = 3600,
    ) -> None:
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.signer = signer
        self.max_stale_seconds = int(max_stale_seconds)
        if self.max_stale_seconds < 0:
            raise ValueError("max_stale_seconds must be >= 0")

    def _path(self, organization_id: str, name: str, environment: str, agent_id: str) -> Path:
        key = digest_value(
            {"organization_id": organization_id, "name": name, "environment": environment, "agent_id": agent_id}
        )
        return self.directory / f"{key}.json"

    def save(
        self, bundle: PolicyBundle, *, agent_id: str = ""
    ) -> Path:
        bundle.verify(self.signer)
        path = self._path(bundle.organization_id, bundle.name, bundle.environment, agent_id)
        temporary = path.with_suffix(f".{uuid.uuid4().hex}.tmp")
        temporary.write_text(
            canonical_json({"cached_at_epoch_ms": int(time.time() * 1000), "bundle": bundle.to_dict()}),
            encoding="utf-8",
        )
        temporary.replace(path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        return path

    def load(
        self, organization_id: str, name: str, environment: str, *, agent_id: str = "", allow_stale: bool = False
    ) -> PolicyBundle:
        path = self._path(organization_id, name, environment, agent_id)
        if not path.is_file():
            raise KeyError("No cached policy bundle")
        data = json.loads(path.read_text(encoding="utf-8"))
        age_seconds = max(0.0, (int(time.time() * 1000) - int(data["cached_at_epoch_ms"])) / 1000)
        if age_seconds > self.max_stale_seconds and not allow_stale:
            raise ControlPlaneError("Cached policy bundle is stale")
        bundle = PolicyBundle.from_dict(data["bundle"])
        bundle.verify(self.signer)
        return bundle


class CachedControlPlaneClient:
    """Control-plane client with verified offline cache and explicit stale policy."""

    def __init__(
        self,
        client: ControlPlaneClient,
        cache: PolicyBundleCache,
        *,
        allow_stale_on_error: bool = False,
    ) -> None:
        self.client = client
        self.cache = cache
        self.allow_stale_on_error = bool(allow_stale_on_error)

    def get_active_policy(self, organization_id: str, name: str, environment: str) -> PolicyBundle:
        try:
            bundle = self.client.get_active_policy(organization_id, name, environment)
            self.cache.save(bundle)
            return bundle
        except Exception:
            return self.cache.load(
                organization_id, name, environment, allow_stale=self.allow_stale_on_error
            )

    def get_policy_for_agent(
        self, organization_id: str, name: str, environment: str, agent_id: str
    ) -> PolicyBundle:
        try:
            bundle = self.client.get_policy_for_agent(organization_id, name, environment, agent_id)
            self.cache.save(bundle, agent_id=agent_id)
            return bundle
        except Exception:
            return self.cache.load(
                organization_id,
                name,
                environment,
                agent_id=agent_id,
                allow_stale=self.allow_stale_on_error,
            )

    def heartbeat(self, **kwargs: Any) -> dict[str, Any]:
        return self.client.heartbeat(**kwargs)

def create_fastapi_app(
    service: ControlPlaneService,
    *,
    oidc_verifier: Any = None,
    authorizer: Any = None,
    scim_directory: Any = None,
    roi_ledger: Any = None,
    audit_store: Any = None,
) -> Any:
    """Create the optional FastAPI control-plane application.

    FastAPI is deliberately optional so the core SDK remains lightweight.
    Install ``agent-roi[control-plane]`` to host this application.
    """
    try:
        from fastapi import Depends, FastAPI, Header, HTTPException, Response
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise RuntimeError("FastAPI is required. Install agent-roi[control-plane].") from exc

    app = FastAPI(title="Agent-ROI Enterprise Control Plane", version="2.0.1")

    def principal_dependency(authorization: str = Header(default="")) -> Any:
        if oidc_verifier is None:
            return None
        try:
            return oidc_verifier.verify_authorization_header(authorization)
        except Exception as exc:
            raise HTTPException(status_code=401, detail="Authentication failed") from exc

    def require(
        principal: Any,
        action: str,
        resource: str,
        environment: str = "*",
        organization_id: str = "",
    ) -> None:
        if organization_id and principal is not None:
            principal_org = str(getattr(principal, "organization_id", ""))
            if principal_org != organization_id:
                raise HTTPException(status_code=403, detail="Cross-organization access denied")
        if authorizer is not None:
            try:
                authorizer.require(
                    principal, action, resource, context={"environment": environment}
                )
            except Exception as exc:
                raise HTTPException(status_code=403, detail="Authorization denied") from exc

    def expected_revision(if_match: str) -> Optional[int]:
        value = str(if_match or "").strip()
        if value.startswith("W/"):
            value = value[2:].strip()
        if len(value) >= 2 and value.startswith('"') and value.endswith('"'):
            value = value[1:-1]
        if not value:
            return None
        try:
            revision = int(value)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="If-Match must contain an integer revision") from exc
        if revision < 1:
            raise HTTPException(status_code=400, detail="If-Match revision must be >= 1")
        return revision

    def invoke_with_revision(fn: Any, *, if_match: str = "", **kwargs: Any) -> Any:
        import inspect
        revision = expected_revision(if_match)
        if revision is not None and "expected_revision" in inspect.signature(fn).parameters:
            kwargs["expected_revision"] = revision
        return fn(**kwargs)

    @app.middleware("http")
    async def correlation_header(request: Any, call_next: Any) -> Any:
        import uuid as _uuid
        correlation_id = request.headers.get("X-Correlation-ID") or str(_uuid.uuid4())
        response = await call_next(request)
        response.headers["X-Correlation-ID"] = correlation_id
        response.headers["X-Agent-ROI-API-Version"] = "2.0"
        return response

    @app.get("/healthz")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/v1/organizations/{organization_id}/policies/{environment}/{name}/{version}")
    def publish_policy(
        organization_id: str,
        environment: str,
        name: str,
        version: str,
        body: dict[str, Any],
        principal: Any = Depends(principal_dependency),
    ) -> dict[str, Any]:
        require(principal, "policy.publish", name, environment, organization_id)
        try:
            return service.publish_policy(
                organization_id=organization_id,
                name=name,
                environment=environment,
                version=version,
                policy=body["policy"],
                created_by=getattr(principal, "subject", body.get("created_by", "api")),
                signer_key_id=str(body.get("signer_key_id", "")),
            ).to_dict()
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/v1/organizations/{organization_id}/policies/{environment}/{name}/{version}/activate")
    def activate_policy(
        organization_id: str,
        environment: str,
        name: str,
        version: str,
        if_match: str = Header(default="", alias="If-Match"),
        principal: Any = Depends(principal_dependency),
    ) -> dict[str, Any]:
        require(principal, "policy.activate", name, environment, organization_id)
        try:
            bundle = invoke_with_revision(
                service.activate_policy,
                if_match=if_match,
                organization_id=organization_id,
                name=name,
                environment=environment,
                version=version,
                activated_by=getattr(principal, "subject", "api"),
            )
            return {
                **bundle.to_dict(),
                "revision": service.store.get_active_revision(
                    organization_id, name, environment
                ),
            }
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ControlPlaneError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.get("/v1/organizations/{organization_id}/policies/{environment}/{name}/active")
    def active_policy(
        organization_id: str,
        environment: str,
        name: str,
        principal: Any = Depends(principal_dependency),
    ) -> dict[str, Any]:
        require(principal, "policy.read", name, environment, organization_id)
        try:
            bundle = service.active_policy(organization_id, name, environment)
            return {
                **bundle.to_dict(),
                "revision": service.store.get_active_revision(
                    organization_id, name, environment
                ),
            }
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.post("/v1/organizations/{organization_id}/policies/{source_environment}/{name}/{source_version}/promote/{target_environment}")
    def promote_policy(
        organization_id: str,
        source_environment: str,
        name: str,
        source_version: str,
        target_environment: str,
        body: dict[str, Any],
        principal: Any = Depends(principal_dependency),
    ) -> dict[str, Any]:
        require(principal, "policy.promote", name, target_environment, organization_id)
        try:
            return service.promote_policy(
                organization_id=organization_id,
                name=name,
                source_environment=source_environment,
                target_environment=target_environment,
                source_version=source_version,
                target_version=str(body.get("target_version", "")),
                promoted_by=getattr(principal, "subject", body.get("promoted_by", "api")),
                activate=bool(body.get("activate", False)),
                signer_key_id=str(body.get("signer_key_id", "")),
            ).to_dict()
        except (KeyError, ValueError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/v1/organizations/{organization_id}/policies/{environment}/{name}/{version}/rollback")
    def rollback_policy(
        organization_id: str,
        environment: str,
        name: str,
        version: str,
        principal: Any = Depends(principal_dependency),
    ) -> dict[str, Any]:
        require(principal, "policy.rollback", name, environment, organization_id)
        try:
            return service.rollback_policy(
                organization_id=organization_id,
                name=name,
                environment=environment,
                version=version,
                rolled_back_by=getattr(principal, "subject", "api"),
            ).to_dict()
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.post("/v1/organizations/{organization_id}/policies/{environment}/{name}/{candidate_version}/rollout")
    def start_rollout(
        organization_id: str,
        environment: str,
        name: str,
        candidate_version: str,
        body: dict[str, Any],
        if_match: str = Header(default="", alias="If-Match"),
        principal: Any = Depends(principal_dependency),
    ) -> dict[str, Any]:
        require(principal, "policy.rollout", name, environment, organization_id)
        try:
            return invoke_with_revision(service.start_rollout, if_match=if_match,
                organization_id=organization_id,
                name=name,
                environment=environment,
                candidate_version=candidate_version,
                candidate_percentage=int(body["candidate_percentage"]),
                seed=str(body.get("seed", "")),
                updated_by=getattr(principal, "subject", body.get("updated_by", "api")),
            )
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.delete("/v1/organizations/{organization_id}/policies/{environment}/{name}/rollout")
    def cancel_rollout(
        organization_id: str,
        environment: str,
        name: str,
        principal: Any = Depends(principal_dependency),
    ) -> dict[str, str]:
        require(principal, "policy.rollout", name, environment, organization_id)
        service.cancel_rollout(organization_id, name, environment)
        return {"status": "cancelled"}

    @app.get("/v1/organizations/{organization_id}/policies/{environment}/{name}/resolve")
    def resolve_policy(
        organization_id: str,
        environment: str,
        name: str,
        agent_id: str,
        principal: Any = Depends(principal_dependency),
    ) -> dict[str, Any]:
        require(principal, "policy.read", name, environment, organization_id)
        try:
            return service.policy_for_agent(organization_id, name, environment, agent_id).to_dict()
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.post("/v1/organizations/{organization_id}/agents")
    def register_agent(
        organization_id: str,
        body: dict[str, Any],
        if_match: str = Header(default="", alias="If-Match"),
        principal: Any = Depends(principal_dependency),
    ) -> dict[str, Any]:
        require(principal, "agent.register", str(body.get("agent_id", "")), str(body.get("environment", "*")), organization_id)
        try:
            return invoke_with_revision(service.register_agent, if_match=if_match, organization_id=organization_id, **body)
        except ControlPlaneError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/v1/organizations/{organization_id}/agents/{agent_id}/{environment}/heartbeat")
    def heartbeat(
        organization_id: str,
        agent_id: str,
        environment: str,
        body: dict[str, Any],
        if_match: str = Header(default="", alias="If-Match"),
        principal: Any = Depends(principal_dependency),
    ) -> dict[str, Any]:
        require(principal, "agent.heartbeat", agent_id, environment, organization_id)
        try:
            return invoke_with_revision(service.heartbeat, if_match=if_match,
                organization_id=organization_id,
                agent_id=agent_id,
                environment=environment,
                policy_digest=str(body.get("policy_digest", "")),
                version=str(body.get("version", "")),
                status=str(body.get("status", "production")),
            )
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ControlPlaneError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.get("/v1/organizations/{organization_id}/agents")
    def list_agents(
        organization_id: str,
        environment: str = "",
        status: str = "",
        limit: int = 100,
        offset: int = 0,
        principal: Any = Depends(principal_dependency),
    ) -> list[dict[str, Any]]:
        require(principal, "agent.read", "*", organization_id=organization_id)
        import inspect
        parameters = inspect.signature(service.store.list_agents).parameters
        kwargs: dict[str, Any] = {}
        if "environment" in parameters:
            kwargs["environment"] = environment
        if "status" in parameters:
            kwargs["status"] = status
        if "limit" in parameters:
            kwargs["limit"] = max(1, min(limit, 500))
        if "offset" in parameters:
            kwargs["offset"] = max(0, offset)
        return list(service.store.list_agents(organization_id, **kwargs))

    if audit_store is not None:
        @app.post("/v1/audit/events", status_code=201)
        def audit_record(body: dict[str, Any], principal: Any = Depends(principal_dependency)) -> dict[str, Any]:
            require(principal, "audit.write", str(body.get("event_type", "event")))
            try:
                event = audit_store.record(
                    correlation_id=str(body["correlation_id"]),
                    run_id=str(body["run_id"]),
                    event_type=str(body["event_type"]),
                    payload=dict(body.get("payload", {})),
                )
                return event.to_dict()
            except Exception as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc

        @app.post("/v1/audit/events/append", status_code=201)
        def audit_append(body: dict[str, Any], principal: Any = Depends(principal_dependency)) -> dict[str, Any]:
            require(principal, "audit.write", str(body.get("event_type", "event")))
            from agent_roi.audit.event import AuditEvent
            event = AuditEvent(
                event_id=str(body["event_id"]),
                correlation_id=str(body["correlation_id"]),
                run_id=str(body["run_id"]),
                ts_epoch_ms=int(body["ts_epoch_ms"]),
                event_type=str(body["event_type"]),
                payload=dict(body["payload"]),
                prev_hash=body.get("prev_hash"),
                hash=body.get("hash"),
            )
            try:
                audit_store.append(event)
                return event.to_dict()
            except Exception as exc:
                raise HTTPException(status_code=409, detail=str(exc)) from exc

        @app.get("/v1/audit/chains/{correlation_id}/tail")
        def audit_tail(correlation_id: str, principal: Any = Depends(principal_dependency)) -> dict[str, Any]:
            require(principal, "audit.read", correlation_id)
            return {"last_hash": audit_store.last_hash(correlation_id)}

        @app.get("/v1/audit/verify")
        def audit_verify(correlation_id: str = "", principal: Any = Depends(principal_dependency)) -> dict[str, Any]:
            require(principal, "audit.read", correlation_id or "*")
            try:
                try:
                    count = audit_store.verify(correlation_id) if correlation_id else audit_store.verify()
                except TypeError:
                    count = audit_store.verify()
                return {"events_verified": count}
            except Exception as exc:
                raise HTTPException(status_code=409, detail=str(exc)) from exc

    if scim_directory is not None:
        @app.get("/scim/v2/Users")
        def scim_users(startIndex: int = 1, count: int = 100, principal: Any = Depends(principal_dependency)) -> dict[str, Any]:
            require(principal, "identity.read", "users")
            import inspect
            kwargs: dict[str, Any] = {}
            parameters = inspect.signature(scim_directory.list_users).parameters
            if "limit" in parameters:
                kwargs["limit"] = max(1, min(count, 500))
            if "offset" in parameters:
                kwargs["offset"] = max(0, startIndex - 1)
            resources = [item.to_scim() for item in scim_directory.list_users(**kwargs)]
            total = scim_directory.count_users() if hasattr(scim_directory, "count_users") else len(resources)
            return {"schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"], "totalResults": int(total), "startIndex": max(1, startIndex), "itemsPerPage": len(resources), "Resources": resources}

        @app.post("/scim/v2/Users", status_code=201)
        def scim_create_user(body: dict[str, Any], principal: Any = Depends(principal_dependency)) -> dict[str, Any]:
            require(principal, "identity.write", "users")
            try:
                return scim_directory.create_user(body).to_scim()
            except ValueError as exc:
                raise HTTPException(status_code=409, detail=str(exc)) from exc

        @app.get("/scim/v2/Groups")
        def scim_groups(startIndex: int = 1, count: int = 100, principal: Any = Depends(principal_dependency)) -> dict[str, Any]:
            require(principal, "identity.read", "groups")
            import inspect
            kwargs: dict[str, Any] = {}
            parameters = inspect.signature(scim_directory.list_groups).parameters
            if "limit" in parameters:
                kwargs["limit"] = max(1, min(count, 500))
            if "offset" in parameters:
                kwargs["offset"] = max(0, startIndex - 1)
            resources = [item.to_scim() for item in scim_directory.list_groups(**kwargs)]
            total = scim_directory.count_groups() if hasattr(scim_directory, "count_groups") else len(resources)
            return {"schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"], "totalResults": int(total), "startIndex": max(1, startIndex), "itemsPerPage": len(resources), "Resources": resources}

        @app.post("/scim/v2/Groups", status_code=201)
        def scim_create_group(body: dict[str, Any], principal: Any = Depends(principal_dependency)) -> dict[str, Any]:
            require(principal, "identity.write", "groups")
            try:
                return scim_directory.create_group(body).to_scim()
            except ValueError as exc:
                raise HTTPException(status_code=409, detail=str(exc)) from exc

        @app.get("/scim/v2/Users/{user_id}")
        def scim_get_user(user_id: str, principal: Any = Depends(principal_dependency)) -> dict[str, Any]:
            require(principal, "identity.read", "users")
            try:
                return scim_directory.get_user(user_id).to_scim()
            except KeyError as exc:
                raise HTTPException(status_code=404, detail=str(exc)) from exc

        @app.put("/scim/v2/Users/{user_id}")
        def scim_replace_user(user_id: str, body: dict[str, Any], principal: Any = Depends(principal_dependency)) -> dict[str, Any]:
            require(principal, "identity.write", "users")
            try:
                return scim_directory.replace_user(user_id, body).to_scim()
            except KeyError as exc:
                raise HTTPException(status_code=404, detail=str(exc)) from exc
            except ValueError as exc:
                raise HTTPException(status_code=409, detail=str(exc)) from exc

        @app.delete("/scim/v2/Users/{user_id}", status_code=204)
        def scim_delete_user(user_id: str, principal: Any = Depends(principal_dependency)) -> None:
            require(principal, "identity.write", "users")
            try:
                scim_directory.delete_user(user_id)
            except KeyError as exc:
                raise HTTPException(status_code=404, detail=str(exc)) from exc

        @app.get("/scim/v2/Groups/{group_id}")
        def scim_get_group(group_id: str, principal: Any = Depends(principal_dependency)) -> dict[str, Any]:
            require(principal, "identity.read", "groups")
            try:
                return scim_directory.get_group(group_id).to_scim()
            except KeyError as exc:
                raise HTTPException(status_code=404, detail=str(exc)) from exc

        @app.put("/scim/v2/Groups/{group_id}")
        def scim_replace_group(group_id: str, body: dict[str, Any], principal: Any = Depends(principal_dependency)) -> dict[str, Any]:
            require(principal, "identity.write", "groups")
            try:
                return scim_directory.replace_group(group_id, body).to_scim()
            except KeyError as exc:
                raise HTTPException(status_code=404, detail=str(exc)) from exc
            except ValueError as exc:
                raise HTTPException(status_code=409, detail=str(exc)) from exc

        @app.delete("/scim/v2/Groups/{group_id}", status_code=204)
        def scim_delete_group(group_id: str, principal: Any = Depends(principal_dependency)) -> None:
            require(principal, "identity.write", "groups")
            try:
                scim_directory.delete_group(group_id)
            except KeyError as exc:
                raise HTTPException(status_code=404, detail=str(exc)) from exc

        if all(hasattr(scim_directory, name) for name in ("save_role", "save_binding", "list_roles", "list_bindings")):
            from agent_roi.enterprise.identity import RoleBinding, RoleDefinition

            @app.get("/v1/identity/roles")
            def rbac_roles(principal: Any = Depends(principal_dependency)) -> list[dict[str, Any]]:
                require(principal, "identity.read", "roles")
                return [
                    {"name": role.name, "permissions": sorted(role.permissions), "description": role.description}
                    for role in scim_directory.list_roles()
                ]

            @app.put("/v1/identity/roles/{role_name}")
            def rbac_save_role(role_name: str, body: dict[str, Any], principal: Any = Depends(principal_dependency)) -> dict[str, Any]:
                require(principal, "identity.write", "roles")
                try:
                    role = RoleDefinition(
                        role_name,
                        frozenset(str(value) for value in body.get("permissions", [])),
                        str(body.get("description", "")),
                    )
                    scim_directory.save_role(role)
                    return {"name": role.name, "permissions": sorted(role.permissions), "description": role.description}
                except ValueError as exc:
                    raise HTTPException(status_code=400, detail=str(exc)) from exc

            @app.delete("/v1/identity/roles/{role_name}", status_code=204)
            def rbac_delete_role(role_name: str, principal: Any = Depends(principal_dependency)) -> None:
                require(principal, "identity.write", "roles")
                try:
                    scim_directory.delete_role(role_name)
                except KeyError as exc:
                    raise HTTPException(status_code=404, detail=str(exc)) from exc

            @app.get("/v1/identity/bindings")
            def rbac_bindings(principal: Any = Depends(principal_dependency)) -> list[dict[str, Any]]:
                require(principal, "identity.read", "bindings")
                return [
                    {
                        "binding_id": binding_id,
                        "role": binding.role,
                        "organization_id": binding.organization_id,
                        "subject": binding.subject,
                        "group": binding.group,
                        "environment": binding.environment,
                    }
                    for binding_id, binding in scim_directory.list_bindings()
                ]

            @app.post("/v1/identity/bindings", status_code=201)
            def rbac_save_binding(body: dict[str, Any], principal: Any = Depends(principal_dependency)) -> dict[str, Any]:
                require(principal, "identity.write", "bindings")
                try:
                    binding = RoleBinding(
                        str(body["role"]),
                        str(body["organization_id"]),
                        subject=str(body.get("subject", "")),
                        group=str(body.get("group", "")),
                        environment=str(body.get("environment", "*")),
                    )
                    binding_id = scim_directory.save_binding(binding)
                    return {"binding_id": binding_id}
                except (KeyError, ValueError) as exc:
                    raise HTTPException(status_code=400, detail=str(exc)) from exc

            @app.delete("/v1/identity/bindings/{binding_id}", status_code=204)
            def rbac_delete_binding(binding_id: str, principal: Any = Depends(principal_dependency)) -> None:
                require(principal, "identity.write", "bindings")
                try:
                    scim_directory.delete_binding(binding_id)
                except KeyError as exc:
                    raise HTTPException(status_code=404, detail=str(exc)) from exc

    if roi_ledger is not None:
        @app.get("/v1/organizations/{organization_id}/roi/summary")
        def roi_summary(organization_id: str, principal: Any = Depends(principal_dependency)) -> dict[str, Any]:
            require(principal, "roi.read", "portfolio", organization_id=organization_id)
            return roi_ledger.portfolio_summary(organization_id=organization_id)

        @app.post("/v1/organizations/{organization_id}/roi/opportunities", status_code=201)
        def roi_create(organization_id: str, body: dict[str, Any], principal: Any = Depends(principal_dependency)) -> dict[str, Any]:
            require(principal, "roi.create", "portfolio", organization_id=organization_id)
            body = dict(body)
            body["organization_id"] = organization_id
            try:
                return roi_ledger.create_opportunity(**body).to_dict()
            except (KeyError, TypeError, ValueError) as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc

        @app.get("/v1/organizations/{organization_id}/roi/opportunities")
        def roi_list(
            organization_id: str,
            agent_id: str = "",
            status: str = "",
            limit: int = 100,
            offset: int = 0,
            principal: Any = Depends(principal_dependency),
        ) -> list[dict[str, Any]]:
            require(principal, "roi.read", "portfolio", organization_id=organization_id)
            try:
                return [
                    item.to_dict()
                    for item in roi_ledger.list_opportunities(
                        organization_id=organization_id,
                        agent_id=agent_id,
                        status=status or None,
                        **({"limit": max(1, min(limit, 500)), "offset": max(0, offset)} if "limit" in __import__("inspect").signature(roi_ledger.list_opportunities).parameters else {}),
                    )
                ]
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc

        @app.get("/v1/organizations/{organization_id}/roi/opportunities/{opportunity_id}")
        def roi_get(organization_id: str, opportunity_id: str, principal: Any = Depends(principal_dependency)) -> dict[str, Any]:
            require(principal, "roi.read", opportunity_id, organization_id=organization_id)
            try:
                opportunity = roi_ledger.get_opportunity(opportunity_id)
            except KeyError as exc:
                raise HTTPException(status_code=404, detail=str(exc)) from exc
            if opportunity.organization_id != organization_id:
                raise HTTPException(status_code=404, detail="ROI opportunity not found")
            return opportunity.to_dict()

        @app.post("/v1/organizations/{organization_id}/roi/opportunities/{opportunity_id}/transition")
        def roi_transition(organization_id: str, opportunity_id: str, body: dict[str, Any], if_match: str = Header(default="", alias="If-Match"), principal: Any = Depends(principal_dependency)) -> dict[str, Any]:
            require(principal, "roi.update", opportunity_id, organization_id=organization_id)
            try:
                opportunity = roi_ledger.get_opportunity(opportunity_id)
                if opportunity.organization_id != organization_id:
                    raise KeyError(opportunity_id)
                transition_kwargs = {
                    "changed_by": getattr(principal, "subject", body.get("changed_by", "api")),
                    "reason": str(body.get("reason", "")),
                }
                revision = expected_revision(if_match)
                if revision is not None and "expected_revision" in __import__("inspect").signature(roi_ledger.transition).parameters:
                    transition_kwargs["expected_revision"] = revision
                return roi_ledger.transition(
                    opportunity_id, str(body["status"]), **transition_kwargs
                ).to_dict()
            except KeyError as exc:
                raise HTTPException(status_code=404, detail=str(exc)) from exc
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc

        @app.post("/v1/organizations/{organization_id}/roi/opportunities/{opportunity_id}/values", status_code=201)
        def roi_record_value(organization_id: str, opportunity_id: str, body: dict[str, Any], principal: Any = Depends(principal_dependency)) -> dict[str, Any]:
            action = "roi.validate" if str(body.get("stage", "")) == "validated" else "roi.record"
            require(principal, action, opportunity_id, organization_id=organization_id)
            try:
                opportunity = roi_ledger.get_opportunity(opportunity_id)
                if opportunity.organization_id != organization_id:
                    raise KeyError(opportunity_id)
                payload = dict(body)
                payload.setdefault("recorded_by", getattr(principal, "subject", "api"))
                return roi_ledger.record_value(opportunity_id, **payload)
            except KeyError as exc:
                raise HTTPException(status_code=404, detail=str(exc)) from exc
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc

        @app.post("/v1/organizations/{organization_id}/roi/costs", status_code=201)
        def roi_record_cost(organization_id: str, body: dict[str, Any], principal: Any = Depends(principal_dependency)) -> dict[str, Any]:
            require(principal, "roi.record", "cost", organization_id=organization_id)
            try:
                payload = dict(body)
                payload["organization_id"] = organization_id
                payload.setdefault("recorded_by", getattr(principal, "subject", "api"))
                return roi_ledger.record_cost(**payload)
            except (KeyError, TypeError, ValueError) as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc

    return app
