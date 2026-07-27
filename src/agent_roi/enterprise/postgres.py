from __future__ import annotations

import hashlib
import json
from typing import Any, Iterable, Mapping, Optional
import uuid

from agent_roi._serialization import canonical_json, digest_value
from agent_roi.db import (
    PostgresConnectionFactory,
    PostgresMigrationManager,
    fetchall_mappings,
    fetchone_mapping,
)

from .control_plane import ControlPlaneError, PolicyBundle, _utc_now
from .identity import (
    AuthenticationError,
    Principal,
    RBACAuthorizer,
    RoleBinding,
    RoleDefinition,
    SCIMGroup,
    SCIMUser,
)


def _json_value(value: Any, default: Any) -> Any:
    if value is None:
        return default
    if isinstance(value, str):
        return json.loads(value)
    return value


def _iso(value: Any) -> str:
    return value.isoformat() if hasattr(value, "isoformat") else str(value)


class PostgresControlPlaneStore:
    """High-availability control-plane repository backed by PostgreSQL.

    Mutable rows carry a monotonically increasing ``revision``. Callers may pass
    ``expected_revision`` to reject lost updates from concurrent administrators.
    """

    def __init__(
        self,
        dsn: str,
        *,
        schema: str = "agent_roi",
        connect_factory: Any = None,
        auto_migrate: bool = True,
    ) -> None:
        self.connection_factory = PostgresConnectionFactory(
            dsn, schema=schema, connect_factory=connect_factory
        )
        if auto_migrate:
            PostgresMigrationManager(self.connection_factory).migrate()

    def save_bundle(self, bundle: PolicyBundle) -> None:
        with self.connection_factory.connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute(
                    """INSERT INTO policy_bundles(
                           organization_id, name, environment, version, payload_json,
                           digest, signature, signer_key_id, status, created_at_utc, created_by
                       ) VALUES (%s,%s,%s,%s,%s::jsonb,%s,%s,%s,%s,%s,%s)""",
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
            except Exception as exc:
                raise ControlPlaneError("Policy version already exists or could not be saved") from exc
            finally:
                cursor.close()

    def get_bundle(
        self, organization_id: str, name: str, environment: str, version: str
    ) -> PolicyBundle:
        with self.connection_factory.connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute(
                    """SELECT * FROM policy_bundles
                       WHERE organization_id=%s AND name=%s AND environment=%s AND version=%s""",
                    (organization_id, name, environment, version),
                )
                row = fetchone_mapping(cursor)
            finally:
                cursor.close()
        if row is None:
            raise KeyError(f"Policy bundle not found: {organization_id}/{environment}/{name}/{version}")
        return PolicyBundle(
            organization_id=str(row["organization_id"]),
            name=str(row["name"]),
            environment=str(row["environment"]),
            version=str(row["version"]),
            policy=dict(_json_value(row["payload_json"], {})),
            digest=str(row["digest"]),
            signature=str(row["signature"]),
            signer_key_id=str(row["signer_key_id"]),
            status=str(row["status"]),
            created_at_utc=_iso(row["created_at_utc"]),
            created_by=str(row["created_by"]),
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
        with self.connection_factory.connection() as conn:
            cursor = conn.cursor()
            try:
                if expected_revision is None:
                    cursor.execute(
                        """INSERT INTO active_policies(
                               organization_id,name,environment,version,activated_at_utc,activated_by,revision
                           ) VALUES (%s,%s,%s,%s,%s,%s,1)
                           ON CONFLICT(organization_id,name,environment) DO UPDATE SET
                             version=EXCLUDED.version,
                             activated_at_utc=EXCLUDED.activated_at_utc,
                             activated_by=EXCLUDED.activated_by,
                             revision=active_policies.revision+1""",
                        (organization_id, name, environment, version, _utc_now(), activated_by),
                    )
                else:
                    cursor.execute(
                        """UPDATE active_policies SET version=%s, activated_at_utc=%s,
                               activated_by=%s, revision=revision+1
                           WHERE organization_id=%s AND name=%s AND environment=%s AND revision=%s""",
                        (
                            version,
                            _utc_now(),
                            activated_by,
                            organization_id,
                            name,
                            environment,
                            int(expected_revision),
                        ),
                    )
                    if cursor.rowcount != 1:
                        raise ControlPlaneError("Active policy revision conflict")
                cursor.execute(
                    "DELETE FROM policy_rollouts WHERE organization_id=%s AND name=%s AND environment=%s",
                    (organization_id, name, environment),
                )
            finally:
                cursor.close()
        return bundle

    def get_active(self, organization_id: str, name: str, environment: str) -> PolicyBundle:
        with self.connection_factory.connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute(
                    """SELECT version FROM active_policies
                       WHERE organization_id=%s AND name=%s AND environment=%s""",
                    (organization_id, name, environment),
                )
                row = fetchone_mapping(cursor)
            finally:
                cursor.close()
        if row is None:
            raise KeyError(f"No active policy: {organization_id}/{environment}/{name}")
        return self.get_bundle(organization_id, name, environment, str(row["version"]))

    def get_active_revision(self, organization_id: str, name: str, environment: str) -> int:
        with self.connection_factory.connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute(
                    """SELECT revision FROM active_policies
                       WHERE organization_id=%s AND name=%s AND environment=%s""",
                    (organization_id, name, environment),
                )
                row = fetchone_mapping(cursor)
            finally:
                cursor.close()
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
            {
                "organization_id": organization_id,
                "name": name,
                "environment": environment,
                "candidate": candidate_version,
            }
        )[:16]
        with self.connection_factory.connection() as conn:
            cursor = conn.cursor()
            try:
                if expected_revision is None:
                    cursor.execute(
                        """INSERT INTO policy_rollouts(
                               organization_id,name,environment,primary_version,candidate_version,
                               candidate_percentage,seed,updated_at_utc,updated_by,revision
                           ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,1)
                           ON CONFLICT(organization_id,name,environment) DO UPDATE SET
                             primary_version=EXCLUDED.primary_version,
                             candidate_version=EXCLUDED.candidate_version,
                             candidate_percentage=EXCLUDED.candidate_percentage,
                             seed=EXCLUDED.seed,
                             updated_at_utc=EXCLUDED.updated_at_utc,
                             updated_by=EXCLUDED.updated_by,
                             revision=policy_rollouts.revision+1""",
                        (
                            organization_id,
                            name,
                            environment,
                            primary.version,
                            candidate_version,
                            int(candidate_percentage),
                            seed_value,
                            _utc_now(),
                            updated_by,
                        ),
                    )
                else:
                    cursor.execute(
                        """UPDATE policy_rollouts SET primary_version=%s,candidate_version=%s,
                               candidate_percentage=%s,seed=%s,updated_at_utc=%s,updated_by=%s,
                               revision=revision+1
                           WHERE organization_id=%s AND name=%s AND environment=%s AND revision=%s""",
                        (
                            primary.version,
                            candidate_version,
                            int(candidate_percentage),
                            seed_value,
                            _utc_now(),
                            updated_by,
                            organization_id,
                            name,
                            environment,
                            int(expected_revision),
                        ),
                    )
                    if cursor.rowcount != 1:
                        raise ControlPlaneError("Policy rollout revision conflict")
            finally:
                cursor.close()
        return self.get_rollout(organization_id, name, environment)

    def get_rollout(self, organization_id: str, name: str, environment: str) -> dict[str, Any]:
        with self.connection_factory.connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute(
                    """SELECT * FROM policy_rollouts
                       WHERE organization_id=%s AND name=%s AND environment=%s""",
                    (organization_id, name, environment),
                )
                row = fetchone_mapping(cursor)
            finally:
                cursor.close()
        if row is None:
            raise KeyError("No active policy rollout")
        return {key: (_iso(value) if key.endswith("_utc") else value) for key, value in row.items()}

    def cancel_rollout(self, organization_id: str, name: str, environment: str) -> None:
        with self.connection_factory.connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute(
                    "DELETE FROM policy_rollouts WHERE organization_id=%s AND name=%s AND environment=%s",
                    (organization_id, name, environment),
                )
            finally:
                cursor.close()

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
        return self.get_bundle(organization_id, name, environment, str(version))

    def list_bundles(
        self,
        organization_id: str,
        *,
        name: str = "",
        environment: str = "",
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[PolicyBundle, ...]:
        limit = max(1, min(int(limit), 500))
        offset = max(0, int(offset))
        clauses = ["organization_id=%s"]
        params: list[Any] = [organization_id]
        if name:
            clauses.append("name=%s")
            params.append(name)
        if environment:
            clauses.append("environment=%s")
            params.append(environment)
        params.extend([limit, offset])
        with self.connection_factory.connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute(
                    "SELECT name,environment,version FROM policy_bundles WHERE "
                    + " AND ".join(clauses)
                    + " ORDER BY created_at_utc DESC LIMIT %s OFFSET %s",
                    tuple(params),
                )
                rows = fetchall_mappings(cursor)
            finally:
                cursor.close()
        return tuple(
            self.get_bundle(organization_id, str(row["name"]), str(row["environment"]), str(row["version"]))
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
        with self.connection_factory.connection() as conn:
            cursor = conn.cursor()
            try:
                if expected_revision is None:
                    cursor.execute(
                        """INSERT INTO agents(
                               organization_id,agent_id,environment,owner,purpose,status,
                               metadata_json,registered_at_utc,last_heartbeat_utc,policy_digest,version,revision
                           ) VALUES (%s,%s,%s,%s,%s,%s,%s::jsonb,%s,NULL,NULL,%s,1)
                           ON CONFLICT(organization_id,agent_id,environment) DO UPDATE SET
                             owner=EXCLUDED.owner,purpose=EXCLUDED.purpose,status=EXCLUDED.status,
                             metadata_json=EXCLUDED.metadata_json,version=EXCLUDED.version,
                             revision=agents.revision+1""",
                        (
                            organization_id,
                            agent_id,
                            environment,
                            owner,
                            purpose,
                            status,
                            canonical_json(dict(metadata or {})),
                            now,
                            version,
                        ),
                    )
                else:
                    cursor.execute(
                        """UPDATE agents SET owner=%s,purpose=%s,status=%s,metadata_json=%s::jsonb,
                               version=%s,revision=revision+1
                           WHERE organization_id=%s AND agent_id=%s AND environment=%s AND revision=%s""",
                        (
                            owner,
                            purpose,
                            status,
                            canonical_json(dict(metadata or {})),
                            version,
                            organization_id,
                            agent_id,
                            environment,
                            int(expected_revision),
                        ),
                    )
                    if cursor.rowcount != 1:
                        raise ControlPlaneError("Agent revision conflict")
            finally:
                cursor.close()
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
        with self.connection_factory.connection() as conn:
            cursor = conn.cursor()
            try:
                query = """UPDATE agents SET last_heartbeat_utc=%s,policy_digest=%s,version=%s,
                           status=%s,revision=revision+1
                           WHERE organization_id=%s AND agent_id=%s AND environment=%s"""
                params: list[Any] = [
                    _utc_now(),
                    policy_digest,
                    version,
                    status,
                    organization_id,
                    agent_id,
                    environment,
                ]
                if expected_revision is not None:
                    query += " AND revision=%s"
                    params.append(int(expected_revision))
                cursor.execute(query, tuple(params))
                if cursor.rowcount != 1:
                    if expected_revision is None:
                        raise KeyError(f"Agent not registered: {agent_id}")
                    raise ControlPlaneError("Agent heartbeat revision conflict")
            finally:
                cursor.close()
        return self.get_agent(organization_id, agent_id, environment)

    def get_agent(self, organization_id: str, agent_id: str, environment: str) -> dict[str, Any]:
        with self.connection_factory.connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute(
                    """SELECT * FROM agents
                       WHERE organization_id=%s AND agent_id=%s AND environment=%s""",
                    (organization_id, agent_id, environment),
                )
                row = fetchone_mapping(cursor)
            finally:
                cursor.close()
        if row is None:
            raise KeyError(agent_id)
        result = dict(row)
        result["metadata"] = dict(_json_value(result.pop("metadata_json"), {}))
        for key in ("registered_at_utc", "last_heartbeat_utc"):
            if result.get(key) is not None:
                result[key] = _iso(result[key])
        return result

    def list_agents(
        self,
        organization_id: str,
        *,
        environment: str = "",
        status: str = "",
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[dict[str, Any], ...]:
        clauses = ["organization_id=%s"]
        params: list[Any] = [organization_id]
        if environment:
            clauses.append("environment=%s")
            params.append(environment)
        if status:
            clauses.append("status=%s")
            params.append(status)
        params.extend([max(1, min(int(limit), 500)), max(0, int(offset))])
        with self.connection_factory.connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute(
                    "SELECT * FROM agents WHERE " + " AND ".join(clauses)
                    + " ORDER BY agent_id,environment LIMIT %s OFFSET %s",
                    tuple(params),
                )
                rows = fetchall_mappings(cursor)
            finally:
                cursor.close()
        results: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["metadata"] = dict(_json_value(item.pop("metadata_json"), {}))
            for key in ("registered_at_utc", "last_heartbeat_utc"):
                if item.get(key) is not None:
                    item[key] = _iso(item[key])
            results.append(item)
        return tuple(results)


class PostgresIdentityStore:
    """PostgreSQL SCIM and RBAC repository for horizontally scaled services."""

    def __init__(
        self,
        dsn: str,
        *,
        schema: str = "agent_roi",
        connect_factory: Any = None,
        auto_migrate: bool = True,
    ) -> None:
        self.connection_factory = PostgresConnectionFactory(
            dsn, schema=schema, connect_factory=connect_factory
        )
        if auto_migrate:
            PostgresMigrationManager(self.connection_factory).migrate()

    @staticmethod
    def _parse_user(payload: Mapping[str, Any], *, user_id: str = "") -> SCIMUser:
        user_name = str(payload.get("userName", "")).strip()
        if not user_name:
            raise ValueError("SCIM userName is required")
        emails: list[str] = []
        for item in payload.get("emails", []) if isinstance(payload.get("emails", []), list) else []:
            value = item.get("value") if isinstance(item, Mapping) else item
            if isinstance(value, str) and value.strip():
                emails.append(value.strip())
        core = {"schemas", "id", "externalId", "userName", "active", "displayName", "emails"}
        return SCIMUser(
            id=user_id or str(payload.get("id") or uuid.uuid4()),
            user_name=user_name,
            active=bool(payload.get("active", True)),
            display_name=str(payload.get("displayName", "")),
            emails=tuple(emails),
            external_id=str(payload.get("externalId", "") or ""),
            attributes={key: value for key, value in payload.items() if key not in core},
        )

    def create_user(self, payload: Mapping[str, Any], *, organization_id: str = "default") -> SCIMUser:
        user = self._parse_user(payload)
        with self.connection_factory.connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute(
                    """INSERT INTO scim_users(
                           user_id,user_name,display_name,active,emails_json,attributes_json,
                           organization_id,external_id
                       ) VALUES (%s,%s,%s,%s,%s::jsonb,%s::jsonb,%s,%s)""",
                    (
                        user.id,
                        user.user_name,
                        user.display_name,
                        user.active,
                        canonical_json(list(user.emails)),
                        canonical_json(dict(user.attributes)),
                        organization_id,
                        user.external_id,
                    ),
                )
            except Exception as exc:
                raise ValueError(f"SCIM userName already exists: {user.user_name}") from exc
            finally:
                cursor.close()
        return user

    def _row_to_user(self, row: Mapping[str, Any]) -> SCIMUser:
        return SCIMUser(
            id=str(row["user_id"]),
            user_name=str(row["user_name"]),
            active=bool(row["active"]),
            display_name=str(row["display_name"]),
            emails=tuple(_json_value(row["emails_json"], [])),
            external_id=str(row["external_id"]),
            attributes={
                **dict(_json_value(row.get("attributes_json"), {})),
                "organization_id": str(row["organization_id"]),
                "revision": int(row["revision"]),
            },
        )

    def get_user(self, user_id: str) -> SCIMUser:
        with self.connection_factory.connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("SELECT * FROM scim_users WHERE user_id=%s", (user_id,))
                row = fetchone_mapping(cursor)
            finally:
                cursor.close()
        if row is None:
            raise KeyError(f"SCIM user not found: {user_id}")
        return self._row_to_user(row)

    def list_users(
        self, *, organization_id: str = "", limit: int = 100, offset: int = 0
    ) -> tuple[SCIMUser, ...]:
        query = "SELECT * FROM scim_users"
        params: list[Any] = []
        if organization_id:
            query += " WHERE organization_id=%s"
            params.append(organization_id)
        query += " ORDER BY user_name LIMIT %s OFFSET %s"
        params.extend([max(1, min(int(limit), 500)), max(0, int(offset))])
        with self.connection_factory.connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute(query, tuple(params))
                rows = fetchall_mappings(cursor)
            finally:
                cursor.close()
        return tuple(self._row_to_user(row) for row in rows)

    def count_users(self, *, organization_id: str = "") -> int:
        query = "SELECT COUNT(*) AS count FROM scim_users"
        params: tuple[Any, ...] = ()
        if organization_id:
            query += " WHERE organization_id=%s"
            params = (organization_id,)
        with self.connection_factory.connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute(query, params)
                row = fetchone_mapping(cursor)
            finally:
                cursor.close()
        return int((row or {}).get("count", 0))

    def replace_user(
        self,
        user_id: str,
        payload: Mapping[str, Any],
        *,
        expected_revision: Optional[int] = None,
    ) -> SCIMUser:
        current = self.get_user(user_id)
        user = self._parse_user(payload, user_id=user_id)
        organization_id = str(current.attributes.get("organization_id", "default"))
        revision = int(expected_revision if expected_revision is not None else current.attributes.get("revision", 1))
        with self.connection_factory.connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute(
                    """UPDATE scim_users SET user_name=%s,display_name=%s,active=%s,
                           emails_json=%s::jsonb,attributes_json=%s::jsonb,external_id=%s,
                           revision=revision+1 WHERE user_id=%s AND revision=%s""",
                    (
                        user.user_name,
                        user.display_name,
                        user.active,
                        canonical_json(list(user.emails)),
                        canonical_json(dict(user.attributes)),
                        user.external_id,
                        user_id,
                        revision,
                    ),
                )
                if cursor.rowcount != 1:
                    raise ValueError("SCIM user revision conflict")
            finally:
                cursor.close()
        return self.get_user(user_id)

    def delete_user(self, user_id: str, *, expected_revision: Optional[int] = None) -> None:
        query = "DELETE FROM scim_users WHERE user_id=%s"
        params: list[Any] = [user_id]
        if expected_revision is not None:
            query += " AND revision=%s"
            params.append(int(expected_revision))
        with self.connection_factory.connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute(query, tuple(params))
                if cursor.rowcount != 1:
                    raise KeyError(user_id)
            finally:
                cursor.close()

    @staticmethod
    def _parse_group(payload: Mapping[str, Any], *, group_id: str = "") -> SCIMGroup:
        display_name = str(payload.get("displayName", "")).strip()
        if not display_name:
            raise ValueError("SCIM group displayName is required")
        members = {
            str(item.get("value") if isinstance(item, Mapping) else item).strip()
            for item in payload.get("members", [])
            if str(item.get("value") if isinstance(item, Mapping) else item).strip()
        }
        return SCIMGroup(
            id=group_id or str(payload.get("id") or uuid.uuid4()),
            display_name=display_name,
            members=frozenset(members),
            external_id=str(payload.get("externalId", "") or ""),
        )

    def create_group(self, payload: Mapping[str, Any], *, organization_id: str = "default") -> SCIMGroup:
        group = self._parse_group(payload)
        known = {user.id for user in self.list_users(organization_id=organization_id, limit=500)}
        unknown = set(group.members) - known
        if unknown:
            raise ValueError(f"SCIM group references unknown users: {sorted(unknown)}")
        with self.connection_factory.connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute(
                    """INSERT INTO scim_groups(group_id,display_name,organization_id,external_id)
                       VALUES (%s,%s,%s,%s)""",
                    (group.id, group.display_name, organization_id, group.external_id),
                )
                for user_id in sorted(group.members):
                    cursor.execute(
                        "INSERT INTO scim_group_members(group_id,user_id) VALUES (%s,%s)",
                        (group.id, user_id),
                    )
            except Exception as exc:
                raise ValueError(f"SCIM group already exists: {group.display_name}") from exc
            finally:
                cursor.close()
        return group

    def get_group(self, group_id: str) -> SCIMGroup:
        with self.connection_factory.connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("SELECT * FROM scim_groups WHERE group_id=%s", (group_id,))
                row = fetchone_mapping(cursor)
                cursor.execute(
                    "SELECT user_id FROM scim_group_members WHERE group_id=%s ORDER BY user_id",
                    (group_id,),
                )
                members = fetchall_mappings(cursor)
            finally:
                cursor.close()
        if row is None:
            raise KeyError(f"SCIM group not found: {group_id}")
        return SCIMGroup(
            id=str(row["group_id"]),
            display_name=str(row["display_name"]),
            members=frozenset(str(item["user_id"]) for item in members),
            external_id=str(row["external_id"]),
        )

    def list_groups(
        self, *, organization_id: str = "", limit: int = 100, offset: int = 0
    ) -> tuple[SCIMGroup, ...]:
        query = "SELECT group_id FROM scim_groups"
        params: list[Any] = []
        if organization_id:
            query += " WHERE organization_id=%s"
            params.append(organization_id)
        query += " ORDER BY display_name LIMIT %s OFFSET %s"
        params.extend([max(1, min(int(limit), 500)), max(0, int(offset))])
        with self.connection_factory.connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute(query, tuple(params))
                rows = fetchall_mappings(cursor)
            finally:
                cursor.close()
        return tuple(self.get_group(str(row["group_id"])) for row in rows)

    def count_groups(self, *, organization_id: str = "") -> int:
        query = "SELECT COUNT(*) AS count FROM scim_groups"
        params: tuple[Any, ...] = ()
        if organization_id:
            query += " WHERE organization_id=%s"
            params = (organization_id,)
        with self.connection_factory.connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute(query, params)
                row = fetchone_mapping(cursor)
            finally:
                cursor.close()
        return int((row or {}).get("count", 0))

    def replace_group(
        self,
        group_id: str,
        payload: Mapping[str, Any],
        *,
        expected_revision: Optional[int] = None,
    ) -> SCIMGroup:
        group = self._parse_group(payload, group_id=group_id)
        current = self.get_group(group_id)
        known = {user.id for user in self.list_users(limit=500)}
        if set(group.members) - known:
            raise ValueError("SCIM group references unknown users")
        with self.connection_factory.connection() as conn:
            cursor = conn.cursor()
            try:
                query = """UPDATE scim_groups SET display_name=%s,external_id=%s,revision=revision+1
                           WHERE group_id=%s"""
                params: list[Any] = [group.display_name, group.external_id, group_id]
                if expected_revision is not None:
                    query += " AND revision=%s"
                    params.append(int(expected_revision))
                cursor.execute(query, tuple(params))
                if cursor.rowcount != 1:
                    raise ValueError("SCIM group revision conflict")
                cursor.execute("DELETE FROM scim_group_members WHERE group_id=%s", (group_id,))
                for user_id in sorted(group.members):
                    cursor.execute(
                        "INSERT INTO scim_group_members(group_id,user_id) VALUES (%s,%s)",
                        (group_id, user_id),
                    )
            finally:
                cursor.close()
        return self.get_group(group_id)

    def delete_group(self, group_id: str, *, expected_revision: Optional[int] = None) -> None:
        query = "DELETE FROM scim_groups WHERE group_id=%s"
        params: list[Any] = [group_id]
        if expected_revision is not None:
            query += " AND revision=%s"
            params.append(int(expected_revision))
        with self.connection_factory.connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute(query, tuple(params))
                if cursor.rowcount != 1:
                    raise KeyError(group_id)
            finally:
                cursor.close()

    def save_role(self, role: RoleDefinition, *, expected_revision: Optional[int] = None) -> None:
        with self.connection_factory.connection() as conn:
            cursor = conn.cursor()
            try:
                if expected_revision is None:
                    cursor.execute(
                        """INSERT INTO rbac_roles(name,permissions_json,description,revision)
                           VALUES (%s,%s::jsonb,%s,1)
                           ON CONFLICT(name) DO UPDATE SET permissions_json=EXCLUDED.permissions_json,
                           description=EXCLUDED.description,revision=rbac_roles.revision+1""",
                        (role.name, canonical_json(sorted(role.permissions)), role.description),
                    )
                else:
                    cursor.execute(
                        """UPDATE rbac_roles SET permissions_json=%s::jsonb,description=%s,
                           revision=revision+1 WHERE name=%s AND revision=%s""",
                        (
                            canonical_json(sorted(role.permissions)),
                            role.description,
                            role.name,
                            int(expected_revision),
                        ),
                    )
                    if cursor.rowcount != 1:
                        raise ValueError("RBAC role revision conflict")
            finally:
                cursor.close()

    def save_binding(self, binding: RoleBinding) -> str:
        binding_id = str(uuid.uuid4())
        with self.connection_factory.connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute(
                    """INSERT INTO rbac_bindings(
                           binding_id,role,organization_id,subject,group_name,environment
                       ) VALUES (%s,%s,%s,%s,%s,%s)""",
                    (
                        binding_id,
                        binding.role,
                        binding.organization_id,
                        binding.subject,
                        binding.group,
                        binding.environment,
                    ),
                )
            except Exception as exc:
                raise ValueError(f"Unknown RBAC role: {binding.role}") from exc
            finally:
                cursor.close()
        return binding_id

    def list_roles(self) -> tuple[RoleDefinition, ...]:
        with self.connection_factory.connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("SELECT * FROM rbac_roles ORDER BY name")
                rows = fetchall_mappings(cursor)
            finally:
                cursor.close()
        return tuple(
            RoleDefinition(
                str(row["name"]),
                frozenset(_json_value(row["permissions_json"], [])),
                str(row["description"]),
            )
            for row in rows
        )

    def delete_role(self, role_name: str) -> None:
        with self.connection_factory.connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("DELETE FROM rbac_roles WHERE name=%s", (role_name,))
                if cursor.rowcount != 1:
                    raise KeyError(role_name)
            finally:
                cursor.close()

    def list_bindings(self) -> tuple[tuple[str, RoleBinding], ...]:
        with self.connection_factory.connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("SELECT * FROM rbac_bindings ORDER BY binding_id")
                rows = fetchall_mappings(cursor)
            finally:
                cursor.close()
        return tuple(
            (
                str(row["binding_id"]),
                RoleBinding(
                    str(row["role"]),
                    str(row["organization_id"]),
                    subject=str(row["subject"]),
                    group=str(row["group_name"]),
                    environment=str(row["environment"]),
                ),
            )
            for row in rows
        )

    def delete_binding(self, binding_id: str) -> None:
        with self.connection_factory.connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("DELETE FROM rbac_bindings WHERE binding_id=%s", (binding_id,))
                if cursor.rowcount != 1:
                    raise KeyError(binding_id)
            finally:
                cursor.close()

    def authorizer(self) -> RBACAuthorizer:
        return RBACAuthorizer(self.list_roles(), [binding for _, binding in self.list_bindings()])

    def principal_for(
        self,
        user_id: str,
        *,
        organization_id: str,
        role_mapping: Optional[Mapping[str, Iterable[str]]] = None,
    ) -> Principal:
        user = self.get_user(user_id)
        if not user.active:
            raise AuthenticationError(f"SCIM user is inactive: {user_id}")
        groups = {
            group.display_name
            for group in self.list_groups(organization_id=organization_id, limit=500)
            if user_id in group.members
        }
        roles: set[str] = set()
        for group in groups:
            roles.update((role_mapping or {}).get(group, ()))
        return Principal(
            subject=user.id,
            organization_id=organization_id,
            display_name=user.display_name,
            email=user.emails[0] if user.emails else "",
            roles=frozenset(roles),
            groups=frozenset(groups),
            attributes={"user_name": user.user_name, "active": user.active, "identity_type": "human"},
        )
