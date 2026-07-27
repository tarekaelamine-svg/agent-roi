from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatchcase
import threading
from types import MappingProxyType
from typing import Any, Iterable, Mapping, Optional, Protocol
import uuid


class AuthenticationError(RuntimeError):
    """Raised when an identity token cannot be authenticated."""


class AuthorizationError(PermissionError):
    """Raised when an authenticated principal lacks a required permission."""


def _clean_set(values: Iterable[str] | None) -> frozenset[str]:
    if values is None:
        return frozenset()
    cleaned: set[str] = set()
    for value in values:
        if not isinstance(value, str) or not value.strip():
            raise ValueError("Identity collections must contain non-empty strings")
        cleaned.add(value.strip())
    return frozenset(cleaned)


@dataclass(frozen=True)
class Principal:
    subject: str
    organization_id: str
    display_name: str = ""
    email: str = ""
    roles: frozenset[str] = field(default_factory=frozenset)
    groups: frozenset[str] = field(default_factory=frozenset)
    attributes: Mapping[str, Any] = field(default_factory=dict)
    token_id: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.subject, str) or not self.subject.strip():
            raise ValueError("subject must be a non-empty string")
        if not isinstance(self.organization_id, str) or not self.organization_id.strip():
            raise ValueError("organization_id must be a non-empty string")
        object.__setattr__(self, "subject", self.subject.strip())
        object.__setattr__(self, "organization_id", self.organization_id.strip())
        object.__setattr__(self, "roles", _clean_set(self.roles))
        object.__setattr__(self, "groups", _clean_set(self.groups))
        object.__setattr__(self, "attributes", MappingProxyType(dict(self.attributes)))

    def to_dict(self) -> dict[str, Any]:
        return {
            "subject": self.subject,
            "organization_id": self.organization_id,
            "display_name": self.display_name,
            "email": self.email,
            "roles": sorted(self.roles),
            "groups": sorted(self.groups),
            "attributes": dict(self.attributes),
            "token_id": self.token_id,
        }


@dataclass(frozen=True)
class RoleDefinition:
    name: str
    permissions: frozenset[str]
    description: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name.strip():
            raise ValueError("Role name must be a non-empty string")
        object.__setattr__(self, "name", self.name.strip())
        object.__setattr__(self, "permissions", _clean_set(self.permissions))


@dataclass(frozen=True)
class RoleBinding:
    role: str
    organization_id: str
    subject: str = ""
    group: str = ""
    environment: str = "*"

    def __post_init__(self) -> None:
        if not self.role.strip() or not self.organization_id.strip():
            raise ValueError("role and organization_id are required")
        if bool(self.subject.strip()) == bool(self.group.strip()):
            raise ValueError("Exactly one of subject or group must be set")


class Authorizer(Protocol):
    def authorize(
        self,
        principal: Principal,
        action: str,
        resource: str,
        *,
        context: Optional[Mapping[str, Any]] = None,
    ) -> bool: ...


class RBACAuthorizer:
    """Role-based authorization with organization and environment scoping.

    Permission entries support shell-style wildcards. For example,
    ``tool.execute:*`` grants execution of all tools while
    ``tool.execute:invoice_lookup`` grants one tool.
    """

    def __init__(
        self,
        roles: Iterable[RoleDefinition] = (),
        bindings: Iterable[RoleBinding] = (),
        *,
        default_deny: bool = True,
    ) -> None:
        self._roles = {role.name: role for role in roles}
        self._bindings = tuple(bindings)
        self.default_deny = bool(default_deny)
        for binding in self._bindings:
            if binding.role not in self._roles:
                raise ValueError(f"Binding references unknown role: {binding.role}")

    @classmethod
    def enterprise_defaults(cls) -> "RBACAuthorizer":
        roles = [
            RoleDefinition("platform_admin", frozenset({"*"})),
            RoleDefinition(
                "policy_admin",
                frozenset({"policy.*", "agent.read", "audit.read", "approval.read"}),
            ),
            RoleDefinition(
                "agent_owner",
                frozenset({"agent.read", "agent.execute", "tool.execute:*", "roi.*"}),
            ),
            RoleDefinition(
                "approver",
                frozenset({"approval.read", "approval.decide", "audit.read"}),
            ),
            RoleDefinition("auditor", frozenset({"audit.read", "policy.read", "roi.read"})),
            RoleDefinition("finance_reviewer", frozenset({"roi.read", "roi.validate"})),
        ]
        return cls(roles=roles)

    def with_bindings(self, bindings: Iterable[RoleBinding]) -> "RBACAuthorizer":
        return RBACAuthorizer(self._roles.values(), bindings, default_deny=self.default_deny)

    def effective_roles(
        self, principal: Principal, *, environment: str = "*"
    ) -> frozenset[str]:
        effective = set(principal.roles)
        for binding in self._bindings:
            if binding.organization_id != principal.organization_id:
                continue
            if binding.environment not in {"*", environment}:
                continue
            if binding.subject and binding.subject == principal.subject:
                effective.add(binding.role)
            if binding.group and binding.group in principal.groups:
                effective.add(binding.role)
        return frozenset(effective)

    def permissions_for(
        self, principal: Principal, *, environment: str = "*"
    ) -> frozenset[str]:
        permissions: set[str] = set()
        for role_name in self.effective_roles(principal, environment=environment):
            role = self._roles.get(role_name)
            if role is not None:
                permissions.update(role.permissions)
        return frozenset(permissions)

    def authorize(
        self,
        principal: Principal,
        action: str,
        resource: str,
        *,
        context: Optional[Mapping[str, Any]] = None,
    ) -> bool:
        if not isinstance(principal, Principal):
            return False
        environment = str((context or {}).get("environment", "*"))
        requested = f"{action}:{resource}" if resource else action
        candidates = {action, requested}
        for permission in self.permissions_for(principal, environment=environment):
            if permission == "*":
                return True
            if any(fnmatchcase(candidate, permission) for candidate in candidates):
                return True
        return not self.default_deny

    def require(
        self,
        principal: Principal,
        action: str,
        resource: str = "",
        *,
        context: Optional[Mapping[str, Any]] = None,
    ) -> None:
        if not self.authorize(principal, action, resource, context=context):
            raise AuthorizationError(
                f"Principal '{principal.subject}' is not authorized for {action} on {resource or '*'}"
            )


@dataclass(frozen=True)
class SCIMUser:
    id: str
    user_name: str
    active: bool = True
    display_name: str = ""
    emails: tuple[str, ...] = ()
    external_id: str = ""
    attributes: Mapping[str, Any] = field(default_factory=dict)

    def to_scim(self) -> dict[str, Any]:
        return {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "id": self.id,
            "externalId": self.external_id or None,
            "userName": self.user_name,
            "active": self.active,
            "displayName": self.display_name,
            "emails": [{"value": email, "primary": index == 0} for index, email in enumerate(self.emails)],
            **dict(self.attributes),
        }


@dataclass(frozen=True)
class SCIMGroup:
    id: str
    display_name: str
    members: frozenset[str] = field(default_factory=frozenset)
    external_id: str = ""

    def to_scim(self) -> dict[str, Any]:
        return {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "id": self.id,
            "externalId": self.external_id or None,
            "displayName": self.display_name,
            "members": [{"value": member} for member in sorted(self.members)],
        }


class SCIMDirectory:
    """Thread-safe SCIM 2.0-compatible identity directory primitive."""

    def __init__(self) -> None:
        self._users: dict[str, SCIMUser] = {}
        self._groups: dict[str, SCIMGroup] = {}
        self._lock = threading.RLock()

    def create_user(self, payload: Mapping[str, Any]) -> SCIMUser:
        user_name = str(payload.get("userName", "")).strip()
        if not user_name:
            raise ValueError("SCIM userName is required")
        emails_raw = payload.get("emails", [])
        emails: list[str] = []
        if isinstance(emails_raw, list):
            for item in emails_raw:
                value = item.get("value") if isinstance(item, Mapping) else item
                if isinstance(value, str) and value.strip():
                    emails.append(value.strip())
        core_fields = {"schemas", "id", "externalId", "userName", "active", "displayName", "emails"}
        user = SCIMUser(
            id=str(payload.get("id") or uuid.uuid4()),
            user_name=user_name,
            active=bool(payload.get("active", True)),
            display_name=str(payload.get("displayName", "")),
            emails=tuple(emails),
            external_id=str(payload.get("externalId", "") or ""),
            attributes={key: value for key, value in payload.items() if key not in core_fields},
        )
        with self._lock:
            if any(existing.user_name == user.user_name for existing in self._users.values()):
                raise ValueError(f"SCIM userName already exists: {user.user_name}")
            self._users[user.id] = user
        return user

    def replace_user(self, user_id: str, payload: Mapping[str, Any]) -> SCIMUser:
        merged = dict(payload)
        merged["id"] = user_id
        with self._lock:
            if user_id not in self._users:
                raise KeyError(user_id)
            previous = self._users.pop(user_id)
            try:
                return self.create_user(merged)
            except Exception:
                self._users[user_id] = previous
                raise

    def get_user(self, user_id: str) -> SCIMUser:
        with self._lock:
            try:
                return self._users[user_id]
            except KeyError as exc:
                raise KeyError(f"SCIM user not found: {user_id}") from exc

    def list_users(
        self, *, limit: Optional[int] = None, offset: int = 0
    ) -> tuple[SCIMUser, ...]:
        if offset < 0:
            raise ValueError("offset must be >= 0")
        if limit is not None and limit < 1:
            raise ValueError("limit must be >= 1")
        with self._lock:
            users = tuple(sorted(self._users.values(), key=lambda item: item.user_name))
        stop = None if limit is None else offset + min(int(limit), 500)
        return users[offset:stop]

    def count_users(self) -> int:
        with self._lock:
            return len(self._users)

    def delete_user(self, user_id: str) -> None:
        with self._lock:
            if user_id not in self._users:
                raise KeyError(user_id)
            del self._users[user_id]
            for group_id, group in list(self._groups.items()):
                if user_id in group.members:
                    self._groups[group_id] = SCIMGroup(
                        id=group.id,
                        display_name=group.display_name,
                        members=frozenset(group.members - {user_id}),
                        external_id=group.external_id,
                    )

    def create_group(self, payload: Mapping[str, Any]) -> SCIMGroup:
        display_name = str(payload.get("displayName", "")).strip()
        if not display_name:
            raise ValueError("SCIM group displayName is required")
        members_raw = payload.get("members", [])
        members: set[str] = set()
        if isinstance(members_raw, list):
            for item in members_raw:
                value = item.get("value") if isinstance(item, Mapping) else item
                if isinstance(value, str) and value.strip():
                    members.add(value.strip())
        with self._lock:
            unknown = members - self._users.keys()
            if unknown:
                raise ValueError(f"SCIM group references unknown users: {sorted(unknown)}")
            group = SCIMGroup(
                id=str(payload.get("id") or uuid.uuid4()),
                display_name=display_name,
                members=frozenset(members),
                external_id=str(payload.get("externalId", "") or ""),
            )
            if any(existing.display_name == group.display_name for existing in self._groups.values()):
                raise ValueError(f"SCIM group already exists: {group.display_name}")
            self._groups[group.id] = group
            return group

    def replace_group(self, group_id: str, payload: Mapping[str, Any]) -> SCIMGroup:
        merged = dict(payload)
        merged["id"] = group_id
        with self._lock:
            if group_id not in self._groups:
                raise KeyError(group_id)
            previous = self._groups.pop(group_id)
            try:
                return self.create_group(merged)
            except Exception:
                self._groups[group_id] = previous
                raise

    def get_group(self, group_id: str) -> SCIMGroup:
        with self._lock:
            try:
                return self._groups[group_id]
            except KeyError as exc:
                raise KeyError(f"SCIM group not found: {group_id}") from exc

    def list_groups(
        self, *, limit: Optional[int] = None, offset: int = 0
    ) -> tuple[SCIMGroup, ...]:
        if offset < 0:
            raise ValueError("offset must be >= 0")
        if limit is not None and limit < 1:
            raise ValueError("limit must be >= 1")
        with self._lock:
            groups = tuple(sorted(self._groups.values(), key=lambda item: item.display_name))
        stop = None if limit is None else offset + min(int(limit), 500)
        return groups[offset:stop]

    def count_groups(self) -> int:
        with self._lock:
            return len(self._groups)

    def delete_group(self, group_id: str) -> None:
        with self._lock:
            if group_id not in self._groups:
                raise KeyError(group_id)
            del self._groups[group_id]

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
            for group in self.list_groups()
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
            attributes={"user_name": user.user_name, "active": user.active},
        )


@dataclass(frozen=True)
class OIDCConfig:
    issuer: str
    audience: str
    organization_claim: str = "org_id"
    roles_claim: str = "roles"
    groups_claim: str = "groups"
    subject_claim: str = "sub"
    algorithms: tuple[str, ...] = ("RS256",)
    jwks_url: str = ""
    leeway_seconds: int = 30
    required_claims: tuple[str, ...] = ("exp", "iat", "sub")

    def __post_init__(self) -> None:
        issuer = str(self.issuer).strip().rstrip("/")
        audience = str(self.audience).strip()
        if not issuer or not audience:
            raise ValueError("OIDC issuer and audience are required")
        if not issuer.lower().startswith("https://"):
            raise ValueError("OIDC issuer must use HTTPS")
        algorithms = tuple(str(value).strip() for value in self.algorithms if str(value).strip())
        if not algorithms or any(value.lower() == "none" for value in algorithms):
            raise ValueError("OIDC algorithms must contain signed JWT algorithms")
        if isinstance(self.leeway_seconds, bool) or int(self.leeway_seconds) < 0:
            raise ValueError("OIDC leeway_seconds must be a nonnegative integer")
        jwks_url = str(self.jwks_url).strip()
        if jwks_url and not jwks_url.lower().startswith("https://"):
            raise ValueError("OIDC jwks_url must use HTTPS")
        object.__setattr__(self, "issuer", issuer)
        object.__setattr__(self, "audience", audience)
        object.__setattr__(self, "algorithms", algorithms)
        object.__setattr__(self, "leeway_seconds", int(self.leeway_seconds))
        object.__setattr__(self, "jwks_url", jwks_url)


class OIDCVerifier:
    """OIDC JWT verifier with JWKS support through optional PyJWT.

    ``verification_key`` is useful for private-key deployments and deterministic
    tests. Without it, PyJWT's ``PyJWKClient`` retrieves and caches the issuer's
    JWKS endpoint.
    """

    def __init__(
        self,
        config: OIDCConfig,
        *,
        verification_key: Any = None,
        role_mapping: Optional[Mapping[str, Iterable[str]]] = None,
    ) -> None:
        self.config = config
        self.verification_key = verification_key
        self.role_mapping = {key: tuple(values) for key, values in (role_mapping or {}).items()}
        self._jwk_client: Any = None
        self._discovered_jwks_url = ""

    def _jwt_module(self) -> Any:
        try:
            import jwt  # type: ignore
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise RuntimeError(
                "OIDC verification requires PyJWT. Install agent-roi[identity]."
            ) from exc
        return jwt

    def _jwks_url(self) -> str:
        if self.config.jwks_url:
            return self.config.jwks_url
        if self._discovered_jwks_url:
            return self._discovered_jwks_url
        import json
        from urllib import request as urlrequest

        discovery_url = self.config.issuer + "/.well-known/openid-configuration"
        try:
            with urlrequest.urlopen(discovery_url, timeout=10.0) as response:
                document = json.loads(response.read())
        except Exception as exc:
            raise AuthenticationError("OIDC discovery failed") from exc
        jwks_url = str(document.get("jwks_uri", "")).strip() if isinstance(document, Mapping) else ""
        if not jwks_url.lower().startswith("https://"):
            raise AuthenticationError("OIDC discovery did not return a secure jwks_uri")
        self._discovered_jwks_url = jwks_url
        return jwks_url

    def _key_for(self, token: str) -> Any:
        if self.verification_key is not None:
            return self.verification_key
        jwt = self._jwt_module()
        if self._jwk_client is None:
            self._jwk_client = jwt.PyJWKClient(self._jwks_url())
        return self._jwk_client.get_signing_key_from_jwt(token).key

    def verify(self, token: str) -> Principal:
        if not isinstance(token, str) or not token.strip():
            raise AuthenticationError("Bearer token is required")
        jwt = self._jwt_module()
        try:
            claims = jwt.decode(
                token.strip(),
                self._key_for(token.strip()),
                algorithms=list(self.config.algorithms),
                audience=self.config.audience,
                issuer=self.config.issuer,
                leeway=self.config.leeway_seconds,
                options={"require": list(self.config.required_claims)},
            )
        except Exception as exc:
            raise AuthenticationError("OIDC token validation failed") from exc

        subject = str(claims.get(self.config.subject_claim, "")).strip()
        organization_id = str(claims.get(self.config.organization_claim, "")).strip()
        if not subject or not organization_id:
            raise AuthenticationError("OIDC token is missing subject or organization claim")

        roles_raw = claims.get(self.config.roles_claim, [])
        groups_raw = claims.get(self.config.groups_claim, [])
        if isinstance(roles_raw, str):
            roles_raw = [roles_raw]
        if isinstance(groups_raw, str):
            groups_raw = [groups_raw]
        roles = set(str(value) for value in roles_raw if str(value).strip())
        groups = set(str(value) for value in groups_raw if str(value).strip())
        for group in groups:
            roles.update(self.role_mapping.get(group, ()))

        return Principal(
            subject=subject,
            organization_id=organization_id,
            display_name=str(claims.get("name", "")),
            email=str(claims.get("email", "")),
            roles=frozenset(roles),
            groups=frozenset(groups),
            attributes={
                key: value
                for key, value in claims.items()
                if key not in {self.config.roles_claim, self.config.groups_claim}
            },
            token_id=str(claims.get("jti", "")),
        )

    def verify_authorization_header(self, header: str) -> Principal:
        scheme, _, token = str(header or "").partition(" ")
        if scheme.lower() != "bearer" or not token.strip():
            raise AuthenticationError("Authorization header must use Bearer authentication")
        return self.verify(token)

class SqliteIdentityStore:
    """Durable SCIM directory and RBAC configuration for one control-plane node."""

    def __init__(self, path: str | "Path") -> None:
        from pathlib import Path
        import sqlite3

        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._sqlite3 = sqlite3
        self._lock = threading.RLock()
        self._initialize()

    def _connect(self):
        conn = self._sqlite3.connect(self.path, timeout=30.0)
        conn.row_factory = self._sqlite3.Row
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
                CREATE TABLE IF NOT EXISTS scim_users (
                    id TEXT PRIMARY KEY,
                    user_name TEXT NOT NULL UNIQUE,
                    active INTEGER NOT NULL,
                    display_name TEXT NOT NULL,
                    emails_json TEXT NOT NULL,
                    external_id TEXT NOT NULL,
                    attributes_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS scim_groups (
                    id TEXT PRIMARY KEY,
                    display_name TEXT NOT NULL UNIQUE,
                    external_id TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS scim_group_members (
                    group_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    PRIMARY KEY (group_id, user_id),
                    FOREIGN KEY (group_id) REFERENCES scim_groups(id) ON DELETE CASCADE,
                    FOREIGN KEY (user_id) REFERENCES scim_users(id) ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS rbac_roles (
                    name TEXT PRIMARY KEY,
                    permissions_json TEXT NOT NULL,
                    description TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS rbac_bindings (
                    binding_id TEXT PRIMARY KEY,
                    role TEXT NOT NULL,
                    organization_id TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    group_name TEXT NOT NULL,
                    environment TEXT NOT NULL,
                    FOREIGN KEY (role) REFERENCES rbac_roles(name) ON DELETE CASCADE
                );
                """
            )

    def create_user(self, payload: Mapping[str, Any]) -> SCIMUser:
        import json

        user_name = str(payload.get("userName", "")).strip()
        if not user_name:
            raise ValueError("SCIM userName is required")
        emails_raw = payload.get("emails", [])
        emails: list[str] = []
        if isinstance(emails_raw, list):
            for item in emails_raw:
                value = item.get("value") if isinstance(item, Mapping) else item
                if isinstance(value, str) and value.strip():
                    emails.append(value.strip())
        core_fields = {"schemas", "id", "externalId", "userName", "active", "displayName", "emails"}
        user = SCIMUser(
            id=str(payload.get("id") or uuid.uuid4()),
            user_name=user_name,
            active=bool(payload.get("active", True)),
            display_name=str(payload.get("displayName", "")),
            emails=tuple(emails),
            external_id=str(payload.get("externalId", "") or ""),
            attributes={key: value for key, value in payload.items() if key not in core_fields},
        )
        with self._lock, self._connection() as conn:
            try:
                conn.execute(
                    "INSERT INTO scim_users VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        user.id,
                        user.user_name,
                        int(user.active),
                        user.display_name,
                        json.dumps(list(user.emails), sort_keys=True),
                        user.external_id,
                        json.dumps(dict(user.attributes), sort_keys=True),
                    ),
                )
            except self._sqlite3.IntegrityError as exc:
                raise ValueError(f"SCIM userName already exists: {user.user_name}") from exc
        return user

    def _row_to_user(self, row: Any) -> SCIMUser:
        import json

        return SCIMUser(
            id=row["id"],
            user_name=row["user_name"],
            active=bool(row["active"]),
            display_name=row["display_name"],
            emails=tuple(json.loads(row["emails_json"])),
            external_id=row["external_id"],
            attributes=json.loads(row["attributes_json"]),
        )

    def get_user(self, user_id: str) -> SCIMUser:
        with self._connection() as conn:
            row = conn.execute("SELECT * FROM scim_users WHERE id=?", (user_id,)).fetchone()
        if row is None:
            raise KeyError(f"SCIM user not found: {user_id}")
        return self._row_to_user(row)

    def list_users(
        self, *, limit: Optional[int] = None, offset: int = 0
    ) -> tuple[SCIMUser, ...]:
        if offset < 0:
            raise ValueError("offset must be >= 0")
        if limit is not None and limit < 1:
            raise ValueError("limit must be >= 1")
        query = "SELECT * FROM scim_users ORDER BY user_name"
        params: tuple[Any, ...] = ()
        if limit is not None:
            query += " LIMIT ? OFFSET ?"
            params = (min(int(limit), 500), int(offset))
        elif offset:
            query += " LIMIT -1 OFFSET ?"
            params = (int(offset),)
        with self._connection() as conn:
            rows = conn.execute(query, params).fetchall()
        return tuple(self._row_to_user(row) for row in rows)

    def count_users(self) -> int:
        with self._connection() as conn:
            row = conn.execute("SELECT COUNT(*) AS count FROM scim_users").fetchone()
        return int(row["count"])

    def replace_user(self, user_id: str, payload: Mapping[str, Any]) -> SCIMUser:
        import json

        if not self.get_user(user_id):  # pragma: no cover - get raises
            raise KeyError(user_id)
        user_name = str(payload.get("userName", "")).strip()
        if not user_name:
            raise ValueError("SCIM userName is required")
        emails = tuple(
            str(item.get("value") if isinstance(item, Mapping) else item).strip()
            for item in payload.get("emails", [])
            if str(item.get("value") if isinstance(item, Mapping) else item).strip()
        )
        core_fields = {"schemas", "id", "externalId", "userName", "active", "displayName", "emails"}
        user = SCIMUser(
            id=user_id,
            user_name=user_name,
            active=bool(payload.get("active", True)),
            display_name=str(payload.get("displayName", "")),
            emails=emails,
            external_id=str(payload.get("externalId", "") or ""),
            attributes={key: value for key, value in payload.items() if key not in core_fields},
        )
        with self._lock, self._connection() as conn:
            conn.execute(
                """UPDATE scim_users SET user_name=?, active=?, display_name=?,
                   emails_json=?, external_id=?, attributes_json=? WHERE id=?""",
                (
                    user.user_name,
                    int(user.active),
                    user.display_name,
                    json.dumps(list(user.emails), sort_keys=True),
                    user.external_id,
                    json.dumps(dict(user.attributes), sort_keys=True),
                    user_id,
                ),
            )
        return user

    def delete_user(self, user_id: str) -> None:
        with self._lock, self._connection() as conn:
            cursor = conn.execute("DELETE FROM scim_users WHERE id=?", (user_id,))
            if cursor.rowcount != 1:
                raise KeyError(user_id)

    def create_group(self, payload: Mapping[str, Any]) -> SCIMGroup:
        display_name = str(payload.get("displayName", "")).strip()
        if not display_name:
            raise ValueError("SCIM group displayName is required")
        members = {
            str(item.get("value") if isinstance(item, Mapping) else item).strip()
            for item in payload.get("members", [])
            if str(item.get("value") if isinstance(item, Mapping) else item).strip()
        }
        known = {user.id for user in self.list_users()}
        unknown = members - known
        if unknown:
            raise ValueError(f"SCIM group references unknown users: {sorted(unknown)}")
        group = SCIMGroup(
            id=str(payload.get("id") or uuid.uuid4()),
            display_name=display_name,
            members=frozenset(members),
            external_id=str(payload.get("externalId", "") or ""),
        )
        with self._lock, self._connection() as conn:
            try:
                conn.execute(
                    "INSERT INTO scim_groups VALUES (?, ?, ?)",
                    (group.id, group.display_name, group.external_id),
                )
                conn.executemany(
                    "INSERT INTO scim_group_members VALUES (?, ?)",
                    [(group.id, user_id) for user_id in sorted(group.members)],
                )
            except self._sqlite3.IntegrityError as exc:
                raise ValueError(f"SCIM group already exists: {display_name}") from exc
        return group

    def get_group(self, group_id: str) -> SCIMGroup:
        with self._connection() as conn:
            row = conn.execute("SELECT * FROM scim_groups WHERE id=?", (group_id,)).fetchone()
            members = conn.execute(
                "SELECT user_id FROM scim_group_members WHERE group_id=? ORDER BY user_id",
                (group_id,),
            ).fetchall()
        if row is None:
            raise KeyError(f"SCIM group not found: {group_id}")
        return SCIMGroup(
            id=row["id"],
            display_name=row["display_name"],
            members=frozenset(member["user_id"] for member in members),
            external_id=row["external_id"],
        )

    def list_groups(
        self, *, limit: Optional[int] = None, offset: int = 0
    ) -> tuple[SCIMGroup, ...]:
        if offset < 0:
            raise ValueError("offset must be >= 0")
        if limit is not None and limit < 1:
            raise ValueError("limit must be >= 1")
        query = "SELECT id FROM scim_groups ORDER BY display_name"
        params: tuple[Any, ...] = ()
        if limit is not None:
            query += " LIMIT ? OFFSET ?"
            params = (min(int(limit), 500), int(offset))
        elif offset:
            query += " LIMIT -1 OFFSET ?"
            params = (int(offset),)
        with self._connection() as conn:
            ids = [row["id"] for row in conn.execute(query, params).fetchall()]
        return tuple(self.get_group(group_id) for group_id in ids)

    def count_groups(self) -> int:
        with self._connection() as conn:
            row = conn.execute("SELECT COUNT(*) AS count FROM scim_groups").fetchone()
        return int(row["count"])

    def replace_group(self, group_id: str, payload: Mapping[str, Any]) -> SCIMGroup:
        self.get_group(group_id)
        display_name = str(payload.get("displayName", "")).strip()
        if not display_name:
            raise ValueError("SCIM group displayName is required")
        members = {
            str(item.get("value") if isinstance(item, Mapping) else item).strip()
            for item in payload.get("members", [])
            if str(item.get("value") if isinstance(item, Mapping) else item).strip()
        }
        known = {user.id for user in self.list_users()}
        if members - known:
            raise ValueError("SCIM group references unknown users")
        with self._lock, self._connection() as conn:
            conn.execute(
                "UPDATE scim_groups SET display_name=?, external_id=? WHERE id=?",
                (display_name, str(payload.get("externalId", "") or ""), group_id),
            )
            conn.execute("DELETE FROM scim_group_members WHERE group_id=?", (group_id,))
            conn.executemany(
                "INSERT INTO scim_group_members VALUES (?, ?)",
                [(group_id, user_id) for user_id in sorted(members)],
            )
        return self.get_group(group_id)

    def delete_group(self, group_id: str) -> None:
        with self._lock, self._connection() as conn:
            cursor = conn.execute("DELETE FROM scim_groups WHERE id=?", (group_id,))
            if cursor.rowcount != 1:
                raise KeyError(group_id)

    def save_role(self, role: RoleDefinition) -> None:
        import json

        with self._lock, self._connection() as conn:
            conn.execute(
                """INSERT INTO rbac_roles VALUES (?, ?, ?)
                   ON CONFLICT(name) DO UPDATE SET permissions_json=excluded.permissions_json,
                   description=excluded.description""",
                (role.name, json.dumps(sorted(role.permissions)), role.description),
            )

    def save_binding(self, binding: RoleBinding) -> str:
        binding_id = str(uuid.uuid4())
        with self._lock, self._connection() as conn:
            try:
                conn.execute(
                    "INSERT INTO rbac_bindings VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        binding_id,
                        binding.role,
                        binding.organization_id,
                        binding.subject,
                        binding.group,
                        binding.environment,
                    ),
                )
            except self._sqlite3.IntegrityError as exc:
                raise ValueError(f"Unknown RBAC role: {binding.role}") from exc
        return binding_id

    def list_roles(self) -> tuple[RoleDefinition, ...]:
        import json

        with self._connection() as conn:
            rows = conn.execute("SELECT * FROM rbac_roles ORDER BY name").fetchall()
        return tuple(
            RoleDefinition(
                row["name"],
                frozenset(json.loads(row["permissions_json"])),
                row["description"],
            )
            for row in rows
        )

    def delete_role(self, role_name: str) -> None:
        with self._lock, self._connection() as conn:
            cursor = conn.execute("DELETE FROM rbac_roles WHERE name=?", (role_name,))
            if cursor.rowcount != 1:
                raise KeyError(role_name)

    def list_bindings(self) -> tuple[tuple[str, RoleBinding], ...]:
        with self._connection() as conn:
            rows = conn.execute("SELECT * FROM rbac_bindings ORDER BY binding_id").fetchall()
        return tuple(
            (
                row["binding_id"],
                RoleBinding(
                    row["role"],
                    row["organization_id"],
                    subject=row["subject"],
                    group=row["group_name"],
                    environment=row["environment"],
                ),
            )
            for row in rows
        )

    def delete_binding(self, binding_id: str) -> None:
        with self._lock, self._connection() as conn:
            cursor = conn.execute(
                "DELETE FROM rbac_bindings WHERE binding_id=?", (binding_id,)
            )
            if cursor.rowcount != 1:
                raise KeyError(binding_id)

    def authorizer(self) -> RBACAuthorizer:
        import json

        with self._connection() as conn:
            role_rows = conn.execute("SELECT * FROM rbac_roles ORDER BY name").fetchall()
            binding_rows = conn.execute("SELECT * FROM rbac_bindings ORDER BY binding_id").fetchall()
        roles = [
            RoleDefinition(row["name"], frozenset(json.loads(row["permissions_json"])), row["description"])
            for row in role_rows
        ]
        bindings = [
            RoleBinding(
                row["role"],
                row["organization_id"],
                subject=row["subject"],
                group=row["group_name"],
                environment=row["environment"],
            )
            for row in binding_rows
        ]
        return RBACAuthorizer(roles, bindings)

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
        groups = {group.display_name for group in self.list_groups() if user_id in group.members}
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
            attributes={"user_name": user.user_name, "active": user.active},
        )


class DynamicRBACAuthorizer:
    """Reload RBAC roles and bindings from a durable store for each decision.

    This avoids stale authorization decisions after SCIM/RBAC administration
    changes without requiring control-plane process restarts.
    """

    def __init__(self, store: SqliteIdentityStore) -> None:
        self.store = store

    def authorize(
        self,
        principal: Principal,
        action: str,
        resource: str,
        *,
        context: Optional[Mapping[str, Any]] = None,
    ) -> bool:
        return self.store.authorizer().authorize(
            principal, action, resource, context=context
        )

    def require(
        self,
        principal: Principal,
        action: str,
        resource: str = "",
        *,
        context: Optional[Mapping[str, Any]] = None,
    ) -> None:
        self.store.authorizer().require(
            principal, action, resource, context=context
        )
