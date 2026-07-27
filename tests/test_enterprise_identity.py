from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from agent_roi.enterprise.identity import (
    AuthenticationError,
    AuthorizationError,
    OIDCConfig,
    OIDCVerifier,
    Principal,
    RBACAuthorizer,
    RoleBinding,
    RoleDefinition,
    SCIMDirectory,
)


def test_rbac_scopes_subject_group_and_environment() -> None:
    roles = [
        RoleDefinition("reader", frozenset({"audit.read:*"})),
        RoleDefinition("executor", frozenset({"tool.execute:lookup_*"})),
    ]
    bindings = [
        RoleBinding("reader", "acme", group="auditors"),
        RoleBinding("executor", "acme", subject="user-1", environment="prod"),
    ]
    auth = RBACAuthorizer(roles, bindings)
    principal = Principal(
        subject="user-1",
        organization_id="acme",
        groups=frozenset({"auditors"}),
    )
    assert auth.authorize(principal, "audit.read", "chain-1")
    assert auth.authorize(
        principal, "tool.execute", "lookup_invoice", context={"environment": "prod"}
    )
    assert not auth.authorize(
        principal, "tool.execute", "lookup_invoice", context={"environment": "dev"}
    )
    assert not auth.authorize(principal, "tool.execute", "delete_invoice")


def test_rbac_require_raises_with_denial() -> None:
    auth = RBACAuthorizer([RoleDefinition("reader", frozenset({"audit.read"}))])
    principal = Principal("user-1", "acme", roles=frozenset({"reader"}))
    auth.require(principal, "audit.read")
    with pytest.raises(AuthorizationError):
        auth.require(principal, "policy.publish", "finance")


def test_scim_directory_creates_users_groups_and_principal() -> None:
    directory = SCIMDirectory()
    user = directory.create_user(
        {
            "userName": "approver@example.com",
            "displayName": "Approver",
            "emails": [{"value": "approver@example.com"}],
        }
    )
    group = directory.create_group(
        {"displayName": "Finance Approvers", "members": [{"value": user.id}]}
    )
    principal = directory.principal_for(
        user.id,
        organization_id="acme",
        role_mapping={"Finance Approvers": ["approver"]},
    )
    assert principal.email == "approver@example.com"
    assert principal.groups == frozenset({"Finance Approvers"})
    assert principal.roles == frozenset({"approver"})
    directory.delete_user(user.id)
    assert directory.get_group(group.id).members == frozenset()


def test_scim_rejects_unknown_group_members() -> None:
    directory = SCIMDirectory()
    with pytest.raises(ValueError, match="unknown users"):
        directory.create_group(
            {"displayName": "Bad", "members": [{"value": "missing"}]}
        )


def test_oidc_verifier_validates_hs256_token() -> None:
    jwt = pytest.importorskip("jwt")
    now = datetime.now(timezone.utc)
    claims = {
        "iss": "https://issuer.example",
        "aud": "agent-roi",
        "sub": "user-1",
        "org_id": "acme",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=5)).timestamp()),
        "roles": ["agent_owner"],
        "groups": ["Finance"],
        "email": "user@example.com",
    }
    token = jwt.encode(claims, "secret-key-with-at-least-32-bytes!!", algorithm="HS256")
    verifier = OIDCVerifier(
        OIDCConfig(
            issuer="https://issuer.example",
            audience="agent-roi",
            algorithms=("HS256",),
        ),
        verification_key="secret-key-with-at-least-32-bytes!!",
        role_mapping={"Finance": ["finance_reviewer"]},
    )
    principal = verifier.verify(token)
    assert principal.subject == "user-1"
    assert principal.organization_id == "acme"
    assert principal.roles == frozenset({"agent_owner", "finance_reviewer"})


def test_oidc_rejects_wrong_audience() -> None:
    jwt = pytest.importorskip("jwt")
    now = datetime.now(timezone.utc)
    token = jwt.encode(
        {
            "iss": "https://issuer.example",
            "aud": "wrong",
            "sub": "user-1",
            "org_id": "acme",
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(minutes=5)).timestamp()),
        },
        "secret-key-with-at-least-32-bytes!!",
        algorithm="HS256",
    )
    verifier = OIDCVerifier(
        OIDCConfig(
            issuer="https://issuer.example",
            audience="agent-roi",
            algorithms=("HS256",),
        ),
        verification_key="secret-key-with-at-least-32-bytes!!",
    )
    with pytest.raises(AuthenticationError):
        verifier.verify(token)


def test_sqlite_identity_store_persists_scim_and_rbac(tmp_path) -> None:
    from agent_roi.enterprise.identity import SqliteIdentityStore

    store = SqliteIdentityStore(tmp_path / "identity.sqlite3")
    user = store.create_user(
        {"userName": "owner@example.com", "emails": [{"value": "owner@example.com"}]}
    )
    store.create_group(
        {"displayName": "Owners", "members": [{"value": user.id}]}
    )
    store.save_role(RoleDefinition("owner", frozenset({"tool.execute:*"})))
    store.save_binding(RoleBinding("owner", "acme", group="Owners", environment="prod"))

    reopened = SqliteIdentityStore(tmp_path / "identity.sqlite3")
    principal = reopened.principal_for(user.id, organization_id="acme")
    assert principal.groups == frozenset({"Owners"})
    assert reopened.authorizer().authorize(
        principal, "tool.execute", "lookup", context={"environment": "prod"}
    )


def test_dynamic_rbac_reloads_bindings_and_inactive_users_are_rejected(tmp_path) -> None:
    from agent_roi.enterprise.identity import DynamicRBACAuthorizer, SqliteIdentityStore

    store = SqliteIdentityStore(tmp_path / "dynamic.sqlite3")
    user = store.create_user(
        {
            "userName": "live@example.com",
            "active": True,
            "urn:example:department": {"name": "Finance"},
        }
    )
    store.save_role(RoleDefinition("executor", frozenset({"tool.execute:lookup"})))
    principal = store.principal_for(user.id, organization_id="acme")
    dynamic = DynamicRBACAuthorizer(store)
    assert not dynamic.authorize(principal, "tool.execute", "lookup")

    store.save_binding(RoleBinding("executor", "acme", subject=user.id))
    assert dynamic.authorize(principal, "tool.execute", "lookup")
    assert store.get_user(user.id).attributes["urn:example:department"]["name"] == "Finance"

    store.replace_user(user.id, {"userName": "live@example.com", "active": False})
    with pytest.raises(AuthenticationError, match="inactive"):
        store.principal_for(user.id, organization_id="acme")


def test_sqlite_identity_role_and_binding_administration(tmp_path) -> None:
    from agent_roi.enterprise.identity import SqliteIdentityStore

    store = SqliteIdentityStore(tmp_path / "admin.sqlite3")
    store.save_role(RoleDefinition("auditor", frozenset({"audit.read:*"})))
    binding_id = store.save_binding(
        RoleBinding("auditor", "acme", subject="user-1", environment="prod")
    )
    assert store.list_roles()[0].name == "auditor"
    assert store.list_bindings()[0][0] == binding_id
    store.delete_binding(binding_id)
    assert store.list_bindings() == ()
    store.delete_role("auditor")
    assert store.list_roles() == ()
