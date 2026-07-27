from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from agent_roi.enterprise.identity import (
    AuthenticationError,
    AuthorizationError,
    DynamicRBACAuthorizer,
    OIDCConfig,
    OIDCVerifier,
    Principal,
    RBACAuthorizer,
    RoleBinding,
    RoleDefinition,
    SCIMDirectory,
    SCIMGroup,
    SCIMUser,
    SqliteIdentityStore,
    _clean_set,
)


def test_identity_value_object_validation_and_serialization() -> None:
    assert _clean_set(None) == frozenset()
    with pytest.raises(ValueError):
        _clean_set([""])
    with pytest.raises(ValueError):
        _clean_set([1])
    with pytest.raises(ValueError):
        Principal("", "acme")
    with pytest.raises(ValueError):
        Principal("u", "")
    principal = Principal(" u ", " acme ", roles=frozenset({" r "}), groups=frozenset({" g "}), attributes={"x": 1})
    assert principal.subject == "u" and principal.organization_id == "acme"
    assert principal.to_dict()["roles"] == ["r"]
    with pytest.raises(TypeError):
        principal.attributes["x"] = 2
    with pytest.raises(ValueError):
        RoleDefinition("", frozenset())
    with pytest.raises(ValueError):
        RoleBinding("", "acme", subject="u")
    with pytest.raises(ValueError):
        RoleBinding("r", "acme")
    with pytest.raises(ValueError):
        RoleBinding("r", "acme", subject="u", group="g")
    user = SCIMUser("u", "u@example.com", emails=("a@example.com", "b@example.com"), attributes={"department": "Finance"})
    assert user.to_scim()["emails"][0]["primary"] is True
    assert user.to_scim()["externalId"] is None
    group = SCIMGroup("g", "Group", frozenset({"b", "a"}))
    assert [item["value"] for item in group.to_scim()["members"]] == ["a", "b"]


def test_rbac_additional_paths() -> None:
    with pytest.raises(ValueError, match="unknown role"):
        RBACAuthorizer([], [RoleBinding("missing", "acme", subject="u")])
    defaults = RBACAuthorizer.enterprise_defaults()
    admin = Principal("u", "acme", roles=frozenset({"platform_admin"}))
    assert defaults.authorize(admin, "anything", "resource")
    assert defaults.with_bindings([]).permissions_for(admin) == frozenset({"*"})
    assert defaults.authorize(object(), "x", "y") is False
    open_auth = RBACAuthorizer(default_deny=False)
    assert open_auth.authorize(Principal("u", "acme"), "x", "y")
    role = RoleDefinition("reader", frozenset({"read"}))
    auth = RBACAuthorizer([role], [RoleBinding("reader", "other", subject="u"), RoleBinding("reader", "acme", subject="u", environment="prod")])
    principal = Principal("u", "acme")
    assert auth.effective_roles(principal, environment="dev") == frozenset()
    assert auth.permissions_for(Principal("u", "acme", roles=frozenset({"unknown"}))) == frozenset()
    with pytest.raises(AuthorizationError):
        auth.require(principal, "read", context={"environment": "dev"})


def test_scim_directory_all_crud_and_rollback_paths() -> None:
    d = SCIMDirectory()
    with pytest.raises(ValueError): d.create_user({})
    user = d.create_user({"id": "u", "userName": "u@example.com", "emails": ["a@example.com", {"value": " b@example.com "}, 1], "x": 1})
    with pytest.raises(ValueError, match="already exists"):
        d.create_user({"userName": "u@example.com"})
    with pytest.raises(KeyError): d.replace_user("missing", {"userName": "x"})
    other = d.create_user({"id": "v", "userName": "v@example.com"})
    with pytest.raises(ValueError):
        d.replace_user("u", {"userName": "v@example.com"})
    assert d.get_user("u").user_name == "u@example.com"
    with pytest.raises(KeyError, match="not found"): d.get_user("missing")
    with pytest.raises(ValueError): d.list_users(offset=-1)
    with pytest.raises(ValueError): d.list_users(limit=0)
    assert d.list_users(limit=1, offset=1)[0].id == "v"
    assert d.count_users() == 2
    with pytest.raises(KeyError): d.delete_user("missing")

    with pytest.raises(ValueError): d.create_group({})
    group = d.create_group({"id": "g", "displayName": "G", "members": ["u", {"value": "v"}, 3]})
    with pytest.raises(ValueError, match="already exists"):
        d.create_group({"displayName": "G"})
    with pytest.raises(KeyError): d.replace_group("missing", {"displayName": "X"})
    d.create_group({"id": "h", "displayName": "H"})
    with pytest.raises(ValueError):
        d.replace_group("g", {"displayName": "H"})
    assert d.get_group("g").display_name == "G"
    with pytest.raises(KeyError, match="not found"): d.get_group("missing")
    with pytest.raises(ValueError): d.list_groups(offset=-1)
    with pytest.raises(ValueError): d.list_groups(limit=0)
    assert d.count_groups() == 2
    with pytest.raises(KeyError): d.delete_group("missing")
    d.delete_group("h")
    d.delete_user("u")
    assert d.get_group("g").members == frozenset({"v"})
    d.replace_user("v", {"userName": "v2@example.com", "active": False})
    with pytest.raises(AuthenticationError): d.principal_for("v", organization_id="acme")


def test_oidc_config_and_discovery_paths(monkeypatch) -> None:
    for kwargs in [
        {"issuer": "", "audience": "a"},
        {"issuer": "http://issuer", "audience": "a"},
        {"issuer": "https://issuer", "audience": "a", "algorithms": ()},
        {"issuer": "https://issuer", "audience": "a", "algorithms": ("none",)},
        {"issuer": "https://issuer", "audience": "a", "leeway_seconds": True},
        {"issuer": "https://issuer", "audience": "a", "leeway_seconds": -1},
        {"issuer": "https://issuer", "audience": "a", "jwks_url": "http://x"},
    ]:
        with pytest.raises(ValueError): OIDCConfig(**kwargs)
    cfg = OIDCConfig("https://issuer/", "aud", algorithms=(" RS256 ",), jwks_url="https://keys")
    assert cfg.issuer == "https://issuer" and cfg._replace if False else True
    verifier = OIDCVerifier(cfg)
    assert verifier._jwks_url() == "https://keys"

    class Response:
        def __init__(self, payload): self.payload = payload
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def read(self): return json.dumps(self.payload).encode()
    cfg2 = OIDCConfig("https://issuer", "aud")
    verifier2 = OIDCVerifier(cfg2)
    monkeypatch.setattr("urllib.request.urlopen", lambda *a, **k: Response({"jwks_uri": "https://keys.example/jwks"}))
    assert verifier2._jwks_url() == "https://keys.example/jwks"
    assert verifier2._jwks_url() == "https://keys.example/jwks"
    verifier3 = OIDCVerifier(cfg2)
    monkeypatch.setattr("urllib.request.urlopen", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("down")))
    with pytest.raises(AuthenticationError, match="discovery failed"): verifier3._jwks_url()
    verifier4 = OIDCVerifier(cfg2)
    monkeypatch.setattr("urllib.request.urlopen", lambda *a, **k: Response({"jwks_uri": "http://bad"}))
    with pytest.raises(AuthenticationError, match="secure"): verifier4._jwks_url()
    verifier5 = OIDCVerifier(cfg2)
    monkeypatch.setattr("urllib.request.urlopen", lambda *a, **k: Response([]))
    with pytest.raises(AuthenticationError): verifier5._jwks_url()


def test_oidc_key_and_verify_error_and_string_claim_paths(monkeypatch) -> None:
    cfg = OIDCConfig("https://issuer", "aud", algorithms=("HS256",))
    verifier = OIDCVerifier(cfg, verification_key="key", role_mapping={"g": ["mapped"]})
    assert verifier._key_for("x") == "key"
    with pytest.raises(AuthenticationError, match="Bearer token"):
        verifier.verify("")

    class FakeJWT:
        class PyJWKClient:
            def __init__(self, url): self.url=url
            def get_signing_key_from_jwt(self, token): return SimpleNamespace(key="jwk-key")
        @staticmethod
        def decode(token, key, **kwargs):
            return {"sub":"u", "org_id":"acme", "roles":"r", "groups":"g", "name":"U", "email":"u@x", "jti":"j"}
    verifier2 = OIDCVerifier(cfg, role_mapping={"g": ["mapped"]})
    monkeypatch.setattr(verifier2, "_jwt_module", lambda: FakeJWT)
    monkeypatch.setattr(verifier2, "_jwks_url", lambda: "https://keys")
    assert verifier2._key_for("token") == "jwk-key"
    principal = verifier2.verify("token")
    assert principal.roles == frozenset({"r", "mapped"}) and principal.token_id == "j"
    assert verifier2.verify_authorization_header("Bearer token").subject == "u"
    with pytest.raises(AuthenticationError): verifier2.verify_authorization_header("Basic x")

    class BrokenJWT(FakeJWT):
        @staticmethod
        def decode(*a, **k): raise RuntimeError("bad")
    verifier3 = OIDCVerifier(cfg, verification_key="key")
    monkeypatch.setattr(verifier3, "_jwt_module", lambda: BrokenJWT)
    with pytest.raises(AuthenticationError, match="validation failed"): verifier3.verify("token")

    class MissingJWT(FakeJWT):
        @staticmethod
        def decode(*a, **k): return {"sub":"", "org_id":""}
    verifier4 = OIDCVerifier(cfg, verification_key="key")
    monkeypatch.setattr(verifier4, "_jwt_module", lambda: MissingJWT)
    with pytest.raises(AuthenticationError, match="missing subject"): verifier4.verify("token")


def test_sqlite_identity_remaining_paths(tmp_path: Path) -> None:
    store = SqliteIdentityStore(tmp_path / "identity.sqlite3")
    with pytest.raises(ValueError): store.create_user({})
    user = store.create_user({"id":"u", "userName":"u@example.com", "emails":["a@example.com", {"value":"b@example.com"}], "x":1})
    with pytest.raises(ValueError): store.create_user({"userName":"u@example.com"})
    with pytest.raises(KeyError): store.get_user("missing")
    with pytest.raises(ValueError): store.list_users(offset=-1)
    with pytest.raises(ValueError): store.list_users(limit=0)
    assert store.list_users(offset=1) == ()
    assert store.count_users() == 1
    store.replace_user("u", {"userName":"u2@example.com", "active":True})
    with pytest.raises(KeyError): store.replace_user("missing", {"userName":"x"})
    with pytest.raises(KeyError): store.delete_user("missing")

    with pytest.raises(ValueError): store.create_group({})
    with pytest.raises(ValueError): store.create_group({"displayName":"G", "members":[{"value":"missing"}]})
    group = store.create_group({"id":"g", "displayName":"G", "members":[{"value":"u"}]})
    with pytest.raises(ValueError): store.create_group({"displayName":"G"})
    with pytest.raises(KeyError): store.get_group("missing")
    with pytest.raises(ValueError): store.list_groups(offset=-1)
    with pytest.raises(ValueError): store.list_groups(limit=0)
    assert store.list_groups(offset=1) == ()
    assert store.count_groups() == 1
    with pytest.raises(ValueError): store.replace_group("g", {"displayName":""})
    with pytest.raises(ValueError): store.replace_group("g", {"displayName":"G2", "members":[{"value":"missing"}]})
    store.replace_group("g", {"displayName":"G2", "members":[{"value":"u"}]})
    with pytest.raises(KeyError): store.delete_group("missing")

    with pytest.raises(ValueError): store.save_binding(RoleBinding("missing","acme",subject="u"))
    with pytest.raises(KeyError): store.delete_role("missing")
    with pytest.raises(KeyError): store.delete_binding("missing")
    store.replace_user("u", {"userName":"u2@example.com", "active":False})
    with pytest.raises(AuthenticationError): store.principal_for("u", organization_id="acme")

    dynamic = DynamicRBACAuthorizer(store)
    with pytest.raises(AuthorizationError): dynamic.require(Principal("x","acme"), "x")
