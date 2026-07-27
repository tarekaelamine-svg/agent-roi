from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import pytest

from agent_roi.enterprise.control_plane import ControlPlaneError, PolicyBundle, HMACPolicySigner
from agent_roi.enterprise.identity import AuthenticationError, Principal, RoleBinding, RoleDefinition, SCIMGroup, SCIMUser
from agent_roi.enterprise.postgres import PostgresControlPlaneStore, PostgresIdentityStore, _iso, _json_value


@dataclass
class Step:
    contains: str
    rows: list[Any]
    rowcount: int = 0
    error: Exception | None = None


class DB:
    def __init__(self, steps=()):
        self.steps = list(steps)
        self.calls = []
        self.commits = 0
        self.rollbacks = 0

    def connect(self, dsn, **kwargs):
        return Conn(self)

    def done(self):
        assert not self.steps, self.steps


class Conn:
    def __init__(self, db): self.db = db
    def cursor(self): return Cursor(self.db)
    def commit(self): self.db.commits += 1
    def rollback(self): self.db.rollbacks += 1
    def close(self): pass


class Cursor:
    description = None
    def __init__(self, db):
        self.db = db; self.rows=[]; self.rowcount=0
    def execute(self, sql, params=None):
        sql = " ".join(str(sql).split()); params=tuple(params or ())
        self.db.calls.append((sql, params))
        if sql.startswith("CREATE SCHEMA") or sql.startswith("SET search_path"):
            return
        assert self.db.steps, f"Unexpected SQL: {sql}"
        step=self.db.steps.pop(0)
        assert step.contains.lower() in sql.lower(), (step.contains, sql)
        if step.error: raise step.error
        self.rows=list(step.rows); self.rowcount=step.rowcount
        if self.rows and isinstance(self.rows[0], dict):
            self.description=[(k,) for k in self.rows[0]]
    def fetchone(self): return self.rows[0] if self.rows else None
    def fetchall(self): return list(self.rows)
    def close(self): pass


def bundle(version="1"):
    return PolicyBundle.create(
        organization_id="acme", name="p", environment="prod", version=version,
        policy={"guardrails": {"max_steps":1,"max_tool_calls":1,"max_cost_usd":1,"allowed_tools":[]}, "decision_policy":{"min_confidence":.5,"abstain_action":"human_review"}},
        signer=HMACPolicySigner(b"x"*32), created_by="a"
    )


def bundle_row(b):
    return {"organization_id":b.organization_id,"name":b.name,"environment":b.environment,"version":b.version,
            "payload_json":dict(b.policy),"digest":b.digest,"signature":b.signature,"signer_key_id":b.signer_key_id,
            "status":b.status,"created_at_utc":b.created_at_utc,"created_by":b.created_by}


def agent_row(**overrides):
    row={"organization_id":"acme","agent_id":"a","environment":"prod","owner":"o","purpose":"p","status":"production",
         "metadata_json":"{\"x\":1}","registered_at_utc":datetime(2026,1,1,tzinfo=timezone.utc),"last_heartbeat_utc":None,
         "policy_digest":"d","version":"2.0.0","revision":2}
    row.update(overrides); return row


def user_row(**overrides):
    row={"user_id":"u","user_name":"u@example.com","display_name":"User","active":True,"emails_json":"[\"u@example.com\"]",
         "attributes_json":"{\"dept\":\"F\"}","organization_id":"acme","external_id":"e","revision":1}
    row.update(overrides); return row


def group_row(**overrides):
    row={"group_id":"g","display_name":"Approvers","organization_id":"acme","external_id":"eg","revision":1}
    row.update(overrides); return row


def store(db):
    return PostgresControlPlaneStore("dsn", connect_factory=db.connect, auto_migrate=False)


def istore(db):
    return PostgresIdentityStore("dsn", connect_factory=db.connect, auto_migrate=False)


def test_helpers_and_auto_migrate(monkeypatch):
    assert _json_value(None, []) == []
    assert _json_value('{"x":1}', {}) == {"x":1}
    assert _json_value({"x":2}, {}) == {"x":2}
    assert _iso(datetime(2026,1,1,tzinfo=timezone.utc)).startswith("2026")
    assert _iso("x") == "x"
    called=[]
    monkeypatch.setattr("agent_roi.enterprise.postgres.PostgresMigrationManager.migrate", lambda self: called.append(1))
    PostgresControlPlaneStore("dsn", connect_factory=DB().connect)
    PostgresIdentityStore("dsn", connect_factory=DB().connect)
    assert called == [1,1]


def test_policy_error_and_expected_revision_paths(monkeypatch):
    b=bundle()
    db=DB([Step("INSERT INTO policy_bundles", [], error=RuntimeError("dup"))])
    with pytest.raises(ControlPlaneError): store(db).save_bundle(b)
    db=DB([Step("SELECT * FROM policy_bundles", [])])
    with pytest.raises(KeyError): store(db).get_bundle("acme","p","prod","x")
    db=DB([Step("UPDATE active_policies", [], rowcount=1), Step("DELETE FROM policy_rollouts", [])])
    s=store(db); monkeypatch.setattr(s,"get_bundle",lambda *a:b)
    assert s.activate("acme","p","prod","1",activated_by="x",expected_revision=2) is b
    db=DB([Step("UPDATE active_policies", [], rowcount=0)])
    s=store(db); monkeypatch.setattr(s,"get_bundle",lambda *a:b)
    with pytest.raises(ControlPlaneError): s.activate("acme","p","prod","1",activated_by="x",expected_revision=2)
    for method, sql in [("get_active","SELECT version"),("get_active_revision","SELECT revision")]:
        db=DB([Step(sql, [])]); s=store(db)
        with pytest.raises(KeyError): getattr(s,method)("acme","p","prod")


def test_rollout_lifecycle_and_resolution(monkeypatch):
    primary=bundle("1"); candidate=bundle("2")
    s=store(DB())
    for pct in [True,0,100]:
        with pytest.raises(ValueError): s.start_rollout("acme","p","prod","2",candidate_percentage=pct,updated_by="x")
    monkeypatch.setattr(s,"get_active",lambda *a:primary)
    monkeypatch.setattr(s,"get_bundle",lambda *a: primary if a[-1]=="1" else candidate)
    with pytest.raises(ValueError, match="differ"):
        s.start_rollout("acme","p","prod","1",candidate_percentage=10,updated_by="x")

    rollout={"organization_id":"acme","name":"p","environment":"prod","primary_version":"1","candidate_version":"2",
             "candidate_percentage":100,"seed":"s","updated_at_utc":datetime(2026,1,1,tzinfo=timezone.utc),"updated_by":"x","revision":1}
    db=DB([Step("INSERT INTO policy_rollouts", [], rowcount=1),Step("SELECT * FROM policy_rollouts",[rollout])])
    s=store(db); monkeypatch.setattr(s,"get_active",lambda *a:primary); monkeypatch.setattr(s,"get_bundle",lambda *a:candidate)
    out=s.start_rollout("acme","p","prod","2",candidate_percentage=99,updated_by="x")
    assert out["updated_at_utc"].startswith("2026")

    db=DB([Step("UPDATE policy_rollouts", [], rowcount=0)])
    s=store(db); monkeypatch.setattr(s,"get_active",lambda *a:primary); monkeypatch.setattr(s,"get_bundle",lambda *a:candidate)
    with pytest.raises(ControlPlaneError): s.start_rollout("acme","p","prod","2",candidate_percentage=50,updated_by="x",expected_revision=1)
    db=DB([Step("SELECT * FROM policy_rollouts", [])])
    with pytest.raises(KeyError): store(db).get_rollout("acme","p","prod")
    db=DB([Step("DELETE FROM policy_rollouts", [], rowcount=1)])
    store(db).cancel_rollout("acme","p","prod")

    s=store(DB()); monkeypatch.setattr(s,"get_active",lambda *a:primary); monkeypatch.setattr(s,"get_rollout",lambda *a: (_ for _ in ()).throw(KeyError()))
    assert s.resolve_active("acme","p","prod",agent_id="a") is primary
    monkeypatch.setattr(s,"get_rollout",lambda *a:{"seed":"s","candidate_percentage":100,"candidate_version":"2","primary_version":"1"})
    monkeypatch.setattr(s,"get_bundle",lambda *a:candidate)
    assert s.resolve_active("acme","p","prod",agent_id="a") is candidate
    monkeypatch.setattr(s,"get_rollout",lambda *a:{"seed":"s","candidate_percentage":0,"candidate_version":"2","primary_version":"1"})
    monkeypatch.setattr(s,"get_bundle",lambda *a:primary)
    assert s.resolve_active("acme","p","prod",agent_id="a") is primary


def test_list_bundles_and_agent_crud(monkeypatch):
    b=bundle(); row=bundle_row(b)
    db=DB([Step("SELECT name,environment,version", [{"name":"p","environment":"prod","version":"1"}])])
    s=store(db); monkeypatch.setattr(s,"get_bundle",lambda *a:b)
    assert s.list_bundles("acme",name="p",environment="prod",limit=999,offset=-2)==(b,)

    db=DB([Step("INSERT INTO agents",[],rowcount=1)])
    s=store(db); monkeypatch.setattr(s,"get_agent",lambda *a:{"revision":1})
    assert s.register_agent(organization_id="acme",agent_id="a",environment="prod",owner="o",purpose="p")["revision"]==1
    db=DB([Step("UPDATE agents",[],rowcount=1)])
    s=store(db); monkeypatch.setattr(s,"get_agent",lambda *a:{"revision":3})
    assert s.register_agent(organization_id="acme",agent_id="a",environment="prod",owner="o",purpose="p",expected_revision=2)["revision"]==3
    db=DB([Step("UPDATE agents",[],rowcount=0)])
    s=store(db); monkeypatch.setattr(s,"get_agent",lambda *a:{})
    with pytest.raises(ControlPlaneError): s.register_agent(organization_id="acme",agent_id="a",environment="prod",owner="o",purpose="p",expected_revision=2)

    db=DB([Step("UPDATE agents SET last_heartbeat",[],rowcount=1)])
    s=store(db); monkeypatch.setattr(s,"get_agent",lambda *a:{"status":"production"})
    assert s.heartbeat(organization_id="acme",agent_id="a",environment="prod",policy_digest="d",version="2")["status"]=="production"
    for expected, exc in [(None,KeyError),(1,ControlPlaneError)]:
        db=DB([Step("UPDATE agents SET last_heartbeat",[],rowcount=0)]); s=store(db)
        with pytest.raises(exc): s.heartbeat(organization_id="acme",agent_id="a",environment="prod",policy_digest="d",version="2",expected_revision=expected)

    db=DB([Step("SELECT * FROM agents",[])])
    with pytest.raises(KeyError): store(db).get_agent("acme","a","prod")
    db=DB([Step("SELECT * FROM agents",[agent_row(last_heartbeat_utc=datetime(2026,1,2,tzinfo=timezone.utc))])])
    assert store(db).get_agent("acme","a","prod")["metadata"]=={"x":1}
    db=DB([Step("SELECT * FROM agents",[agent_row()])])
    items=store(db).list_agents("acme",limit=0,offset=-1)
    assert items[0]["metadata"]=={"x":1}


def test_identity_user_paths(monkeypatch):
    with pytest.raises(ValueError): PostgresIdentityStore._parse_user({})
    parsed=PostgresIdentityStore._parse_user({"userName":" u ","emails":["a",{"value":" b "},42],"x":1})
    assert parsed.emails==("a","b") and parsed.attributes=={"x":1}
    db=DB([Step("INSERT INTO scim_users",[],error=RuntimeError())])
    with pytest.raises(ValueError,match="exists"): istore(db).create_user({"userName":"u"})
    db=DB([Step("SELECT * FROM scim_users",[])])
    with pytest.raises(KeyError): istore(db).get_user("x")
    db=DB([Step("SELECT * FROM scim_users",[user_row()])])
    assert istore(db).list_users(limit=999,offset=-1)[0].attributes["dept"]=="F"
    db=DB([Step("SELECT COUNT",[])])
    assert istore(db).count_users()==0

    current=SCIMUser("u","old",True,"Old",("o",),"e",{"organization_id":"acme","revision":2})
    updated=SCIMUser("u","new",True,"New",(),"",{"organization_id":"acme","revision":3})
    db=DB([Step("UPDATE scim_users",[],rowcount=1)])
    s=istore(db); monkeypatch.setattr(s,"get_user",lambda *_: current if db.steps else updated)
    assert s.replace_user("u",{"userName":"new","displayName":"New"}).user_name=="new"
    db=DB([Step("UPDATE scim_users",[],rowcount=0)])
    s=istore(db); monkeypatch.setattr(s,"get_user",lambda *_:current)
    with pytest.raises(ValueError,match="revision"): s.replace_user("u",{"userName":"new"},expected_revision=2)
    db=DB([Step("DELETE FROM scim_users",[],rowcount=1)]); istore(db).delete_user("u",expected_revision=1)
    db=DB([Step("DELETE FROM scim_users",[],rowcount=0)])
    with pytest.raises(KeyError): istore(db).delete_user("u")


def test_identity_group_and_rbac_paths(monkeypatch):
    with pytest.raises(ValueError): PostgresIdentityStore._parse_group({})
    assert PostgresIdentityStore._parse_group({"displayName":" g ","members":[{"value":"u"},"v",""]}).members==frozenset({"u","v"})
    s=istore(DB()); monkeypatch.setattr(s,"list_users",lambda **k:(SCIMUser("u","u",True),))
    with pytest.raises(ValueError,match="unknown"): s.create_group({"displayName":"g","members":[{"value":"x"}]})
    db=DB([Step("INSERT INTO scim_groups",[],error=RuntimeError())]); s=istore(db); monkeypatch.setattr(s,"list_users",lambda **k:())
    with pytest.raises(ValueError,match="exists"): s.create_group({"displayName":"g"})
    db=DB([Step("SELECT * FROM scim_groups",[]),Step("SELECT user_id",[])])
    with pytest.raises(KeyError): istore(db).get_group("x")
    db=DB([Step("SELECT * FROM scim_groups",[group_row()]),Step("SELECT user_id",[{"user_id":"u"}])])
    assert istore(db).get_group("g").members==frozenset({"u"})
    db=DB([Step("SELECT group_id FROM scim_groups",[{"group_id":"g"}])]); s=istore(db); monkeypatch.setattr(s,"get_group",lambda *_:SCIMGroup("g","G"))
    assert s.list_groups(organization_id="acme",limit=999,offset=-1)[0].id=="g"
    db=DB([Step("SELECT COUNT",[])]); assert istore(db).count_groups()==0

    current=SCIMGroup("g","Old",frozenset({"u"}),"e")
    s=istore(DB()); monkeypatch.setattr(s,"get_group",lambda *_:current); monkeypatch.setattr(s,"list_users",lambda **k:())
    with pytest.raises(ValueError,match="unknown"): s.replace_group("g",{"displayName":"New","members":[{"value":"x"}]})
    db=DB([Step("UPDATE scim_groups",[],rowcount=1),Step("DELETE FROM scim_group_members",[]),Step("INSERT INTO scim_group_members",[])])
    s=istore(db); calls=[current,SCIMGroup("g","New",frozenset({"u"}),"e")]
    monkeypatch.setattr(s,"get_group",lambda *_:calls.pop(0)); monkeypatch.setattr(s,"list_users",lambda **k:(SCIMUser("u","u",True),))
    assert s.replace_group("g",{"displayName":"New","members":[{"value":"u"}]},expected_revision=2).display_name=="New"
    db=DB([Step("UPDATE scim_groups",[],rowcount=0)]); s=istore(db); monkeypatch.setattr(s,"get_group",lambda *_:current); monkeypatch.setattr(s,"list_users",lambda **k:(SCIMUser("u","u",True),))
    with pytest.raises(ValueError,match="revision"): s.replace_group("g",{"displayName":"New"})
    db=DB([Step("DELETE FROM scim_groups",[],rowcount=1)]); istore(db).delete_group("g",expected_revision=1)
    db=DB([Step("DELETE FROM scim_groups",[],rowcount=0)])
    with pytest.raises(KeyError): istore(db).delete_group("g")

    role=RoleDefinition("r",frozenset({"x"}),"d")
    db=DB([Step("INSERT INTO rbac_roles",[],rowcount=1)]); istore(db).save_role(role)
    db=DB([Step("UPDATE rbac_roles",[],rowcount=0)])
    with pytest.raises(ValueError): istore(db).save_role(role,expected_revision=1)
    db=DB([Step("INSERT INTO rbac_bindings",[],error=RuntimeError())])
    with pytest.raises(ValueError,match="Unknown"): istore(db).save_binding(RoleBinding("r","acme",subject="u"))
    db=DB([Step("INSERT INTO rbac_bindings",[],rowcount=1)]); assert istore(db).save_binding(RoleBinding("r","acme",subject="u"))
    db=DB([Step("SELECT * FROM rbac_roles",[{"name":"r","permissions_json":"[\"x\"]","description":"d"}])]); assert istore(db).list_roles()[0].permissions==frozenset({"x"})
    db=DB([Step("DELETE FROM rbac_roles",[],rowcount=0)])
    with pytest.raises(KeyError): istore(db).delete_role("r")
    db=DB([Step("SELECT * FROM rbac_bindings",[{"binding_id":"b","role":"r","organization_id":"acme","subject":"u","group_name":"","environment":"prod"}])]); assert istore(db).list_bindings()[0][0]=="b"
    db=DB([Step("DELETE FROM rbac_bindings",[],rowcount=0)])
    with pytest.raises(KeyError): istore(db).delete_binding("b")


def test_identity_authorizer_and_principal(monkeypatch):
    s=istore(DB())
    monkeypatch.setattr(s,"list_roles",lambda: (RoleDefinition("r",frozenset({"x"})),))
    monkeypatch.setattr(s,"list_bindings",lambda: (("b",RoleBinding("r","acme",subject="u")),))
    assert s.authorizer().authorize(Principal(subject="u", organization_id="acme"),"x","resource")
    inactive=SCIMUser("u","u",False)
    monkeypatch.setattr(s,"get_user",lambda *_:inactive)
    with pytest.raises(AuthenticationError): s.principal_for("u",organization_id="acme")
    active=SCIMUser("u","u",True,"U",("u@x",))
    monkeypatch.setattr(s,"get_user",lambda *_:active)
    monkeypatch.setattr(s,"list_groups",lambda **k:(SCIMGroup("g","Approvers",frozenset({"u"})),))
    principal=s.principal_for("u",organization_id="acme",role_mapping={"Approvers":["r"]})
    assert principal.roles==frozenset({"r"}) and principal.email=="u@x"
