from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from agent_roi import Guardrails, SentinelRunner
from agent_roi.control.guardrails import GuardrailViolation
from agent_roi.policies.loader import _freeze, load_policy, policy_from_mapping
from agent_roi.policies.validate import PolicyValidationError, validate_policy
from agent_roi.runtime.context import RunState, SentinelContext
from agent_roi.runtime.resilience import IdempotencyPolicy, IdempotencyResult, RetryPolicy
from agent_roi.runtime.tools import ApprovalGrant, HumanApprovalRequired, ToolRegistrationError, ToolRegistry, ToolSpec


def valid_policy():
    return {
        "policy_name": "qa",
        "guardrails": {
            "max_steps": 2,
            "max_tool_calls": 2,
            "max_cost_usd": 2.0,
            "allowed_tools": ["x"],
            "deterministic": True,
            "require_registered_tools": False,
            "require_bound_approval_grants": False,
        },
        "decision_policy": {"min_confidence": 0.5, "abstain_action": "human_review"},
    }


def test_policy_validator_reports_all_defensive_errors():
    bad = {
        "policy_name": "",
        "guardrails": {
            "max_steps": 0,
            "max_tool_calls": 1.2,
            "max_cost_usd": float("inf"),
            "allowed_tools": "x",
            "deterministic": "yes",
            "require_registered_tools": 1,
            "require_bound_approval_grants": None,
        },
        "decision_policy": {
            "min_confidence": 2,
            "abstain_action": 3,
            "w_prob": "x",
            "w_margin": float("nan"),
            "w_z": -1,
            "w_entropy": 0,
            "w_llm": 0,
        },
        "thresholds": {
            "bad": "not-map",
            "mixed": {"always_flag": "yes", "bool": True, "nan": float("nan"), "neg": -1},
        },
        "scoring": {"savings_multipliers": {"bad": "x", "range": 2}},
        "approval_routing": {
            "requires_approval_for_risk": "high",
            "production_requires_approval_for_risk": ["critical"],
        },
    }
    with pytest.raises(PolicyValidationError) as err:
        validate_policy(bad)
    message = str(err.value)
    for fragment in (
        "policy_name", "max_steps", "max_tool_calls", "max_cost_usd", "allowed_tools",
        "must be a boolean", "min_confidence", "abstain_action", "w_prob", "w_margin",
        "w_z", "bad must be a mapping", "always_flag", "must be a finite number",
        "must be >= 0", "savings_multipliers.bad", "between 0 and 1",
        "must be a list", "must contain only",
    ):
        assert fragment in message


@pytest.mark.parametrize(
    "mutator, fragment",
    [
        (lambda p: p.pop("guardrails"), "guardrails"),
        (lambda p: p["guardrails"].pop("max_steps"), "max_steps"),
        (lambda p: p["guardrails"].update(max_cost_usd=True), "max_cost_usd"),
        (lambda p: p["guardrails"].update(allowed_tools=["", 1]), "allowed_tools"),
        (lambda p: p["decision_policy"].update(abstain_action="bogus"), "must be one of"),
        (lambda p: p["decision_policy"].update(w_prob=0, w_margin=0, w_z=0, w_entropy=0, w_llm=0), "cannot all be zero"),
        (lambda p: p.update(scoring={"savings_multipliers": []}), "must be a mapping"),
    ],
)
def test_policy_validator_individual_paths(mutator, fragment):
    p = valid_policy()
    mutator(p)
    with pytest.raises(PolicyValidationError, match=fragment):
        validate_policy(p)


def test_policy_loader_freeze_and_failures(tmp_path: Path, monkeypatch):
    assert _freeze(({"x": [1]},)) == ({"x": (1,)},)
    assert _freeze({1, 2}) == frozenset({1, 2})
    with pytest.raises(ValueError):
        policy_from_mapping(" ", valid_policy())
    policy = policy_from_mapping(" qa ", valid_policy())
    assert policy.name == "qa" and policy.guardrails().allowed_tools == frozenset({"x"})
    with pytest.raises(ValueError):
        load_policy("")
    with pytest.raises(FileNotFoundError):
        load_policy("missing.yaml")
    with pytest.raises(FileNotFoundError):
        load_policy("x", override_path=tmp_path / "missing.yaml")
    blank = tmp_path / "blank.yaml"; blank.write_text("", encoding="utf-8")
    with pytest.raises(PolicyValidationError):
        load_policy("blank", override_path=blank)
    saved = sys.modules.pop("yaml", None)
    monkeypatch.setitem(sys.modules, "yaml", None)
    with pytest.raises(RuntimeError, match="PyYAML"):
        load_policy("finops_policy.yaml")
    sys.modules.pop("yaml", None)
    if saved is not None:
        sys.modules["yaml"] = saved


def test_tool_spec_registry_and_grant_validation_paths():
    def handler(): return "ok"
    invalid = [
        dict(name="", handler=handler), dict(name="x", handler=1),
        dict(name="x", handler=handler, requires_approval="yes"),
        dict(name="x", handler=handler, default_cost_usd=-1),
        dict(name="x", handler=handler, version=""),
        dict(name="x", handler=handler, approval_ttl_seconds=True),
        dict(name="x", handler=handler, cost_estimator=1),
        dict(name="x", handler=handler, retry_policy="bad"),
        dict(name="x", handler=handler, circuit_breaker="bad"),
        dict(name="x", handler=handler, idempotency_policy="bad"),
        dict(name="x", handler=handler, timeout_seconds=0),
    ]
    for kwargs in invalid:
        with pytest.raises(ToolRegistrationError): ToolSpec(**kwargs)
    async def ah(): return 1
    assert ToolSpec("a", ah).is_async
    registry = ToolRegistry()
    registry.add("x", handler)
    with pytest.raises(ToolRegistrationError): registry.add("x", handler)
    registry.add("x", lambda: "new", replace=True)
    with pytest.raises(ToolRegistrationError): registry.require("missing")
    assert registry.names() == frozenset({"x"}) and registry.manifest()[0]["name"] == "x"
    registry.freeze()
    with pytest.raises(ToolRegistrationError): registry.add("y", handler)

    for kwargs in (
        dict(action_digest="x", approved_by="a", expires_at_epoch_ms=1),
        dict(action_digest="0"*64, approved_by="", expires_at_epoch_ms=1),
        dict(action_digest="0"*64, approved_by="a", expires_at_epoch_ms=True),
    ):
        with pytest.raises(ValueError): ApprovalGrant(**kwargs)
    checkpoint={"action_digest":"0"*64,"checkpoint_id":"c"}
    with pytest.raises(ValueError, match="requested action"):
        ApprovalGrant("1"*64,"a",int(time.time()*1000)+1000).validate(checkpoint)
    with pytest.raises(ValueError, match="checkpoint"):
        ApprovalGrant("0"*64,"a",int(time.time()*1000)+1000,"wrong").validate(checkpoint)
    with pytest.raises(ValueError, match="expired"):
        ApprovalGrant("0"*64,"a",0,"c").validate(checkpoint)
    assert "unknown" in str(HumanApprovalRequired({}))


class FakeIdemStore:
    def __init__(self, result: IdempotencyResult): self.result=result; self.completed=[]; self.failed=[]
    def begin(self, namespace, key, request_digest, *, ttl_seconds): return self.result
    def complete(self, namespace, key, response): self.completed.append((namespace,key,response))
    def fail(self, namespace, key, error): self.failed.append((namespace,key,error))


class Authorizer:
    def __init__(self, allowed): self.allowed=allowed
    def authorize(self, *args, **kwargs): return self.allowed


def test_context_properties_authorization_approval_and_cost_paths():
    events=[]
    ctx=SentinelContext(started_at_epoch_ms=1, metadata={"nested":{"x":1}}, state=RunState(),
                        principal=SimpleNamespace(subject="u"), organization_id="o", environment="e", agent_id="a",
                        audit_emitter=lambda t,p: events.append((t,p)))
    assert (ctx.started_at_epoch_ms,ctx.principal.subject,ctx.organization_id,ctx.environment,ctx.agent_id)==(1,"u","o","e","a")
    meta=ctx.metadata
    with pytest.raises(TypeError): meta["x"]=1
    ctx.bump_tool_call(); ctx.add_cost(.5); assert ctx.state.tool_calls==1 and ctx.state.cost_usd==.5
    assert ctx.call_tool("legacy", lambda x:x+1, 1)==2
    with pytest.raises(TypeError): ctx.call_tool("legacy")

    denied=SentinelContext(authorizer=Authorizer(False), principal=SimpleNamespace(subject="u"), audit_emitter=lambda t,p: events.append((t,p)))
    with pytest.raises(GuardrailViolation, match="not authorized"): denied.call_tool("x", lambda:1)
    missing=SentinelContext(authorizer=Authorizer(True), audit_emitter=lambda t,p: events.append((t,p)))
    with pytest.raises(GuardrailViolation, match="authenticated"): missing.call_tool("x", lambda:1)

    reg=ToolRegistry(); spec=reg.add("priced",lambda x:x,default_cost_usd=1,cost_estimator=lambda a,k:2)
    ctx=SentinelContext(tool_registry=reg)
    assert ctx.call_tool("priced", spec.handler, 3, cost_usd=2)==3
    with pytest.raises(GuardrailViolation, match="does not match"): ctx.call_tool("priced", lambda:3)

    reg=ToolRegistry(); reg.add("approve",lambda:1,requires_approval=True)
    strict=SentinelContext(tool_registry=reg,guardrails=Guardrails(require_bound_approval_grants=True),approval_callback=lambda *a:True)
    with pytest.raises(GuardrailViolation,match="payload-bound"): strict.call_tool("approve")
    old=SentinelContext(tool_registry=reg,approval_callback=lambda spec,args,kwargs: True)
    assert old.call_tool("approve")==1
    required=SentinelContext(tool_registry=reg)
    with pytest.raises(HumanApprovalRequired): required.call_tool("approve")


@pytest.mark.asyncio
async def test_context_async_sync_misuse_idempotency_and_failures():
    async def async_handler(x): return x+1
    reg=ToolRegistry(); reg.add("async",async_handler)
    ctx=SentinelContext(tool_registry=reg)
    with pytest.raises(GuardrailViolation,match="asynchronous"): ctx.call_tool("async",1)
    assert await ctx.acall_tool("async",1)==2

    reg=ToolRegistry(); reg.add("sync-time",lambda:1,timeout_seconds=.1)
    ctx=SentinelContext(tool_registry=reg)
    with pytest.raises(GuardrailViolation,match="acall_tool"): ctx.call_tool("sync-time")
    with pytest.raises(GuardrailViolation,match="cannot cancel"): await ctx.acall_tool("sync-time")

    async def returned_awaitable(): return 1
    ctx=SentinelContext()
    with pytest.raises(GuardrailViolation,match="returned an awaitable"):
        ctx.call_tool("bad", lambda: returned_awaitable())

    completed=FakeIdemStore(IdempotencyResult("completed",response=7))
    failed=FakeIdemStore(IdempotencyResult("failed",error="boom"))
    for store, expected in ((completed,7),(failed,None)):
        reg=ToolRegistry(); reg.add("i",lambda:9,idempotency_policy=IdempotencyPolicy(store,"n",lambda a,k:"key"))
        ctx=SentinelContext(tool_registry=reg)
        if expected is None:
            with pytest.raises(GuardrailViolation,match="Previous"): ctx.call_tool("i")
        else: assert ctx.call_tool("i")==expected

    pending=FakeIdemStore(IdempotencyResult("started"))
    reg=ToolRegistry(); reg.add("fail",lambda:(_ for _ in ()).throw(RuntimeError("x")),idempotency_policy=IdempotencyPolicy(pending,"n",lambda a,k:"key"))
    ctx=SentinelContext(tool_registry=reg)
    with pytest.raises(RuntimeError): ctx.call_tool("fail")
    assert pending.failed

    pending_async=FakeIdemStore(IdempotencyResult("started"))
    async def afail(): raise RuntimeError("x")
    reg=ToolRegistry(); reg.add("afail",afail,idempotency_policy=IdempotencyPolicy(pending_async,"n",lambda a,k:"key"),retry_policy=RetryPolicy(max_attempts=1))
    ctx=SentinelContext(tool_registry=reg)
    with pytest.raises(RuntimeError): await ctx.acall_tool("afail")
    assert pending_async.failed


def test_runner_capture_sink_legacy_store_and_agent_errors(tmp_path):
    class LegacyStore:
        def __init__(self): self.events=[]
        def last_hash(self,c): return self.events[-1].hash if self.events else ""
        def append(self,e): self.events.append(e)
    class Sink:
        def __init__(self,fail=False): self.events=[]; self.fail=fail
        def emit(self,e):
            if self.fail: raise RuntimeError("sink")
            self.events.append(e)
    legacy=LegacyStore(); sink=Sink()
    runner=SentinelRunner(audit_store=legacy,event_sinks=[sink],capture_input=True,capture_output=True,metadata={"x":1})
    assert runner.run(lambda c,p:("ok",p), None).output[0]=="ok"
    assert legacy.events and sink.events
    bad=Sink(True)
    runner=SentinelRunner(event_sinks=[bad],fail_on_event_sink_error=False)
    runner.run(lambda c,p:"ok",None); assert runner.event_sink_errors
    with pytest.raises(RuntimeError,match="sink"):
        SentinelRunner(event_sinks=[bad],fail_on_event_sink_error=True).run(lambda c,p:"ok",None)
    async def agent(c,p): return "ok"
    with pytest.raises(TypeError,match="Asynchronous agents"):
        SentinelRunner().run(agent,None)
    def returns_awaitable(c,p): return agent(c,p)
    with pytest.raises(TypeError,match="returned an awaitable"):
        SentinelRunner().run(returns_awaitable,None)


@pytest.mark.asyncio
async def test_runner_arun_sync_and_async_paths():
    runner=SentinelRunner()
    assert (await runner.arun(lambda c,p:"sync",None)).output=="sync"
    async def async_agent(c,p): return "async"
    assert (await runner.arun(async_agent,None)).output=="async"
    def sync_returns_awaitable(c,p): return async_agent(c,p)
    assert (await runner.arun(sync_returns_awaitable,None)).output=="async"
    with pytest.raises(TypeError,match="requires an async agent"):
        await SentinelRunner(run_timeout_seconds=.1).arun(lambda c,p:"x",None)
