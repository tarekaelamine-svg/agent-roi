from __future__ import annotations

import io
import json
import time
from pathlib import Path
from urllib import error as urlerror

import pytest

from agent_roi.approvals.base import (
    ApprovalBroker, ApprovalRecord, ApprovalRequest, ApprovalStatus,
    InMemoryApprovalProvider, JsonHttpApprovalProvider, SqliteApprovalRepository,
)
from agent_roi.approvals.integrations import (
    JiraServiceManagementApprovalProvider, PagerDutyApprovalProvider,
    ServiceNowApprovalProvider, SMTPApprovalProvider,
)
from agent_roi.runtime.tools import ApprovalGrant, ToolSpec


def checkpoint(*, checkpoint_id="cp", action="action", expires=None):
    now = int(time.time() * 1000)
    return {
        "checkpoint_id": checkpoint_id, "action_digest": action,
        "correlation_id":"c", "run_id":"r", "tool_name":"tool", "tool_version":"1",
        "risk":"high", "estimated_cost_usd":1, "arguments_digest":"args", "policy_digest":"policy",
        "created_at_epoch_ms":now, "expires_at_epoch_ms":expires or now+60_000,
    }


def request(**kwargs):
    return ApprovalRequest.from_checkpoint(checkpoint(**kwargs), organization_id="o", environment="prod", agent_id="a", requested_by="requester", metadata={"x":1})


def spec():
    return ToolSpec(name="tool", handler=lambda: None, risk="high", requires_approval=True)


def test_http_provider_validation_response_and_failures(monkeypatch) -> None:
    with pytest.raises(ValueError):
        JsonHttpApprovalProvider("http://insecure")
    provider = JsonHttpApprovalProvider("http://local", require_https=False, headers={"X":"Y"})
    req = request()
    assert provider.build_payload(req)["checkpoint_id"] == "cp"
    assert provider.extract_external_id({"id":"1"}, req) == "1"
    assert provider.extract_external_id({"key":"2"}, req) == "2"
    assert provider.extract_external_id({}, req) == req.request_id
    assert provider.extract_external_id("x", req) == req.request_id
    assert provider.update(ApprovalRecord(req, ApprovalStatus.PENDING)) is None

    class Response:
        def __init__(self, body=b"{}", status=200): self.body=body; self.status=status
        def __enter__(self): return self
        def __exit__(self,*a): return False
        def read(self): return self.body
    monkeypatch.setattr("agent_roi.approvals.base.urlrequest.urlopen", lambda *a,**k: Response(b'{"id":"ext"}'))
    assert provider.submit(req) == "ext"
    monkeypatch.setattr("agent_roi.approvals.base.urlrequest.urlopen", lambda *a,**k: Response(b"", 500))
    with pytest.raises(RuntimeError, match="500"): provider.submit(req)
    err=urlerror.HTTPError("u",400,"bad",{},io.BytesIO(b"detail"))
    monkeypatch.setattr("agent_roi.approvals.base.urlrequest.urlopen", lambda *a,**k: (_ for _ in ()).throw(err))
    with pytest.raises(RuntimeError, match="detail"): provider.submit(req)
    monkeypatch.setattr("agent_roi.approvals.base.urlrequest.urlopen", lambda *a,**k: (_ for _ in ()).throw(OSError()))
    with pytest.raises(RuntimeError, match="unavailable"): provider.submit(req)


def test_integration_external_ids_and_validation() -> None:
    req=request()
    snow=ServiceNowApprovalProvider("https://x", bearer_token="t")
    assert snow.extract_external_id({"result":{"sys_id":"s"}},req)=="s"
    assert snow.extract_external_id({"result":{"number":"n"}},req)=="n"
    assert snow.extract_external_id({},req)==req.request_id
    jira=JiraServiceManagementApprovalProvider("https://x",bearer_token="t",service_desk_id="1",request_type_id="2")
    assert jira.extract_external_id({"issueKey":"K"},req)=="K"
    assert jira.extract_external_id({"requestId":"R"},req)=="R"
    assert jira.extract_external_id("x",req)==req.request_id
    with pytest.raises(ValueError): PagerDutyApprovalProvider(" ")
    pd=PagerDutyApprovalProvider("key")
    assert pd.extract_external_id({"dedup_key":"d"},req)=="d"
    assert pd.extract_external_id("x",req)==req.checkpoint_id
    for args in [("", "s", ["r"]), ("h", "", ["r"]), ("h", "s", [])]:
        with pytest.raises(ValueError): SMTPApprovalProvider(args[0],sender=args[1],recipients=args[2])
    with pytest.raises(ValueError): SMTPApprovalProvider("h",sender="s",recipients=[" "])


def test_broker_invalid_stale_expired_denied_and_repository_paths(tmp_path: Path) -> None:
    provider=InMemoryApprovalProvider()
    repo=SqliteApprovalRepository(tmp_path/"a.db")
    broker=ApprovalBroker(provider, repository=repo, requested_by="requester")
    cp=checkpoint()
    assert broker(spec(), (), {}, cp) is False
    assert broker(spec(), (), {}, cp) is False
    rec=broker.record("cp")
    assert rec.status is ApprovalStatus.PENDING
    with pytest.raises(KeyError): broker.record("missing")
    with pytest.raises(KeyError, match="not found"):
        broker.decide("missing", approved=True, principal="x")
    with pytest.raises(ValueError, match="identity"):
        broker.decide("cp", approved=True, principal=" ")
    denied=broker.decide("cp", approved=False, principal="approver", reason="no")
    assert denied.status is ApprovalStatus.DENIED
    with pytest.raises(ValueError, match="already"):
        broker.decide("cp", approved=True, principal="approver")

    expired_cp=checkpoint(checkpoint_id="expired", action="expired", expires=int(time.time()*1000)-1)
    assert broker(spec(),(),{},expired_cp) is False
    with pytest.raises(ValueError, match="expired"):
        broker.decide("expired", approved=True, principal="approver")
    assert repo.get_record("expired").status is ApprovalStatus.EXPIRED

    # Invalid cached grant is discarded and a request is submitted.
    cp2=checkpoint(checkpoint_id="cp2", action="a2")
    broker._grants["cp2"] = ApprovalGrant("0"*64,"u",int(time.time()*1000)+10000,"cp2")
    assert broker(spec(),(),{},cp2) is False

    # Expired action grants are discarded.
    broker._approved_actions["a3"] = ApprovalGrant("a"*64,"u",0,"old")
    cp3=checkpoint(checkpoint_id="cp3",action="a3")
    assert broker(spec(),(),{},cp3) is False

    # Repository replay path.
    grant=ApprovalGrant("b"*64,"u",int(time.time()*1000)+10000,"old",reason="ok")
    repo.save_grant(grant)
    cp4=checkpoint(checkpoint_id="new",action="b"*64)
    replay=ApprovalBroker(InMemoryApprovalProvider(),repository=repo)(spec(),(),{},cp4)
    assert isinstance(replay,ApprovalGrant) and replay.checkpoint_id=="new"
    assert broker.pending()


def test_sqlite_repository_round_trip_and_missing(tmp_path: Path) -> None:
    repo=SqliteApprovalRepository(tmp_path/"repo.db")
    req=request()
    rec=ApprovalRecord(req,ApprovalStatus.PENDING,external_id="x")
    repo.save_record(rec)
    assert repo.get_record("cp").external_id=="x"
    assert repo.pending()[0].request.metadata=={"x":1}
    with pytest.raises(KeyError): repo.get_record("none")
    grant=ApprovalGrant("c"*64,"u",int(time.time()*1000)+10000,"cp","why")
    repo.save_grant(grant)
    assert repo.get_grant("c"*64).reason=="why"
    with pytest.raises(KeyError): repo.get_grant("none")
