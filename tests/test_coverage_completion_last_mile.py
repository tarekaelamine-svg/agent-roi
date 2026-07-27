from __future__ import annotations

import signal
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from agent_roi.adapters.mcp import MCPAdapter
from agent_roi.adapters.openai import OpenAIAgentsAdapter
from agent_roi.enterprise.outbox import OutboxEvent, OutboxWorker
from agent_roi.procurement.analyzer import ProcurementLeakageAnalyzer
from agent_roi.policies import load_policy
from agent_roi.roi.executive import _safe_float as executive_safe_float
from agent_roi.roi.ledger import _cents_to_money
from agent_roi.runtime.artifacts import atomic_write_text
from agent_roi.runtime.context import SentinelContext
from agent_roi.runtime.executor import _hard_sync_timeout
from agent_roi.runtime.resilience import CircuitBreaker
from agent_roi.runtime.tools import ToolRegistry


def test_openai_type_hint_fallback_and_mcp_execute() -> None:
    def handler(value: "UndefinedAnnotation"):
        return value
    registry=ToolRegistry(); registry.add("tool",handler)
    definition=OpenAIAgentsAdapter(registry).tool_definitions()[0]
    assert definition["function"]["parameters"]["properties"]["value"]["type"]=="string"
    mcp_registry=ToolRegistry()
    adapter=MCPAdapter(SimpleNamespace(call_tool=lambda name,arguments: arguments["value"]))
    adapter.register_tool(mcp_registry,"remote")
    assert adapter.execute(SentinelContext(tool_registry=mcp_registry),"remote",{"value":3})==3


def test_remaining_simple_helpers_and_procurement_auto_approval() -> None:
    assert executive_safe_float(object())==0
    assert _cents_to_money(123)==1.23
    analyzer=ProcurementLeakageAnalyzer(load_policy("procurement_policy.yaml"),{"environment":"dev"})
    assert analyzer.approval_status({},"low")=="auto_approve_candidate"


def test_atomic_write_removes_temporary_after_replace_failure(tmp_path: Path, monkeypatch) -> None:
    original=Path.replace
    def broken(self,target):
        if self.name.endswith(".tmp"):
            raise OSError("replace failed")
        return original(self,target)
    monkeypatch.setattr(Path,"replace",broken)
    with pytest.raises(OSError,match="replace failed"):
        atomic_write_text(tmp_path/"x.txt","x")
    assert not list(tmp_path.glob("*.tmp")) and not list(tmp_path.glob(".*.tmp"))


def test_context_callback_signature_failure_uses_legacy_callback() -> None:
    class Callback:
        @property
        def __signature__(self):
            raise ValueError("unknown")
        def __call__(self,*args):
            return True
    registry=ToolRegistry(); registry.add("approve",lambda:5,requires_approval=True)
    assert SentinelContext(tool_registry=registry,approval_callback=Callback()).call_tool("approve")==5


def test_hard_timeout_restores_existing_timer() -> None:
    if not hasattr(signal,"SIGALRM"):
        pytest.skip("Unix timer required")
    signal.setitimer(signal.ITIMER_REAL,5)
    try:
        with _hard_sync_timeout(0.1):
            pass
        remaining=signal.getitimer(signal.ITIMER_REAL)[0]
        assert remaining>0
    finally:
        signal.setitimer(signal.ITIMER_REAL,0)


def test_outbox_worker_uses_circuit_breaker() -> None:
    delivered=[]
    event=OutboxEvent.create(topic="t",destination="d",payload={},idempotency_key="k")
    store=SimpleNamespace(
        claim=lambda **kwargs:(event,),
        mark_delivered=lambda event_id,*,worker_id: delivered.append(event_id),
        mark_failed=lambda *args,**kwargs: None,
    )
    breaker=CircuitBreaker(failure_threshold=2,recovery_timeout_seconds=1)
    worker=OutboxWorker(store,handlers={"d":lambda item: delivered.append(item.event_id)},circuit_breakers={"d":breaker})
    assert worker.run_once()["delivered"]==1
    assert len(delivered)==2
