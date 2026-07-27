import json
from pathlib import Path

import pytest

from agent_roi import (
    AuditIntegrityError,
    ConfidenceInputs,
    Guardrails,
    JsonlAuditStore,
    SentinelRunner,
    ToolRegistry,
)


def _high_confidence():
    return ConfidenceInputs(
        prob=0.99,
        margin=0.8,
        z_score=3.0,
        entropy=0.05,
        llm_self_score=0.95,
    )


def test_audit_omits_output_by_default_and_records_tool_events(tmp_path: Path):
    path = tmp_path / "audit.jsonl"
    store = JsonlAuditStore(path)
    registry = ToolRegistry()
    registry.add("echo", lambda payload: payload)
    runner = SentinelRunner(
        guardrails=Guardrails(
            allowed_tools=frozenset({"echo"}), require_registered_tools=True
        ),
        audit_store=store,
        tool_registry=registry,
    )

    result = runner.run(
        lambda ctx, payload: (
            ctx.call_tool("echo", payload),
            _high_confidence(),
        ),
        {"secret": "TOP-SECRET", "value": 1},
    )
    assert result.output["secret"] == "TOP-SECRET"
    assert store.verify() >= 8

    raw = path.read_text(encoding="utf-8")
    assert "TOP-SECRET" not in raw
    events = [json.loads(line) for line in raw.splitlines()]
    event_types = {event["event_type"] for event in events}
    assert {"tool_requested", "tool_authorized", "tool_started", "tool_completed"} <= event_types


def test_capture_input_redacts_sensitive_keys(tmp_path: Path):
    path = tmp_path / "audit.jsonl"
    runner = SentinelRunner(
        audit_store=JsonlAuditStore(path),
        capture_input=True,
    )
    runner.run(lambda ctx, payload: "ok", {"token": "abc123"})
    raw = path.read_text(encoding="utf-8")
    assert "abc123" not in raw
    assert "[REDACTED]" in raw


def test_tamper_detection(tmp_path: Path):
    path = tmp_path / "audit.jsonl"
    store = JsonlAuditStore(path)
    SentinelRunner(audit_store=store).run(lambda ctx, payload: "ok", None)
    assert store.verify() > 0

    text = path.read_text(encoding="utf-8").replace('"status":"ok"', '"status":"changed"')
    path.write_text(text, encoding="utf-8")
    with pytest.raises(AuditIntegrityError):
        JsonlAuditStore(path).verify()


def test_malformed_audit_line_is_not_silently_ignored(tmp_path: Path):
    path = tmp_path / "audit.jsonl"
    path.write_text("not-json\n", encoding="utf-8")
    with pytest.raises(AuditIntegrityError, match="Malformed audit JSON"):
        JsonlAuditStore(path).verify()
