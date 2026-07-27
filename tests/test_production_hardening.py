from __future__ import annotations

import asyncio
import csv
from dataclasses import FrozenInstanceError
from datetime import datetime, timezone
import json
import multiprocessing as mp
from pathlib import Path
import subprocess
import sys
import time

import pytest

from agent_roi import (
    ApprovalGrant,
    ConfidenceInputs,
    DecisionOutcome,
    GuardrailViolation,
    Guardrails,
    JsonlAuditStore,
    SqliteAuditStore,
    SentinelRunner,
    ToolRegistry,
)
from agent_roi.finops import FinOpsAnalyzer
from agent_roi.policies import PolicyValidationError, load_policy
from agent_roi.procurement import ProcurementLeakageAnalyzer
from agent_roi.roi.report import build_procurement_roi_report
from agent_roi.runtime.artifacts import create_artifact_dir


def _high_confidence() -> ConfidenceInputs:
    return ConfidenceInputs(
        prob=0.99,
        margin=0.8,
        z_score=3.0,
        entropy=0.05,
        llm_self_score=0.95,
    )


def _audit_record_worker(path: str, queue: mp.Queue) -> None:
    try:
        event = JsonlAuditStore(path).record(
            correlation_id="shared",
            run_id=f"run-{mp.current_process().pid}",
            event_type="worker",
            payload={"pid": mp.current_process().pid},
        )
        queue.put(("ok", event.event_id))
    except Exception as exc:  # pragma: no cover - assertion reports details
        queue.put(("error", type(exc).__name__, str(exc)))



def _sqlite_record_worker(path: str, queue: mp.Queue) -> None:
    try:
        event = SqliteAuditStore(path).record(
            correlation_id="shared",
            run_id=f"run-{mp.current_process().pid}",
            event_type="worker",
            payload={"pid": mp.current_process().pid},
        )
        queue.put(("ok", event.event_id))
    except Exception as exc:  # pragma: no cover
        queue.put(("error", type(exc).__name__, str(exc)))


def test_agent_cannot_reassign_controls_or_reset_state() -> None:
    calls: list[str] = []
    registry = ToolRegistry()
    registry.add("safe", lambda: calls.append("safe") or "safe")
    runner = SentinelRunner(
        guardrails=Guardrails(
            max_tool_calls=1,
            allowed_tools=frozenset({"safe"}),
            require_registered_tools=True,
        ),
        tool_registry=registry,
    )

    def agent(ctx, payload):
        with pytest.raises(AttributeError):
            ctx.guardrails = None
        with pytest.raises(AttributeError):
            ctx.tool_registry = None
        with pytest.raises(FrozenInstanceError):
            ctx.state.tool_calls = 0
        assert ctx.call_tool("safe") == "safe"
        with pytest.raises(GuardrailViolation):
            ctx.call_tool("safe")
        return "done", _high_confidence()

    result = runner.run(agent, None)
    assert calls == ["safe"]
    assert result.ctx_snapshot["state"]["tool_calls"] == 1


def test_registered_cost_is_a_non_bypassable_minimum() -> None:
    executed: list[bool] = []
    registry = ToolRegistry()
    registry.add(
        "expensive",
        lambda: executed.append(True) or "ok",
        default_cost_usd=10.0,
    )
    runner = SentinelRunner(
        guardrails=Guardrails(
            max_cost_usd=20.0,
            allowed_tools=frozenset({"expensive"}),
            require_registered_tools=True,
        ),
        tool_registry=registry,
    )
    with pytest.raises(GuardrailViolation, match="cannot be lower"):
        runner.run(lambda ctx, payload: ctx.call_tool("expensive", cost_usd=0.0), None)
    assert executed == []


def test_approval_checkpoint_is_bound_to_payload_and_policy() -> None:
    registry = ToolRegistry()
    registry.add(
        "delete",
        lambda record: "deleted",
        version="2026-07",
        risk="high",
        requires_approval=True,
    )
    runner = SentinelRunner(
        guardrails=Guardrails(
            allowed_tools=frozenset({"delete"}), require_registered_tools=True
        ),
        tool_registry=registry,
    )
    a = runner.run(lambda ctx, payload: ctx.call_tool("delete", payload), {"id": "A"})
    b = runner.run(lambda ctx, payload: ctx.call_tool("delete", payload), {"id": "B"})
    checkpoint_a = a.output["approval_checkpoint"]
    checkpoint_b = b.output["approval_checkpoint"]
    assert checkpoint_a["action_digest"] != checkpoint_b["action_digest"]
    assert checkpoint_a["arguments_digest"] != checkpoint_b["arguments_digest"]
    assert checkpoint_a["tool_version"] == "2026-07"
    assert checkpoint_a["policy_digest"] == runner.policy_digest
    assert checkpoint_a["expires_at_epoch_ms"] > checkpoint_a["created_at_epoch_ms"]


def test_payload_bound_approval_grant_allows_exact_action() -> None:
    executed: list[str] = []
    registry = ToolRegistry()
    registry.add(
        "delete",
        lambda record_id: executed.append(record_id) or "deleted",
        risk="high",
        requires_approval=True,
    )

    def approve(spec, args, kwargs, checkpoint):
        return ApprovalGrant(
            action_digest=checkpoint["action_digest"],
            checkpoint_id=checkpoint["checkpoint_id"],
            approved_by="qa-approver",
            expires_at_epoch_ms=checkpoint["expires_at_epoch_ms"],
            reason="validated",
        )

    runner = SentinelRunner(
        guardrails=Guardrails(
            allowed_tools=frozenset({"delete"}), require_registered_tools=True
        ),
        tool_registry=registry,
        approval_callback=approve,
    )
    result = runner.run(lambda ctx, payload: ctx.call_tool("delete", payload), "R-1")
    assert result.output == "deleted"
    assert executed == ["R-1"]


def test_audit_record_is_atomic_across_processes(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    context = mp.get_context("spawn")
    queue = context.Queue()
    processes = [context.Process(target=_audit_record_worker, args=(str(path), queue)) for _ in range(4)]
    for process in processes:
        process.start()
    for process in processes:
        process.join(10)
        assert process.exitcode == 0
    results = [queue.get(timeout=5) for _ in processes]
    assert all(result[0] == "ok" for result in results)
    assert JsonlAuditStore(path).verify() == 4


def test_audit_serializes_datetime_metadata(tmp_path: Path) -> None:
    store = JsonlAuditStore(tmp_path / "audit.jsonl")
    runner = SentinelRunner(
        audit_store=store,
        metadata={"as_of": datetime(2026, 7, 26, tzinfo=timezone.utc)},
    )
    runner.run(lambda ctx, payload: "ok", None)
    assert store.verify() == 4
    assert "2026-07-26T00:00:00+00:00" in (tmp_path / "audit.jsonl").read_text()


def test_procurement_csv_neutralizes_formulas(tmp_path: Path) -> None:
    analyzer = ProcurementLeakageAnalyzer(load_policy("procurement_policy.yaml"), {})
    output = {
        "recommendations": [
            {
                "record_id": "1",
                "vendor": '=HYPERLINK("http://example.invalid")',
                "invoice_id": "+1+1",
                "business_unit": "@cmd",
                "finding_type": "test",
                "action": "duplicate_invoice",
                "risk": "high",
                "approval_status": "review",
                "gross_est_recoverable_value_usd": 100,
                "overlap_adjustment_usd": 0,
                "est_recoverable_value_usd": 100,
                "rationale": "-10+20",
            }
        ]
    }
    path = analyzer.export_recommendations_csv(output, tmp_path / "procurement.csv")
    with path.open(encoding="utf-8") as handle:
        row = next(csv.DictReader(handle))
    assert row["vendor"].startswith("'")
    assert row["invoice_id"].startswith("'")
    assert row["business_unit"].startswith("'")
    assert row["rationale"].startswith("'")


def test_finops_csv_neutralizes_formulas(tmp_path: Path) -> None:
    analyzer = FinOpsAnalyzer(load_policy("finops_policy.yaml"), {})
    output = {
        "recommendations": [
            {
                "resource_id": "=1+1",
                "resource_type": "ec2",
                "environment": "prod",
                "owner": "@owner",
                "action": "rightsizing_recommendation",
                "risk": "low",
                "approval_status": "review",
                "est_monthly_savings_usd": 100,
                "rationale": "+formula",
            }
        ]
    }
    path = analyzer.export_recommendations_csv(output, tmp_path / "finops.csv")
    with path.open(encoding="utf-8") as handle:
        row = next(csv.DictReader(handle))
    assert row["resource_id"].startswith("'")
    assert row["owner"].startswith("'")
    assert row["rationale"].startswith("'")


def test_procurement_recovery_is_deduplicated_and_capped() -> None:
    analyzer = ProcurementLeakageAnalyzer(
        load_policy("procurement_policy.yaml"), {"environment": "production"}
    )
    invoices = [
        {
            "record_id": "1",
            "vendor": "UNAPPROVED",
            "invoice_id": "INV-1",
            "amount_usd": 5200,
            "sku": "SKU",
            "qty": 500,
            "unit_price_usd": 20,
        },
        {
            "record_id": "2",
            "vendor": "UNAPPROVED",
            "invoice_id": "INV-1",
            "amount_usd": 5200,
            "sku": "SKU",
            "qty": 500,
            "unit_price_usd": 20,
        },
    ]
    output = analyzer.analyze(
        {
            "approved_vendors": [],
            "baseline_unit_prices": {"SKU": 10},
            "invoices": invoices,
        }
    )
    total = output["summary"]["est_total_recoverable_value_usd"]
    assert total <= sum(invoice["amount_usd"] for invoice in invoices)
    assert total == sum(
        recommendation["est_recoverable_value_usd"]
        for recommendation in output["recommendations"]
    )
    assert any(
        recommendation["overlap_adjustment_usd"] > 0
        for recommendation in output["recommendations"]
    )
    assert all(
        recommendation["approval_status"] == "procurement_approval_required"
        for recommendation in output["recommendations"]
        if recommendation["risk"] in {"med", "high"}
    )


def test_missing_invoice_ids_are_not_classified_as_duplicates() -> None:
    analyzer = ProcurementLeakageAnalyzer(load_policy("procurement_policy.yaml"), {})
    output = analyzer.analyze(
        {
            "approved_vendors": ["A"],
            "baseline_unit_prices": {},
            "invoices": [
                {"record_id": "1", "vendor": "A", "invoice_id": "", "amount_usd": 2000},
                {"record_id": "2", "vendor": "A", "invoice_id": "", "amount_usd": 2000},
            ],
        }
    )
    actions = [item["action"] for item in output["recommendations"]]
    assert "duplicate_invoice" not in actions
    assert actions.count("missing_invoice_id") == 2


def test_approved_vendors_string_is_rejected() -> None:
    analyzer = ProcurementLeakageAnalyzer(load_policy("procurement_policy.yaml"), {})
    with pytest.raises(TypeError, match="approved_vendors"):
        analyzer.analyze(
            {"approved_vendors": "ACME", "baseline_unit_prices": {}, "invoices": []}
        )


def test_malformed_nested_policy_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text(
        """
guardrails:
  max_steps: 1
  max_tool_calls: 1
  max_cost_usd: 1
decision_policy:
  min_confidence: 0.5
thresholds: []
scoring:
  savings_multipliers: []
""",
        encoding="utf-8",
    )
    with pytest.raises(PolicyValidationError, match="thresholds"):
        load_policy("unused.yaml", override_path=path)


def test_async_agent_and_tool_execute_with_timeout_support() -> None:
    registry = ToolRegistry()

    async def double(value: int) -> int:
        await asyncio.sleep(0)
        return value * 2

    registry.add("double", double, timeout_seconds=0.5)
    runner = SentinelRunner(
        guardrails=Guardrails(
            allowed_tools=frozenset({"double"}), require_registered_tools=True
        ),
        tool_registry=registry,
        run_timeout_seconds=1.0,
    )

    async def agent(ctx, payload):
        return await ctx.acall_tool("double", payload), _high_confidence()

    result = asyncio.run(runner.arun(agent, 4))
    assert result.output == 8
    assert result.outcome is DecisionOutcome.ACCEPT


def test_sync_runner_rejects_async_tool_before_execution() -> None:
    executed: list[bool] = []

    async def async_tool() -> str:
        executed.append(True)
        return "ok"

    registry = ToolRegistry()
    registry.add("async_tool", async_tool)
    runner = SentinelRunner(
        guardrails=Guardrails(
            allowed_tools=frozenset({"async_tool"}), require_registered_tools=True
        ),
        tool_registry=registry,
    )
    with pytest.raises(GuardrailViolation, match="asynchronous"):
        runner.run(lambda ctx, payload: ctx.call_tool("async_tool"), None)
    assert executed == []


def test_async_tool_timeout_is_enforced() -> None:
    async def slow() -> None:
        await asyncio.sleep(0.2)

    registry = ToolRegistry()
    registry.add("slow", slow, timeout_seconds=0.01)
    runner = SentinelRunner(
        guardrails=Guardrails(
            allowed_tools=frozenset({"slow"}), require_registered_tools=True
        ),
        tool_registry=registry,
    )

    async def agent(ctx, payload):
        return await ctx.acall_tool("slow")

    with pytest.raises(asyncio.TimeoutError):
        asyncio.run(runner.arun(agent, None))


def test_nonempty_artifact_directory_is_rejected_unless_explicitly_cleaned(tmp_path: Path) -> None:
    path = create_artifact_dir("demo", tmp_path / "run")
    (path / "manifest.json").write_text("{}", encoding="utf-8")
    with pytest.raises(FileExistsError, match="not empty"):
        create_artifact_dir("demo", path)
    recreated = create_artifact_dir("demo", path, clean_known_artifacts=True)
    assert recreated == path
    assert list(path.iterdir()) == []


def test_markdown_table_values_are_escaped() -> None:
    class Result:
        outcome = DecisionOutcome.ACCEPT
        confidence = 0.9
        correlation_id = "corr"
        run_id = "run"
        ctx_snapshot = {"state": {"cost_usd": 1.0}}

    output = {
        "summary": {
            "currency": "EUR",
            "num_records_scanned": 1,
            "num_recommendations": 1,
            "est_total_recoverable_value_usd": 10,
        },
        "recommendations": [
            {
                "record_id": "A|B",
                "vendor": "Vendor|Name",
                "action": "review|hold",
                "risk": "high",
                "est_recoverable_value_usd": 10,
                "rationale": "Line one|line two",
            }
        ],
    }
    markdown = build_procurement_roi_report(
        sentinel_result=Result(), agent_output=output
    ).to_markdown()
    assert "A\\|B" in markdown
    assert "Vendor\\|Name" in markdown
    assert "Line one\\|line two" in markdown
    assert "€10.00" in markdown


def test_example_cli_honors_outdir(tmp_path: Path) -> None:
    outdir = tmp_path / "example"
    process = subprocess.run(
        [
            sys.executable,
            "examples/demo_procurement_spend_leakage.py",
            "--outdir",
            str(outdir),
        ],
        cwd=Path(__file__).resolve().parents[1],
        text=True,
        capture_output=True,
        check=True,
    )
    assert outdir.is_dir()
    assert (outdir / "manifest.json").is_file()
    assert str(outdir) in process.stdout


def test_runner_freezes_tool_registry() -> None:
    registry = ToolRegistry()
    registry.add("safe", lambda: "ok")
    SentinelRunner(
        guardrails=Guardrails(
            allowed_tools=frozenset({"safe"}), require_registered_tools=True
        ),
        tool_registry=registry,
    )
    assert registry.is_frozen is True
    with pytest.raises(Exception, match="frozen"):
        registry.add("late", lambda: "late")


def test_policy_can_require_payload_bound_approval_grants() -> None:
    executed: list[bool] = []
    registry = ToolRegistry()
    registry.add(
        "danger",
        lambda: executed.append(True),
        risk="high",
        requires_approval=True,
    )
    runner = SentinelRunner(
        guardrails=Guardrails(
            allowed_tools=frozenset({"danger"}),
            require_registered_tools=True,
            require_bound_approval_grants=True,
        ),
        tool_registry=registry,
        approval_callback=lambda spec, args, kwargs: True,
    )
    with pytest.raises(GuardrailViolation, match="ApprovalGrant"):
        runner.run(lambda ctx, payload: ctx.call_tool("danger"), None)
    assert executed == []


def test_async_wrapper_rejects_false_timeout_for_sync_handler() -> None:
    registry = ToolRegistry()
    registry.add("sync", lambda: "ok", timeout_seconds=0.01)
    runner = SentinelRunner(
        guardrails=Guardrails(
            allowed_tools=frozenset({"sync"}), require_registered_tools=True
        ),
        tool_registry=registry,
    )

    async def agent(ctx, payload):
        return await ctx.acall_tool("sync")

    with pytest.raises(GuardrailViolation, match="cannot cancel"):
        asyncio.run(runner.arun(agent, None))


def test_sync_run_timeout_interrupts_on_supported_platform() -> None:
    if not hasattr(__import__("signal"), "SIGALRM"):
        pytest.skip("SIGALRM is unavailable")
    runner = SentinelRunner(run_timeout_seconds=0.02)
    with pytest.raises(TimeoutError, match="exceeded"):
        runner.run(lambda ctx, payload: time.sleep(0.2), None)


def test_sqlite_audit_is_atomic_across_processes_and_exports_jsonl(tmp_path: Path) -> None:
    path = tmp_path / "audit.sqlite3"
    context = mp.get_context("spawn")
    queue = context.Queue()
    processes = [
        context.Process(target=_sqlite_record_worker, args=(str(path), queue))
        for _ in range(6)
    ]
    for process in processes:
        process.start()
    for process in processes:
        process.join(10)
        assert process.exitcode == 0
    results = [queue.get(timeout=5) for _ in processes]
    assert all(result[0] == "ok" for result in results)
    store = SqliteAuditStore(path)
    assert store.verify() == 6
    exported = store.export_jsonl(tmp_path / "audit.jsonl")
    assert len(exported.read_text(encoding="utf-8").splitlines()) == 6


def test_sqlite_audit_detects_database_tampering(tmp_path: Path) -> None:
    import sqlite3

    path = tmp_path / "audit.sqlite3"
    store = SqliteAuditStore(path)
    store.record(
        correlation_id="c", run_id="r", event_type="test", payload={"status": "ok"}
    )
    connection = sqlite3.connect(path)
    try:
        event_json = connection.execute(
            "SELECT event_json FROM audit_events LIMIT 1"
        ).fetchone()[0]
        connection.execute(
            "UPDATE audit_events SET event_json = ? WHERE sequence = 1",
            (event_json.replace('"status":"ok"', '"status":"changed"'),),
        )
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(Exception, match="invalid hash"):
        store.verify()


def test_sqlite_audit_detects_denormalized_column_tampering(tmp_path: Path) -> None:
    import sqlite3

    path = tmp_path / "audit.sqlite3"
    store = SqliteAuditStore(path)
    event = store.record(
        correlation_id="c", run_id="r", event_type="test", payload={"status": "ok"}
    )
    connection = sqlite3.connect(path)
    try:
        connection.execute(
            "UPDATE audit_events SET event_hash = ? WHERE sequence = 1",
            ("0" * 64,),
        )
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(Exception, match="metadata does not match"):
        store.verify()
    assert event.hash != "0" * 64


def test_loaded_policy_is_recursively_immutable() -> None:
    policy = load_policy("finops_policy.yaml")
    with pytest.raises(TypeError):
        policy.data["thresholds"] = {}  # type: ignore[index]
    with pytest.raises(TypeError):
        policy.data["thresholds"]["idle_cpu_pct"] = 99  # type: ignore[index]
