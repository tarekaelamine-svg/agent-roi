from __future__ import annotations

import asyncio

import pytest

from agent_roi import Guardrails, SentinelRunner, ToolRegistry
from agent_roi.runtime import (
    CircuitBreaker,
    CircuitOpenError,
    CircuitState,
    IdempotencyConflict,
    IdempotencyInProgress,
    IdempotencyPolicy,
    RetryPolicy,
    SqliteIdempotencyStore,
    aretry_call,
    retry_call,
)


def test_retry_policy_retries_only_configured_exceptions(monkeypatch) -> None:
    monkeypatch.setattr("agent_roi.runtime.resilience.time.sleep", lambda _: None)
    calls = 0

    def flaky():
        nonlocal calls
        calls += 1
        if calls < 3:
            raise OSError("temporary")
        return "ok"

    assert retry_call(flaky, RetryPolicy(max_attempts=3, jitter_ratio=0)) == "ok"
    assert calls == 3

    with pytest.raises(ValueError):
        retry_call(lambda: (_ for _ in ()).throw(ValueError("permanent")), RetryPolicy())


def test_async_retry_policy_retries_without_blocking(monkeypatch) -> None:
    async def no_sleep(_):
        return None

    monkeypatch.setattr("agent_roi.runtime.resilience.asyncio.sleep", no_sleep)
    calls = 0

    async def flaky():
        nonlocal calls
        calls += 1
        if calls == 1:
            raise TimeoutError("temporary")
        return 7

    assert asyncio.run(aretry_call(flaky, RetryPolicy(max_attempts=2, jitter_ratio=0))) == 7
    assert calls == 2


def test_circuit_breaker_opens_and_recovers_with_single_probe() -> None:
    clock = [0.0]
    breaker = CircuitBreaker(failure_threshold=2, recovery_timeout_seconds=5, clock=lambda: clock[0])
    for _ in range(2):
        with pytest.raises(OSError):
            breaker.call(lambda: (_ for _ in ()).throw(OSError("down")))
    assert breaker.state is CircuitState.OPEN
    with pytest.raises(CircuitOpenError):
        breaker.before_call()
    clock[0] = 6.0
    assert breaker.state is CircuitState.HALF_OPEN
    breaker.before_call()
    with pytest.raises(CircuitOpenError, match="probe"):
        breaker.before_call()
    breaker.record_success()
    assert breaker.state is CircuitState.CLOSED


def test_sqlite_idempotency_store_completed_conflict_and_in_progress(tmp_path) -> None:
    store = SqliteIdempotencyStore(tmp_path / "idem.sqlite3")
    first = store.begin("payments", "key-1", "digest-1", ttl_seconds=60)
    assert first.status == "started"
    with pytest.raises(IdempotencyInProgress):
        store.begin("payments", "key-1", "digest-1", ttl_seconds=60)
    with pytest.raises(IdempotencyConflict):
        store.begin("payments", "key-1", "different", ttl_seconds=60)
    store.complete("payments", "key-1", {"payment": "P-1"})
    replay = store.begin("payments", "key-1", "digest-1", ttl_seconds=60)
    assert replay.status == "completed"
    assert replay.response == {"payment": "P-1"}


def test_tool_resilience_retries_and_suppresses_duplicate_action(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr("agent_roi.runtime.resilience.time.sleep", lambda _: None)
    attempts = 0

    def charge(invoice_id: str):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise OSError("gateway unavailable")
        return {"invoice_id": invoice_id, "status": "paid"}

    store = SqliteIdempotencyStore(tmp_path / "idempotency.sqlite3")
    registry = ToolRegistry()
    registry.add(
        "charge",
        charge,
        retry_policy=RetryPolicy(max_attempts=2, jitter_ratio=0),
        idempotency_policy=IdempotencyPolicy(
            store=store,
            namespace="charge",
            key_factory=lambda args, kwargs: str(args[0]),
        ),
    )
    runner = SentinelRunner(
        guardrails=Guardrails(
            allowed_tools=frozenset({"charge"}), require_registered_tools=True
        ),
        tool_registry=registry,
    )
    first = runner.run(lambda ctx, _: ctx.call_tool("charge", "INV-1"), None)
    second = runner.run(lambda ctx, _: ctx.call_tool("charge", "INV-1"), None)
    assert first.output == second.output == {"invoice_id": "INV-1", "status": "paid"}
    assert attempts == 2


def test_tool_circuit_breaker_blocks_repeated_failures() -> None:
    calls = 0

    def down():
        nonlocal calls
        calls += 1
        raise OSError("down")

    breaker = CircuitBreaker(failure_threshold=1, recovery_timeout_seconds=60)
    registry = ToolRegistry()
    registry.add("down", down, circuit_breaker=breaker)
    runner = SentinelRunner(
        guardrails=Guardrails(allowed_tools=frozenset({"down"}), require_registered_tools=True),
        tool_registry=registry,
    )
    with pytest.raises(OSError):
        runner.run(lambda ctx, _: ctx.call_tool("down"), None)
    with pytest.raises(CircuitOpenError):
        runner.run(lambda ctx, _: ctx.call_tool("down"), None)
    assert calls == 1


def test_async_tool_retry_and_timeout(monkeypatch) -> None:
    async def no_sleep(_):
        return None

    monkeypatch.setattr("agent_roi.runtime.resilience.asyncio.sleep", no_sleep)
    attempts = 0

    async def flaky(value: int):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise TimeoutError("temporary")
        return value * 2

    registry = ToolRegistry()
    registry.add("flaky", flaky, retry_policy=RetryPolicy(max_attempts=2, jitter_ratio=0), timeout_seconds=1)
    runner = SentinelRunner(
        guardrails=Guardrails(allowed_tools=frozenset({"flaky"}), require_registered_tools=True),
        tool_registry=registry,
    )

    async def agent(ctx, _):
        return await ctx.acall_tool("flaky", 4)

    result = asyncio.run(runner.arun(agent, None))
    assert result.output == 8
    assert attempts == 2
