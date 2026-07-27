"""Standalone enterprise regression checks for Agent-ROI 2.0.0.

Run from an extracted source package:
    python qa/agent-roi-2.0.0-enterprise-qa.py
"""
from __future__ import annotations

from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if SRC.is_dir() and str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from agent_roi import Guardrails, SentinelRunner, ToolRegistry, __version__
from agent_roi.db import load_postgres_migrations
from agent_roi.enterprise import (
    AWSKMSPolicySigner,
    HMACPolicySigner,
    SPIFFEIdentityVerifier,
    SqliteControlPlaneStore,
    ControlPlaneService,
)
from agent_roi.enterprise.outbox import OutboxEvent, OutboxWorker, SqliteOutboxStore
from agent_roi.policies import load_policy
from agent_roi.runtime.resilience import (
    CircuitBreaker,
    IdempotencyPolicy,
    RetryPolicy,
    SqliteIdempotencyStore,
)


class FakeKMS:
    def sign(self, **kwargs):
        return {"Signature": b"signed:" + kwargs["Message"]}

    def verify(self, **kwargs):
        return {"SignatureValid": kwargs["Signature"] == b"signed:" + kwargs["Message"]}


def main() -> int:
    checks: list[str] = []
    assert __version__ == "2.0.0"
    checks.append("version")

    migrations = load_postgres_migrations()
    assert [item.version for item in migrations] == [1, 2, 3, 4, 5]
    combined = "\n".join(item.sql for item in migrations)
    for table in (
        "policy_bundles",
        "scim_users",
        "approval_records",
        "roi_opportunities",
        "enterprise_outbox",
        "idempotency_records",
        "agent_roi_audit_events",
    ):
        assert table in combined
    checks.append("migrations")

    with tempfile.TemporaryDirectory(prefix="agent-roi-20-qa-") as directory:
        root = Path(directory)

        signer = HMACPolicySigner(b"enterprise-qa-signing-key-at-least-32-bytes", key_id="qa")
        service = ControlPlaneService(
            SqliteControlPlaneStore(root / "control.sqlite3"),
            signers={"qa": signer},
            default_signer_key_id="qa",
        )
        policy = load_policy("finops_policy.yaml")
        service.publish_policy(
            organization_id="acme",
            name="finops",
            environment="prod",
            version="2.0.0",
            policy=policy.data,
            created_by="qa",
        )
        service.activate_policy(
            organization_id="acme",
            name="finops",
            environment="prod",
            version="2.0.0",
            activated_by="qa",
        )
        assert service.store.get_active_revision("acme", "finops", "prod") == 1
        checks.append("policy_revision")

        # Authoritative retry + circuit-breaker + idempotency behavior.
        calls = {"count": 0}

        def flaky(value: int) -> int:
            calls["count"] += 1
            if calls["count"] == 1:
                raise OSError("transient")
            return value * 2

        registry = ToolRegistry()
        registry.add(
            "flaky",
            flaky,
            retry_policy=RetryPolicy(max_attempts=2, initial_backoff_seconds=0),
            circuit_breaker=CircuitBreaker(failure_threshold=2, recovery_timeout_seconds=1),
            idempotency_policy=IdempotencyPolicy(
                store=SqliteIdempotencyStore(root / "idempotency.sqlite3"),
                namespace="qa",
                key_factory=lambda args, kwargs: str(args[0]),
            ),
        )
        runner = SentinelRunner(
            guardrails=Guardrails(
                allowed_tools=frozenset({"flaky"}),
                require_registered_tools=True,
            ),
            tool_registry=registry,
        )
        first = runner.run(lambda ctx, _: ctx.call_tool("flaky", 21), None)
        second = runner.run(lambda ctx, _: ctx.call_tool("flaky", 21), None)
        assert first.output == second.output == 42
        assert calls["count"] == 2
        checks.append("resilience_idempotency")

        outbox = SqliteOutboxStore(root / "outbox.sqlite3")
        delivered: list[str] = []
        outbox.enqueue(
            OutboxEvent.create(
                topic="telemetry",
                destination="sink",
                payload={"result": "ok"},
                idempotency_key="event-1",
            )
        )
        worker = OutboxWorker(outbox, {"sink": lambda event: delivered.append(event.event_id)})
        outcome = worker.run_once()
        assert outcome == {"claimed": 1, "delivered": 1, "retried": 0, "dead_lettered": 0}
        assert len(delivered) == 1
        checks.append("durable_outbox")

        # Duplicate destination/idempotency key returns the authoritative record.
        duplicate = outbox.enqueue(
            OutboxEvent.create(
                topic="telemetry",
                destination="sink",
                payload={"result": "different"},
                idempotency_key="event-1",
            )
        )
        assert duplicate.event_id == delivered[0]
        checks.append("outbox_idempotency")

    kms = AWSKMSPolicySigner("arn:aws:kms:region:account:key/test", client=FakeKMS())
    signature = kms.sign(b"policy")
    assert kms.verify(b"policy", signature)
    checks.append("external_signer")

    principal = SPIFFEIdentityVerifier(
        trust_domain="example.org",
        organization_id="acme",
        allowed_paths=("/prod/*",),
        roles=("agent_runtime",),
    ).verify("spiffe://example.org/prod/invoice-agent")
    assert principal.organization_id == "acme"
    checks.append("workload_identity")

    deployment = ROOT / "deployment"
    assert (deployment / "docker" / "Dockerfile").is_file()
    assert (deployment / "helm" / "agent-roi" / "Chart.yaml").is_file()
    assert all((deployment / "terraform" / cloud / "main.tf").is_file() for cloud in ("aws", "azure", "gcp"))
    checks.append("deployment_assets")

    print(f"Agent-ROI 2.0.0 enterprise QA: {len(checks)} checks passed")
    for check in checks:
        print(f"  PASS {check}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
