# Agent-ROI

Agent-ROI is an enterprise control and value layer for Python agent workflows. It governs which registered tools may execute, distributes signed policies, authenticates and authorizes operators, routes payload-bound approvals, records tamper-evident audit evidence, emits enterprise telemetry, and tracks forecast and realized business value.

The package is framework-neutral. It can be embedded in custom Python applications or used through adapters for common agent and cloud platforms.

## Security boundary

Agent-ROI 2.0 assumes **trusted in-process Python application code**. All external actions must pass through `SentinelContext.call_tool()` or `SentinelContext.acall_tool()` and a frozen `ToolRegistry`.

Agent-ROI is not a sandbox for hostile Python, generated plugins, arbitrary native extensions, or untrusted executables. Isolate those workloads in a separate process, container, or microVM and expose only controlled RPC tools to Agent-ROI.

## Enterprise capabilities

| Area | Included in 2.0.0 |
|---|---|
| Central policy and control plane | Signed/versioned policy bundles, activation, environment promotion, rollback, deterministic canaries, verified offline cache, agent inventory, heartbeats, REST service and client |
| Enterprise identity | OIDC JWT validation, OIDC discovery/JWKS, SCIM user/group CRUD, durable identity store, static and dynamic RBAC, scoped roles and bindings, organization isolation |
| Framework and platform adapters | OpenAI Agents, LangGraph, LangChain, MCP, Azure AI Foundry, Amazon Bedrock Agents, Vertex AI, Semantic Kernel, AutoGen, Databricks Mosaic AI, generic function calling and controlled HTTPS |
| Observability and SIEM | CloudEvents 1.0, OpenTelemetry spans/metrics, OTLP, Splunk HEC, Elastic, Microsoft Sentinel/Azure Log Analytics, Datadog, CloudWatch Logs and generic HTTPS sinks |
| Central audit | Transactional SQLite, cross-process JSONL, PostgreSQL multi-host chains, remote central audit client, chain verification and canonical JSONL export |
| Enterprise approvals | Durable approval broker, separation of duties, ServiceNow, Jira Service Management, Slack, Microsoft Teams, PagerDuty, SMTP and generic webhook providers |
| Realized ROI ledger | Baseline, forecast, realized and validated value; evidence deduplication; cost ledger; lifecycle transitions; net validated value and centralized APIs |

## Installation

Base runtime:

```bash
pip install agent-roi
```

Complete enterprise dependency set:

```bash
pip install "agent-roi[enterprise]"
```

Focused extras:

```bash
pip install "agent-roi[identity]"
pip install "agent-roi[control-plane]"
pip install "agent-roi[observability]"
pip install "agent-roi[postgres]"
pip install "agent-roi[aws]"
pip install "agent-roi[azure]"
pip install "agent-roi[gcp]"
```

The distribution name is `agent-roi`; the import name is `agent_roi`.

```python
import agent_roi
print(agent_roi.__version__)
```

## Controlled runtime

```python
from agent_roi import ConfidenceInputs, Guardrails, SentinelRunner, ToolRegistry


def lookup_invoice(invoice_id: str) -> dict[str, str]:
    return {"invoice_id": invoice_id, "status": "approved"}


registry = ToolRegistry()
registry.add(
    "lookup_invoice",
    lookup_invoice,
    version="1.0",
    risk="low",
    default_cost_usd=0.001,
)

runner = SentinelRunner(
    name="invoice-agent",
    guardrails=Guardrails(
        max_steps=10,
        max_tool_calls=10,
        max_cost_usd=1.00,
        allowed_tools=frozenset({"lookup_invoice"}),
        require_registered_tools=True,
    ),
    tool_registry=registry,
)


def agent(ctx, payload):
    output = ctx.call_tool("lookup_invoice", payload["invoice_id"])
    confidence = ConfidenceInputs(
        prob=0.99,
        margin=0.90,
        z_score=3.0,
        entropy=0.05,
        llm_self_score=0.95,
    )
    return output, confidence


result = runner.run(agent, {"invoice_id": "INV-123"})
print(result.outcome.value, result.output)
```

Registered costs are authoritative minimums. Agent code cannot lower a registered default or estimator-derived reservation. Tool registries and runtime control references are frozen before execution.

## Central control plane

The included control plane is self-hosted and supports either single-node SQLite or multi-node PostgreSQL repositories for policy, identity, audit and ROI services. PostgreSQL migrations, optimistic revisions, paginated APIs and durable delivery workers are included in 2.0.

Generate a signing key and run the service:

```bash
export AGENT_ROI_POLICY_SIGNING_KEY='replace-with-at-least-32-random-bytes'
agent-roi-control-plane \
  --host 127.0.0.1 \
  --port 8080 \
  --data-dir ./agent-roi-data \
  --allow-unauthenticated
```

`--allow-unauthenticated` is intended only for isolated development. Production deployments should configure OIDC:

```bash
agent-roi-control-plane \
  --host 0.0.0.0 \
  --port 8080 \
  --signing-key-file /run/secrets/agent-roi-policy-key \
  --oidc-issuer https://id.example.com \
  --oidc-audience agent-roi
```

Unprefixed signing-key environment values are treated as raw bytes. Prefix a Base64-encoded key with `base64:`. Prefer a mounted secret file or a custom `PolicySigner` backed by KMS/HSM for higher-assurance deployments.

On the first authenticated deployment, the OIDC token used for administration must include the `platform_admin` role in the configured roles claim. That role can then create durable SCIM users, groups, custom roles and scoped bindings.

### Publish and activate a signed policy

```python
from agent_roi.enterprise import ControlPlaneClient, HMACPolicySigner
from agent_roi.policies import load_policy

signer = HMACPolicySigner(b"replace-with-at-least-32-random-bytes", key_id="prod-key")
client = ControlPlaneClient(
    "https://agent-roi.example.com",
    bearer_token="OIDC_ACCESS_TOKEN",
    signer=signer,
)

policy = load_policy("finops_policy.yaml")
bundle = client.publish_policy(
    organization_id="acme",
    name="finops",
    environment="dev",
    version="2.0.0",
    policy=policy.data,
    created_by="policy-admin",
)
client.activate_policy("acme", "finops", "dev", bundle.version)
client.promote_policy(
    organization_id="acme",
    name="finops",
    source_environment="dev",
    source_version=bundle.version,
    target_environment="prod",
    activate=True,
)
```

The client verifies signed bundles when a signer is supplied. `PolicyBundleCache` and `CachedControlPlaneClient` support explicit, age-bounded offline operation.

### Enterprise runtime from centralized policy

```python
from agent_roi.enterprise.runtime import EnterpriseSentinelRunner

runner = EnterpriseSentinelRunner.from_control_plane(
    control_plane_client=client,
    organization_id="acme",
    environment="prod",
    agent_id="invoice-agent",
    policy_name="invoice-policy",
    tool_registry=registry,
    principal=principal,
    authorizer=authorizer,
    heartbeat_fail_closed=True,
)
```

The runner resolves the assigned active or canary policy, verifies its signature, sends agent heartbeats, and applies identity-aware tool authorization.

## OIDC, SCIM and RBAC

OIDC validation verifies issuer, audience, signature, required claims and expiration. When no explicit JWKS URL is supplied, Agent-ROI uses standard OIDC discovery and requires an HTTPS `jwks_uri`.

```python
from agent_roi.enterprise import OIDCConfig, OIDCVerifier

verifier = OIDCVerifier(
    OIDCConfig(
        issuer="https://id.example.com",
        audience="agent-roi",
        organization_claim="org_id",
        roles_claim="roles",
        groups_claim="groups",
    ),
    role_mapping={"Finance Approvers": ["finance_approver"]},
)
principal = verifier.verify_authorization_header("Bearer eyJ...")
```

RBAC supports wildcard permissions and optional organization, environment, subject and group scopes. `SqliteIdentityStore` provides durable SCIM and role/binding administration for a single control-plane node; `DynamicRBACAuthorizer` reloads current roles and bindings on each decision.

Representative permissions include:

```text
policy.publish:*
policy.activate:*
agent.register:*
tool.execute:lookup_invoice
approval.decide:*
audit.read:*
roi.write:*
```

The FastAPI service exposes SCIM 2.0-style user/group endpoints and centralized role/binding administration. Organization identifiers in authenticated paths are checked against the authenticated principal to prevent cross-tenant access.

## Framework and platform adapters

Adapters normalize external tool-call formats into registered Agent-ROI executions. They intentionally use duck typing so framework packages remain optional.

```python
from agent_roi.adapters import LangChainAdapter, bind_context

with bind_context(ctx):
    adapter = LangChainAdapter(ctx)
    result = adapter.invoke_tool("lookup_invoice", {"invoice_id": "INV-123"})
```

Available adapters:

- `OpenAIAgentsAdapter`
- `LangGraphAdapter`
- `LangChainAdapter`
- `MCPAdapter`
- `AzureAIFoundryAdapter`
- `BedrockAgentsAdapter`
- `VertexAIAdapter`
- `SemanticKernelAdapter`
- `AutoGenAdapter`
- `DatabricksMosaicAIAdapter`
- `FunctionCallAdapter`
- `ControlledHTTPAdapter`
- `@controlled_tool` and `BoundToolExecutor`

The adapters do not install or manage the corresponding platform SDKs. They translate framework requests into the same frozen registry, policy, cost, approval and audit controls used by native Agent-ROI calls.

## OpenTelemetry and SIEM

Runtime events can be emitted as CloudEvents and routed to one or more sinks.

```python
from agent_roi.enterprise import CompositeEventSink, SplunkHECSink, configure_otlp_sink

sink = CompositeEventSink(
    [
        configure_otlp_sink(
            "https://otel-collector.example.com",
            service_name="invoice-agent",
            headers={"Authorization": "Bearer TOKEN"},
        ),
        SplunkHECSink("https://splunk.example.com:8088", "HEC_TOKEN"),
    ],
    fail_closed=False,
)
```

Supported sinks include OTLP/OpenTelemetry, generic CloudEvents over HTTPS, Splunk HEC, Elastic, Azure Log Analytics/Microsoft Sentinel, Datadog and CloudWatch Logs. Plaintext OTLP requires `insecure=True` and should be limited to protected development networks.

## Central audit

Local production deployments can use `SqliteAuditStore`. Multi-host deployments can use PostgreSQL:

```python
from agent_roi.audit import PostgresAuditStore

store = PostgresAuditStore(
    "postgresql://agent_roi:secret@db.example.com/agent_roi",
    table_name="agent_roi_audit_events",
)
```

Each PostgreSQL correlation chain uses a transaction-scoped advisory lock so tail selection and event insertion are atomic across hosts. Verification checks chain links, canonical event hashes and denormalized database columns. `RemoteAuditStore` writes through the central control-plane audit API.

The hash chain is tamper-evident, not independently immutable. For regulated retention, export signed evidence to WORM/object-lock storage and protect database administration separately.

## Approval integrations

Protected tools produce payload-, policy-, tool-version- and expiration-bound checkpoints before execution. `ApprovalBroker` creates durable requests and returns a valid `ApprovalGrant` only after an authorized decision.

```python
from agent_roi.approvals import ApprovalBroker, ServiceNowApprovalProvider, SqliteApprovalRepository

provider = ServiceNowApprovalProvider(
    instance_url="https://acme.service-now.com",
    username="integration-user",
    password="SECRET",
)
broker = ApprovalBroker(
    provider,
    organization_id="acme",
    environment="prod",
    agent_id="invoice-agent",
    requested_by="requester@example.com",
    authorizer=authorizer,
    repository=SqliteApprovalRepository("approvals.sqlite3"),
)
```

Providers are included for ServiceNow, Jira Service Management, Slack, Microsoft Teams, PagerDuty, SMTP and generic webhooks. The surrounding identity system must authenticate approvers. The broker enforces grant binding, expiry and requester/approver separation where configured.

## Realized ROI ledger

```python
from agent_roi.roi import RealizedROILedger

ledger = RealizedROILedger("roi.sqlite3")
opportunity = ledger.create_opportunity(
    organization_id="acme",
    agent_id="invoice-agent",
    business_unit="Finance",
    business_owner="Controller",
    title="Duplicate payment recovery",
    value_type="cost_recovery",
    value_period="one_time",
    baseline_usd=250000,
    forecast_value_usd=30000,
    confidence=0.90,
    source_key="analysis-run-123",
    created_by="finance-analyst",
)
```

The ledger records forecast, realized and validated value separately from model, infrastructure, implementation, human-review and support costs. Evidence keys prevent repeated credit for the same source. Monetary values are stored as integer cents, and summaries reject implicit mixed-currency aggregation.

## Production release automation

The source distribution includes GitHub Actions for Python 3.10-3.13 CI, TestPyPI and PyPI Trusted Publishing, GHCR multi-architecture images, SBOM/provenance attestations, CodeQL and Dependabot. VS Code tasks and PowerShell release scripts are included for Windows operators.

Start with [`docs/VS_CODE_PRODUCTION_RELEASE.md`](docs/VS_CODE_PRODUCTION_RELEASE.md) and complete [`PRODUCTION_RELEASE_CHECKLIST.md`](PRODUCTION_RELEASE_CHECKLIST.md) before tagging the release. The production Helm chart accepts an immutable image digest and supports optional ingress, autoscaling and network-policy resources.

Policy signing can be bootstrapped with HMAC, AWS KMS, Azure Key Vault/Managed HSM, Google Cloud KMS or Vault Transit. Production deployments should prefer workload identity with an asymmetric KMS/HSM key.

## Deployment guidance

- The bundled SQLite repositories remain appropriate for embedded and single-node deployments.
- Use `PostgresControlPlaneStore`, `PostgresIdentityStore`, `PostgresApprovalRepository`, `PostgresROILedger`, `PostgresAuditStore`, `PostgresOutboxStore`, and `PostgresIdempotencyStore` for multi-node services.
- Apply all packaged migrations with `agent-roi-db migrate` before rolling out a new version. Migrations are serialized with a PostgreSQL advisory lock.
- Route remote notifications and telemetry through the durable outbox when delivery must survive process restarts or destination outages.
- Use TLS at every service boundary and customer-managed secret storage.
- Use OIDC and scoped RBAC in production; do not use `--allow-unauthenticated` outside isolated development.
- Use fail-closed policy, heartbeat, telemetry and approval settings for actions whose absence must block execution.
- Pin and verify policy signer keys. Use KMS/HSM-backed asymmetric signing when policy producers and consumers cross trust domains.
- Place the control plane behind an enterprise API gateway or service mesh for rate limiting, mTLS, request-size limits and denial-of-service controls.
- Run untrusted tools outside the Python interpreter.


## Agent-ROI 2.0 enterprise deployability

### PostgreSQL repositories and migrations

```bash
export AGENT_ROI_POSTGRES_DSN='postgresql://agentroi:secret@db.example.com/agentroi?sslmode=require'
agent-roi-db list
agent-roi-db migrate
agent-roi-db status
```

All PostgreSQL-backed repositories accept an isolated schema name and create it before selecting the search path. The migration set provisions policy, inventory, SCIM/RBAC, approvals, ROI, outbox, idempotency and audit tables.

### Durable outbox worker

```bash
export AGENT_ROI_OUTBOX_DESTINATIONS='{"siem":"https://events.example.com/agent-roi"}'
agent-roi-outbox --once
```

The outbox provides transactional enqueueing, idempotent destination keys, leases, retry backoff, circuit-breaker integration, dead-letter handling and `FOR UPDATE SKIP LOCKED` claims for horizontally scaled PostgreSQL workers.

### Runtime resilience

Registered tools can declare retry, circuit-breaker and idempotency controls. Idempotency records bind a key to a canonical request digest, preventing the same key from being reused for a different action. Synchronous handlers must use enforceable process-level timeouts when cancellation is required.

### Workload identity and signing

Agent-ROI includes OAuth client credentials, Azure managed identity, Google metadata identity, SPIFFE identity mapping, AWS KMS, Azure Key Vault/Managed HSM, Google Cloud KMS, Vault Transit and PKCS#11 signer adapters. Cloud SDK dependencies are lazy and available through focused extras.

### Deployment assets

`deployment/` contains a non-root container build, Docker Compose development topology, a hardened Helm chart and AWS/Azure/GCP Terraform reference modules. These assets intentionally require integration with the customer's private networking, ingress, certificate, identity, key and secrets standards.

## CLI and examples

```bash
agent-roi --version
agent-roi-control-plane --version
python examples/demo_finops_cost_governance.py --outdir ./finops-output
python examples/demo_procurement_spend_leakage.py --outdir ./procurement-output
python examples/demo_enterprise_p0.py --outdir ./enterprise-output
```

## Testing

```bash
python -m pip install -e ".[dev]"
pytest
pytest --cov=agent_roi --cov-branch --cov-report=term-missing
```

The v2.0 release gate requires at least **98.00% combined line/branch coverage**. The validated release candidate currently achieves **99.27% statement coverage**, **95.00% branch coverage**, and **98.39% combined coverage** across **268 passing tests**. Coverage is treated as a risk indicator rather than proof of correctness; adversarial, concurrency, integration-contract, packaging, and installed-wheel tests remain mandatory.

See `TEST_RESULTS.md` and `PRODUCTION_VALIDATION.md` for the exact release-candidate validation scope and known environmental limitations.
