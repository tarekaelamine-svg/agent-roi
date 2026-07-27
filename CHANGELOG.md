# Changelog

## 2.0.0

Agent-ROI 2.0.0 is the consolidated enterprise release. It combines centralized governance and production-deployability capabilities in one major release.

### Central policy and control plane

- Added signed and versioned policy bundles with pluggable signing protocols.
- Added policy publication, activation, environment promotion, rollback and deterministic percentage canaries.
- Added verified on-disk policy caching with explicit maximum staleness and offline behavior.
- Added agent inventory, status, version and policy heartbeats.
- Added a dependency-light HTTP client and a secured FastAPI reference service.
- Added organization-path isolation and centralized policy, agent, audit, identity and ROI APIs.
- Added an `agent-roi-control-plane` launcher with OIDC enforcement by default.

### Enterprise repositories and database lifecycle

- Added PostgreSQL repositories for control-plane policy and inventory, SCIM/RBAC identity, approvals, realized ROI, central audit, durable outbox and idempotency data.
- Added five ordered, packaged PostgreSQL migrations with isolated-schema support and advisory-locked execution.
- Added revision-based optimistic concurrency, paginated queries and explicit migration/runtime database-role separation.
- Added the `agent-roi-db` migration command and controlled `--auto-migrate` support for non-production use.

### Identity and authorization

- Added OIDC JWT verification for issuer, audience, expiration, required claims and signed algorithms.
- Added standard OIDC discovery and secure JWKS resolution.
- Added SCIM-style user and group CRUD with durable SQLite and PostgreSQL storage.
- Added static and dynamically reloaded RBAC roles and scoped bindings.
- Added organization, environment, subject and group authorization scopes.
- Added identity-aware runtime tool authorization and audit events.
- Added OAuth client credentials, Azure managed identity, Google metadata identity and SPIFFE workload identity support.

### Enterprise adapters

- Added framework-neutral decorators, bound executors and controlled HTTPS calls.
- Added adapters for OpenAI Agents, LangGraph, LangChain, MCP, Azure AI Foundry, Amazon Bedrock Agents, Vertex AI, Semantic Kernel, AutoGen, Databricks Mosaic AI and generic function-call formats.

### Observability and SIEM

- Added CloudEvents 1.0 runtime envelopes and composite fail-open/fail-closed delivery.
- Added OpenTelemetry spans, counters and histograms plus OTLP trace and metric export.
- Added Splunk HEC, Elastic, Microsoft Sentinel/Azure Log Analytics, Datadog, CloudWatch Logs and generic HTTPS sinks.
- Added secure endpoint validation and explicit opt-in for plaintext OTLP.

### Central audit

- Added PostgreSQL multi-host audit storage with transaction-scoped advisory locks.
- Added remote central-audit HTTP storage.
- Added canonical event verification, denormalized-column tamper detection and JSONL export.
- Added control-plane endpoints for append, tail, verification and ingestion.

### Enterprise approvals

- Added durable approval requests and payload-bound grant replay.
- Added separation-of-duties checks and RBAC-aware approval decisions.
- Added ServiceNow, Jira Service Management, Slack, Microsoft Teams, PagerDuty, SMTP and generic webhook providers.

### Realized ROI

- Added a persistent value ledger for baseline, forecast, realized and validated value.
- Added evidence and source deduplication, integer-cent monetary storage, lifecycle transitions and explicit cost categories.
- Added net validated value calculations and centralized ROI lifecycle APIs.

### Reliable delivery and execution

- Added SQLite and PostgreSQL durable outboxes with leases, retries, dead letters, idempotency keys and horizontally safe `SKIP LOCKED` claims.
- Added retry policies, circuit breakers and SQLite/PostgreSQL idempotency stores integrated with registered-tool execution.
- Added runtime execution-budget and concurrency controls.
- Added the `agent-roi-outbox` worker command.

### Enterprise signing and key management

- Added AWS KMS, Azure Key Vault and Managed HSM, Google Cloud KMS, Vault Transit and PKCS#11 policy-signer adapters.

### API and deployment

- Added pagination, correlation IDs, API-version headers, active-resource revision visibility, conditional mutations and robust ETag parsing.
- Added a non-root container, Docker Compose PostgreSQL topology, hardened Helm workloads and AWS/Azure/GCP Terraform reference assets.
- Added cloud-specific dependency extras and packaged deployment and migration resources.

### Reliability and packaging

- Added deterministic SQLite connection cleanup across enterprise repositories.
- Added strict path and query escaping in the HTTP client.
- Added `identity`, `control-plane`, `observability`, `postgres`, `aws`, `azure`, `gcp` and complete `enterprise` dependency extras.
- Expanded Python 3.10 grammar compatibility and warnings-as-errors validation.

### Coverage and QA hardening

- Increased statement coverage from 77.84% to 99.28% and branch coverage to 95.06%.
- Added a 98.00% combined coverage release gate.
- Expanded the suite from 171 to 278 tests with targeted validation of failure, defensive, async, timeout, idempotency, approval, audit, reporting, artifact, adapter, telemetry and control-plane paths.
- Fixed postponed-annotation resolution in OpenAI tool schemas, malformed ROI API request handling, conditional agent-update support, PostgreSQL audit JSON error normalization and finite monetary validation.

### Production release and deployment automation

- Added Python 3.10-3.13 GitHub Actions CI with the enforced 98% combined coverage gate.
- Added TestPyPI and PyPI Trusted Publishing workflows, tag/version verification and GitHub release creation.
- Added multi-architecture GHCR publication with SBOM generation and provenance attestations.
- Added CodeQL, Dependabot, pull-request controls and release-oriented repository templates.
- Added VS Code tasks, Windows PowerShell and POSIX release-preparation scripts, deterministic artifact validation and SHA-256 manifests.
- Added immutable image-digest support, optional ingress, autoscaling, network policy and production values to the Helm chart.
- Added direct control-plane bootstrap for HMAC, AWS KMS, Azure Key Vault/Managed HSM, Google Cloud KMS and Vault Transit policy signing.
- Added a complete VS Code production-release runbook and operator checklist.

### Validation

- Expanded the release suite beyond the 1.0 production-hardening baseline with control-plane, OIDC, SCIM, RBAC, adapter, telemetry, central-audit, approval, ROI, migration, PostgreSQL contract, outbox, resilience, signer, workload-identity, API and deployment tests.
- Added live local HTTP service tests, concurrency tests and adversarial regression coverage.

## 1.0.0

- Hardened the trusted in-process control boundary with immutable state, frozen registries, authoritative costs, payload-bound approvals, transactional auditing, async support, safe artifacts and deduplicated ROI calculations.
- Added 64 production and adversarial regression tests.

## 0.1.5

- Added registered tools, pre-execution approval, cost validation, audit redaction, JSONL verification, corrected confidence scoring, artifact fixes and expanded alpha tests.
