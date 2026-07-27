# Agent-ROI 2.0.0 Production Validation

## Disposition

Agent-ROI 2.0.0 passes the local release validation suite for the consolidated enterprise release. It combines centralized policy, identity, approval, audit, observability, adapter and ROI capabilities with scalable repositories, explicit database lifecycle management, durable delivery, execution resilience, enterprise signing, workload identity, API concurrency controls and deployment assets.

Deployment approval remains contingent on environment-specific testing against the customer's PostgreSQL service, identity provider, cloud KMS or HSM, message destinations, container platform, and private networking controls.


## Release naming

All capabilities in this source package are consolidated under version **2.0.0**. Package metadata, runtime version reporting, API headers, Helm chart metadata, examples, QA utilities, test module names, validation documents, wheel metadata and source-distribution metadata use 2.0 naming consistently.

## Validation summary

| Validation | Result |
|---|---:|
| Complete source suite | **278 passed** |
| Warning-as-error suite | **278 passed** |
| Statement coverage | **99.28%** (6,762 / 6,811) |
| Branch coverage | **95.06%** (1,692 / 1,780) |
| Combined coverage | **98.41%** |
| Coverage release gate | **Passed — minimum 98.00%** |
| Python compilation | Passed |
| Standalone 2.0 enterprise QA | **9 checks passed** |
| FinOps demonstration | Passed |
| Procurement demonstration | Passed |
| Enterprise control-plane demonstration | Passed |
| PostgreSQL migration discovery | Passed |
| PostgreSQL repository contract tests | Passed |
| Outbox and dead-letter tests | Passed |
| Resilience and idempotency tests | Passed |
| KMS/HSM signer contract tests | Passed |
| Workload-identity tests | Passed |
| API pagination and concurrency tests | Passed |
| Deployment-manifest static validation | Passed |

## Coverage assurance

The v2.0 test suite was realigned from broad integration coverage to near-complete executable-path coverage. The work reduced uncovered statements from 1,487 to 49 and added tests for failure, validation, timeout, retry, idempotency, approval, audit, reporting, packaging, and optional-integration behavior. No production modules are omitted from coverage measurement.

Coverage does not establish correctness by itself. Release approval therefore also requires warnings-as-errors execution, adversarial controls, concurrency tests, source compilation, example execution, wheel integrity verification, an installed-wheel test pass, and an extracted-source test pass.

## Implemented 2.0 capabilities

1. PostgreSQL control-plane, identity, approval, ROI, audit, outbox, and idempotency repositories with schema isolation and transaction-aware operations.
2. Five ordered, packaged migrations and a dedicated `agent-roi-db` migration command so production application roles do not require DDL privileges.
3. Durable event outbox with leasing, retries, exponential backoff, delivery idempotency, dead-letter handling, and an `agent-roi-outbox` worker.
4. Runtime retry, circuit-breaker, idempotency, execution-budget, and concurrency controls integrated with registered tools.
5. AWS KMS, Azure Key Vault and Managed HSM, Google Cloud KMS, Vault Transit, and PKCS#11 signing adapters.
6. OAuth client credentials, Azure managed identity, Google workload identity, and SPIFFE workload-identity providers.
7. API pagination, correlation and version headers, ETags, revision visibility, and conditional updates.
8. Non-root container build, local PostgreSQL topology, Helm migration/control-plane/outbox workloads, and reference Terraform for AWS, Azure, and Google Cloud.


## Production release automation

The release source now includes protected CI/release workflow definitions, TestPyPI and PyPI Trusted Publishing, GHCR multi-architecture builds, SBOM and provenance attestation, CodeQL, Dependabot, VS Code tasks and deterministic release verification. The Helm chart supports immutable image digests, OIDC-required startup, cloud KMS/Vault signing bootstrap, optional ingress, horizontal autoscaling and network policy.

These files prepare the release but do not create or configure the owner’s GitHub repository, PyPI Trusted Publisher, cloud identities, database, registry, Kubernetes cluster or production secrets. Those actions require the owner’s credentials and approvals and are documented in `docs/VS_CODE_PRODUCTION_RELEASE.md`.

## Operational requirements

- Run migrations as a dedicated deployment job using a database role with schema DDL privileges.
- Run control-plane replicas and outbox workers with restricted runtime roles after migration completion.
- Use managed PostgreSQL backups, point-in-time recovery, connection pooling, monitoring, and tested failover appropriate to the customer's recovery objectives.
- Select and validate the built-in AWS KMS, Azure Key Vault/Managed HSM, Google Cloud KMS or Vault Transit bootstrap, or explicitly accept the HMAC risk.
- Configure OIDC and workload identity; unauthenticated mode is development-only.
- Connect deployment assets to customer-managed private networking, ingress, certificates, secrets, logging, monitoring, and policy controls.
- Treat Agent-ROI as a trusted-code control layer, not as a hostile-code sandbox.
