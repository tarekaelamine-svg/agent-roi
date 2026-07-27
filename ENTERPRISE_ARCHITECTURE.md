# Enterprise architecture

## Logical components

```text
Agent/application
    |
    v
Agent-ROI runtime and adapters
    |-- frozen tool registry and guardrails
    |-- identity-aware authorization
    |-- payload-bound approvals
    |-- confidence and outcome routing
    |
    +--> signed policy control plane
    +--> approval provider / ticket or collaboration system
    +--> audit service / PostgreSQL
    +--> OpenTelemetry and SIEM sinks
    +--> realized ROI ledger
```

## Reference versus scalable components

SQLite repositories support embedded and single-node deployments. Agent-ROI 2.0 adds PostgreSQL repositories for the control plane, identity/RBAC, approvals, ROI, audit, outbox and idempotency records. Packaged migrations are serialized by an advisory lock and support isolated schemas.

Multi-node deployments should run stateless API replicas over PostgreSQL, use multiple outbox workers with `FOR UPDATE SKIP LOCKED`, and externalize signing keys through KMS, Managed HSM, Vault Transit or PKCS#11. Database backup, replication, failover, capacity and tenant-isolation policies remain deployment responsibilities.

## Reliable delivery

External notifications and telemetry can be written to a durable outbox in the same application transaction as the authoritative state change. Workers lease events, apply retries and circuit breakers, and move terminal failures into a dead-letter store. Idempotency keys prevent duplicate delivery records per destination.

## Workload identity

Human control-plane access uses OIDC and RBAC. Service-to-service access can use OAuth client credentials, Azure managed identity, Google metadata identity tokens, or SPIFFE IDs. Workload policies restrict accepted subjects, identity types and attributes.

## Policy lifecycle

1. Validate policy structure.
2. Create a canonical bundle and cryptographic signature.
3. Publish an immutable version.
4. Activate in an environment or assign through a deterministic canary.
5. Resolve and verify the bundle at the agent runtime.
6. Cache only verified bundles with an explicit age limit.
7. Record heartbeats with policy digest and agent version.
8. Promote or rollback through the central service.

## Identity lifecycle

OIDC authenticates requests. SCIM provisions users and groups. RBAC binds roles to subjects or groups within organization and optional environment scopes. The runtime reuses the resulting `Principal` for per-tool authorization.

## Approval lifecycle

1. A protected tool produces a checkpoint before the handler executes.
2. The checkpoint binds the arguments, tool version, policy and expiration.
3. The approval broker submits a durable external request.
4. An authenticated and authorized approver decides the request.
5. A bound grant is issued and validated on retry.
6. The handler executes only after the grant matches the current action.

## Evidence and telemetry

Audit events use per-correlation hash chains. OpenTelemetry and CloudEvents provide operational telemetry; audit storage provides evidentiary records. These channels are intentionally separate because telemetry systems often sample or retain less data than audit systems.

## ROI lifecycle

Value opportunities progress from forecast through realized and validated stages. Evidence keys prevent duplicate credit. Costs remain separate and are subtracted from validated value to provide net validated ROI.
