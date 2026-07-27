# Agent-ROI 2.0 deployment assets

The deployment directory provides reference assets for a self-hosted Agent-ROI control plane.

## Contents

- `docker/`: non-root wheel-based container build and a local PostgreSQL topology.
- `helm/agent-roi/`: migration job, control-plane deployment, outbox worker, service, service account, and disruption budget.
- `terraform/aws/`: Aurora PostgreSQL, KMS, and Secrets Manager reference resources.
- `terraform/azure/`: PostgreSQL Flexible Server, Key Vault/Managed HSM signing key, and identity assignments.
- `terraform/gcp/`: HA Cloud SQL PostgreSQL, Cloud KMS HSM signing key, and Secret Manager.

## Database lifecycle

Production deployments should separate migration and runtime privileges:

```bash
agent-roi-db migrate \
  --dsn "$AGENT_ROI_POSTGRES_DSN" \
  --schema agent_roi

agent-roi-db status \
  --dsn "$AGENT_ROI_POSTGRES_DSN" \
  --schema agent_roi
```

The Helm migration job performs this step before normal workloads. `agent-roi-control-plane --auto-migrate` exists for controlled development or single-instance environments and should not replace a dedicated production migration job.

## Durable delivery

Run the outbox worker independently from the API service:

```bash
agent-roi-outbox \
  --dsn "$AGENT_ROI_POSTGRES_DSN" \
  --schema agent_roi \
  --destinations-json '{"audit":"https://events.example/audit"}'
```

Use multiple workers for throughput; PostgreSQL row leasing uses `FOR UPDATE SKIP LOCKED` to prevent duplicate claims.

## Production integration requirements

These assets intentionally omit public ingress and customer-specific network topology. Connect them to existing controls for:

- Private networking and database connectivity
- OIDC and workload identity
- TLS certificates and ingress policy
- KMS/HSM access and key rotation
- Secret delivery
- Database pooling, backups, and failover
- Central logging, metrics, tracing, and alerting
- Container admission and image-signing policy
- Egress controls for outbox destinations

The Terraform modules are reference modules and assume customer networking prerequisites such as private DNS, delegated subnets, or private service access are supplied by the surrounding platform.

## Immutable images and release automation

Set `image.digest` in Helm values to deploy an immutable GHCR manifest. When a digest is present, the chart renders `repository@sha256:...`; otherwise it falls back to `repository:tag`. `values-production.example.yaml` documents production-required settings.

The release workflows publish a multi-architecture image with an SBOM and GitHub provenance attestation. Validate the digest in staging and use the identical digest in production.

## Policy signing providers

Set `signing.provider` to one of `hmac`, `aws-kms`, `azure-key-vault`, `gcp-kms`, or `vault-transit`. Cloud KMS modes use the pod's workload identity. Vault Transit reads its token from the configured Kubernetes secret. HMAC remains supported for private deployments but requires direct secret delivery.

The production container installs the `enterprise` extra so all bundled cloud signer bootstraps are available.
