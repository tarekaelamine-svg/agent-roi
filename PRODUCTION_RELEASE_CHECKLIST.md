# Agent-ROI 2.0 production release checklist

## Repository and package

- [ ] Source is committed to a protected GitHub repository.
- [ ] CI passes on Python 3.10-3.13.
- [ ] Combined coverage is at least 98%.
- [ ] Wheel and source distribution pass `twine check`.
- [ ] Clean-wheel installation and `pip check` pass.
- [ ] TestPyPI installation passes.
- [ ] PyPI Trusted Publisher is configured for `release.yml` and environment `pypi`.
- [ ] Signed tag `v2.0.0` is approved.

## Container and supply chain

- [ ] GHCR image is built from the release tag.
- [ ] Multi-architecture digest is recorded.
- [ ] SBOM and provenance attestation exist.
- [ ] Image vulnerability scan meets policy.
- [ ] Helm values use the immutable digest.

## Infrastructure

- [ ] PostgreSQL backup, restore, PITR, failover, and capacity tests pass.
- [ ] Migration and runtime database roles are separated.
- [ ] OIDC, RBAC, and workload identity are validated against production providers.
- [ ] KMS/HSM or Vault signing is validated, including key rotation.
- [ ] Kubernetes network policy, ingress TLS, egress controls, and secrets delivery are approved.
- [ ] Outbox outage, retry, replay, and dead-letter tests pass.

## Rollout

- [ ] Staging uses the production image digest.
- [ ] Staging smoke and adversarial tests pass.
- [ ] Rollback is rehearsed.
- [ ] Production change record has approvers, owner, monitoring window, and rollback owner.
- [ ] Canary cohort and success thresholds are defined.
