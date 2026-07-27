# Agent-ROI 2.0.0 production push readiness

## Prepared in this release

- Python 3.10-3.13 GitHub Actions CI matrix.
- A mandatory 98% combined line/branch coverage gate.
- Clean wheel and source-distribution build and metadata validation.
- TestPyPI and PyPI Trusted Publishing workflows.
- GitHub release publication from protected version tags.
- GHCR multi-architecture image publication with SBOM and provenance attestation.
- CodeQL and Dependabot configuration.
- VS Code tasks and Windows PowerShell release scripts.
- Non-root production container.
- Helm deployment with immutable image-digest support, migration job, outbox workers,
  health probes, rolling updates, autoscaling, disruption budget, ingress, and network policy.
- PostgreSQL migrations and runtime/migrator privilege separation.
- OIDC enforcement and cloud KMS, managed HSM, or Vault policy-signing bootstrap.
- Production release checklist and VS Code operator runbook.

## Locally verified

- 278 automated tests passed.
- 98.41% combined line/branch coverage; the release threshold is 98.00%.
- Source and installed-wheel test suites passed.
- Wheel dependency and metadata checks passed.
- FinOps, procurement, and enterprise demonstrations passed.
- Nine standalone enterprise QA checks passed.
- Wheel and source distributions rebuilt from the final source.

## Actions that require customer-controlled access

The following cannot be performed from an offline build environment and must be completed
by an authorized repository or platform administrator:

1. Create or select the GitHub repository and configure branch and tag protections.
2. Rename `.github/CODEOWNERS.example` to `.github/CODEOWNERS` and assign real teams.
3. Create GitHub `testpypi` and `pypi` environments with production reviewers.
4. Register GitHub Trusted Publishers in TestPyPI and PyPI.
5. Confirm ownership or maintainer access to the existing `agent-roi` PyPI project.
6. Push the repository and create the signed `v2.0.0` tag.
7. Approve the PyPI deployment and verify the published distributions.
8. Provision PostgreSQL, Kubernetes, DNS, TLS, OIDC, registry, KMS/HSM, SIEM, and outbox destinations.
9. Replace all placeholders in `values-production.example.yaml` and configure secret-manager synchronization.
10. Run migration, backup/restore, failover, identity, signing, network, load, and rollback tests in the customer environment.
11. Approve and execute the staged production canary.

## Release boundary

The release is ready for repository publication and environment-specific staging. It must not
be described as fully deployed until the customer-controlled infrastructure and live integration
checks above have passed and the production change record has been approved.
