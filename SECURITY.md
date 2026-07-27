# Security policy

## Supported release

Security fixes are maintained for the latest major release. Version 2.0.0 is the supported release represented by this source package.

## Trust boundary

Agent-ROI governs trusted Python application code whose external actions are routed through its registered-tool APIs. It is not an isolation boundary for hostile Python, arbitrary plugins, native extensions or untrusted executables.

Run untrusted code in a separate process, container or microVM with independent filesystem, network, CPU, memory and credential controls.

## Deployment requirements

- Require OIDC authentication and scoped RBAC for the control plane.
- Use HTTPS or mTLS for every network integration.
- Store signing keys, database credentials, API tokens and SMTP credentials in a secrets manager.
- Prefer KMS/HSM-backed asymmetric policy signing across trust domains.
- Use the PostgreSQL repositories for multi-node services; bundled SQLite repositories are single-node implementations.
- Run `agent-roi-db migrate` under a database role authorized to create the configured schema and tables, then reduce runtime privileges according to organizational standards.
- Use durable outbox delivery for remote events whose loss or synchronous destination failure is unacceptable.
- Use short-lived workload identities instead of static service credentials where the target platform supports them.
- Export audit evidence to independently protected immutable storage when regulatory retention requires it.
- Place public or shared deployments behind an API gateway or service mesh with rate limits and request-size controls.
- Review custom adapters, signers, event sinks and repositories as privileged extension points.


## Release and supply-chain controls

- Publish Python distributions through PyPI Trusted Publishing rather than a stored API token.
- Require protected signed tags and reviewed GitHub environments for production publication.
- Deploy the GHCR image by immutable digest, not by a mutable tag.
- Retain and verify the generated SBOM and build-provenance attestation.
- Keep GitHub Actions permissions minimal and review changes to `.github/workflows/` as privileged release changes.
- Run the release validation script and verify `release-output/SHA256SUMS.txt` before tagging.

## Reporting a vulnerability

Report suspected vulnerabilities privately to the package maintainer or through the repository host's private security-advisory mechanism. Do not include active credentials, regulated data or customer production records in a report.

A useful report includes the affected version, reproduction steps, expected and observed behavior, impact assessment and a minimal proof of concept.
