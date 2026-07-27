# Production release from Visual Studio Code

This runbook separates actions that are already automated in this repository from actions that require your GitHub, PyPI, cloud, registry, identity-provider, database, and Kubernetes permissions.

## What is already prepared

The repository includes:

- Python 3.10-3.13 CI with the 98% combined coverage gate.
- Clean wheel and source-distribution validation.
- Manual TestPyPI publishing with Trusted Publishing.
- Tag-controlled PyPI publishing with Trusted Publishing.
- GitHub release creation.
- Multi-architecture GHCR image publication, SBOM generation, and provenance attestation.
- CodeQL and Dependabot configuration.
- A non-root container and Helm deployment with image-digest support.
- A dedicated PostgreSQL migration job and outbox worker.
- OIDC-required production startup.
- HMAC, AWS KMS, Azure Key Vault/Managed HSM, Google Cloud KMS, and Vault Transit policy-signing bootstrap.
- VS Code tasks and PowerShell release validation.

## 1. Install prerequisites on Windows

Install these tools and restart VS Code after installation:

1. Git for Windows.
2. Python 3.13.
3. Visual Studio Code.
4. GitHub CLI (`gh`).
5. Docker Desktop, when publishing the container locally or testing it before CI.
6. Helm 3 and `kubectl`, when deploying to Kubernetes.
7. Terraform, when using the included cloud reference modules.

From a new VS Code PowerShell terminal, confirm:

```powershell
git --version
py -3.13 --version
gh --version
docker --version
kubectl version --client
helm version
terraform version
```

Only Git and Python are required for the package release. The remaining tools are required for the self-hosted control-plane deployment.

## 2. Open the release source in VS Code

Extract `agent-roi-2.0.0-prod-ready-source.zip` into a permanent working directory. In VS Code:

1. Select **File > Open Folder**.
2. Select the extracted `agent-roi-2.0.0` directory.
3. Install the recommended extensions when VS Code prompts you.
4. Open **Terminal > New Terminal**.

Do not work from inside the ZIP file or from a temporary downloads directory.

## 3. Initialize and validate the repository

Run:

```powershell
git init
git branch -M main
.\scripts\prepare_release.ps1
```

The script creates `.venv`, installs the development dependencies, runs all tests, enforces coverage, builds the wheel and source distribution, validates both files, and writes `release-output\SHA256SUMS.txt`.

You can run the same validation through VS Code:

1. Press `Ctrl+Shift+P`.
2. Select **Tasks: Run Task**.
3. Select **Agent-ROI: Full production validation**.

Do not continue unless the script exits successfully.

## 4. Create the GitHub repository

Create an empty GitHub repository without adding a README, license, or `.gitignore`; those files already exist locally.

Authenticate the GitHub CLI:

```powershell
gh auth login
```

Then create and push the repository from the VS Code terminal:

```powershell
git add .
git commit -m "Release Agent-ROI 2.0.0"
gh repo create agent-roi --source . --private --remote origin --push
```

Use `--public` instead of `--private` only when you intend to publish the source publicly. When an organization owns the repository, use:

```powershell
gh repo create YOUR_ORG/agent-roi --source . --private --remote origin --push
```

## 5. Configure GitHub repository protections

On GitHub, configure the following before publishing:

### Main branch

Under **Settings > Branches** or **Rules > Rulesets**:

- Require a pull request before merging.
- Require at least one approval.
- Require the `CI` and `CodeQL` checks.
- Require branches to be up to date.
- Block force pushes and deletion.
- Restrict bypass permissions.

### Actions

Under **Settings > Actions > General**:

- Allow the workflows included in this repository.
- Set the default `GITHUB_TOKEN` permission to read-only.
- Require approval for external contributors when applicable.

### Environments

Under **Settings > Environments**, create:

- `testpypi`
- `pypi`
- `production`

For `pypi` and `production`, add required reviewers and prevent self-approval where your GitHub plan supports it.

### Private vulnerability reporting

Under **Settings > Security**, enable private vulnerability reporting or security advisories. Update `SECURITY.md` with the organization’s private security contact if one exists.

## 6. Configure PyPI Trusted Publishing

The public `agent-roi` project currently has releases through `0.1.4`, so `2.0.0` is available as of July 26, 2026. You must be a maintainer of that PyPI project.

### TestPyPI

In TestPyPI, create a Trusted Publisher with:

- Owner: your GitHub username or organization.
- Repository: `agent-roi`.
- Workflow: `testpypi.yml`.
- Environment: `testpypi`.

### Production PyPI

In the existing PyPI `agent-roi` project, create a Trusted Publisher with:

- Owner: your GitHub username or organization.
- Repository: `agent-roi`.
- Workflow: `release.yml`.
- Environment: `pypi`.

No long-lived PyPI API token should be stored in GitHub.

## 7. Run the GitHub CI workflow

Push a branch or open a pull request. In VS Code, open the **GitHub Actions** extension or use:

```powershell
gh workflow run CI
gh run watch
```

Confirm that Python 3.10, 3.11, 3.12, and 3.13 all pass and that the distributions are produced.

## 8. Publish to TestPyPI

From VS Code:

```powershell
gh workflow run "Publish to TestPyPI"
gh run watch
```

After the workflow succeeds, test the remote package in a new environment:

```powershell
py -3.13 -m venv .testpypi-venv
.\.testpypi-venv\Scripts\python.exe -m pip install --upgrade pip
.\.testpypi-venv\Scripts\python.exe -m pip install `
  --index-url https://test.pypi.org/simple/ `
  --extra-index-url https://pypi.org/simple/ `
  "agent-roi[enterprise]==2.0.0"
.\.testpypi-venv\Scripts\agent-roi.exe --version
.\.testpypi-venv\Scripts\agent-roi-control-plane.exe --version
```

The TestPyPI workflow may not be rerun with the same version after a successful upload. If you need another TestPyPI iteration, use a pre-release version such as `2.0.0rc1` before the production tag.

## 9. Merge and create the production tag

After CI and TestPyPI validation:

```powershell
git checkout main
git pull --ff-only
.\scripts\prepare_release.ps1 -RequireCleanGit
git tag -s v2.0.0 -m "Agent-ROI 2.0.0"
git push origin v2.0.0
```

If you do not have a configured GPG signing key, configure one before this step. Do not create an unsigned release tag for production.

Pushing `v2.0.0` starts two workflows:

- **Publish Python release** publishes the exact tested wheel and source distribution to PyPI and creates the GitHub release.
- **Publish container image** publishes the multi-architecture container to GHCR with SBOM and provenance attestations.

Monitor them:

```powershell
gh run list --limit 10
gh run watch
```

## 10. Verify the published package

Create another clean environment:

```powershell
py -3.13 -m venv .pypi-venv
.\.pypi-venv\Scripts\python.exe -m pip install --upgrade pip
.\.pypi-venv\Scripts\python.exe -m pip install "agent-roi[enterprise]==2.0.0"
.\.pypi-venv\Scripts\python.exe -m pip check
.\.pypi-venv\Scripts\agent-roi.exe --version
```

Compare the PyPI file hashes with `SHA256SUMS.txt` attached to the GitHub release. That checksum file is generated from the exact CI artifacts sent to PyPI. Also verify the PyPI attestations.

## 11. Obtain the immutable container digest

In GitHub, open **Packages > agent-roi**, or run:

```powershell
docker buildx imagetools inspect ghcr.io/YOUR_ORG/agent-roi:2.0.0
```

Copy the `sha256:...` manifest digest. Never deploy the mutable tag alone.

Copy the production values template:

```powershell
Copy-Item deployment\helm\agent-roi\values-production.example.yaml values-production.yaml
```

Edit `values-production.yaml` and set:

- The actual GHCR repository.
- The immutable image digest.
- OIDC issuer, audience, and JWKS URL.
- The selected signing provider and KMS/Vault key identifier.
- Network-policy egress rules.
- Internal ingress host and TLS secret.
- Workload-identity service-account annotations.

Do not commit `values-production.yaml` if it contains environment-specific sensitive configuration.

## 12. Provision infrastructure

Use one cloud-specific directory under `deployment/terraform/` as a reference. Create a separate environment directory rather than applying directly from the reference module.

Example:

```powershell
Set-Location deployment\terraform\aws
terraform init
terraform plan -out agent-roi-prod.tfplan
terraform apply agent-roi-prod.tfplan
```

Before applying, have a cloud/platform reviewer confirm:

- Private network routing.
- PostgreSQL high availability, backups, point-in-time recovery, and deletion protection.
- Workload-identity permissions.
- KMS/HSM signing permissions.
- Secret-manager integration.
- Logging and alerting.

## 13. Create production Kubernetes secrets

Use External Secrets, Secrets Store CSI, or your cloud’s workload identity when available. The following direct commands are examples, not the preferred long-term secret-management method:

```powershell
kubectl create namespace agent-roi
kubectl -n agent-roi create secret generic agent-roi-database `
  --from-literal=dsn='postgresql://RUNTIME_USER:PASSWORD@HOST:5432/agentroi?sslmode=require'
kubectl -n agent-roi create secret generic agent-roi-outbox `
  --from-file=destinations.json='.\destinations.production.json'
```

For HMAC only:

```powershell
kubectl -n agent-roi create secret generic agent-roi-signing `
  --from-literal=secret='base64:REPLACE_WITH_RANDOM_VALUE'
```

KMS-backed configurations should use workload identity and do not require the HMAC secret.

## 14. Run migrations with a dedicated role

Use a migration DSN that has DDL privileges:

```powershell
$env:AGENT_ROI_POSTGRES_DSN = 'postgresql://MIGRATION_USER:PASSWORD@HOST:5432/agentroi?sslmode=require'
.\.pypi-venv\Scripts\agent-roi-db.exe status --schema agent_roi
.\.pypi-venv\Scripts\agent-roi-db.exe migrate --schema agent_roi
.\.pypi-venv\Scripts\agent-roi-db.exe status --schema agent_roi
```

Take and verify a database backup before migration. The application runtime account should not retain schema-creation privileges.

The Helm chart also includes a pre-install/pre-upgrade migration job. Use one migration mechanism per release and make the ownership explicit in your runbook.

## 15. Deploy to staging

Validate the chart locally:

```powershell
helm lint deployment\helm\agent-roi
helm template agent-roi deployment\helm\agent-roi `
  --namespace agent-roi-staging `
  --values values-staging.yaml > rendered-staging.yaml
```

Deploy:

```powershell
helm upgrade --install agent-roi deployment\helm\agent-roi `
  --namespace agent-roi-staging `
  --create-namespace `
  --values values-staging.yaml `
  --atomic `
  --wait `
  --timeout 15m
```

Run staging tests for authentication, cross-tenant denial, policy publication and rollback, approval separation of duties, ROI evidence deduplication, audit-chain verification, outbox retries, dead-letter handling, database failover, and KMS signing.

## 16. Deploy a production canary

Use the same image digest tested in staging. Start with a restricted internal cohort and conservative approval policies:

```powershell
helm upgrade --install agent-roi deployment\helm\agent-roi `
  --namespace agent-roi `
  --create-namespace `
  --values values-production.yaml `
  --atomic `
  --wait `
  --timeout 15m
```

Monitor:

- API and policy-resolution latency.
- Authentication and authorization failures.
- PostgreSQL connections and transaction latency.
- Audit-chain verification failures.
- Outbox lag, retries, and dead letters.
- Approval latency.
- Agent cost and realized-value metrics.

Expand from one low-risk agent to additional agents only after the agreed observation period passes.

## 17. Rollback

Application rollback:

```powershell
helm history agent-roi -n agent-roi
helm rollback agent-roi PREVIOUS_REVISION -n agent-roi --wait
```

Policy rollback should use the control-plane policy rollback operation independently of Helm.

If the PyPI release is defective, yank `2.0.0`, correct the defect, and publish `2.0.1`. Do not delete and attempt to replace the `2.0.0` files.

## Final production approval checklist

Production approval requires evidence that:

- All GitHub checks pass on the tagged commit.
- TestPyPI and PyPI clean-environment installs pass.
- The container digest, SBOM, and provenance attestation are recorded.
- Real PostgreSQL integration, backup, restore, and failover tests pass.
- Actual OIDC and workload identity tests pass.
- KMS/HSM signing and rotation tests pass.
- Network policy, TLS, ingress, and egress controls are approved.
- Outbox outage and recovery testing passes.
- Dashboards and alerts are active.
- Staging rollback has been rehearsed.
- The production change record has approvals and a rollback owner.
