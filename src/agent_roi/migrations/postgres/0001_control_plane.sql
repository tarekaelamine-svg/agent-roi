CREATE TABLE IF NOT EXISTS policy_bundles (
    organization_id TEXT NOT NULL,
    name TEXT NOT NULL,
    environment TEXT NOT NULL,
    version TEXT NOT NULL,
    payload_json JSONB NOT NULL,
    digest TEXT NOT NULL,
    signature TEXT NOT NULL,
    signer_key_id TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at_utc TIMESTAMPTZ NOT NULL,
    created_by TEXT NOT NULL,
    revision BIGINT NOT NULL DEFAULT 1,
    PRIMARY KEY (organization_id, name, environment, version)
);
CREATE TABLE IF NOT EXISTS active_policies (
    organization_id TEXT NOT NULL,
    name TEXT NOT NULL,
    environment TEXT NOT NULL,
    version TEXT NOT NULL,
    activated_at_utc TIMESTAMPTZ NOT NULL,
    activated_by TEXT NOT NULL,
    revision BIGINT NOT NULL DEFAULT 1,
    PRIMARY KEY (organization_id, name, environment),
    FOREIGN KEY (organization_id, name, environment, version)
      REFERENCES policy_bundles(organization_id, name, environment, version)
);
CREATE TABLE IF NOT EXISTS policy_rollouts (
    organization_id TEXT NOT NULL,
    name TEXT NOT NULL,
    environment TEXT NOT NULL,
    primary_version TEXT NOT NULL,
    candidate_version TEXT NOT NULL,
    candidate_percentage INTEGER NOT NULL CHECK(candidate_percentage BETWEEN 1 AND 99),
    seed TEXT NOT NULL,
    updated_at_utc TIMESTAMPTZ NOT NULL,
    updated_by TEXT NOT NULL,
    revision BIGINT NOT NULL DEFAULT 1,
    PRIMARY KEY (organization_id, name, environment),
    FOREIGN KEY (organization_id, name, environment, primary_version)
      REFERENCES policy_bundles(organization_id, name, environment, version),
    FOREIGN KEY (organization_id, name, environment, candidate_version)
      REFERENCES policy_bundles(organization_id, name, environment, version)
);
CREATE TABLE IF NOT EXISTS agents (
    organization_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    environment TEXT NOT NULL,
    owner TEXT NOT NULL,
    purpose TEXT NOT NULL,
    status TEXT NOT NULL,
    metadata_json JSONB NOT NULL,
    registered_at_utc TIMESTAMPTZ NOT NULL,
    last_heartbeat_utc TIMESTAMPTZ,
    policy_digest TEXT,
    version TEXT,
    revision BIGINT NOT NULL DEFAULT 1,
    PRIMARY KEY (organization_id, agent_id, environment)
);
CREATE INDEX IF NOT EXISTS idx_policy_bundles_lookup
    ON policy_bundles(organization_id, environment, name, created_at_utc DESC);
CREATE INDEX IF NOT EXISTS idx_agents_org_status
    ON agents(organization_id, environment, status, agent_id);
