CREATE TABLE IF NOT EXISTS approval_records (
    checkpoint_id TEXT PRIMARY KEY,
    action_digest TEXT NOT NULL,
    organization_id TEXT NOT NULL,
    environment TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    request_json JSONB NOT NULL,
    status TEXT NOT NULL,
    external_id TEXT NOT NULL,
    decided_by TEXT NOT NULL,
    decision_reason TEXT NOT NULL,
    decided_at_epoch_ms BIGINT NOT NULL DEFAULT 0,
    updated_at_utc TIMESTAMPTZ NOT NULL,
    revision BIGINT NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS approval_grants (
    action_digest TEXT PRIMARY KEY,
    checkpoint_id TEXT NOT NULL,
    approved_by TEXT NOT NULL,
    expires_at_epoch_ms BIGINT NOT NULL,
    reason TEXT NOT NULL,
    consumed_at_utc TIMESTAMPTZ,
    revision BIGINT NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_approval_pending
    ON approval_records(organization_id, environment, status, updated_at_utc);

CREATE TABLE IF NOT EXISTS roi_opportunities (
    opportunity_id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    business_unit TEXT NOT NULL,
    business_owner TEXT NOT NULL,
    title TEXT NOT NULL,
    value_type TEXT NOT NULL,
    value_period TEXT NOT NULL,
    status TEXT NOT NULL,
    currency_code TEXT NOT NULL,
    baseline_cents BIGINT NOT NULL,
    forecast_cents BIGINT NOT NULL,
    confidence DOUBLE PRECISION NOT NULL,
    source_key TEXT NOT NULL,
    measurement_start TEXT NOT NULL,
    measurement_end TEXT NOT NULL,
    created_at_utc TIMESTAMPTZ NOT NULL,
    created_by TEXT NOT NULL,
    metadata_json JSONB NOT NULL,
    revision BIGINT NOT NULL DEFAULT 1,
    UNIQUE (organization_id, source_key)
);
CREATE TABLE IF NOT EXISTS roi_values (
    measurement_id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL,
    opportunity_id TEXT NOT NULL,
    stage TEXT NOT NULL,
    amount_cents BIGINT NOT NULL,
    currency_code TEXT NOT NULL,
    evidence_key TEXT NOT NULL,
    evidence_uri TEXT NOT NULL,
    measurement_date TEXT NOT NULL,
    recorded_at_utc TIMESTAMPTZ NOT NULL,
    recorded_by TEXT NOT NULL,
    notes TEXT NOT NULL,
    UNIQUE (organization_id, evidence_key),
    FOREIGN KEY (opportunity_id) REFERENCES roi_opportunities(opportunity_id)
);
CREATE TABLE IF NOT EXISTS roi_costs (
    cost_id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    opportunity_id TEXT,
    cost_type TEXT NOT NULL,
    amount_cents BIGINT NOT NULL,
    currency_code TEXT NOT NULL,
    evidence_key TEXT NOT NULL,
    incurred_date TEXT NOT NULL,
    recorded_at_utc TIMESTAMPTZ NOT NULL,
    recorded_by TEXT NOT NULL,
    notes TEXT NOT NULL,
    UNIQUE (organization_id, evidence_key),
    FOREIGN KEY (opportunity_id) REFERENCES roi_opportunities(opportunity_id)
);
CREATE TABLE IF NOT EXISTS roi_status_history (
    history_id TEXT PRIMARY KEY,
    opportunity_id TEXT NOT NULL,
    old_status TEXT NOT NULL,
    new_status TEXT NOT NULL,
    changed_at_utc TIMESTAMPTZ NOT NULL,
    changed_by TEXT NOT NULL,
    reason TEXT NOT NULL,
    FOREIGN KEY (opportunity_id) REFERENCES roi_opportunities(opportunity_id)
);
CREATE INDEX IF NOT EXISTS idx_roi_org_agent ON roi_opportunities(organization_id, agent_id);
CREATE INDEX IF NOT EXISTS idx_roi_values_org_stage ON roi_values(organization_id, stage);
CREATE INDEX IF NOT EXISTS idx_roi_costs_org_agent ON roi_costs(organization_id, agent_id);
