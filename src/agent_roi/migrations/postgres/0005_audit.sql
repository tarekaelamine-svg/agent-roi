CREATE TABLE IF NOT EXISTS agent_roi_audit_events (
    sequence_id BIGSERIAL PRIMARY KEY,
    event_id UUID NOT NULL UNIQUE,
    correlation_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    ts_epoch_ms BIGINT NOT NULL,
    event_type TEXT NOT NULL,
    payload_json JSONB NOT NULL,
    prev_hash CHAR(64),
    event_hash CHAR(64),
    event_json JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_agent_roi_audit_events_correlation_sequence
    ON agent_roi_audit_events(correlation_id, sequence_id);
CREATE INDEX IF NOT EXISTS idx_agent_roi_audit_events_run
    ON agent_roi_audit_events(run_id);
