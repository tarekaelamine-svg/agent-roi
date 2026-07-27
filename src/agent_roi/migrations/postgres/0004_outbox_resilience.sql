CREATE TABLE IF NOT EXISTS enterprise_outbox (
    event_id TEXT PRIMARY KEY,
    topic TEXT NOT NULL,
    destination TEXT NOT NULL,
    payload_json JSONB NOT NULL,
    idempotency_key TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    attempts INTEGER NOT NULL DEFAULT 0,
    available_at_utc TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    lease_owner TEXT,
    lease_expires_at_utc TIMESTAMPTZ,
    last_error TEXT NOT NULL DEFAULT '',
    created_at_utc TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    delivered_at_utc TIMESTAMPTZ,
    UNIQUE(destination, idempotency_key)
);
CREATE INDEX IF NOT EXISTS idx_outbox_claim
    ON enterprise_outbox(status, available_at_utc, destination, created_at_utc);
CREATE TABLE IF NOT EXISTS enterprise_dead_letters (
    event_id TEXT PRIMARY KEY,
    topic TEXT NOT NULL,
    destination TEXT NOT NULL,
    payload_json JSONB NOT NULL,
    idempotency_key TEXT NOT NULL,
    attempts INTEGER NOT NULL,
    last_error TEXT NOT NULL,
    created_at_utc TIMESTAMPTZ NOT NULL,
    dead_lettered_at_utc TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS idempotency_records (
    namespace TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    status TEXT NOT NULL,
    response_json JSONB,
    error_text TEXT NOT NULL DEFAULT '',
    created_at_utc TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at_utc TIMESTAMPTZ NOT NULL,
    revision BIGINT NOT NULL DEFAULT 1,
    PRIMARY KEY(namespace, idempotency_key)
);
CREATE INDEX IF NOT EXISTS idx_idempotency_expiry ON idempotency_records(expires_at_utc);
