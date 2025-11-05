-- Migration 005: Add Alert Sharing
CREATE TABLE IF NOT EXISTS alert_shares (
    id SERIAL PRIMARY KEY,
    alert_id VARCHAR(255) REFERENCES alerts(alert_id) ON DELETE CASCADE,
    shared_by_org_id INTEGER REFERENCES organizations(id) ON DELETE CASCADE,
    shared_with_org_id INTEGER REFERENCES organizations(id) ON DELETE CASCADE,
    wrapped_key_for_recipient BYTEA NOT NULL,
    permission VARCHAR(20) DEFAULT 'read',
    shared_at TIMESTAMP DEFAULT NOW(),
    revoked BOOLEAN DEFAULT FALSE,
    revoked_at TIMESTAMP,
    
    UNIQUE(alert_id, shared_with_org_id)
);

CREATE INDEX idx_shares_recipient ON alert_shares(shared_with_org_id);
CREATE INDEX idx_shares_alert ON alert_shares(alert_id);

ALTER TABLE alerts ADD COLUMN IF NOT EXISTS visibility VARCHAR(20) DEFAULT 'private';
