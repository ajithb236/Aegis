-- src/app/db/migrations/001_create_tables.sql

-- Table to manage organizations or users
CREATE TABLE IF NOT EXISTS organizations (
    id SERIAL PRIMARY KEY,
    org_id VARCHAR(128) UNIQUE NOT NULL,
    org_name VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- RSA keys linked to organizations (public keys only)
CREATE TABLE IF NOT EXISTS rsa_keys (
    id SERIAL PRIMARY KEY,
    org_id INT NOT NULL REFERENCES organizations(id),
    public_key TEXT NOT NULL,
    key_type VARCHAR(50) NOT NULL,  -- e.g., 'signing', 'encryption'
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Encrypted alerts table
CREATE TABLE IF NOT EXISTS alerts (
    id SERIAL PRIMARY KEY,
    alert_id VARCHAR(64) UNIQUE NOT NULL,
    submitter_org_id INT NOT NULL REFERENCES organizations(id),
    encrypted_payload BYTEA NOT NULL,
    wrapped_aes_key BYTEA NOT NULL,
    signature BYTEA NOT NULL,
    hmac_beacon VARCHAR(128) NOT NULL,
    paillier_ciphertext BYTEA,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Index for searchable encryption
CREATE INDEX IF NOT EXISTS idx_hmac_beacon ON alerts (hmac_beacon);

-- Audit logs for traceability
CREATE TABLE IF NOT EXISTS audit_logs (
    id SERIAL PRIMARY KEY,
    action VARCHAR(128),
    actor_org_id INT REFERENCES organizations(id),
    details JSONB,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
