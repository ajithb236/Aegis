-- Add password authentication to organizations
ALTER TABLE organizations 
ADD COLUMN password_hash VARCHAR(255) NOT NULL DEFAULT '',
ADD COLUMN is_active BOOLEAN DEFAULT TRUE,
ADD COLUMN email VARCHAR(255),
ADD COLUMN failed_login_attempts INT DEFAULT 0,
ADD COLUMN locked_until TIMESTAMP,
ADD COLUMN last_login TIMESTAMP,
ADD COLUMN created_by VARCHAR(128),
ADD COLUMN updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;

-- Create indexes for performance
CREATE INDEX idx_org_email ON organizations(email);
CREATE INDEX idx_org_active ON organizations(is_active) WHERE is_active = TRUE;

-- JWT refresh tokens table
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id SERIAL PRIMARY KEY,
    token VARCHAR(512) UNIQUE NOT NULL,
    org_id INT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    revoked BOOLEAN DEFAULT FALSE,
    revoked_at TIMESTAMP,
    user_agent VARCHAR(512),
    ip_address VARCHAR(45)
);

CREATE INDEX idx_refresh_token ON refresh_tokens(token) WHERE revoked = FALSE;
CREATE INDEX idx_refresh_expiry ON refresh_tokens(expires_at) WHERE revoked = FALSE;

-- Audit log for security events
CREATE TABLE IF NOT EXISTS security_audit_logs (
    id SERIAL PRIMARY KEY,
    event_type VARCHAR(64) NOT NULL,  -- login_success, login_failed, token_refresh, etc.
    org_id INT REFERENCES organizations(id),
    org_id_attempted VARCHAR(128),  -- Store even if org doesn't exist
    success BOOLEAN NOT NULL,
    ip_address VARCHAR(45),
    user_agent VARCHAR(512),
    details JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_audit_event_type ON security_audit_logs(event_type);
CREATE INDEX idx_audit_org ON security_audit_logs(org_id);
CREATE INDEX idx_audit_timestamp ON security_audit_logs(created_at DESC);