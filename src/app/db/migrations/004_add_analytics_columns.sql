-- Add columns for analytics
ALTER TABLE alerts 
ADD COLUMN IF NOT EXISTS alert_type VARCHAR(50),
ADD COLUMN IF NOT EXISTS severity VARCHAR(20);

-- Add indexes
CREATE INDEX IF NOT EXISTS idx_alerts_type ON alerts(alert_type);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_created_date ON alerts(DATE(created_at));
