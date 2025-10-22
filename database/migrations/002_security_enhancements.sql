-- Security Enhancement Migration for CoreFlow360 V4
-- Adds critical security columns and tables per OWASP recommendations

-- Add security columns to users table
ALTER TABLE users ADD COLUMN salt TEXT;
ALTER TABLE users ADD COLUMN password_version INTEGER DEFAULT 2;
ALTER TABLE users ADD COLUMN failed_login_attempts INTEGER DEFAULT 0;
ALTER TABLE users ADD COLUMN locked_until INTEGER;
ALTER TABLE users ADD COLUMN two_factor_secret TEXT;
ALTER TABLE users ADD COLUMN two_factor_backup_codes TEXT;
ALTER TABLE users ADD COLUMN security_questions TEXT;
ALTER TABLE users ADD COLUMN password_reset_token TEXT;
ALTER TABLE users ADD COLUMN password_reset_expires INTEGER;
ALTER TABLE users ADD COLUMN last_password_change INTEGER;
ALTER TABLE users ADD COLUMN password_history TEXT;
ALTER TABLE users ADD COLUMN account_lockout_count INTEGER DEFAULT 0;

-- Create comprehensive audit logs table
CREATE TABLE IF NOT EXISTS audit_logs (
  id TEXT PRIMARY KEY,
  event_type TEXT NOT NULL,
  user_id TEXT,
  business_id TEXT NOT NULL,
  ip_address TEXT,
  user_agent TEXT,
  details JSON,
  risk_score INTEGER,
  timestamp INTEGER NOT NULL,
  session_id TEXT,
  request_id TEXT,
  response_status INTEGER,
  response_time_ms INTEGER,
  error_message TEXT,
  stack_trace TEXT
);

-- Create indexes for audit logs
CREATE INDEX IF NOT EXISTS idx_audit_business ON audit_logs(business_id);
CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_event_type ON audit_logs(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_risk_score ON audit_logs(risk_score);

-- Create encryption keys table for key rotation
CREATE TABLE IF NOT EXISTS encryption_keys (
  id TEXT PRIMARY KEY,
  business_id TEXT NOT NULL,
  key_version INTEGER NOT NULL,
  encrypted_key TEXT NOT NULL,
  algorithm TEXT NOT NULL,
  purpose TEXT NOT NULL, -- 'data', 'api', 'session'
  created_at INTEGER NOT NULL,
  rotated_at INTEGER,
  expires_at INTEGER,
  created_by TEXT,
  is_active INTEGER DEFAULT 1,
  FOREIGN KEY (business_id) REFERENCES businesses(id)
);

-- Create index for encryption keys
CREATE INDEX IF NOT EXISTS idx_encryption_keys_business ON encryption_keys(business_id);
CREATE INDEX IF NOT EXISTS idx_encryption_keys_active ON encryption_keys(is_active);

-- Create compliance logs table for GDPR/CCPA
CREATE TABLE IF NOT EXISTS compliance_logs (
  id TEXT PRIMARY KEY,
  business_id TEXT NOT NULL,
  compliance_type TEXT NOT NULL, -- 'GDPR', 'CCPA', 'HIPAA', etc
  action TEXT NOT NULL, -- 'data_access', 'data_export', 'data_deletion'
  user_id TEXT,
  data_categories TEXT,
  lawful_basis TEXT,
  consent_id TEXT,
  retention_period_days INTEGER,
  timestamp INTEGER NOT NULL,
  completed_at INTEGER,
  status TEXT DEFAULT 'pending', -- 'pending', 'completed', 'failed'
  FOREIGN KEY (business_id) REFERENCES businesses(id),
  FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Create index for compliance logs
CREATE INDEX IF NOT EXISTS idx_compliance_business ON compliance_logs(business_id);
CREATE INDEX IF NOT EXISTS idx_compliance_user ON compliance_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_compliance_timestamp ON compliance_logs(timestamp);

-- Create security events table for threat detection
CREATE TABLE IF NOT EXISTS security_events (
  id TEXT PRIMARY KEY,
  event_type TEXT NOT NULL, -- 'brute_force', 'sql_injection', 'xss_attempt', 'rate_limit', 'unauthorized_access'
  severity TEXT NOT NULL, -- 'critical', 'high', 'medium', 'low'
  user_id TEXT,
  business_id TEXT,
  ip_address TEXT,
  user_agent TEXT,
  request_path TEXT,
  request_method TEXT,
  request_body TEXT,
  threat_indicators TEXT,
  mitigation_action TEXT, -- 'blocked', 'rate_limited', 'logged', 'alerted'
  timestamp INTEGER NOT NULL,
  resolved_at INTEGER,
  resolved_by TEXT,
  notes TEXT
);

-- Create indexes for security events
CREATE INDEX IF NOT EXISTS idx_security_events_timestamp ON security_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_security_events_severity ON security_events(severity);
CREATE INDEX IF NOT EXISTS idx_security_events_ip ON security_events(ip_address);

-- Create rate limiting table
CREATE TABLE IF NOT EXISTS rate_limits (
  id TEXT PRIMARY KEY,
  identifier TEXT NOT NULL, -- IP, user_id, fingerprint
  identifier_type TEXT NOT NULL, -- 'ip', 'user', 'fingerprint', 'api_key'
  endpoint TEXT NOT NULL,
  request_count INTEGER DEFAULT 1,
  window_start INTEGER NOT NULL,
  window_end INTEGER NOT NULL,
  max_requests INTEGER NOT NULL,
  blocked_until INTEGER,
  created_at INTEGER NOT NULL
);

-- Create indexes for rate limiting
CREATE INDEX IF NOT EXISTS idx_rate_limits_identifier ON rate_limits(identifier);
CREATE INDEX IF NOT EXISTS idx_rate_limits_window ON rate_limits(window_end);

-- Enhanced sessions table with security features
ALTER TABLE sessions ADD COLUMN fingerprint_hash TEXT;
ALTER TABLE sessions ADD COLUMN last_activity INTEGER;
ALTER TABLE sessions ADD COLUMN refresh_token TEXT;
ALTER TABLE sessions ADD COLUMN refresh_token_expires INTEGER;
ALTER TABLE sessions ADD COLUMN device_info TEXT;
ALTER TABLE sessions ADD COLUMN location TEXT;
ALTER TABLE sessions ADD COLUMN is_suspicious INTEGER DEFAULT 0;

-- Create token blacklist table
CREATE TABLE IF NOT EXISTS token_blacklist (
  id TEXT PRIMARY KEY,
  token_hash TEXT NOT NULL,
  token_type TEXT NOT NULL, -- 'jwt', 'api_key', 'refresh_token'
  user_id TEXT,
  blacklisted_at INTEGER NOT NULL,
  reason TEXT,
  expires_at INTEGER NOT NULL
);

-- Create index for token blacklist
CREATE INDEX IF NOT EXISTS idx_token_blacklist_hash ON token_blacklist(token_hash);
CREATE INDEX IF NOT EXISTS idx_token_blacklist_expires ON token_blacklist(expires_at);

-- Create data encryption audit table
CREATE TABLE IF NOT EXISTS data_encryption_audit (
  id TEXT PRIMARY KEY,
  business_id TEXT NOT NULL,
  table_name TEXT NOT NULL,
  column_name TEXT NOT NULL,
  record_id TEXT NOT NULL,
  encryption_key_id TEXT NOT NULL,
  encrypted_at INTEGER NOT NULL,
  decrypted_at INTEGER,
  decrypted_by TEXT,
  purpose TEXT,
  FOREIGN KEY (business_id) REFERENCES businesses(id),
  FOREIGN KEY (encryption_key_id) REFERENCES encryption_keys(id)
);

-- Create index for data encryption audit
CREATE INDEX IF NOT EXISTS idx_encryption_audit_business ON data_encryption_audit(business_id);
CREATE INDEX IF NOT EXISTS idx_encryption_audit_record ON data_encryption_audit(record_id);

-- Create API key metadata table
ALTER TABLE api_keys ADD COLUMN last_rotated INTEGER;
ALTER TABLE api_keys ADD COLUMN rotation_count INTEGER DEFAULT 0;
ALTER TABLE api_keys ADD COLUMN scopes TEXT;
ALTER TABLE api_keys ADD COLUMN allowed_ips TEXT;
ALTER TABLE api_keys ADD COLUMN allowed_domains TEXT;
ALTER TABLE api_keys ADD COLUMN rate_limit_override INTEGER;

-- Create permission sets table
CREATE TABLE IF NOT EXISTS permission_sets (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT,
  permissions JSON NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

-- Create user permissions mapping
CREATE TABLE IF NOT EXISTS user_permissions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  permission_set_id TEXT NOT NULL,
  granted_at INTEGER NOT NULL,
  granted_by TEXT,
  expires_at INTEGER,
  FOREIGN KEY (user_id) REFERENCES users(id),
  FOREIGN KEY (permission_set_id) REFERENCES permission_sets(id)
);

-- Create indexes for permissions
CREATE INDEX IF NOT EXISTS idx_user_permissions_user ON user_permissions(user_id);
CREATE INDEX IF NOT EXISTS idx_user_permissions_set ON user_permissions(permission_set_id);

-- Add migration version tracking
CREATE TABLE IF NOT EXISTS migration_history (
  id TEXT PRIMARY KEY,
  version INTEGER NOT NULL,
  name TEXT NOT NULL,
  applied_at INTEGER NOT NULL,
  checksum TEXT NOT NULL
);

-- Insert migration record
INSERT INTO migration_history (id, version, name, applied_at, checksum)
VALUES (
  '002-security',
  2,
  'security_enhancements',
  strftime('%s', 'now'),
  'sha256:security_enhancement_migration_v2'
);