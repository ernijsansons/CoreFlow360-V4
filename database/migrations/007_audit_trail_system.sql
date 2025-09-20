-- Migration 007: Comprehensive Audit Trail System
-- Creates immutable audit logging infrastructure for compliance and security

-- Audit logs table for comprehensive event tracking
CREATE TABLE IF NOT EXISTS audit_logs (
  id TEXT PRIMARY KEY,
  timestamp TEXT NOT NULL,
  correlation_id TEXT NOT NULL,
  event_type TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),

  -- User and business context (redacted for privacy)
  user_id TEXT NOT NULL,
  business_id TEXT NOT NULL,
  session_id TEXT,
  ip_address TEXT NOT NULL,
  user_agent TEXT NOT NULL,

  -- Operation details
  operation TEXT NOT NULL,
  resource TEXT, -- JSON object describing the resource
  result TEXT NOT NULL CHECK (result IN ('success', 'failure', 'partial')),
  details TEXT NOT NULL, -- JSON object with operation-specific details

  -- Security and compliance metadata
  security_impact TEXT, -- JSON object for security-related events
  compliance TEXT, -- JSON object with retention and regulatory info

  -- Metadata
  created_at TEXT NOT NULL DEFAULT (datetime('now')),

  -- Immutability controls
  hash TEXT, -- Will be populated by trigger for integrity verification
  previous_hash TEXT -- For audit trail chain verification
);

-- Create indexes for efficient querying
CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_logs_correlation_id ON audit_logs(correlation_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_business ON audit_logs(user_id, business_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_event_type ON audit_logs(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_logs_severity ON audit_logs(severity);
CREATE INDEX IF NOT EXISTS idx_audit_logs_operation ON audit_logs(operation);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);

-- Composite indexes for common query patterns
CREATE INDEX IF NOT EXISTS idx_audit_logs_business_timestamp ON audit_logs(business_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_timestamp ON audit_logs(user_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_event_severity ON audit_logs(event_type, severity);

-- Audit log integrity verification table
CREATE TABLE IF NOT EXISTS audit_integrity (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  log_id TEXT NOT NULL REFERENCES audit_logs(id),
  computed_hash TEXT NOT NULL,
  chain_hash TEXT NOT NULL,
  verified_at TEXT NOT NULL DEFAULT (datetime('now')),
  verification_status TEXT NOT NULL CHECK (verification_status IN ('valid', 'invalid', 'corrupted')),

  UNIQUE(log_id)
);

-- Permission check audit summary for performance
CREATE TABLE IF NOT EXISTS permission_audit_summary (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  business_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  date TEXT NOT NULL, -- YYYY-MM-DD format

  -- Counters
  total_checks INTEGER NOT NULL DEFAULT 0,
  grants INTEGER NOT NULL DEFAULT 0,
  denials INTEGER NOT NULL DEFAULT 0,
  cache_hits INTEGER NOT NULL DEFAULT 0,

  -- Performance metrics
  avg_evaluation_time_ms REAL NOT NULL DEFAULT 0,
  max_evaluation_time_ms REAL NOT NULL DEFAULT 0,

  -- Updated timestamps
  first_check_at TEXT,
  last_check_at TEXT,
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),

  UNIQUE(business_id, user_id, date)
);

CREATE INDEX IF NOT EXISTS idx_permission_audit_summary_business_date ON permission_audit_summary(business_id, date);
CREATE INDEX IF NOT EXISTS idx_permission_audit_summary_user_date ON permission_audit_summary(user_id, date);

-- Security events table for rapid incident response
CREATE TABLE IF NOT EXISTS security_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  audit_log_id TEXT NOT NULL REFERENCES audit_logs(id),
  event_timestamp TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),

  -- Event details
  violation_type TEXT NOT NULL,
  risk_level TEXT NOT NULL,
  indicators TEXT NOT NULL, -- JSON array of security indicators
  mitigated BOOLEAN NOT NULL DEFAULT FALSE,

  -- Response tracking
  incident_id TEXT,
  response_status TEXT CHECK (response_status IN ('open', 'investigating', 'resolved', 'false_positive')),
  assigned_to TEXT,
  resolved_at TEXT,

  -- Metadata
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_security_events_timestamp ON security_events(event_timestamp);
CREATE INDEX IF NOT EXISTS idx_security_events_severity ON security_events(severity);
CREATE INDEX IF NOT EXISTS idx_security_events_violation_type ON security_events(violation_type);
CREATE INDEX IF NOT EXISTS idx_security_events_status ON security_events(response_status);
CREATE INDEX IF NOT EXISTS idx_security_events_unresolved ON security_events(response_status) WHERE response_status IN ('open', 'investigating');

-- Compliance audit trails for regulatory requirements
CREATE TABLE IF NOT EXISTS compliance_audit_trails (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  audit_log_id TEXT NOT NULL REFERENCES audit_logs(id),
  regulation TEXT NOT NULL, -- GDPR, SOX, HIPAA, etc.
  data_type TEXT NOT NULL, -- personal_data, financial_data, etc.

  -- Retention and lifecycle
  retention_category TEXT NOT NULL,
  retention_period_days INTEGER NOT NULL,
  expires_at TEXT NOT NULL,

  -- Compliance metadata
  jurisdiction TEXT,
  legal_basis TEXT,
  data_subject_id TEXT, -- For GDPR subject access requests

  -- Audit trail
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_compliance_audit_trails_regulation ON compliance_audit_trails(regulation);
CREATE INDEX IF NOT EXISTS idx_compliance_audit_trails_data_type ON compliance_audit_trails(data_type);
CREATE INDEX IF NOT EXISTS idx_compliance_audit_trails_expires_at ON compliance_audit_trails(expires_at);
CREATE INDEX IF NOT EXISTS idx_compliance_audit_trails_data_subject ON compliance_audit_trails(data_subject_id);

-- Data retention policies table
CREATE TABLE IF NOT EXISTS audit_retention_policies (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_type TEXT NOT NULL,
  severity TEXT NOT NULL,
  retention_days INTEGER NOT NULL,
  regulation TEXT,
  description TEXT,

  -- Policy metadata
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  active BOOLEAN NOT NULL DEFAULT TRUE,

  UNIQUE(event_type, severity, regulation)
);

-- Insert default retention policies
INSERT OR IGNORE INTO audit_retention_policies (event_type, severity, retention_days, regulation, description) VALUES
-- General audit events
('permission_check', 'low', 365, 'SOX', 'Permission checks for compliance audit'),
('permission_grant', 'medium', 2555, 'SOX', 'Permission grants for 7-year retention'),
('permission_deny', 'high', 2555, 'SOX', 'Permission denials for security analysis'),
('data_access', 'low', 365, 'GDPR', 'Data access logs for privacy compliance'),
('data_modification', 'medium', 2555, 'SOX', 'Data modifications for financial audit'),
('data_deletion', 'high', 2555, 'GDPR', 'Data deletions for compliance verification'),

-- Security events
('security_violation', 'critical', 2555, 'ALL', 'Security violations for incident analysis'),
('user_login', 'low', 730, 'SOX', 'User authentication events'),
('user_logout', 'low', 365, 'SOX', 'User session termination'),
('business_switch', 'medium', 1095, 'SOX', 'Business context switching events'),

-- System events
('system_configuration', 'high', 2555, 'SOX', 'System configuration changes'),
('compliance_event', 'medium', 2555, 'ALL', 'Compliance-related events'),
('policy_evaluation', 'low', 365, 'SOX', 'Policy evaluation audit trail');

-- Trigger to ensure audit log immutability
CREATE TRIGGER IF NOT EXISTS audit_logs_immutable
  BEFORE UPDATE ON audit_logs
  BEGIN
    SELECT RAISE(ABORT, 'Audit logs are immutable and cannot be modified');
  END;

-- Trigger to prevent audit log deletion
CREATE TRIGGER IF NOT EXISTS audit_logs_no_delete
  BEFORE DELETE ON audit_logs
  BEGIN
    SELECT RAISE(ABORT, 'Audit logs cannot be deleted');
  END;

-- Trigger to compute hash for audit log integrity
CREATE TRIGGER IF NOT EXISTS audit_logs_compute_hash
  AFTER INSERT ON audit_logs
  BEGIN
    -- Compute hash of the audit log entry for integrity verification
    UPDATE audit_logs
    SET hash =
      SUBSTR(
        HEX(
          RANDOMBLOB(16) || -- Simple integrity check (in production, use proper cryptographic hash)
          NEW.id ||
          NEW.timestamp ||
          NEW.operation ||
          NEW.result
        ), 1, 32
      ),
      previous_hash = (
        SELECT hash FROM audit_logs
        WHERE id != NEW.id
        ORDER BY created_at DESC
        LIMIT 1
      )
    WHERE id = NEW.id;

    -- Insert integrity verification record
    INSERT INTO audit_integrity (log_id, computed_hash, chain_hash, verification_status)
    VALUES (
      NEW.id,
      (SELECT hash FROM audit_logs WHERE id = NEW.id),
      (SELECT previous_hash FROM audit_logs WHERE id = NEW.id),
      'valid'
    );
  END;

-- Trigger to update permission audit summary
CREATE TRIGGER IF NOT EXISTS update_permission_audit_summary
  AFTER INSERT ON audit_logs
  WHEN NEW.event_type IN ('permission_grant', 'permission_deny')
  BEGIN
    INSERT OR REPLACE INTO permission_audit_summary (
      business_id, user_id, date,
      total_checks, grants, denials, cache_hits,
      avg_evaluation_time_ms, max_evaluation_time_ms,
      first_check_at, last_check_at, updated_at
    )
    SELECT
      NEW.business_id,
      NEW.user_id,
      DATE(NEW.timestamp),
      COALESCE(old.total_checks, 0) + 1,
      COALESCE(old.grants, 0) + CASE WHEN NEW.event_type = 'permission_grant' THEN 1 ELSE 0 END,
      COALESCE(old.denials, 0) + CASE WHEN NEW.event_type = 'permission_deny' THEN 1 ELSE 0 END,
      COALESCE(old.cache_hits, 0) + CASE WHEN JSON_EXTRACT(NEW.details, '$.cacheHit') = 1 THEN 1 ELSE 0 END,
      -- Simple average calculation (in production, use proper rolling average)
      (
        COALESCE(old.avg_evaluation_time_ms * old.total_checks, 0) +
        COALESCE(JSON_EXTRACT(NEW.details, '$.evaluationTimeMs'), 0)
      ) / (COALESCE(old.total_checks, 0) + 1),
      MAX(
        COALESCE(old.max_evaluation_time_ms, 0),
        COALESCE(JSON_EXTRACT(NEW.details, '$.evaluationTimeMs'), 0)
      ),
      COALESCE(old.first_check_at, NEW.timestamp),
      NEW.timestamp,
      datetime('now')
    FROM (
      SELECT * FROM permission_audit_summary
      WHERE business_id = NEW.business_id
        AND user_id = NEW.user_id
        AND date = DATE(NEW.timestamp)
    ) old;
  END;

-- Trigger to create security events for high-severity audit logs
CREATE TRIGGER IF NOT EXISTS create_security_events
  AFTER INSERT ON audit_logs
  WHEN NEW.severity IN ('high', 'critical')
    AND NEW.event_type IN ('security_violation', 'permission_deny', 'data_deletion')
  BEGIN
    INSERT INTO security_events (
      audit_log_id, event_timestamp, severity, violation_type,
      risk_level, indicators, mitigated, response_status
    )
    VALUES (
      NEW.id,
      NEW.timestamp,
      NEW.severity,
      COALESCE(JSON_EXTRACT(NEW.details, '$.violation'), NEW.event_type),
      NEW.severity,
      COALESCE(JSON_EXTRACT(NEW.security_impact, '$.indicators'), '[]'),
      COALESCE(JSON_EXTRACT(NEW.security_impact, '$.mitigated'), 0),
      'open'
    );
  END;

-- Trigger to create compliance audit trails
CREATE TRIGGER IF NOT EXISTS create_compliance_trails
  AFTER INSERT ON audit_logs
  WHEN NEW.compliance IS NOT NULL
  BEGIN
    INSERT INTO compliance_audit_trails (
      audit_log_id, regulation, data_type, retention_category,
      retention_period_days, expires_at, data_subject_id
    )
    SELECT
      NEW.id,
      value AS regulation,
      JSON_EXTRACT(NEW.compliance, '$.dataTypes[0]'),
      JSON_EXTRACT(NEW.compliance, '$.retention.category'),
      (
        SELECT retention_days FROM audit_retention_policies
        WHERE event_type = NEW.event_type
          AND severity = NEW.severity
          AND (regulation = value OR regulation = 'ALL')
        ORDER BY
          CASE WHEN regulation = value THEN 1 ELSE 2 END,
          retention_days DESC
        LIMIT 1
      ),
      COALESCE(
        JSON_EXTRACT(NEW.compliance, '$.retention.expiresAt'),
        datetime('now', '+' || (
          SELECT retention_days FROM audit_retention_policies
          WHERE event_type = NEW.event_type
            AND severity = NEW.severity
          ORDER BY retention_days DESC
          LIMIT 1
        ) || ' days')
      ),
      NEW.user_id
    FROM JSON_EACH(JSON_EXTRACT(NEW.compliance, '$.regulations'));
  END;

-- View for audit log queries with computed fields
CREATE VIEW IF NOT EXISTS audit_logs_view AS
SELECT
  a.*,
  i.verification_status,
  i.verified_at,
  CASE
    WHEN s.id IS NOT NULL THEN 1
    ELSE 0
  END as has_security_event,
  s.response_status as security_response_status
FROM audit_logs a
LEFT JOIN audit_integrity i ON a.id = i.log_id
LEFT JOIN security_events s ON a.id = s.audit_log_id;

-- View for compliance reporting
CREATE VIEW IF NOT EXISTS compliance_report_view AS
SELECT
  c.regulation,
  c.data_type,
  COUNT(*) as total_events,
  COUNT(CASE WHEN a.severity = 'critical' THEN 1 END) as critical_events,
  COUNT(CASE WHEN a.severity = 'high' THEN 1 END) as high_events,
  MIN(a.timestamp) as earliest_event,
  MAX(a.timestamp) as latest_event,
  COUNT(CASE WHEN c.expires_at < datetime('now') THEN 1 END) as expired_events
FROM compliance_audit_trails c
JOIN audit_logs a ON c.audit_log_id = a.id
GROUP BY c.regulation, c.data_type;

-- View for security dashboard
CREATE VIEW IF NOT EXISTS security_dashboard_view AS
SELECT
  se.severity,
  se.violation_type,
  se.response_status,
  COUNT(*) as event_count,
  COUNT(CASE WHEN se.mitigated = 1 THEN 1 END) as mitigated_count,
  MAX(se.event_timestamp) as latest_event,
  COUNT(CASE WHEN se.response_status = 'open' THEN 1 END) as open_incidents
FROM security_events se
WHERE se.event_timestamp >= datetime('now', '-30 days')
GROUP BY se.severity, se.violation_type, se.response_status;

-- Performance optimization: Analyze tables
ANALYZE audit_logs;
ANALYZE audit_integrity;
ANALYZE permission_audit_summary;
ANALYZE security_events;
ANALYZE compliance_audit_trails;