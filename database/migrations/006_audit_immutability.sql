-- Migration: 006_audit_immutability
-- Description: Add immutability controls to audit logs
-- Created: 2024-12-01
-- Author: CoreFlow360 V4

-- Create audit log checksums table for integrity verification
CREATE TABLE IF NOT EXISTS audit_log_checksums (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    audit_log_id TEXT NOT NULL UNIQUE,
    checksum TEXT NOT NULL,
    previous_checksum TEXT,
    chain_valid INTEGER DEFAULT 1,
    created_at TEXT DEFAULT (datetime('now')),

    FOREIGN KEY (audit_log_id) REFERENCES audit_logs(id) ON DELETE RESTRICT
);

-- Create trigger to prevent audit log updates
CREATE TRIGGER IF NOT EXISTS prevent_audit_log_update
BEFORE UPDATE ON audit_logs
BEGIN
    SELECT RAISE(ABORT, 'Audit logs are immutable and cannot be updated');
END;

-- Create trigger to prevent audit log deletes (except by system after retention period)
CREATE TRIGGER IF NOT EXISTS prevent_audit_log_delete
BEFORE DELETE ON audit_logs
WHEN OLD.created_at > datetime('now', '-7 years') -- 7 year retention
BEGIN
    SELECT RAISE(ABORT, 'Audit logs cannot be deleted within retention period');
END;

-- Create trigger to generate checksums on insert
CREATE TRIGGER IF NOT EXISTS generate_audit_checksum
AFTER INSERT ON audit_logs
BEGIN
    INSERT INTO audit_log_checksums (
        audit_log_id,
        checksum,
        previous_checksum
    )
    SELECT
        NEW.id,
        lower(hex(randomblob(32))), -- In production, use proper hash of row data
        (SELECT checksum FROM audit_log_checksums ORDER BY created_at DESC LIMIT 1);
END;

-- Data retention policies table
CREATE TABLE IF NOT EXISTS data_retention_policies (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT,
    table_name TEXT NOT NULL,
    retention_days INTEGER NOT NULL,
    delete_after_days INTEGER,
    archive_after_days INTEGER,
    anonymize_after_days INTEGER,
    last_cleanup_at TEXT,
    next_cleanup_at TEXT,
    status TEXT DEFAULT 'active' CHECK (status IN ('active', 'inactive')),
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now')),

    FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
    UNIQUE(business_id, table_name)
);

-- Insert default retention policies
INSERT OR IGNORE INTO data_retention_policies (business_id, table_name, retention_days, delete_after_days) VALUES
    (NULL, 'audit_logs', 2555, 2555), -- 7 years
    (NULL, 'system_events', 365, 365), -- 1 year
    (NULL, 'activity_logs', 90, 90), -- 90 days
    (NULL, 'user_sessions', 30, 30), -- 30 days
    (NULL, 'workflow_instances', 180, NULL); -- 180 days, archive don't delete

-- GDPR compliance table for tracking consent and data processing
CREATE TABLE IF NOT EXISTS gdpr_consents (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT NOT NULL,
    user_id TEXT NOT NULL,

    -- Consent types
    consent_type TEXT NOT NULL CHECK (consent_type IN (
        'terms_of_service',
        'privacy_policy',
        'marketing_emails',
        'data_processing',
        'cookies',
        'third_party_sharing',
        'analytics'
    )),

    -- Consent details
    consent_given INTEGER NOT NULL,
    consent_version TEXT NOT NULL,
    consent_text TEXT,
    ip_address TEXT,
    user_agent TEXT,

    -- Withdrawal
    withdrawn_at TEXT,
    withdrawal_reason TEXT,

    -- Timestamps
    created_at TEXT DEFAULT (datetime('now')),
    expires_at TEXT,

    FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE RESTRICT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE RESTRICT,

    UNIQUE(business_id, user_id, consent_type)
);

-- Data export requests table for GDPR compliance
CREATE TABLE IF NOT EXISTS data_export_requests (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT NOT NULL,
    user_id TEXT NOT NULL,

    -- Request details
    request_type TEXT NOT NULL CHECK (request_type IN ('export', 'deletion', 'correction')),
    status TEXT DEFAULT 'pending' CHECK (status IN ('pending', 'processing', 'completed', 'failed')),

    -- Processing details
    processed_by_user_id TEXT,
    processed_at TEXT,
    export_url TEXT,
    export_expires_at TEXT,

    -- Error handling
    error_message TEXT,
    retry_count INTEGER DEFAULT 0,

    -- Timestamps
    created_at TEXT DEFAULT (datetime('now')),
    completed_at TEXT,

    FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (processed_by_user_id) REFERENCES users(id) ON DELETE SET NULL
);

-- Create indexes for compliance tables
CREATE INDEX idx_audit_checksums_created ON audit_log_checksums(created_at DESC);
CREATE INDEX idx_retention_policies_cleanup ON data_retention_policies(next_cleanup_at) WHERE status = 'active';
CREATE INDEX idx_gdpr_consents_user ON gdpr_consents(user_id, consent_type);
CREATE INDEX idx_gdpr_consents_business ON gdpr_consents(business_id, consent_type);
CREATE INDEX idx_export_requests_status ON data_export_requests(status, created_at) WHERE status != 'completed';

-- Update schema migrations
INSERT OR IGNORE INTO schema_migrations (version, name, status) VALUES
    ('006', 'audit_immutability', 'completed');