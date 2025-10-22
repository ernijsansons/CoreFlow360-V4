-- Migration: 058_crm_data_validation
-- Description: Data validation and cleaning automation
-- Feature: #11 in Phase 1 Sprint 1

CREATE TABLE IF NOT EXISTS crm_data_validation_rules (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT NOT NULL,

    field_name TEXT NOT NULL,
    validation_type TEXT NOT NULL CHECK(validation_type IN (
        'email_format', 'phone_format', 'url_format', 'required', 'regex', 'range'
    )),
    validation_pattern TEXT,
    is_active INTEGER DEFAULT 1,

    FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS crm_data_quality_issues (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT NOT NULL,

    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    field_name TEXT NOT NULL,
    issue_type TEXT NOT NULL,
    issue_description TEXT,

    status TEXT DEFAULT 'open' CHECK(status IN ('open', 'fixed', 'ignored')),
    fixed_at TEXT,

    detected_at TEXT DEFAULT (datetime('now')),

    FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE
);

CREATE INDEX idx_crm_data_quality_issues_entity ON crm_data_quality_issues(entity_type, entity_id);
CREATE INDEX idx_crm_data_quality_issues_status ON crm_data_quality_issues(business_id, status);
