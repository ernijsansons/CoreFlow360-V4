-- Migration: 021_crm_data_quality
-- Description: Data Quality, Duplicate Detection, and Auto-Capture Infrastructure
-- Created: 2025-10-12

-- ============================================================
-- DATA QUALITY ISSUES TRACKING
-- ============================================================
CREATE TABLE IF NOT EXISTS crm_data_quality_issues (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT NOT NULL REFERENCES businesses(id),

    -- Entity Reference
    entity_type TEXT NOT NULL CHECK(entity_type IN ('contact', 'company', 'lead', 'deal')),
    entity_id TEXT NOT NULL,

    -- Issue Details
    severity TEXT NOT NULL CHECK(severity IN ('low', 'medium', 'high', 'critical')),
    issue_type TEXT NOT NULL CHECK(issue_type IN (
        'missing_required_field',
        'invalid_format',
        'stale_data',
        'invalid_email',
        'invalid_phone',
        'invalid_domain',
        'orphaned_record',
        'low_score_anomaly',
        'duplicate_suspected',
        'inconsistent_data',
        'missing_activity',
        'data_decay'
    )),
    field_name TEXT,
    current_value TEXT,
    suggested_value TEXT,
    description TEXT NOT NULL,

    -- Resolution
    auto_fixable BOOLEAN DEFAULT FALSE,
    resolved BOOLEAN DEFAULT FALSE,
    resolved_at TIMESTAMP,
    resolved_by TEXT REFERENCES users(id),
    resolution_method TEXT CHECK(resolution_method IN ('auto', 'manual', 'dismissed')),

    -- Metadata
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_crm_quality_issues_business ON crm_data_quality_issues(business_id);
CREATE INDEX idx_crm_quality_issues_entity ON crm_data_quality_issues(entity_type, entity_id);
CREATE INDEX idx_crm_quality_issues_severity ON crm_data_quality_issues(severity) WHERE resolved = FALSE;
CREATE INDEX idx_crm_quality_issues_type ON crm_data_quality_issues(issue_type) WHERE resolved = FALSE;

-- ============================================================
-- DUPLICATE DETECTION RESULTS
-- ============================================================
CREATE TABLE IF NOT EXISTS crm_duplicate_matches (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT NOT NULL REFERENCES businesses(id),

    -- Match Details
    entity_type TEXT NOT NULL CHECK(entity_type IN ('contact', 'company')),
    primary_id TEXT NOT NULL,
    duplicate_id TEXT NOT NULL,
    match_score INTEGER NOT NULL CHECK(match_score >= 0 AND match_score <= 100),
    confidence TEXT NOT NULL CHECK(confidence IN ('low', 'medium', 'high')),

    -- Match Reasoning
    match_reasons TEXT NOT NULL, -- JSON array of MatchReason objects
    auto_merge_eligible BOOLEAN DEFAULT FALSE,

    -- Status
    status TEXT DEFAULT 'pending' CHECK(status IN ('pending', 'merged', 'dismissed', 'needs_review')),
    reviewed_by TEXT REFERENCES users(id),
    reviewed_at TIMESTAMP,

    -- Merge Details (if merged)
    merged_into TEXT,
    merged_at TIMESTAMP,
    merge_strategy TEXT, -- JSON object of MergeStrategy

    -- Metadata
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_crm_duplicates_business ON crm_duplicate_matches(business_id);
CREATE INDEX idx_crm_duplicates_entity ON crm_duplicate_matches(entity_type, primary_id);
CREATE INDEX idx_crm_duplicates_status ON crm_duplicate_matches(status);
CREATE INDEX idx_crm_duplicates_score ON crm_duplicate_matches(match_score DESC) WHERE status = 'pending';

-- Prevent duplicate duplicate matches
CREATE UNIQUE INDEX idx_crm_duplicates_unique ON crm_duplicate_matches(entity_type, primary_id, duplicate_id);

-- ============================================================
-- AUTO-CAPTURE: EMAIL INTEGRATION
-- ============================================================
CREATE TABLE IF NOT EXISTS crm_email_integrations (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT NOT NULL REFERENCES businesses(id),
    user_id TEXT NOT NULL REFERENCES users(id),

    -- Provider
    provider TEXT NOT NULL CHECK(provider IN ('gmail', 'outlook', 'exchange', 'imap', 'custom')),
    email_address TEXT NOT NULL,

    -- Configuration
    config TEXT NOT NULL, -- JSON: credentials, sync settings, filters
    sync_enabled BOOLEAN DEFAULT TRUE,
    auto_create_activities BOOLEAN DEFAULT TRUE,
    auto_link_contacts BOOLEAN DEFAULT TRUE,

    -- Sync Status
    last_sync_at TIMESTAMP,
    last_sync_status TEXT CHECK(last_sync_status IN ('success', 'failed', 'partial')),
    sync_error TEXT,
    emails_synced INTEGER DEFAULT 0,

    -- Metadata
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_crm_email_integrations_business ON crm_email_integrations(business_id);
CREATE INDEX idx_crm_email_integrations_user ON crm_email_integrations(user_id);

-- ============================================================
-- AUTO-CAPTURE: CALL INTEGRATION
-- ============================================================
CREATE TABLE IF NOT EXISTS crm_call_integrations (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT NOT NULL REFERENCES businesses(id),

    -- Provider
    provider TEXT NOT NULL CHECK(provider IN ('twilio', 'aircall', 'dialpad', 'ringcentral', 'custom')),

    -- Configuration
    config TEXT NOT NULL, -- JSON: API keys, phone numbers, recording settings
    auto_create_activities BOOLEAN DEFAULT TRUE,
    auto_transcribe BOOLEAN DEFAULT TRUE,
    auto_analyze_sentiment BOOLEAN DEFAULT TRUE,

    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    calls_captured INTEGER DEFAULT 0,
    last_call_at TIMESTAMP,

    -- Metadata
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_crm_call_integrations_business ON crm_call_integrations(business_id);

-- ============================================================
-- AUTO-CAPTURE: CHAT/CONVERSATION LOGS
-- ============================================================
CREATE TABLE IF NOT EXISTS crm_conversation_logs (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT NOT NULL REFERENCES businesses(id),

    -- Source
    source_type TEXT NOT NULL CHECK(source_type IN ('email', 'call', 'chat', 'sms', 'whatsapp', 'linkedin', 'slack', 'teams')),
    source_integration_id TEXT, -- Reference to integration table
    external_id TEXT, -- ID in external system

    -- Content
    subject TEXT,
    body TEXT,
    transcript TEXT, -- For calls/meetings
    participants TEXT NOT NULL, -- JSON array
    direction TEXT CHECK(direction IN ('inbound', 'outbound')),

    -- AI Processing
    processing_status TEXT DEFAULT 'pending' CHECK(processing_status IN ('pending', 'processing', 'completed', 'failed')),
    ai_extracted_data TEXT, -- JSON: entities, sentiment, action items
    ai_sentiment TEXT CHECK(ai_sentiment IN ('positive', 'neutral', 'negative')),
    ai_intent TEXT,

    -- Linkage
    linked_company_id TEXT REFERENCES crm_companies(id),
    linked_contact_id TEXT REFERENCES crm_contacts(id),
    linked_lead_id TEXT REFERENCES crm_leads(id),
    linked_deal_id TEXT REFERENCES crm_deals(id),
    linked_activity_id TEXT REFERENCES crm_activities(id),
    auto_linked BOOLEAN DEFAULT FALSE,

    -- Metadata
    occurred_at TIMESTAMP NOT NULL,
    captured_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    processed_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_crm_conversation_logs_business ON crm_conversation_logs(business_id);
CREATE INDEX idx_crm_conversation_logs_source ON crm_conversation_logs(source_type);
CREATE INDEX idx_crm_conversation_logs_processing ON crm_conversation_logs(processing_status) WHERE processing_status = 'pending';
CREATE INDEX idx_crm_conversation_logs_company ON crm_conversation_logs(linked_company_id);
CREATE INDEX idx_crm_conversation_logs_contact ON crm_conversation_logs(linked_contact_id);
CREATE INDEX idx_crm_conversation_logs_occurred ON crm_conversation_logs(occurred_at DESC);

-- ============================================================
-- DATA QUALITY SCORES (Cached)
-- ============================================================
CREATE TABLE IF NOT EXISTS crm_data_quality_scores (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT NOT NULL REFERENCES businesses(id),

    -- Entity Reference
    entity_type TEXT NOT NULL CHECK(entity_type IN ('contact', 'company', 'lead', 'deal')),
    entity_id TEXT NOT NULL,

    -- Scores
    overall_score INTEGER NOT NULL CHECK(overall_score >= 0 AND overall_score <= 100),
    completeness_score INTEGER NOT NULL CHECK(completeness_score >= 0 AND completeness_score <= 100),
    accuracy_score INTEGER NOT NULL CHECK(accuracy_score >= 0 AND accuracy_score <= 100),
    freshness_score INTEGER NOT NULL CHECK(freshness_score >= 0 AND freshness_score <= 100),
    consistency_score INTEGER NOT NULL CHECK(consistency_score >= 0 AND consistency_score <= 100),

    -- Issue Counts
    issues_count INTEGER DEFAULT 0,
    critical_issues_count INTEGER DEFAULT 0,

    -- Metadata
    calculated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP -- Cache expiry
);

CREATE UNIQUE INDEX idx_crm_quality_scores_entity ON crm_data_quality_scores(entity_type, entity_id);
CREATE INDEX idx_crm_quality_scores_business ON crm_data_quality_scores(business_id);
CREATE INDEX idx_crm_quality_scores_overall ON crm_data_quality_scores(overall_score);

-- ============================================================
-- CLEANSING RULES (User-Configurable)
-- ============================================================
CREATE TABLE IF NOT EXISTS crm_cleansing_rules (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT NOT NULL REFERENCES businesses(id),

    -- Rule Definition
    name TEXT NOT NULL,
    description TEXT,
    entity_type TEXT NOT NULL CHECK(entity_type IN ('contact', 'company', 'lead', 'deal')),
    field_name TEXT NOT NULL,

    -- Rule Type
    rule_type TEXT NOT NULL CHECK(rule_type IN (
        'required',
        'format_validation',
        'auto_format',
        'auto_populate',
        'data_enrichment',
        'duplicate_check'
    )),

    -- Configuration
    rule_config TEXT NOT NULL, -- JSON: regex, transform function, default value, etc.
    severity TEXT DEFAULT 'medium' CHECK(severity IN ('low', 'medium', 'high', 'critical')),
    auto_apply BOOLEAN DEFAULT FALSE,

    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    execution_count INTEGER DEFAULT 0,
    success_count INTEGER DEFAULT 0,

    -- Metadata
    created_by TEXT REFERENCES users(id),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_crm_cleansing_rules_business ON crm_cleansing_rules(business_id);
CREATE INDEX idx_crm_cleansing_rules_entity ON crm_cleansing_rules(entity_type, field_name);
CREATE INDEX idx_crm_cleansing_rules_active ON crm_cleansing_rules(is_active) WHERE is_active = TRUE;

-- ============================================================
-- ANALYTICS VIEW: DATA QUALITY DASHBOARD
-- ============================================================
CREATE VIEW IF NOT EXISTS v_crm_data_quality_summary AS
SELECT
    dqs.business_id,
    dqs.entity_type,
    COUNT(*) as total_records,
    AVG(dqs.overall_score) as avg_quality_score,
    SUM(CASE WHEN dqs.overall_score >= 80 THEN 1 ELSE 0 END) as healthy_count,
    SUM(CASE WHEN dqs.overall_score >= 60 AND dqs.overall_score < 80 THEN 1 ELSE 0 END) as at_risk_count,
    SUM(CASE WHEN dqs.overall_score < 60 THEN 1 ELSE 0 END) as critical_count,
    SUM(dqs.issues_count) as total_issues,
    SUM(dqs.critical_issues_count) as total_critical_issues
FROM crm_data_quality_scores dqs
WHERE dqs.expires_at > CURRENT_TIMESTAMP OR dqs.expires_at IS NULL
GROUP BY dqs.business_id, dqs.entity_type;

-- ============================================================
-- ANALYTICS VIEW: DUPLICATE DETECTION SUMMARY
-- ============================================================
CREATE VIEW IF NOT EXISTS v_crm_duplicate_detection_summary AS
SELECT
    business_id,
    entity_type,
    COUNT(*) as total_matches,
    SUM(CASE WHEN confidence = 'high' THEN 1 ELSE 0 END) as high_confidence_matches,
    SUM(CASE WHEN auto_merge_eligible = TRUE THEN 1 ELSE 0 END) as auto_merge_eligible_count,
    SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending_review,
    SUM(CASE WHEN status = 'merged' THEN 1 ELSE 0 END) as merged_count,
    SUM(CASE WHEN status = 'dismissed' THEN 1 ELSE 0 END) as dismissed_count
FROM crm_duplicate_matches
GROUP BY business_id, entity_type;
