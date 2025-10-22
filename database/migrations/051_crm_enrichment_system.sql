-- Migration: 051_crm_enrichment_system
-- Description: Continuous Data Enrichment Infrastructure (Feature #2)
-- Features: Auto-update contacts daily, 97%+ completeness, multi-source tracking
-- Created: 2025-10-19
-- Part of: Phase 1 Sprint 1

-- ============================================================
-- ENRICHMENT HISTORY & TRACKING
-- ============================================================
CREATE TABLE IF NOT EXISTS crm_enrichment_history (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT NOT NULL REFERENCES businesses(id),

    -- Target Entity
    entity_id TEXT NOT NULL,
    entity_type TEXT NOT NULL CHECK(entity_type IN ('contact', 'company', 'lead')),

    -- Enrichment Source
    data_source TEXT NOT NULL CHECK(data_source IN (
        'apollo',
        'clearbit',
        'hunter',
        'peopledatalabs',
        'zoominfo',
        'linkedin_api',
        'crunchbase',
        'fullcontact',
        'manual',
        'email_signature',
        'web_scrape'
    )),

    -- Enrichment Details
    fields_updated TEXT NOT NULL, -- JSON array: ['job_title', 'company_name', 'linkedin_url']
    fields_added TEXT, -- JSON array: new fields that didn't exist before
    confidence_score REAL, -- 0.0 to 1.0

    -- Data Quality Metrics
    completeness_before INTEGER, -- Percentage (0-100)
    completeness_after INTEGER, -- Percentage (0-100)
    fields_improved INTEGER DEFAULT 0,

    -- Status & Outcome
    status TEXT DEFAULT 'success' CHECK(status IN ('success', 'partial', 'failed', 'no_data_found')),
    error_message TEXT,

    -- Cost Tracking
    api_credits_used INTEGER DEFAULT 0,
    cost_usd REAL DEFAULT 0.0,

    -- Timestamps
    enriched_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_crm_enrichment_history_entity ON crm_enrichment_history(entity_id, entity_type);
CREATE INDEX idx_crm_enrichment_history_source ON crm_enrichment_history(data_source);
CREATE INDEX idx_crm_enrichment_history_status ON crm_enrichment_history(status);
CREATE INDEX idx_crm_enrichment_history_date ON crm_enrichment_history(enriched_at DESC);

-- ============================================================
-- ENRICHMENT QUEUE (Async Processing)
-- ============================================================
CREATE TABLE IF NOT EXISTS crm_enrichment_queue (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT NOT NULL REFERENCES businesses(id),

    -- Target Entity
    entity_id TEXT NOT NULL,
    entity_type TEXT NOT NULL CHECK(entity_type IN ('contact', 'company', 'lead')),

    -- Priority & Scheduling
    priority INTEGER DEFAULT 50 CHECK(priority >= 0 AND priority <= 100), -- Higher = more urgent
    scheduled_for TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    max_retries INTEGER DEFAULT 3,
    retry_count INTEGER DEFAULT 0,

    -- Enrichment Strategy
    preferred_sources TEXT, -- JSON array: ['clearbit', 'hunter'] - sources to try in order
    fields_to_enrich TEXT, -- JSON array: specific fields to update, or null for all

    -- Status
    status TEXT DEFAULT 'pending' CHECK(status IN ('pending', 'processing', 'completed', 'failed', 'cancelled')),
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    error_message TEXT,

    -- Metadata
    triggered_by TEXT, -- 'cron_job', 'user_request', 'new_entity', 'data_staleness'
    metadata TEXT, -- JSON: additional context

    -- Timestamps
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_crm_enrichment_queue_status ON crm_enrichment_queue(status, priority DESC);
CREATE INDEX idx_crm_enrichment_queue_scheduled ON crm_enrichment_queue(scheduled_for) WHERE status = 'pending';
CREATE INDEX idx_crm_enrichment_queue_entity ON crm_enrichment_queue(entity_id, entity_type);

-- ============================================================
-- ENRICHMENT RULES (Auto-Trigger Conditions)
-- ============================================================
CREATE TABLE IF NOT EXISTS crm_enrichment_rules (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT NOT NULL REFERENCES businesses(id),

    -- Rule Definition
    name TEXT NOT NULL,
    description TEXT,
    enabled BOOLEAN DEFAULT TRUE,

    -- Trigger Conditions
    trigger_event TEXT NOT NULL CHECK(trigger_event IN (
        'contact_created',
        'contact_updated',
        'company_created',
        'data_staleness_detected', -- e.g., last enriched > 30 days ago
        'missing_critical_fields', -- e.g., no job_title or company
        'scheduled_daily',
        'scheduled_weekly',
        'manual_trigger'
    )),

    -- Conditions (JSON)
    conditions TEXT, -- JSON: {field_missing: 'job_title', completeness_below: 70}

    -- Actions
    enrichment_sources TEXT NOT NULL, -- JSON array: ['clearbit', 'hunter']
    priority INTEGER DEFAULT 50,

    -- Rate Limiting
    max_executions_per_day INTEGER,
    executions_today INTEGER DEFAULT 0,
    last_executed_at TIMESTAMP,

    -- Metrics
    total_executions INTEGER DEFAULT 0,
    success_count INTEGER DEFAULT 0,
    failure_count INTEGER DEFAULT 0,

    -- Timestamps
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP
);

CREATE INDEX idx_crm_enrichment_rules_enabled ON crm_enrichment_rules(enabled) WHERE deleted_at IS NULL;
CREATE INDEX idx_crm_enrichment_rules_trigger ON crm_enrichment_rules(trigger_event) WHERE enabled = TRUE;

-- ============================================================
-- DATA SOURCE CREDENTIALS (Encrypted)
-- ============================================================
CREATE TABLE IF NOT EXISTS crm_enrichment_credentials (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT NOT NULL REFERENCES businesses(id),

    -- Data Source
    data_source TEXT NOT NULL CHECK(data_source IN (
        'clearbit',
        'hunter',
        'peopledatalabs',
        'zoominfo',
        'linkedin_api',
        'crunchbase',
        'fullcontact'
    )),

    -- Credentials (should be encrypted in production)
    api_key TEXT NOT NULL,
    api_secret TEXT,
    additional_config TEXT, -- JSON: rate limits, endpoints, etc.

    -- Usage Tracking
    monthly_quota INTEGER,
    quota_used INTEGER DEFAULT 0,
    quota_reset_at TIMESTAMP,

    -- Status
    status TEXT DEFAULT 'active' CHECK(status IN ('active', 'inactive', 'rate_limited', 'expired')),
    last_used_at TIMESTAMP,
    last_error TEXT,

    -- Timestamps
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    UNIQUE(business_id, data_source)
);

CREATE INDEX idx_crm_enrichment_credentials_source ON crm_enrichment_credentials(data_source, status);

-- ============================================================
-- DATA COMPLETENESS SCORES (Tracking)
-- ============================================================
CREATE TABLE IF NOT EXISTS crm_data_completeness (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT NOT NULL REFERENCES businesses(id),

    -- Entity
    entity_id TEXT NOT NULL,
    entity_type TEXT NOT NULL CHECK(entity_type IN ('contact', 'company', 'lead')),

    -- Completeness Metrics
    total_fields INTEGER NOT NULL,
    filled_fields INTEGER NOT NULL,
    completeness_percentage INTEGER GENERATED ALWAYS AS (
        CAST((filled_fields * 100.0 / NULLIF(total_fields, 0)) AS INTEGER)
    ) STORED,

    -- Critical Fields Status
    has_email BOOLEAN DEFAULT FALSE,
    has_phone BOOLEAN DEFAULT FALSE,
    has_company BOOLEAN DEFAULT FALSE,
    has_job_title BOOLEAN DEFAULT FALSE,
    has_linkedin BOOLEAN DEFAULT FALSE,
    has_address BOOLEAN DEFAULT FALSE,

    -- Data Freshness
    last_enriched_at TIMESTAMP,
    data_staleness_days INTEGER, -- Days since last enrichment
    needs_refresh BOOLEAN DEFAULT FALSE,

    -- Quality Score (0-100)
    quality_score INTEGER CHECK(quality_score >= 0 AND quality_score <= 100),

    -- Timestamps
    calculated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    UNIQUE(entity_id, entity_type, business_id)
);

CREATE INDEX idx_crm_data_completeness_entity ON crm_data_completeness(entity_id, entity_type);
CREATE INDEX idx_crm_data_completeness_score ON crm_data_completeness(completeness_percentage);
CREATE INDEX idx_crm_data_completeness_refresh ON crm_data_completeness(needs_refresh) WHERE needs_refresh = TRUE;
CREATE INDEX idx_crm_data_completeness_quality ON crm_data_completeness(quality_score);

-- ============================================================
-- JOB CHANGE DETECTION (Feature #3 Integration)
-- ============================================================
CREATE TABLE IF NOT EXISTS crm_job_changes (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT NOT NULL REFERENCES businesses(id),
    contact_id TEXT NOT NULL REFERENCES crm_contacts(id),

    -- Change Details
    change_type TEXT NOT NULL CHECK(change_type IN (
        'job_title_changed',
        'company_changed',
        'promotion',
        'department_changed',
        'left_company',
        'started_new_role'
    )),

    -- Before & After
    old_job_title TEXT,
    new_job_title TEXT,
    old_company_id TEXT REFERENCES crm_companies(id),
    old_company_name TEXT,
    new_company_id TEXT REFERENCES crm_companies(id),
    new_company_name TEXT,
    old_seniority TEXT,
    new_seniority TEXT,

    -- Detection Metadata
    detected_via TEXT NOT NULL, -- 'linkedin_api', 'peopledatalabs', 'email_signature', 'manual'
    detection_confidence REAL CHECK(detection_confidence >= 0 AND detection_confidence <= 1),
    evidence TEXT, -- JSON: supporting data

    -- Alert Status
    alert_sent BOOLEAN DEFAULT FALSE,
    alert_sent_at TIMESTAMP,
    owner_notified BOOLEAN DEFAULT FALSE,

    -- Opportunity Flags
    creates_opportunity BOOLEAN DEFAULT FALSE, -- New role = potential opportunity
    requires_re_engagement BOOLEAN DEFAULT FALSE,
    priority TEXT DEFAULT 'medium' CHECK(priority IN ('low', 'medium', 'high', 'urgent')),

    -- Timestamps
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    changed_at TIMESTAMP, -- Estimated date of actual change
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_crm_job_changes_contact ON crm_job_changes(contact_id);
CREATE INDEX idx_crm_job_changes_detected ON crm_job_changes(detected_at DESC);
CREATE INDEX idx_crm_job_changes_alert ON crm_job_changes(alert_sent) WHERE alert_sent = FALSE;
CREATE INDEX idx_crm_job_changes_opportunity ON crm_job_changes(creates_opportunity) WHERE creates_opportunity = TRUE;

-- ============================================================
-- ENRICHMENT ANALYTICS (Dashboard)
-- ============================================================
CREATE TABLE IF NOT EXISTS crm_enrichment_metrics (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT NOT NULL REFERENCES businesses(id),

    -- Metrics Period
    period_start DATE NOT NULL,
    period_end DATE NOT NULL,
    period_type TEXT DEFAULT 'daily' CHECK(period_type IN ('hourly', 'daily', 'weekly', 'monthly')),

    -- Enrichment Stats
    total_enrichments INTEGER DEFAULT 0,
    successful_enrichments INTEGER DEFAULT 0,
    failed_enrichments INTEGER DEFAULT 0,
    contacts_enriched INTEGER DEFAULT 0,
    companies_enriched INTEGER DEFAULT 0,

    -- Quality Improvements
    avg_completeness_improvement REAL, -- Average percentage point increase
    fields_added_total INTEGER DEFAULT 0,
    fields_updated_total INTEGER DEFAULT 0,

    -- Source Breakdown
    enrichments_by_source TEXT, -- JSON: {clearbit: 50, hunter: 30, peopledatalabs: 20}
    cost_by_source TEXT, -- JSON: {clearbit: 5.00, hunter: 2.50}

    -- Job Changes Detected
    job_changes_detected INTEGER DEFAULT 0,
    opportunities_created INTEGER DEFAULT 0,

    -- Cost Tracking
    total_cost_usd REAL DEFAULT 0.0,
    avg_cost_per_contact REAL,

    -- Timestamps
    calculated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_crm_enrichment_metrics_period ON crm_enrichment_metrics(period_start, period_end);
CREATE INDEX idx_crm_enrichment_metrics_business ON crm_enrichment_metrics(business_id);

-- ============================================================
-- VIEWS FOR ANALYTICS
-- ============================================================

-- View: Contacts Needing Enrichment
CREATE VIEW IF NOT EXISTS view_contacts_needing_enrichment AS
SELECT
    c.id,
    c.full_name,
    c.email,
    c.company_id,
    dc.completeness_percentage,
    dc.data_staleness_days,
    dc.last_enriched_at,
    CASE
        WHEN dc.completeness_percentage < 50 THEN 'high'
        WHEN dc.completeness_percentage < 75 THEN 'medium'
        ELSE 'low'
    END as enrichment_priority,
    CASE
        WHEN dc.has_email = FALSE THEN TRUE
        WHEN dc.has_company = FALSE THEN TRUE
        WHEN dc.has_job_title = FALSE THEN TRUE
        WHEN dc.data_staleness_days > 90 THEN TRUE
        ELSE FALSE
    END as needs_immediate_enrichment
FROM crm_contacts c
LEFT JOIN crm_data_completeness dc ON dc.entity_id = c.id AND dc.entity_type = 'contact'
WHERE c.deleted_at IS NULL
    AND (dc.completeness_percentage < 90 OR dc.data_staleness_days > 90 OR dc.id IS NULL);

-- View: Enrichment Success Rate by Source
CREATE VIEW IF NOT EXISTS view_enrichment_success_rates AS
SELECT
    data_source,
    COUNT(*) as total_attempts,
    SUM(CASE WHEN status = 'success' THEN 1 ELSE 0 END) as successful,
    SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) as failed,
    ROUND(SUM(CASE WHEN status = 'success' THEN 1 ELSE 0 END) * 100.0 / COUNT(*), 2) as success_rate,
    AVG(confidence_score) as avg_confidence,
    AVG(completeness_after - completeness_before) as avg_improvement,
    SUM(cost_usd) as total_cost
FROM crm_enrichment_history
WHERE enriched_at >= date('now', '-30 days')
GROUP BY data_source;

-- ============================================================
-- TRIGGERS
-- ============================================================

-- Trigger: Queue enrichment for new contacts
CREATE TRIGGER IF NOT EXISTS trg_queue_enrichment_new_contact
AFTER INSERT ON crm_contacts
BEGIN
    INSERT INTO crm_enrichment_queue (
        business_id,
        entity_id,
        entity_type,
        priority,
        triggered_by,
        preferred_sources
    ) VALUES (
        NEW.business_id,
        NEW.id,
        'contact',
        80, -- High priority for new contacts
        'new_entity',
        '["clearbit", "hunter", "peopledatalabs"]'
    );
END;

-- Trigger: Update completeness score after enrichment
CREATE TRIGGER IF NOT EXISTS trg_update_completeness_after_enrichment
AFTER INSERT ON crm_enrichment_history
WHEN NEW.status = 'success'
BEGIN
    INSERT OR REPLACE INTO crm_data_completeness (
        business_id,
        entity_id,
        entity_type,
        total_fields,
        filled_fields,
        last_enriched_at,
        data_staleness_days,
        needs_refresh,
        calculated_at
    ) VALUES (
        NEW.business_id,
        NEW.entity_id,
        NEW.entity_type,
        20, -- Assuming 20 total fields for contacts
        NEW.completeness_after * 20 / 100,
        CURRENT_TIMESTAMP,
        0,
        FALSE,
        CURRENT_TIMESTAMP
    );
END;

-- ============================================================
-- INITIALIZATION DATA
-- ============================================================

-- Insert default enrichment rules
INSERT OR IGNORE INTO crm_enrichment_rules (
    business_id,
    name,
    description,
    enabled,
    trigger_event,
    enrichment_sources,
    priority
) VALUES
    ('business-founder-001', 'Daily Contact Refresh', 'Refresh all contacts daily', TRUE, 'scheduled_daily', '["clearbit", "hunter"]', 30),
    ('business-founder-001', 'New Contact Auto-Enrich', 'Enrich new contacts immediately', TRUE, 'contact_created', '["clearbit", "peopledatalabs"]', 90),
    ('business-founder-001', 'Stale Data Refresh', 'Refresh contacts with data older than 90 days', TRUE, 'data_staleness_detected', '["clearbit"]', 50);
