-- Migration: 060_crm_intent_signals
-- Description: Buyer intent signal monitoring and tracking
-- Feature: #9 in Phase 1 Sprint 1

CREATE TABLE IF NOT EXISTS crm_intent_signals (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT NOT NULL,

    -- Entity Association
    entity_type TEXT NOT NULL CHECK(entity_type IN ('contact', 'company', 'lead')),
    entity_id TEXT NOT NULL,

    -- Signal Details
    signal_type TEXT NOT NULL CHECK(signal_type IN (
        'website_visit', 'content_download', 'webinar_registration',
        'pricing_page_view', 'demo_request', 'trial_signup',
        'competitor_research', 'product_research', 'technology_research',
        'job_posting', 'funding_announcement', 'leadership_change'
    )),

    signal_source TEXT NOT NULL CHECK(signal_source IN (
        'bombora', '6sense', 'zoominfo', 'clearbit', 'linkedin',
        'website_analytics', 'email_engagement', 'manual'
    )),

    -- Intent Strength
    intent_score INTEGER NOT NULL CHECK(intent_score >= 0 AND intent_score <= 100),
    intent_level TEXT NOT NULL CHECK(intent_level IN ('low', 'medium', 'high', 'very_high')),

    -- Signal Context
    topic TEXT,                    -- e.g., "CRM Software", "Sales Automation"
    url TEXT,                      -- Page visited or content URL
    metadata TEXT,                 -- JSON: additional signal data

    -- Timing
    signal_timestamp TEXT NOT NULL,
    detected_at TEXT DEFAULT (datetime('now')),
    expires_at TEXT,               -- Signals decay over time

    FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS crm_intent_topics (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT NOT NULL,

    topic_name TEXT NOT NULL,
    category TEXT,                  -- e.g., "Product Category", "Competitor", "Industry"
    keywords TEXT,                  -- JSON array of keywords to monitor
    is_active INTEGER DEFAULT 1,

    created_at TEXT DEFAULT (datetime('now')),

    FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
    UNIQUE(business_id, topic_name)
);

CREATE INDEX idx_crm_intent_signals_entity ON crm_intent_signals(entity_type, entity_id, signal_timestamp DESC);
CREATE INDEX idx_crm_intent_signals_type ON crm_intent_signals(business_id, signal_type, intent_level);
CREATE INDEX idx_crm_intent_signals_high ON crm_intent_signals(business_id, intent_level) WHERE intent_level IN ('high', 'very_high');

CREATE VIEW IF NOT EXISTS view_high_intent_signals AS
SELECT
    s.*,
    c.first_name,
    c.last_name,
    c.email,
    c.company_name
FROM crm_intent_signals s
LEFT JOIN crm_contacts c ON s.entity_id = c.id AND s.entity_type = 'contact'
WHERE s.intent_level IN ('high', 'very_high')
  AND (s.expires_at IS NULL OR s.expires_at > datetime('now'))
ORDER BY s.intent_score DESC, s.signal_timestamp DESC;
