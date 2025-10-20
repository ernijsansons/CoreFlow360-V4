-- Migration: 052_crm_predictive_lead_scoring
-- Description: ML-powered predictive lead scoring system with Cloudflare Workers AI
-- Feature: #4 in Phase 1 Sprint 1 - CRM of Tomorrow
-- Created: 2025-01-19
-- Target: 85%+ accuracy in conversion prediction

-- ============================================================================
-- LEAD SCORING CONFIGURATION
-- ============================================================================

-- Lead scoring models configuration
CREATE TABLE IF NOT EXISTS crm_lead_scoring_models (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT NOT NULL,

    -- Model Information
    model_name TEXT NOT NULL,
    model_version TEXT NOT NULL DEFAULT 'v1',
    model_type TEXT NOT NULL CHECK(model_type IN (
        'ml_regression',          -- Workers AI regression model
        'rule_based',             -- Traditional rules-based scoring
        'hybrid',                 -- ML + rules combination
        'custom'                  -- Custom formula
    )),

    -- Model Configuration
    feature_weights TEXT NOT NULL, -- JSON: { "title_seniority": 0.3, "company_size": 0.25, ... }
    scoring_formula TEXT,          -- Custom formula for rule-based/hybrid
    conversion_threshold INTEGER DEFAULT 70 CHECK(conversion_threshold >= 0 AND conversion_threshold <= 100),

    -- Workers AI Configuration
    workers_ai_model TEXT DEFAULT '@cf/meta/llama-3-8b-instruct', -- Cloudflare Workers AI model
    temperature REAL DEFAULT 0.1,
    max_tokens INTEGER DEFAULT 512,

    -- Performance Metrics
    accuracy_rate REAL,            -- % predictions that matched actual outcome
    precision_rate REAL,           -- % of high-score leads that converted
    recall_rate REAL,              -- % of conversions caught by high scores
    f1_score REAL,                 -- Harmonic mean of precision and recall
    last_trained_at TEXT,
    training_sample_size INTEGER,

    -- Status
    status TEXT DEFAULT 'draft' CHECK(status IN ('draft', 'training', 'active', 'archived')),
    is_default INTEGER DEFAULT 0,  -- Only one default model per business

    -- Metadata
    created_by_user_id TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now')),
    archived_at TEXT,

    FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
    FOREIGN KEY (created_by_user_id) REFERENCES users(id),
    UNIQUE(business_id, model_name, model_version)
);

-- Lead scores history (one per lead/contact)
CREATE TABLE IF NOT EXISTS crm_lead_scores (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT NOT NULL,

    -- Entity Identification
    entity_id TEXT NOT NULL,
    entity_type TEXT NOT NULL CHECK(entity_type IN ('contact', 'lead', 'company')),

    -- Scoring Details
    model_id TEXT NOT NULL,
    score INTEGER NOT NULL CHECK(score >= 0 AND score <= 100),
    confidence_level TEXT NOT NULL DEFAULT 'medium' CHECK(confidence_level IN ('low', 'medium', 'high', 'very_high')),

    -- Score Breakdown
    feature_scores TEXT NOT NULL,  -- JSON: { "title_seniority": 85, "company_size": 70, ... }
    primary_drivers TEXT,          -- JSON array: ["C-level executive", "Fortune 500 company"]
    negative_factors TEXT,         -- JSON array: ["Low engagement", "Budget concerns"]

    -- Predictions
    conversion_probability REAL NOT NULL CHECK(conversion_probability >= 0 AND conversion_probability <= 1.0),
    predicted_deal_size REAL,
    predicted_time_to_close INTEGER, -- Days

    -- AI Insights
    ai_reasoning TEXT,             -- Why this score was assigned (from Workers AI)
    recommended_actions TEXT,      -- JSON array of next steps

    -- Comparison
    previous_score INTEGER,
    score_trend TEXT CHECK(score_trend IN ('improving', 'declining', 'stable', NULL)),

    -- Outcome Tracking (for model training)
    actual_outcome TEXT CHECK(actual_outcome IN ('converted', 'lost', 'ongoing', NULL)),
    actual_deal_size REAL,
    actual_days_to_close INTEGER,
    outcome_recorded_at TEXT,

    -- Metadata
    scored_at TEXT DEFAULT (datetime('now')),
    expires_at TEXT,               -- Scores expire after 30 days by default

    FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
    FOREIGN KEY (model_id) REFERENCES crm_lead_scoring_models(id) ON DELETE CASCADE
);

-- Scoring rules (for rule-based and hybrid models)
CREATE TABLE IF NOT EXISTS crm_scoring_rules (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT NOT NULL,
    model_id TEXT NOT NULL,

    -- Rule Definition
    rule_name TEXT NOT NULL,
    rule_type TEXT NOT NULL CHECK(rule_type IN (
        'demographic',     -- Job title, seniority, location
        'firmographic',    -- Company size, industry, revenue
        'behavioral',      -- Website visits, email opens, downloads
        'engagement',      -- Meeting attendance, response rate
        'intent'          -- Buyer intent signals
    )),

    -- Condition
    field_name TEXT NOT NULL,      -- e.g., "job_title", "company_employee_count"
    operator TEXT NOT NULL CHECK(operator IN (
        'equals', 'not_equals', 'contains', 'not_contains',
        'greater_than', 'less_than', 'in_list', 'matches_regex'
    )),
    field_value TEXT NOT NULL,     -- Value to compare against

    -- Scoring Impact
    points_if_match INTEGER NOT NULL,
    weight REAL DEFAULT 1.0 CHECK(weight >= 0 AND weight <= 1.0),

    -- Rule Configuration
    is_active INTEGER DEFAULT 1,
    priority INTEGER DEFAULT 50,   -- Higher priority rules applied first

    -- Metadata
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now')),

    FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
    FOREIGN KEY (model_id) REFERENCES crm_lead_scoring_models(id) ON DELETE CASCADE
);

-- Model training data (for ML models)
CREATE TABLE IF NOT EXISTS crm_scoring_training_data (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT NOT NULL,
    model_id TEXT NOT NULL,

    -- Training Sample
    entity_id TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    feature_vector TEXT NOT NULL, -- JSON of features used for training

    -- Ground Truth
    actual_outcome TEXT NOT NULL CHECK(actual_outcome IN ('converted', 'lost')),
    actual_deal_size REAL,
    actual_days_to_close INTEGER,

    -- Sample Metadata
    collected_at TEXT DEFAULT (datetime('now')),
    is_used_in_training INTEGER DEFAULT 1,

    FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
    FOREIGN KEY (model_id) REFERENCES crm_lead_scoring_models(id) ON DELETE CASCADE
);

-- Scoring audit log (track all score changes)
CREATE TABLE IF NOT EXISTS crm_scoring_audit_log (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT NOT NULL,

    -- Event Details
    entity_id TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    event_type TEXT NOT NULL CHECK(event_type IN (
        'score_calculated',
        'score_updated',
        'model_changed',
        'manual_override',
        'outcome_recorded'
    )),

    -- Changes
    old_score INTEGER,
    new_score INTEGER,
    score_delta INTEGER GENERATED ALWAYS AS (new_score - old_score) STORED,

    -- Context
    model_id TEXT,
    triggered_by TEXT,             -- 'enrichment', 'activity', 'manual', 'scheduled'
    changed_by_user_id TEXT,
    notes TEXT,

    -- Timestamp
    created_at TEXT DEFAULT (datetime('now')),

    FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
    FOREIGN KEY (model_id) REFERENCES crm_lead_scoring_models(id),
    FOREIGN KEY (changed_by_user_id) REFERENCES users(id)
);

-- ============================================================================
-- INDEXES FOR PERFORMANCE
-- ============================================================================

CREATE INDEX idx_crm_lead_scoring_models_business ON crm_lead_scoring_models(business_id, status);
CREATE INDEX idx_crm_lead_scoring_models_default ON crm_lead_scoring_models(business_id, is_default) WHERE is_default = 1;

CREATE INDEX idx_crm_lead_scores_entity ON crm_lead_scores(entity_id, entity_type);
CREATE INDEX idx_crm_lead_scores_business_score ON crm_lead_scores(business_id, score DESC);
CREATE INDEX idx_crm_lead_scores_expires ON crm_lead_scores(expires_at) WHERE expires_at IS NOT NULL;
CREATE INDEX idx_crm_lead_scores_outcome ON crm_lead_scores(actual_outcome) WHERE actual_outcome IS NOT NULL;

CREATE INDEX idx_crm_scoring_rules_model ON crm_scoring_rules(model_id, is_active);
CREATE INDEX idx_crm_scoring_rules_priority ON crm_scoring_rules(model_id, priority DESC) WHERE is_active = 1;

CREATE INDEX idx_crm_scoring_training_data_model ON crm_scoring_training_data(model_id);
CREATE INDEX idx_crm_scoring_training_data_outcome ON crm_scoring_training_data(actual_outcome);

CREATE INDEX idx_crm_scoring_audit_log_entity ON crm_scoring_audit_log(entity_id, entity_type, created_at DESC);
CREATE INDEX idx_crm_scoring_audit_log_business ON crm_scoring_audit_log(business_id, created_at DESC);

-- ============================================================================
-- ANALYTICS VIEWS
-- ============================================================================

-- High-value leads view (score >= 70)
CREATE VIEW IF NOT EXISTS view_high_value_leads AS
SELECT
    ls.business_id,
    ls.entity_id,
    ls.entity_type,
    ls.score,
    ls.conversion_probability,
    ls.predicted_deal_size,
    ls.predicted_time_to_close,
    ls.primary_drivers,
    ls.recommended_actions,
    ls.scored_at,
    m.model_name,
    m.model_type,
    CASE
        WHEN ls.score >= 90 THEN 'hot'
        WHEN ls.score >= 70 THEN 'warm'
        ELSE 'cold'
    END as lead_temperature
FROM crm_lead_scores ls
JOIN crm_lead_scoring_models m ON ls.model_id = m.id
WHERE ls.score >= 70
  AND (ls.expires_at IS NULL OR ls.expires_at > datetime('now'))
  AND ls.actual_outcome IS NULL
ORDER BY ls.score DESC, ls.conversion_probability DESC;

-- Model performance metrics view
CREATE VIEW IF NOT EXISTS view_scoring_model_performance AS
SELECT
    m.id as model_id,
    m.business_id,
    m.model_name,
    m.model_type,
    m.accuracy_rate,
    m.precision_rate,
    m.recall_rate,
    m.f1_score,
    m.training_sample_size,
    m.last_trained_at,
    COUNT(DISTINCT ls.id) as total_scores,
    SUM(CASE WHEN ls.actual_outcome = 'converted' THEN 1 ELSE 0 END) as actual_conversions,
    AVG(ls.score) as avg_score,
    AVG(ls.conversion_probability) as avg_conversion_prob,
    COUNT(DISTINCT CASE WHEN ls.actual_outcome IS NOT NULL THEN ls.id END) as scored_outcomes
FROM crm_lead_scoring_models m
LEFT JOIN crm_lead_scores ls ON m.id = ls.model_id
WHERE m.status = 'active'
GROUP BY m.id;

-- ============================================================================
-- TRIGGERS FOR AUTO-UPDATES
-- ============================================================================

-- Auto-update model timestamps
CREATE TRIGGER IF NOT EXISTS trg_crm_scoring_model_updated
AFTER UPDATE ON crm_lead_scoring_models
BEGIN
    UPDATE crm_lead_scoring_models
    SET updated_at = datetime('now')
    WHERE id = NEW.id;
END;

-- Auto-log score changes
CREATE TRIGGER IF NOT EXISTS trg_crm_lead_score_audit
AFTER INSERT ON crm_lead_scores
BEGIN
    INSERT INTO crm_scoring_audit_log (
        business_id, entity_id, entity_type, event_type,
        old_score, new_score, model_id, triggered_by
    ) VALUES (
        NEW.business_id, NEW.entity_id, NEW.entity_type, 'score_calculated',
        NEW.previous_score, NEW.score, NEW.model_id, 'system'
    );
END;

-- Auto-expire old scores (cleanup trigger)
CREATE TRIGGER IF NOT EXISTS trg_crm_lead_score_expiry
AFTER INSERT ON crm_lead_scores
BEGIN
    -- Set expiry to 30 days from now if not set
    UPDATE crm_lead_scores
    SET expires_at = datetime('now', '+30 days')
    WHERE id = NEW.id AND expires_at IS NULL;
END;
