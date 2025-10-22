-- Migration: 053_crm_deal_health_scoring
-- Description: Deal health scoring with engagement velocity and win/loss prediction
-- Feature: #5 in Phase 1 Sprint 1 - CRM of Tomorrow
-- Created: 2025-01-19
-- Target: 80%+ win/loss prediction accuracy

-- ============================================================================
-- DEAL HEALTH SCORING
-- ============================================================================

-- Deal health scores
CREATE TABLE IF NOT EXISTS crm_deal_health_scores (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT NOT NULL,
    deal_id TEXT NOT NULL,

    -- Overall Health Score (0-100)
    health_score INTEGER NOT NULL CHECK(health_score >= 0 AND health_score <= 100),
    health_status TEXT NOT NULL CHECK(health_status IN ('critical', 'at_risk', 'healthy', 'excellent')),
    trend TEXT CHECK(trend IN ('improving', 'stable', 'declining')),

    -- Win/Loss Prediction
    win_probability REAL NOT NULL CHECK(win_probability >= 0 AND win_probability <= 1.0),
    predicted_outcome TEXT NOT NULL CHECK(predicted_outcome IN ('win', 'loss', 'uncertain')),
    confidence_level TEXT NOT NULL DEFAULT 'medium' CHECK(confidence_level IN ('low', 'medium', 'high', 'very_high')),

    -- Component Scores (each 0-100)
    engagement_score INTEGER CHECK(engagement_score >= 0 AND engagement_score <= 100),
    velocity_score INTEGER CHECK(velocity_score >= 0 AND velocity_score <= 100),
    stakeholder_score INTEGER CHECK(stakeholder_score >= 0 AND stakeholder_score <= 100),
    budget_score INTEGER CHECK(budget_score >= 0 AND budget_score <= 100),
    timeline_score INTEGER CHECK(timeline_score >= 0 AND timeline_score <= 100),

    -- Engagement Velocity Metrics
    days_since_last_activity INTEGER,
    activity_frequency REAL,          -- Activities per week
    response_time_avg INTEGER,        -- Hours
    meeting_cadence REAL,             -- Meetings per week
    email_engagement_rate REAL,       -- Open + click rate

    -- Stakeholder Engagement
    total_stakeholders INTEGER DEFAULT 0,
    engaged_stakeholders INTEGER DEFAULT 0,
    champion_identified INTEGER DEFAULT 0,
    decision_maker_engaged INTEGER DEFAULT 0,
    multi_threading_score INTEGER,    -- Breadth of relationships

    -- Deal Progression
    current_stage TEXT,
    expected_close_date TEXT,
    days_in_current_stage INTEGER,
    stage_velocity REAL,              -- Days per stage (faster = better)
    deal_age_days INTEGER,

    -- Risk Factors
    risk_factors TEXT,                -- JSON array of identified risks
    red_flags TEXT,                   -- JSON array of warning signs
    competitive_threats TEXT,         -- JSON array of competitors

    -- AI Insights
    ai_analysis TEXT,                 -- Workers AI reasoning
    recommended_actions TEXT NOT NULL, -- JSON array of next steps
    coaching_tips TEXT,               -- JSON array for sales rep

    -- Historical Context
    previous_health_score INTEGER,
    score_change INTEGER GENERATED ALWAYS AS (health_score - previous_health_score) STORED,

    -- Metadata
    scored_at TEXT DEFAULT (datetime('now')),
    scored_by TEXT DEFAULT 'ai_agent',
    expires_at TEXT,

    FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
    FOREIGN KEY (deal_id) REFERENCES crm_deals(id) ON DELETE CASCADE
);

-- Deal engagement events (for velocity calculation)
CREATE TABLE IF NOT EXISTS crm_deal_engagement_events (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT NOT NULL,
    deal_id TEXT NOT NULL,

    -- Event Details
    event_type TEXT NOT NULL CHECK(event_type IN (
        'email_sent', 'email_opened', 'email_clicked', 'email_replied',
        'meeting_scheduled', 'meeting_completed', 'meeting_no_show',
        'call_completed', 'call_missed',
        'document_viewed', 'document_downloaded',
        'proposal_sent', 'proposal_viewed', 'proposal_signed',
        'demo_scheduled', 'demo_completed',
        'stage_advanced', 'stage_regressed',
        'stakeholder_added', 'champion_identified',
        'competitor_mentioned', 'objection_raised', 'objection_resolved'
    )),

    event_timestamp TEXT NOT NULL,
    event_metadata TEXT,              -- JSON: additional context

    -- Participants
    stakeholder_id TEXT,              -- Contact involved
    sales_rep_id TEXT,                -- User who triggered event

    -- Impact Scoring
    engagement_value INTEGER CHECK(engagement_value >= -10 AND engagement_value <= 10), -- Positive/negative impact
    velocity_impact REAL,             -- How this affects deal velocity

    -- Metadata
    created_at TEXT DEFAULT (datetime('now')),

    FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
    FOREIGN KEY (deal_id) REFERENCES crm_deals(id) ON DELETE CASCADE,
    FOREIGN KEY (stakeholder_id) REFERENCES crm_contacts(id),
    FOREIGN KEY (sales_rep_id) REFERENCES users(id)
);

-- Deal stakeholder engagement tracking
CREATE TABLE IF NOT EXISTS crm_deal_stakeholders (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT NOT NULL,
    deal_id TEXT NOT NULL,
    contact_id TEXT NOT NULL,

    -- Stakeholder Role
    role TEXT NOT NULL CHECK(role IN (
        'champion',           -- Internal advocate
        'decision_maker',     -- Final say
        'influencer',         -- Provides input
        'end_user',           -- Will use product
        'blocker',            -- Opposes deal
        'gatekeeper',         -- Controls access
        'technical_buyer',    -- Evaluates technical fit
        'economic_buyer'      -- Controls budget
    )),

    -- Engagement Metrics
    total_interactions INTEGER DEFAULT 0,
    last_interaction_at TEXT,
    engagement_level TEXT CHECK(engagement_level IN ('none', 'low', 'medium', 'high', 'very_high')),
    sentiment TEXT CHECK(sentiment IN ('negative', 'neutral', 'positive', 'very_positive')),

    -- Influence & Power
    influence_score INTEGER CHECK(influence_score >= 0 AND influence_score <= 100),
    is_primary_contact INTEGER DEFAULT 0,

    -- Status
    status TEXT DEFAULT 'active' CHECK(status IN ('active', 'inactive', 'blocked')),

    -- Metadata
    added_at TEXT DEFAULT (datetime('now')),
    added_by_user_id TEXT,

    FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
    FOREIGN KEY (deal_id) REFERENCES crm_deals(id) ON DELETE CASCADE,
    FOREIGN KEY (contact_id) REFERENCES crm_contacts(id) ON DELETE CASCADE,
    FOREIGN KEY (added_by_user_id) REFERENCES users(id),
    UNIQUE(deal_id, contact_id)
);

-- Deal risk alerts
CREATE TABLE IF NOT EXISTS crm_deal_risk_alerts (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT NOT NULL,
    deal_id TEXT NOT NULL,

    -- Alert Details
    risk_type TEXT NOT NULL CHECK(risk_type IN (
        'no_recent_activity',
        'slow_response_time',
        'stakeholder_churn',
        'no_champion',
        'no_decision_maker',
        'competitive_threat',
        'budget_concern',
        'timeline_slippage',
        'low_engagement',
        'negative_sentiment',
        'stalled_stage'
    )),

    severity TEXT NOT NULL CHECK(severity IN ('low', 'medium', 'high', 'critical')),
    risk_description TEXT NOT NULL,

    -- Detection
    detected_at TEXT DEFAULT (datetime('now')),
    detected_by TEXT DEFAULT 'ai_agent',

    -- Resolution
    status TEXT DEFAULT 'open' CHECK(status IN ('open', 'acknowledged', 'resolved', 'dismissed')),
    resolved_at TEXT,
    resolution_notes TEXT,

    -- Recommendations
    recommended_action TEXT,

    FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
    FOREIGN KEY (deal_id) REFERENCES crm_deals(id) ON DELETE CASCADE
);

-- ============================================================================
-- INDEXES FOR PERFORMANCE
-- ============================================================================

CREATE INDEX idx_crm_deal_health_scores_deal ON crm_deal_health_scores(deal_id, scored_at DESC);
CREATE INDEX idx_crm_deal_health_scores_business ON crm_deal_health_scores(business_id, health_status);
CREATE INDEX idx_crm_deal_health_scores_at_risk ON crm_deal_health_scores(business_id, health_status)
    WHERE health_status IN ('critical', 'at_risk');

CREATE INDEX idx_crm_deal_engagement_events_deal ON crm_deal_engagement_events(deal_id, event_timestamp DESC);
CREATE INDEX idx_crm_deal_engagement_events_type ON crm_deal_engagement_events(business_id, event_type, event_timestamp DESC);

CREATE INDEX idx_crm_deal_stakeholders_deal ON crm_deal_stakeholders(deal_id, role);
CREATE INDEX idx_crm_deal_stakeholders_contact ON crm_deal_stakeholders(contact_id);
CREATE INDEX idx_crm_deal_stakeholders_champions ON crm_deal_stakeholders(deal_id, role) WHERE role IN ('champion', 'decision_maker');

CREATE INDEX idx_crm_deal_risk_alerts_deal ON crm_deal_risk_alerts(deal_id, status);
CREATE INDEX idx_crm_deal_risk_alerts_open ON crm_deal_risk_alerts(business_id, severity, status) WHERE status = 'open';

-- ============================================================================
-- ANALYTICS VIEWS
-- ============================================================================

-- At-risk deals view
CREATE VIEW IF NOT EXISTS view_at_risk_deals AS
SELECT
    dhs.business_id,
    dhs.deal_id,
    d.deal_name,
    d.deal_value,
    d.stage,
    dhs.health_score,
    dhs.health_status,
    dhs.win_probability,
    dhs.days_since_last_activity,
    dhs.risk_factors,
    dhs.recommended_actions,
    COUNT(DISTINCT dra.id) as open_risk_alerts,
    dhs.scored_at
FROM crm_deal_health_scores dhs
JOIN crm_deals d ON dhs.deal_id = d.id
LEFT JOIN crm_deal_risk_alerts dra ON dhs.deal_id = dra.deal_id AND dra.status = 'open'
WHERE dhs.health_status IN ('critical', 'at_risk')
  AND (dhs.expires_at IS NULL OR dhs.expires_at > datetime('now'))
GROUP BY dhs.id
ORDER BY dhs.health_score ASC, dhs.win_probability ASC;

-- Deal velocity metrics view
CREATE VIEW IF NOT EXISTS view_deal_velocity_metrics AS
SELECT
    business_id,
    deal_id,
    COUNT(*) as total_events,
    COUNT(CASE WHEN event_type LIKE 'meeting_%' THEN 1 END) as meeting_count,
    COUNT(CASE WHEN event_type LIKE 'email_%' THEN 1 END) as email_count,
    COUNT(CASE WHEN event_type = 'stage_advanced' THEN 1 END) as stages_advanced,
    AVG(engagement_value) as avg_engagement_value,
    MAX(event_timestamp) as last_activity,
    julianday('now') - julianday(MAX(event_timestamp)) as days_since_last_activity,
    COUNT(*) / NULLIF(CAST((julianday('now') - julianday(MIN(event_timestamp))) / 7.0 AS REAL), 0) as activity_frequency_weekly
FROM crm_deal_engagement_events
GROUP BY business_id, deal_id;

-- ============================================================================
-- TRIGGERS FOR AUTO-UPDATES
-- ============================================================================

-- Auto-expire old health scores
CREATE TRIGGER IF NOT EXISTS trg_crm_deal_health_score_expiry
AFTER INSERT ON crm_deal_health_scores
BEGIN
    UPDATE crm_deal_health_scores
    SET expires_at = datetime('now', '+7 days')
    WHERE id = NEW.id AND expires_at IS NULL;
END;

-- Auto-create risk alerts on low health score
CREATE TRIGGER IF NOT EXISTS trg_crm_deal_health_risk_alert
AFTER INSERT ON crm_deal_health_scores
WHEN NEW.health_status IN ('critical', 'at_risk')
BEGIN
    INSERT INTO crm_deal_risk_alerts (
        id, business_id, deal_id, risk_type, severity, risk_description, recommended_action
    )
    SELECT
        lower(hex(randomblob(16))),
        NEW.business_id,
        NEW.deal_id,
        CASE
            WHEN NEW.health_status = 'critical' THEN 'low_engagement'
            ELSE 'no_recent_activity'
        END,
        CASE
            WHEN NEW.health_status = 'critical' THEN 'critical'
            ELSE 'high'
        END,
        'Deal health score dropped to ' || NEW.health_status || ' (' || NEW.health_score || '/100)',
        'Review engagement metrics and take immediate action'
    WHERE NOT EXISTS (
        SELECT 1 FROM crm_deal_risk_alerts
        WHERE deal_id = NEW.deal_id
          AND status = 'open'
          AND risk_type IN ('low_engagement', 'no_recent_activity')
    );
END;
