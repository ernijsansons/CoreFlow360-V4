-- Migration: 055_crm_sentiment_analysis
-- Description: AI-powered sentiment analysis using Claude API
-- Feature: #7 in Phase 1 Sprint 1

CREATE TABLE IF NOT EXISTS crm_sentiment_scores (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT NOT NULL,
    activity_id TEXT NOT NULL,

    sentiment TEXT NOT NULL CHECK(sentiment IN ('very_negative', 'negative', 'neutral', 'positive', 'very_positive')),
    sentiment_score REAL NOT NULL CHECK(sentiment_score >= -1.0 AND sentiment_score <= 1.0),
    confidence REAL CHECK(confidence >= 0 AND confidence <= 1.0),

    -- AI Analysis
    key_phrases TEXT,              -- JSON array of significant phrases
    emotions_detected TEXT,        -- JSON: {"frustration": 0.7, "excitement": 0.3}
    tone TEXT,                     -- professional, casual, urgent, friendly

    -- Context
    contact_id TEXT,
    deal_id TEXT,

    analyzed_at TEXT DEFAULT (datetime('now')),

    FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
    FOREIGN KEY (activity_id) REFERENCES crm_activities(id) ON DELETE CASCADE,
    FOREIGN KEY (contact_id) REFERENCES crm_contacts(id),
    FOREIGN KEY (deal_id) REFERENCES crm_deals(id)
);

CREATE INDEX idx_crm_sentiment_activity ON crm_sentiment_scores(activity_id);
CREATE INDEX idx_crm_sentiment_contact ON crm_sentiment_scores(contact_id, analyzed_at DESC);
