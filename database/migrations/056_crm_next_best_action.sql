-- Migration: 056_crm_next_best_action
-- Description: AI-powered next best action recommendations
-- Feature: #8 in Phase 1 Sprint 1

CREATE TABLE IF NOT EXISTS crm_next_actions (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT NOT NULL,

    entity_type TEXT NOT NULL CHECK(entity_type IN ('contact', 'deal', 'lead')),
    entity_id TEXT NOT NULL,
    user_id TEXT NOT NULL,

    action_type TEXT NOT NULL CHECK(action_type IN (
        'send_email', 'schedule_call', 'schedule_meeting', 'send_proposal',
        'follow_up', 'provide_demo', 'share_case_study', 'introduce_executive',
        'address_objection', 'negotiate_pricing', 'request_referral'
    )),

    priority INTEGER NOT NULL CHECK(priority >= 1 AND priority <= 100),
    action_title TEXT NOT NULL,
    action_description TEXT NOT NULL,
    reasoning TEXT,                -- AI explanation

    -- Outcome
    status TEXT DEFAULT 'pending' CHECK(status IN ('pending', 'in_progress', 'completed', 'skipped')),
    completed_at TEXT,

    -- Metadata
    generated_at TEXT DEFAULT (datetime('now')),
    expires_at TEXT,

    FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_crm_next_actions_user ON crm_next_actions(user_id, status, priority DESC);
CREATE INDEX idx_crm_next_actions_entity ON crm_next_actions(entity_type, entity_id);
