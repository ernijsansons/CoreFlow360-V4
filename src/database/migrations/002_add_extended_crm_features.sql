-- Migration: 002_add_extended_crm_features
-- Description: Add extended CRM features (activities, sequences, scoring)
-- Created: 2025-09-20

-- Lead Activities for tracking all interactions
CREATE TABLE lead_activities (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  business_id TEXT NOT NULL,
  lead_id TEXT NOT NULL,
  contact_id TEXT,
  type TEXT NOT NULL CHECK (type IN ('call', 'email', 'meeting', 'note', 'demo', 'proposal', 'contract', 'ai_action')),
  description TEXT NOT NULL,
  outcome TEXT CHECK (outcome IN ('positive', 'neutral', 'negative')),
  ai_generated BOOLEAN DEFAULT FALSE,
  metadata TEXT CHECK (json_valid(metadata) OR metadata IS NULL),
  created_by TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (lead_id) REFERENCES leads(id),
  FOREIGN KEY (contact_id) REFERENCES contacts(id)
);

-- Email sequences for AI-driven nurturing
CREATE TABLE email_sequences (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  business_id TEXT NOT NULL,
  name TEXT NOT NULL,
  description TEXT,
  trigger_type TEXT NOT NULL CHECK (trigger_type IN ('lead_created', 'status_change', 'time_based', 'behavior_based')),
  trigger_conditions TEXT CHECK (json_valid(trigger_conditions) OR trigger_conditions IS NULL),
  is_active BOOLEAN DEFAULT TRUE,
  ai_optimization BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Email sequence steps
CREATE TABLE email_sequence_steps (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  sequence_id TEXT NOT NULL,
  step_order INTEGER NOT NULL,
  delay_hours INTEGER NOT NULL,
  subject_template TEXT NOT NULL,
  body_template TEXT NOT NULL,
  ai_personalization BOOLEAN DEFAULT TRUE,
  is_active BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (sequence_id) REFERENCES email_sequences(id),
  UNIQUE(sequence_id, step_order)
);

-- Lead scoring rules for AI qualification
CREATE TABLE lead_scoring_rules (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  business_id TEXT NOT NULL,
  name TEXT NOT NULL,
  category TEXT NOT NULL CHECK (category IN ('demographic', 'firmographic', 'behavioral', 'engagement')),
  condition_field TEXT NOT NULL,
  condition_operator TEXT NOT NULL CHECK (condition_operator IN ('equals', 'contains', 'greater_than', 'less_than', 'in', 'not_in')),
  condition_value TEXT NOT NULL,
  score_points INTEGER NOT NULL,
  is_active BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Additional indexes for new tables
CREATE INDEX idx_lead_activities_lead ON lead_activities(lead_id, created_at DESC);
CREATE INDEX idx_lead_activities_type ON lead_activities(business_id, type, created_at DESC);
CREATE INDEX idx_email_sequences_business ON email_sequences(business_id, is_active);
CREATE INDEX idx_email_sequence_steps_sequence ON email_sequence_steps(sequence_id, step_order);
CREATE INDEX idx_lead_scoring_rules_business ON lead_scoring_rules(business_id, is_active);

-- Triggers for updated_at timestamps
CREATE TRIGGER update_email_sequences_updated_at
  AFTER UPDATE ON email_sequences
  BEGIN
    UPDATE email_sequences SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
  END;