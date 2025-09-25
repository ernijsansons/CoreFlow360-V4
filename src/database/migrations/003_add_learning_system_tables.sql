-- Migration: 003_add_learning_system_tables
-- Description: Add tables for self-improving AI learning system
-- Created: 2025-09-21

-- =====================================================
-- STRATEGY MANAGEMENT
-- =====================================================

-- Strategies table for AI sales approaches
CREATE TABLE strategies (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  name TEXT NOT NULL,
  type TEXT NOT NULL CHECK (type IN ('outreach', 'discovery', 'objection_handling', 'negotiation', 'closing')),
  description TEXT,
  strategy_data TEXT NOT NULL CHECK (json_valid(strategy_data)),
  version INTEGER DEFAULT 1,
  active BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Strategy updates tracking
CREATE TABLE strategy_updates (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  strategy_id TEXT NOT NULL,
  update_type TEXT NOT NULL CHECK (update_type IN ('performance_adjustment', 'content_update', 'rule_change')),
  changes TEXT NOT NULL CHECK (json_valid(changes)),
  expected_impact TEXT,
  confidence REAL CHECK (confidence >= 0 AND confidence <= 1),
  applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (strategy_id) REFERENCES strategies(id)
);

-- =====================================================
-- PROMPT VARIANT TESTING
-- =====================================================

-- Prompt variants for A/B testing
CREATE TABLE prompt_variants (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  strategy_id TEXT NOT NULL,
  name TEXT NOT NULL,
  prompt TEXT NOT NULL,
  active BOOLEAN DEFAULT TRUE,
  traffic_split REAL DEFAULT 0.2 CHECK (traffic_split >= 0 AND traffic_split <= 1),
  performance_data TEXT CHECK (json_valid(performance_data) OR performance_data IS NULL),
  metadata TEXT CHECK (json_valid(metadata) OR metadata IS NULL),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (strategy_id) REFERENCES strategies(id)
);

-- =====================================================
-- PATTERN RECOGNITION
-- =====================================================

-- Discovered patterns from successful interactions
CREATE TABLE patterns (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  name TEXT NOT NULL,
  type TEXT NOT NULL CHECK (type IN ('timing', 'content', 'channel', 'sequence', 'objection_handling', 'closing')),
  description TEXT,
  pattern_data TEXT NOT NULL CHECK (json_valid(pattern_data)),
  confidence REAL CHECK (confidence >= 0 AND confidence <= 1),
  discovered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  last_validated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Pattern observations for continuous learning
CREATE TABLE pattern_observations (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  pattern_text TEXT NOT NULL,
  strategy_id TEXT,
  observation_type TEXT CHECK (observation_type IN ('positive', 'negative')),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (strategy_id) REFERENCES strategies(id)
);

-- Pattern recommendations
CREATE TABLE pattern_recommendations (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  pattern_id TEXT NOT NULL,
  type TEXT NOT NULL,
  description TEXT,
  action TEXT,
  expected_impact TEXT,
  confidence REAL CHECK (confidence >= 0 AND confidence <= 1),
  applicability TEXT CHECK (json_valid(applicability) OR applicability IS NULL),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (pattern_id) REFERENCES patterns(id)
);

-- =====================================================
-- PLAYBOOK MANAGEMENT
-- =====================================================

-- AI-generated playbooks
CREATE TABLE playbooks (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  name TEXT NOT NULL,
  segment_id TEXT NOT NULL,
  version INTEGER DEFAULT 1,
  playbook_data TEXT NOT NULL CHECK (json_valid(playbook_data)),
  active BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Playbook usage tracking
CREATE TABLE playbook_usage (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  playbook_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  lead_id TEXT NOT NULL,
  section_used TEXT,
  used_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (playbook_id) REFERENCES playbooks(id)
);

-- =====================================================
-- CUSTOMER SEGMENTS
-- =====================================================

-- Customer segments for targeted approaches
CREATE TABLE customer_segments (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  name TEXT NOT NULL UNIQUE,
  description TEXT,
  segment_data TEXT NOT NULL CHECK (json_valid(segment_data)),
  active BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- =====================================================
-- EXPERIMENT TRACKING
-- =====================================================

-- Experiments for continuous improvement
CREATE TABLE experiments (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  experiment_type TEXT NOT NULL CHECK (experiment_type IN ('strategy', 'prompt', 'timing', 'channel', 'content')),
  hypothesis TEXT NOT NULL,
  experiment_data TEXT NOT NULL CHECK (json_valid(experiment_data)),
  decision TEXT CHECK (decision IN ('adopt', 'reject', 'continue')),
  start_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  end_date TIMESTAMP
);

-- =====================================================
-- LEARNING DATA
-- =====================================================

-- Interaction outcomes for learning
CREATE TABLE interactions (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  lead_id TEXT,
  interaction_type TEXT NOT NULL,
  channel TEXT,
  strategy_id TEXT,
  variant_id TEXT,
  interaction_data TEXT CHECK (json_valid(interaction_data) OR interaction_data IS NULL),
  outcome_success BOOLEAN DEFAULT FALSE,
  response_time_minutes INTEGER,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (strategy_id) REFERENCES strategies(id),
  FOREIGN KEY (variant_id) REFERENCES prompt_variants(id)
);

-- Learning data from interactions
CREATE TABLE learning_data (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  interaction_id TEXT NOT NULL,
  strategy_id TEXT,
  variant_id TEXT,
  outcome_success BOOLEAN NOT NULL,
  analysis_data TEXT CHECK (json_valid(analysis_data) OR analysis_data IS NULL),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (interaction_id) REFERENCES interactions(id),
  FOREIGN KEY (strategy_id) REFERENCES strategies(id),
  FOREIGN KEY (variant_id) REFERENCES prompt_variants(id)
);

-- =====================================================
-- FEEDBACK SYSTEM
-- =====================================================

-- User feedback on playbooks and strategies
CREATE TABLE feedback (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  playbook_id TEXT,
  strategy_id TEXT,
  type TEXT NOT NULL CHECK (type IN ('usability', 'effectiveness', 'accuracy', 'suggestion')),
  rating INTEGER CHECK (rating >= 1 AND rating <= 5),
  comment TEXT,
  category TEXT,
  user_id TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (playbook_id) REFERENCES playbooks(id),
  FOREIGN KEY (strategy_id) REFERENCES strategies(id)
);

-- =====================================================
-- SCORING UPDATES
-- =====================================================

-- Lead scoring model updates
CREATE TABLE scoring_updates (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  interaction_type TEXT,
  channel TEXT,
  timing TEXT,
  outcome BOOLEAN,
  update_data TEXT CHECK (json_valid(update_data) OR update_data IS NULL),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- =====================================================
-- ADDITIONAL TABLES FOR COMPREHENSIVE TRACKING
-- =====================================================

-- Interaction content for analysis
CREATE TABLE interaction_content (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  interaction_id TEXT NOT NULL,
  subject_line TEXT,
  opening_line TEXT,
  content_length INTEGER,
  personalization_score REAL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (interaction_id) REFERENCES interactions(id)
);

-- Objection handling tracking
CREATE TABLE objection_handling (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  interaction_id TEXT NOT NULL,
  objection_type TEXT,
  objection_content TEXT,
  response_strategy TEXT,
  handled_successfully BOOLEAN,
  follow_up_outcome TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (interaction_id) REFERENCES interactions(id)
);

-- Sequence interactions for multi-touch analysis
CREATE TABLE sequence_interactions (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  sequence_id TEXT NOT NULL,
  interaction_id TEXT NOT NULL,
  sequence_step INTEGER NOT NULL,
  days_since_previous INTEGER,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (interaction_id) REFERENCES interactions(id)
);

-- Closing attempts tracking
CREATE TABLE closing_attempts (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  opportunity_id TEXT NOT NULL,
  closing_technique TEXT,
  deal_stage TEXT,
  buying_signals TEXT CHECK (json_valid(buying_signals) OR buying_signals IS NULL),
  urgency_factors TEXT CHECK (json_valid(urgency_factors) OR urgency_factors IS NULL),
  outcome TEXT,
  days_to_close INTEGER,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- =====================================================
-- INDEXES FOR PERFORMANCE
-- =====================================================

-- Strategies indexes
CREATE INDEX idx_strategies_type ON strategies(type, active);
CREATE INDEX idx_strategies_updated ON strategies(updated_at DESC);
CREATE INDEX idx_strategy_updates_strategy ON strategy_updates(strategy_id, applied_at DESC);

-- Variants indexes
CREATE INDEX idx_prompt_variants_strategy ON prompt_variants(strategy_id, active);
CREATE INDEX idx_prompt_variants_performance ON prompt_variants(active, traffic_split);

-- Patterns indexes
CREATE INDEX idx_patterns_type ON patterns(type, confidence DESC);
CREATE INDEX idx_patterns_validated ON patterns(last_validated DESC);
CREATE INDEX idx_pattern_observations_strategy ON pattern_observations(strategy_id, observation_type);
CREATE INDEX idx_pattern_recommendations_pattern ON pattern_recommendations(pattern_id, confidence DESC);

-- Playbooks indexes
CREATE INDEX idx_playbooks_segment ON playbooks(segment_id, active);
CREATE INDEX idx_playbooks_version ON playbooks(version DESC);
CREATE INDEX idx_playbook_usage_playbook ON playbook_usage(playbook_id, used_at DESC);
CREATE INDEX idx_playbook_usage_user ON playbook_usage(user_id, used_at DESC);

-- Segments indexes
CREATE INDEX idx_customer_segments_name ON customer_segments(name, active);

-- Experiments indexes
CREATE INDEX idx_experiments_type ON experiments(experiment_type, start_date DESC);
CREATE INDEX idx_experiments_active ON experiments(end_date) WHERE end_date IS NULL;

-- Interactions indexes
CREATE INDEX idx_interactions_lead ON interactions(lead_id, created_at DESC);
CREATE INDEX idx_interactions_strategy ON interactions(strategy_id, outcome_success);
CREATE INDEX idx_interactions_variant ON interactions(variant_id, outcome_success);

-- Learning data indexes
CREATE INDEX idx_learning_data_interaction ON learning_data(interaction_id);
CREATE INDEX idx_learning_data_strategy ON learning_data(strategy_id, outcome_success);
CREATE INDEX idx_learning_data_created ON learning_data(created_at DESC);

-- Feedback indexes
CREATE INDEX idx_feedback_playbook ON feedback(playbook_id, created_at DESC);
CREATE INDEX idx_feedback_strategy ON feedback(strategy_id, created_at DESC);
CREATE INDEX idx_feedback_rating ON feedback(rating, type);

-- Content analysis indexes
CREATE INDEX idx_interaction_content_interaction ON interaction_content(interaction_id);
CREATE INDEX idx_objection_handling_interaction ON objection_handling(interaction_id);
CREATE INDEX idx_sequence_interactions_sequence ON sequence_interactions(sequence_id, sequence_step);
CREATE INDEX idx_closing_attempts_opportunity ON closing_attempts(opportunity_id);

-- =====================================================
-- TRIGGERS FOR UPDATED_AT
-- =====================================================

CREATE TRIGGER update_strategies_updated_at
  AFTER UPDATE ON strategies
  BEGIN
    UPDATE strategies SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
  END;

CREATE TRIGGER update_prompt_variants_updated_at
  AFTER UPDATE ON prompt_variants
  BEGIN
    UPDATE prompt_variants SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
  END;

CREATE TRIGGER update_patterns_last_validated
  AFTER UPDATE ON patterns
  BEGIN
    UPDATE patterns SET last_validated = CURRENT_TIMESTAMP WHERE id = NEW.id;
  END;

CREATE TRIGGER update_playbooks_updated_at
  AFTER UPDATE ON playbooks
  BEGIN
    UPDATE playbooks SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
  END;

CREATE TRIGGER update_customer_segments_updated_at
  AFTER UPDATE ON customer_segments
  BEGIN
    UPDATE customer_segments SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
  END;