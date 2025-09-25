-- Migration: 004_add_performance_indexes
-- Description: Add critical performance indexes and security constraints
-- Created: 2025-09-21

-- =====================================================
-- CRITICAL: Add business_id columns where missing
-- =====================================================

-- Add business_id to tables that need multi-tenant isolation
ALTER TABLE interactions ADD COLUMN business_id TEXT;
ALTER TABLE learning_data ADD COLUMN business_id TEXT;
ALTER TABLE patterns ADD COLUMN business_id TEXT;
ALTER TABLE playbooks ADD COLUMN business_id TEXT;
ALTER TABLE experiments ADD COLUMN business_id TEXT;
ALTER TABLE workflows ADD COLUMN business_id TEXT;
ALTER TABLE workflow_executions ADD COLUMN business_id TEXT;

-- =====================================================
-- PERFORMANCE: Foreign Key Indexes
-- =====================================================

-- Critical missing indexes on foreign keys
CREATE INDEX IF NOT EXISTS idx_interactions_business_id ON interactions(business_id);
CREATE INDEX IF NOT EXISTS idx_interactions_lead_id_created ON interactions(lead_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_learning_data_business_id ON learning_data(business_id);
CREATE INDEX IF NOT EXISTS idx_learning_data_interaction_strategy ON learning_data(interaction_id, strategy_id);

-- Prompt variants performance
CREATE INDEX IF NOT EXISTS idx_prompt_variants_created_at ON prompt_variants(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_prompt_variants_active_traffic ON prompt_variants(active, traffic_split) WHERE active = 1;

-- Experiments optimization
CREATE INDEX IF NOT EXISTS idx_experiments_decision ON experiments(decision) WHERE decision IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_experiments_active ON experiments(end_date) WHERE end_date IS NULL;

-- Feedback and patterns
CREATE INDEX IF NOT EXISTS idx_feedback_user_id ON feedback(user_id);
CREATE INDEX IF NOT EXISTS idx_feedback_created_rating ON feedback(created_at DESC, rating);
CREATE INDEX IF NOT EXISTS idx_patterns_business_type ON patterns(business_id, type);
CREATE INDEX IF NOT EXISTS idx_patterns_confidence ON patterns(confidence DESC) WHERE confidence > 0.5;

-- Playbook usage
CREATE INDEX IF NOT EXISTS idx_playbook_usage_lead ON playbook_usage(lead_id, used_at DESC);
CREATE INDEX IF NOT EXISTS idx_playbooks_business_active ON playbooks(business_id, active) WHERE active = 1;

-- =====================================================
-- PERFORMANCE: Composite Indexes for Common Queries
-- =====================================================

-- Dashboard queries optimization
CREATE INDEX IF NOT EXISTS idx_opportunities_owner_status_date
  ON opportunities(owner_id, status, close_date DESC);

CREATE INDEX IF NOT EXISTS idx_opportunities_business_stage_value
  ON opportunities(business_id, stage, value DESC)
  WHERE status = 'open';

-- Activity tracking
CREATE INDEX IF NOT EXISTS idx_calls_user_date
  ON calls(user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_calls_business_date
  ON calls(business_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_emails_sender_date
  ON emails(sender_id, sent_at DESC);

CREATE INDEX IF NOT EXISTS idx_meetings_user_scheduled
  ON meetings(user_id, scheduled_at DESC);

-- Lead management
CREATE INDEX IF NOT EXISTS idx_leads_business_status_score
  ON leads(business_id, status, score DESC);

CREATE INDEX IF NOT EXISTS idx_leads_assigned_status
  ON leads(assigned_to, status)
  WHERE status IN ('new', 'qualified');

-- =====================================================
-- PERFORMANCE: Partial Indexes for Filtered Queries
-- =====================================================

-- Active records optimization
CREATE INDEX IF NOT EXISTS idx_integrations_active
  ON integrations(business_id, status)
  WHERE status = 'connected';

CREATE INDEX IF NOT EXISTS idx_workflows_active
  ON workflows(business_id, status)
  WHERE status = 'active';

CREATE INDEX IF NOT EXISTS idx_strategies_active
  ON strategies(type, active)
  WHERE active = 1;

-- Recent activity indexes
CREATE INDEX IF NOT EXISTS idx_sync_logs_recent
  ON sync_logs(integration_id, created_at DESC)
  WHERE created_at >= datetime('now', '-7 days');

CREATE INDEX IF NOT EXISTS idx_workflow_executions_recent
  ON workflow_executions(workflow_id, triggered_at DESC)
  WHERE triggered_at >= datetime('now', '-24 hours');

-- =====================================================
-- PERFORMANCE: Text Search Indexes
-- =====================================================

-- Create virtual table for full-text search on leads
CREATE VIRTUAL TABLE IF NOT EXISTS leads_fts USING fts5(
  id UNINDEXED,
  business_id UNINDEXED,
  first_name,
  last_name,
  email,
  company,
  notes,
  tokenize = 'porter'
);

-- Populate FTS table
INSERT INTO leads_fts (id, business_id, first_name, last_name, email, company, notes)
SELECT id, business_id, first_name, last_name, email, company, notes FROM leads;

-- Trigger to keep FTS updated
CREATE TRIGGER IF NOT EXISTS leads_fts_insert
AFTER INSERT ON leads
BEGIN
  INSERT INTO leads_fts (id, business_id, first_name, last_name, email, company, notes)
  VALUES (NEW.id, NEW.business_id, NEW.first_name, NEW.last_name, NEW.email, NEW.company, NEW.notes);
END;

CREATE TRIGGER IF NOT EXISTS leads_fts_update
AFTER UPDATE ON leads
BEGIN
  UPDATE leads_fts
  SET first_name = NEW.first_name,
      last_name = NEW.last_name,
      email = NEW.email,
      company = NEW.company,
      notes = NEW.notes
  WHERE id = NEW.id;
END;

CREATE TRIGGER IF NOT EXISTS leads_fts_delete
AFTER DELETE ON leads
BEGIN
  DELETE FROM leads_fts WHERE id = OLD.id;
END;

-- =====================================================
-- SECURITY: Row-Level Security Constraints
-- =====================================================

-- Create views with business_id filtering for secure access
CREATE VIEW IF NOT EXISTS secure_leads AS
SELECT * FROM leads
WHERE business_id = (SELECT business_id FROM current_context);

CREATE VIEW IF NOT EXISTS secure_opportunities AS
SELECT * FROM opportunities
WHERE business_id = (SELECT business_id FROM current_context);

CREATE VIEW IF NOT EXISTS secure_interactions AS
SELECT * FROM interactions
WHERE business_id = (SELECT business_id FROM current_context);

-- =====================================================
-- PERFORMANCE: Statistics Update
-- =====================================================

-- Update statistics for query planner
ANALYZE;

-- =====================================================
-- MONITORING: Query Performance Tracking
-- =====================================================

-- Create table for slow query logging
CREATE TABLE IF NOT EXISTS slow_query_log (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  query TEXT NOT NULL,
  execution_time_ms INTEGER NOT NULL,
  rows_examined INTEGER,
  rows_returned INTEGER,
  business_id TEXT,
  user_id TEXT,
  trace_id TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_slow_queries_time
  ON slow_query_log(created_at DESC, execution_time_ms DESC);

-- =====================================================
-- CLEANUP: Remove Redundant Indexes
-- =====================================================

-- Drop any duplicate or redundant indexes
-- (Check EXPLAIN QUERY PLAN before dropping in production)

-- =====================================================
-- VALIDATION: Index Usage Statistics
-- =====================================================

-- Create table to track index usage
CREATE TABLE IF NOT EXISTS index_usage_stats (
  index_name TEXT PRIMARY KEY,
  table_name TEXT NOT NULL,
  times_used INTEGER DEFAULT 0,
  last_used TIMESTAMP,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- =====================================================
-- PERFORMANCE: Connection Pool Settings
-- =====================================================

-- Recommended pragma settings for performance
-- These should be set at connection time in the application:
-- PRAGMA journal_mode = WAL;
-- PRAGMA synchronous = NORMAL;
-- PRAGMA cache_size = -64000;  -- 64MB cache
-- PRAGMA temp_store = MEMORY;
-- PRAGMA mmap_size = 268435456; -- 256MB memory map