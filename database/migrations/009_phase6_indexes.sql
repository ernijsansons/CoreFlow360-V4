-- Phase 6: Additional Performance and Security Indexes
-- Created to address remaining performance issues identified in advanced audit

-- =====================================================
-- Chat System Indexes
-- =====================================================

-- Chat conversations - critical for user queries
CREATE INDEX IF NOT EXISTS idx_conversations_user_business
ON conversations(user_id, business_id, status);

CREATE INDEX IF NOT EXISTS idx_conversations_updated
ON conversations(updated_at DESC);

-- Chat messages - optimize message retrieval
CREATE INDEX IF NOT EXISTS idx_chat_messages_conversation_timestamp
ON chat_messages(conversation_id, timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_chat_messages_type
ON chat_messages(conversation_id, type);

-- =====================================================
-- Agent System Cost Tracking Indexes
-- =====================================================

-- Agent costs - unique constraint for idempotency
CREATE UNIQUE INDEX IF NOT EXISTS idx_agent_costs_task_id
ON agent_costs(task_id, business_id);

-- Agent costs - optimize cost queries
CREATE INDEX IF NOT EXISTS idx_agent_costs_business_timestamp
ON agent_costs(business_id, timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_agent_costs_user
ON agent_costs(user_id, business_id);

-- Agent metrics - optimize dashboard queries
CREATE INDEX IF NOT EXISTS idx_agent_metrics_period
ON agent_metrics(business_id, period_type, period_start DESC);

-- =====================================================
-- Workflow Collaboration Indexes
-- =====================================================

-- Workflow collaborators - business isolation
CREATE INDEX IF NOT EXISTS idx_workflow_collaborators_business
ON workflow_collaborators(business_id, workflow_id);

CREATE INDEX IF NOT EXISTS idx_workflow_collaborators_user
ON workflow_collaborators(user_id, business_id);

-- Workflow instances - optimize status queries
CREATE INDEX IF NOT EXISTS idx_workflow_instances_status
ON workflow_instances(business_id, status, updated_at DESC);

-- =====================================================
-- Alert System Indexes
-- =====================================================

-- Active alerts - optimize dashboard queries
CREATE INDEX IF NOT EXISTS idx_active_alerts_business_severity
ON active_alerts(business_id, severity, triggered_at DESC);

CREATE INDEX IF NOT EXISTS idx_active_alerts_status
ON active_alerts(business_id, status);

-- =====================================================
-- Audit and Compliance Indexes
-- =====================================================

-- Finance audit log - optimize audit trail queries
CREATE INDEX IF NOT EXISTS idx_finance_audit_business_entity
ON finance_audit_log(business_id, entity_type, entity_id, performed_at DESC);

CREATE INDEX IF NOT EXISTS idx_finance_audit_user
ON finance_audit_log(performed_by, business_id, performed_at DESC);

-- Agent system events - optimize audit queries
CREATE INDEX IF NOT EXISTS idx_agent_system_events_business
ON agent_system_events(business_id, event_type, timestamp DESC);

-- =====================================================
-- Session Management Indexes
-- =====================================================

-- User sessions - optimize session lookups
CREATE INDEX IF NOT EXISTS idx_sessions_user
ON sessions(user_id, expires_at DESC);

CREATE INDEX IF NOT EXISTS idx_sessions_token
ON sessions(access_token);

-- =====================================================
-- Knowledge Base Indexes
-- =====================================================

-- Agent knowledge - optimize retrieval
CREATE INDEX IF NOT EXISTS idx_agent_knowledge_business_type
ON agent_knowledge(business_id, knowledge_type, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_agent_knowledge_relevance
ON agent_knowledge(business_id, relevance_score DESC);

-- =====================================================
-- Task Queue Indexes
-- =====================================================

-- Agent task queue - optimize task processing
CREATE INDEX IF NOT EXISTS idx_task_queue_status_priority
ON agent_task_queue(status, priority DESC, created_at);

CREATE INDEX IF NOT EXISTS idx_task_queue_business_status
ON agent_task_queue(business_id, status);

-- =====================================================
-- Data Retention Indexes
-- =====================================================

-- Retention policies - optimize cleanup queries
CREATE INDEX IF NOT EXISTS idx_retention_policies_active
ON retention_policies(is_active, next_run_at);

-- =====================================================
-- Performance Optimization Views
-- =====================================================

-- Create a materialized view for frequently accessed cost summaries
CREATE VIEW IF NOT EXISTS v_daily_cost_summary AS
SELECT
  business_id,
  DATE(timestamp / 1000, 'unixepoch') as date,
  SUM(cost) as total_cost,
  COUNT(*) as transaction_count,
  AVG(latency) as avg_latency
FROM agent_costs
WHERE timestamp > (strftime('%s', 'now', '-30 days') * 1000)
GROUP BY business_id, date;

-- Create a view for active conversation summaries
CREATE VIEW IF NOT EXISTS v_active_conversations AS
SELECT
  c.business_id,
  c.user_id,
  COUNT(DISTINCT c.id) as conversation_count,
  SUM(c.message_count) as total_messages,
  MAX(c.last_message_at) as last_activity
FROM conversations c
WHERE c.status = 'active'
GROUP BY c.business_id, c.user_id;

-- =====================================================
-- Cleanup and Optimization
-- =====================================================

-- Analyze tables to update statistics for query optimizer
ANALYZE conversations;
ANALYZE chat_messages;
ANALYZE agent_costs;
ANALYZE workflow_collaborators;
ANALYZE active_alerts;
ANALYZE finance_audit_log;