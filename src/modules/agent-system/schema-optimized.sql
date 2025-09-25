-- ============================================================================
-- PERFORMANCE OPTIMIZATIONS - Additional Indexes for Agent System
-- Run these after the main schema.sql
-- ============================================================================

-- Composite indexes for common query patterns
CREATE INDEX IF NOT EXISTS idx_agent_costs_business_user_timestamp
    ON agent_costs(business_id, user_id, timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_agent_costs_business_capability_timestamp
    ON agent_costs(business_id, capability, timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_agent_costs_business_department_timestamp
    ON agent_costs(business_id, department, timestamp DESC);

-- Optimize knowledge queries with composite indexes
CREATE INDEX IF NOT EXISTS idx_agent_knowledge_business_relevance_accessed
    ON agent_knowledge(business_id, relevance DESC, accessed_at DESC);

CREATE INDEX IF NOT EXISTS idx_agent_knowledge_business_topic_relevance
    ON agent_knowledge(business_id, topic, relevance DESC);

CREATE INDEX IF NOT EXISTS idx_agent_knowledge_business_status_expires
    ON agent_knowledge(business_id, status, expires_at)
    WHERE status = 'active';

-- Optimize conversation queries
CREATE INDEX IF NOT EXISTS idx_agent_conversations_business_session_timestamp
    ON agent_conversations(business_id, session_id, timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_agent_conversations_user_timestamp_success
    ON agent_conversations(user_id, timestamp DESC, success);

-- Optimize metrics queries
CREATE INDEX IF NOT EXISTS idx_agent_metrics_agent_period_timestamp
    ON agent_metrics(agent_id, period_type, period_start DESC);

CREATE INDEX IF NOT EXISTS idx_agent_metrics_business_period_timestamp
    ON agent_metrics(business_id, period_type, period_start DESC);

-- Optimize task queue queries
CREATE INDEX IF NOT EXISTS idx_agent_task_queue_status_priority_created
    ON agent_task_queue(status, priority DESC, created_at ASC)
    WHERE status IN ('pending', 'processing');

CREATE INDEX IF NOT EXISTS idx_agent_task_queue_agent_status_priority
    ON agent_task_queue(agent_id, status, priority DESC)
    WHERE status = 'pending';

-- Optimize health monitoring queries
CREATE INDEX IF NOT EXISTS idx_agent_health_log_agent_status_timestamp
    ON agent_health_log(agent_id, status, timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_agent_health_log_healthy_timestamp
    ON agent_health_log(healthy, timestamp DESC)
    WHERE healthy = 0;

-- Optimize system events for audit queries
CREATE INDEX IF NOT EXISTS idx_agent_system_events_business_type_timestamp
    ON agent_system_events(business_id, event_type, timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_agent_system_events_severity_business_timestamp
    ON agent_system_events(severity, business_id, timestamp DESC)
    WHERE severity IN ('high', 'critical');

CREATE INDEX IF NOT EXISTS idx_agent_system_events_correlation_id
    ON agent_system_events(correlation_id)
    WHERE correlation_id IS NOT NULL;

-- Optimize cost budget queries
CREATE INDEX IF NOT EXISTS idx_cost_budgets_business_status_period
    ON cost_budgets(business_id, status, period_end DESC)
    WHERE status = 'active';

-- ============================================================================
-- DATA RETENTION POLICIES TABLE
-- ============================================================================

CREATE TABLE IF NOT EXISTS data_retention_policies (
  table_name TEXT PRIMARY KEY,
  retention_days INTEGER NOT NULL,
  cleanup_enabled INTEGER DEFAULT 1,
  last_cleanup INTEGER,
  cleanup_batch_size INTEGER DEFAULT 1000,
  created_at INTEGER DEFAULT (strftime('%s', 'now') * 1000),
  updated_at INTEGER DEFAULT (strftime('%s', 'now') * 1000)
);

-- Insert default retention policies
INSERT OR REPLACE INTO data_retention_policies (table_name, retention_days, cleanup_batch_size)
VALUES
  ('agent_conversations', 90, 1000),
  ('agent_health_log', 30, 5000),
  ('agent_system_events', 365, 500),
  ('agent_costs', 180, 2000),
  ('agent_task_queue', 7, 10000);

-- ============================================================================
-- IMPROVED CLEANUP TRIGGERS WITH CONFIGURABLE RETENTION
-- ============================================================================

-- Drop existing triggers
DROP TRIGGER IF EXISTS cleanup_old_health_logs;
DROP TRIGGER IF EXISTS cleanup_old_conversations;

-- Create configurable cleanup stored procedure (as a view for D1)
CREATE VIEW IF NOT EXISTS cleanup_old_data AS
SELECT
  'agent_conversations' as table_name,
  COUNT(*) as records_to_delete
FROM agent_conversations
WHERE timestamp < strftime('%s', 'now', '-' ||
  (SELECT retention_days FROM data_retention_policies WHERE table_name = 'agent_conversations')
  || ' days') * 1000
UNION ALL
SELECT
  'agent_health_log' as table_name,
  COUNT(*) as records_to_delete
FROM agent_health_log
WHERE timestamp < strftime('%s', 'now', '-' ||
  (SELECT retention_days FROM data_retention_policies WHERE table_name = 'agent_health_log')
  || ' days') * 1000
UNION ALL
SELECT
  'agent_system_events' as table_name,
  COUNT(*) as records_to_delete
FROM agent_system_events
WHERE timestamp < strftime('%s', 'now', '-' ||
  (SELECT retention_days FROM data_retention_policies WHERE table_name = 'agent_system_events')
  || ' days') * 1000;

-- ============================================================================
-- PERFORMANCE MONITORING VIEWS
-- ============================================================================

-- Query performance monitoring
CREATE VIEW IF NOT EXISTS slow_queries AS
SELECT
  business_id,
  COUNT(*) as query_count,
  AVG(latency) as avg_latency,
  MAX(latency) as max_latency,
  MIN(timestamp) as period_start,
  MAX(timestamp) as period_end
FROM agent_costs
WHERE latency > 1000 -- Queries over 1 second
GROUP BY business_id
ORDER BY avg_latency DESC;

-- Agent utilization monitoring
CREATE VIEW IF NOT EXISTS agent_utilization AS
SELECT
  ar.name as agent_name,
  ar.type as agent_type,
  COUNT(DISTINCT ac.task_id) as total_tasks,
  AVG(ac.latency) as avg_latency,
  SUM(ac.cost) as total_cost,
  AVG(CASE WHEN ac.success = 1 THEN 1.0 ELSE 0.0 END) * 100 as success_rate
FROM agent_registry ar
LEFT JOIN agent_costs ac ON ar.id = ac.agent_id
WHERE ac.timestamp >= strftime('%s', 'now', '-24 hours') * 1000
GROUP BY ar.id, ar.name, ar.type
ORDER BY total_tasks DESC;

-- Cost analysis by department
CREATE VIEW IF NOT EXISTS department_cost_analysis AS
SELECT
  department,
  COUNT(DISTINCT business_id) as businesses,
  COUNT(DISTINCT user_id) as users,
  COUNT(*) as total_tasks,
  SUM(cost) as total_cost,
  AVG(cost) as avg_cost_per_task,
  AVG(latency) as avg_latency,
  DATE(timestamp / 1000, 'unixepoch') as date
FROM agent_costs
WHERE timestamp >= strftime('%s', 'now', '-30 days') * 1000
GROUP BY department, DATE(timestamp / 1000, 'unixepoch')
ORDER BY date DESC, total_cost DESC;

-- ============================================================================
-- STATISTICS UPDATE TRIGGERS
-- ============================================================================

-- Update agent registry statistics after task completion
CREATE TRIGGER IF NOT EXISTS update_agent_stats
AFTER INSERT ON agent_costs
FOR EACH ROW
BEGIN
  UPDATE agent_registry
  SET
    avg_latency = (
      SELECT AVG(latency)
      FROM agent_costs
      WHERE agent_id = NEW.agent_id
      AND timestamp >= strftime('%s', 'now', '-24 hours') * 1000
    ),
    success_rate = (
      SELECT AVG(CASE WHEN success = 1 THEN 1.0 ELSE 0.0 END)
      FROM agent_costs
      WHERE agent_id = NEW.agent_id
      AND timestamp >= strftime('%s', 'now', '-24 hours') * 1000
    ),
    cost_per_call = (
      SELECT AVG(cost)
      FROM agent_costs
      WHERE agent_id = NEW.agent_id
      AND timestamp >= strftime('%s', 'now', '-7 days') * 1000
    )
  WHERE id = NEW.agent_id;
END;

-- ============================================================================
-- QUERY OPTIMIZATION HINTS
-- ============================================================================

-- Analyze tables for query optimization (run periodically)
ANALYZE agent_costs;
ANALYZE agent_knowledge;
ANALYZE agent_conversations;
ANALYZE agent_system_events;
ANALYZE agent_registry;
ANALYZE agent_metrics;
ANALYZE agent_health_log;