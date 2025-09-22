-- ============================================================================
-- Agent System Database Schema for D1
-- Stores agent costs, memory, and analytics data
-- ============================================================================

-- Agent cost tracking table
CREATE TABLE IF NOT EXISTS agent_costs (
    id TEXT PRIMARY KEY,
    business_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    user_id TEXT NOT NULL,

    -- Cost breakdown
    cost REAL NOT NULL DEFAULT 0.0,
    input_tokens INTEGER DEFAULT 0,
    output_tokens INTEGER DEFAULT 0,
    total_tokens INTEGER DEFAULT 0,
    model_cost REAL DEFAULT 0.0,
    processing_cost REAL DEFAULT 0.0,
    storage_cost REAL DEFAULT 0.0,

    -- Performance metrics
    latency INTEGER NOT NULL DEFAULT 0, -- milliseconds
    timestamp INTEGER NOT NULL,
    success INTEGER NOT NULL DEFAULT 0, -- 0 = false, 1 = true

    -- Context information
    capability TEXT,
    department TEXT,
    model_used TEXT,
    provider TEXT DEFAULT 'anthropic',
    tier TEXT DEFAULT 'standard',

    -- Tracking metadata
    tracking_id TEXT,
    retry_count INTEGER DEFAULT 0,
    correlation_id TEXT,

    -- Indexing
    created_at INTEGER DEFAULT (strftime('%s', 'now') * 1000)
);

-- Indexes for cost tracking
CREATE INDEX IF NOT EXISTS idx_agent_costs_business_timestamp
    ON agent_costs(business_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_agent_costs_agent_timestamp
    ON agent_costs(agent_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_agent_costs_user_timestamp
    ON agent_costs(user_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_agent_costs_capability
    ON agent_costs(capability, timestamp);
CREATE INDEX IF NOT EXISTS idx_agent_costs_department
    ON agent_costs(department, timestamp);
CREATE INDEX IF NOT EXISTS idx_agent_costs_success
    ON agent_costs(success, timestamp);

-- ============================================================================
-- Agent Knowledge (Long-term Memory)
-- ============================================================================

CREATE TABLE IF NOT EXISTS agent_knowledge (
    id TEXT PRIMARY KEY,
    business_id TEXT NOT NULL,
    user_id TEXT,
    agent_id TEXT,

    -- Knowledge content
    topic TEXT NOT NULL,
    content TEXT NOT NULL,
    summary TEXT,
    embedding TEXT, -- JSON array of embeddings

    -- Relevance and quality
    relevance REAL NOT NULL DEFAULT 0.5,
    confidence REAL NOT NULL DEFAULT 0.5,
    importance INTEGER DEFAULT 1, -- 1-5 scale

    -- Source and metadata
    source TEXT NOT NULL, -- 'agent:claude', 'user:input', 'system:rule'
    source_task_id TEXT,
    category TEXT,
    tags TEXT, -- JSON array

    -- Lifecycle
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    accessed_at INTEGER NOT NULL,
    access_count INTEGER DEFAULT 0,
    expires_at INTEGER, -- Optional expiration
    version INTEGER DEFAULT 1,

    -- Status
    status TEXT DEFAULT 'active', -- 'active', 'archived', 'deprecated'
    verified INTEGER DEFAULT 0 -- 0 = unverified, 1 = verified
);

-- Indexes for knowledge
CREATE INDEX IF NOT EXISTS idx_agent_knowledge_business_topic
    ON agent_knowledge(business_id, topic);
CREATE INDEX IF NOT EXISTS idx_agent_knowledge_relevance
    ON agent_knowledge(business_id, relevance DESC, accessed_at DESC);
CREATE INDEX IF NOT EXISTS idx_agent_knowledge_search
    ON agent_knowledge(business_id, content);
CREATE INDEX IF NOT EXISTS idx_agent_knowledge_category
    ON agent_knowledge(business_id, category, relevance DESC);
CREATE INDEX IF NOT EXISTS idx_agent_knowledge_expires
    ON agent_knowledge(expires_at) WHERE expires_at IS NOT NULL;

-- ============================================================================
-- Agent Conversations (Session History)
-- ============================================================================

CREATE TABLE IF NOT EXISTS agent_conversations (
    id TEXT PRIMARY KEY,
    business_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,

    -- Conversation data
    input TEXT NOT NULL, -- JSON
    output TEXT NOT NULL, -- JSON
    capability TEXT,

    -- Metadata
    timestamp INTEGER NOT NULL,
    success INTEGER NOT NULL DEFAULT 0,
    cost REAL DEFAULT 0.0,
    latency INTEGER DEFAULT 0,
    confidence REAL,

    -- Context
    department TEXT,
    correlation_id TEXT,
    parent_conversation_id TEXT, -- For threading

    -- Lifecycle
    created_at INTEGER DEFAULT (strftime('%s', 'now') * 1000)
);

-- Indexes for conversations
CREATE INDEX IF NOT EXISTS idx_agent_conversations_session
    ON agent_conversations(business_id, session_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_agent_conversations_user
    ON agent_conversations(user_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_agent_conversations_agent
    ON agent_conversations(agent_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_agent_conversations_capability
    ON agent_conversations(capability, timestamp);

-- ============================================================================
-- Agent Registry (Persistent Configuration)
-- ============================================================================

CREATE TABLE IF NOT EXISTS agent_registry (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    type TEXT NOT NULL, -- 'native', 'external', 'specialized', 'custom'
    version TEXT NOT NULL,
    description TEXT,

    -- Configuration
    config TEXT NOT NULL, -- JSON configuration
    capabilities TEXT NOT NULL, -- JSON array
    departments TEXT, -- JSON array

    -- Status and metadata
    enabled INTEGER DEFAULT 1,
    status TEXT DEFAULT 'active', -- 'active', 'inactive', 'deprecated'
    owner TEXT NOT NULL,
    tags TEXT, -- JSON array

    -- Performance baseline
    cost_per_call REAL NOT NULL DEFAULT 0.0,
    max_concurrency INTEGER NOT NULL DEFAULT 1,
    avg_latency INTEGER DEFAULT 0,
    success_rate REAL DEFAULT 0.0,

    -- Lifecycle
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    last_health_check INTEGER,
    health_status TEXT DEFAULT 'unknown',

    -- External agent specifics
    api_endpoint TEXT,
    webhook_url TEXT,
    api_key_hash TEXT, -- Hashed for security

    -- Feature flags
    streaming_enabled INTEGER DEFAULT 1,
    caching_enabled INTEGER DEFAULT 1,
    retry_enabled INTEGER DEFAULT 1,
    fallback_enabled INTEGER DEFAULT 1
);

-- Indexes for agent registry
CREATE INDEX IF NOT EXISTS idx_agent_registry_type_status
    ON agent_registry(type, status, enabled);
CREATE INDEX IF NOT EXISTS idx_agent_registry_capabilities
    ON agent_registry(capabilities);
CREATE INDEX IF NOT EXISTS idx_agent_registry_departments
    ON agent_registry(departments);
CREATE INDEX IF NOT EXISTS idx_agent_registry_health
    ON agent_registry(health_status, last_health_check);

-- ============================================================================
-- Agent Metrics (Performance Tracking)
-- ============================================================================

CREATE TABLE IF NOT EXISTS agent_metrics (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    business_id TEXT,

    -- Time period
    period_type TEXT NOT NULL, -- 'hourly', 'daily', 'weekly', 'monthly'
    period_start INTEGER NOT NULL,
    period_end INTEGER NOT NULL,

    -- Task metrics
    total_tasks INTEGER DEFAULT 0,
    successful_tasks INTEGER DEFAULT 0,
    failed_tasks INTEGER DEFAULT 0,

    -- Performance metrics
    avg_latency REAL DEFAULT 0.0,
    min_latency INTEGER DEFAULT 0,
    max_latency INTEGER DEFAULT 0,
    p95_latency INTEGER DEFAULT 0,

    -- Cost metrics
    total_cost REAL DEFAULT 0.0,
    avg_cost_per_task REAL DEFAULT 0.0,
    total_tokens INTEGER DEFAULT 0,

    -- Load metrics
    peak_concurrency INTEGER DEFAULT 0,
    avg_utilization REAL DEFAULT 0.0,
    queue_time_avg INTEGER DEFAULT 0,

    -- Error analysis
    error_breakdown TEXT, -- JSON with error types and counts
    timeout_count INTEGER DEFAULT 0,
    retry_count INTEGER DEFAULT 0,

    -- Context
    department_breakdown TEXT, -- JSON with department usage
    capability_breakdown TEXT, -- JSON with capability usage

    -- Metadata
    created_at INTEGER DEFAULT (strftime('%s', 'now') * 1000),
    updated_at INTEGER DEFAULT (strftime('%s', 'now') * 1000)
);

-- Indexes for metrics
CREATE INDEX IF NOT EXISTS idx_agent_metrics_agent_period
    ON agent_metrics(agent_id, period_type, period_start);
CREATE INDEX IF NOT EXISTS idx_agent_metrics_business_period
    ON agent_metrics(business_id, period_type, period_start);

-- ============================================================================
-- Capability Contracts (Dynamic Capability Definitions)
-- ============================================================================

CREATE TABLE IF NOT EXISTS capability_contracts (
    name TEXT PRIMARY KEY,
    version TEXT NOT NULL,
    category TEXT NOT NULL,
    description TEXT NOT NULL,

    -- Schema definitions
    input_schema TEXT NOT NULL, -- JSON schema
    output_schema TEXT NOT NULL, -- JSON schema

    -- Requirements
    required_permissions TEXT, -- JSON array
    supported_agents TEXT NOT NULL, -- JSON array

    -- Performance expectations
    estimated_latency INTEGER NOT NULL DEFAULT 0,
    estimated_cost REAL NOT NULL DEFAULT 0.0,

    -- Documentation
    documentation TEXT,
    examples TEXT, -- JSON array of examples

    -- Status
    deprecated INTEGER DEFAULT 0,
    replaced_by TEXT,

    -- Metadata
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    created_by TEXT NOT NULL
);

-- Indexes for capabilities
CREATE INDEX IF NOT EXISTS idx_capability_contracts_category
    ON capability_contracts(category, deprecated);
CREATE INDEX IF NOT EXISTS idx_capability_contracts_agents
    ON capability_contracts(supported_agents);

-- ============================================================================
-- Cost Budgets and Limits
-- ============================================================================

CREATE TABLE IF NOT EXISTS cost_budgets (
    id TEXT PRIMARY KEY,
    business_id TEXT NOT NULL,

    -- Budget configuration
    budget_type TEXT NOT NULL, -- 'daily', 'monthly', 'quarterly', 'annual'
    amount REAL NOT NULL,
    currency TEXT NOT NULL DEFAULT 'USD',

    -- Period
    period_start INTEGER NOT NULL,
    period_end INTEGER NOT NULL,

    -- Tracking
    spent REAL DEFAULT 0.0,
    reserved REAL DEFAULT 0.0, -- For pending tasks

    -- Alerts
    alert_threshold_80 INTEGER DEFAULT 1,
    alert_threshold_95 INTEGER DEFAULT 1,
    alert_sent_80 INTEGER DEFAULT 0,
    alert_sent_95 INTEGER DEFAULT 0,

    -- Status
    status TEXT DEFAULT 'active', -- 'active', 'exceeded', 'suspended'
    auto_suspend INTEGER DEFAULT 1, -- Auto-suspend when exceeded

    -- Metadata
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    created_by TEXT NOT NULL
);

-- Indexes for budgets
CREATE INDEX IF NOT EXISTS idx_cost_budgets_business_period
    ON cost_budgets(business_id, period_start, period_end);
CREATE INDEX IF NOT EXISTS idx_cost_budgets_status
    ON cost_budgets(status, period_end);

-- ============================================================================
-- Agent Task Queue (For Load Balancing)
-- ============================================================================

CREATE TABLE IF NOT EXISTS agent_task_queue (
    id TEXT PRIMARY KEY,
    business_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,

    -- Task information
    task_data TEXT NOT NULL, -- JSON
    capability TEXT NOT NULL,
    priority INTEGER DEFAULT 1, -- 1-5, higher = more priority

    -- Queue management
    status TEXT DEFAULT 'pending', -- 'pending', 'processing', 'completed', 'failed', 'cancelled'
    assigned_at INTEGER,
    started_at INTEGER,
    completed_at INTEGER,

    -- Retry information
    retry_count INTEGER DEFAULT 0,
    max_retries INTEGER DEFAULT 3,
    last_error TEXT,

    -- Constraints
    timeout_ms INTEGER DEFAULT 30000,
    max_cost REAL,
    required_accuracy REAL,

    -- Metadata
    created_at INTEGER DEFAULT (strftime('%s', 'now') * 1000),
    updated_at INTEGER DEFAULT (strftime('%s', 'now') * 1000),
    correlation_id TEXT
);

-- Indexes for task queue
CREATE INDEX IF NOT EXISTS idx_agent_task_queue_status_priority
    ON agent_task_queue(status, priority DESC, created_at);
CREATE INDEX IF NOT EXISTS idx_agent_task_queue_agent_status
    ON agent_task_queue(agent_id, status, created_at);
CREATE INDEX IF NOT EXISTS idx_agent_task_queue_business
    ON agent_task_queue(business_id, status, created_at);

-- ============================================================================
-- Agent Health Monitoring
-- ============================================================================

CREATE TABLE IF NOT EXISTS agent_health_log (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,

    -- Health check results
    status TEXT NOT NULL, -- 'online', 'degraded', 'offline'
    healthy INTEGER NOT NULL, -- 0 = false, 1 = true
    latency INTEGER NOT NULL,

    -- Error information
    errors TEXT, -- JSON array of errors
    warnings TEXT, -- JSON array of warnings

    -- Additional metrics
    memory_usage REAL,
    cpu_usage REAL,
    active_connections INTEGER,
    queue_length INTEGER,

    -- Context
    check_type TEXT DEFAULT 'scheduled', -- 'scheduled', 'manual', 'triggered'
    triggered_by TEXT,

    -- Metadata
    timestamp INTEGER NOT NULL,
    created_at INTEGER DEFAULT (strftime('%s', 'now') * 1000)
);

-- Indexes for health monitoring
CREATE INDEX IF NOT EXISTS idx_agent_health_log_agent_timestamp
    ON agent_health_log(agent_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_agent_health_log_status
    ON agent_health_log(status, timestamp);

-- ============================================================================
-- System Events and Audit Log
-- ============================================================================

CREATE TABLE IF NOT EXISTS agent_system_events (
    id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL, -- 'low', 'medium', 'high', 'critical'

    -- Event details
    agent_id TEXT,
    business_id TEXT,
    user_id TEXT,
    task_id TEXT,

    -- Event data
    event_data TEXT, -- JSON
    message TEXT NOT NULL,

    -- Context
    correlation_id TEXT,
    session_id TEXT,
    ip_address TEXT,
    user_agent TEXT,

    -- Metadata
    timestamp INTEGER NOT NULL,
    created_at INTEGER DEFAULT (strftime('%s', 'now') * 1000)
);

-- Indexes for system events
CREATE INDEX IF NOT EXISTS idx_agent_system_events_type_timestamp
    ON agent_system_events(event_type, timestamp);
CREATE INDEX IF NOT EXISTS idx_agent_system_events_severity_timestamp
    ON agent_system_events(severity, timestamp);
CREATE INDEX IF NOT EXISTS idx_agent_system_events_agent
    ON agent_system_events(agent_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_agent_system_events_business
    ON agent_system_events(business_id, timestamp);

-- ============================================================================
-- Views for Common Queries
-- ============================================================================

-- Agent performance summary
CREATE VIEW IF NOT EXISTS agent_performance_summary AS
SELECT
    agent_id,
    COUNT(*) as total_tasks,
    SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as successful_tasks,
    ROUND(AVG(CASE WHEN success = 1 THEN 1.0 ELSE 0.0 END) * 100, 2) as success_rate,
    ROUND(AVG(latency), 2) as avg_latency,
    ROUND(SUM(cost), 4) as total_cost,
    ROUND(AVG(cost), 6) as avg_cost_per_task,
    MIN(timestamp) as first_task,
    MAX(timestamp) as last_task
FROM agent_costs
WHERE timestamp >= strftime('%s', 'now', '-30 days') * 1000
GROUP BY agent_id;

-- Business cost summary
CREATE VIEW IF NOT EXISTS business_cost_summary AS
SELECT
    business_id,
    COUNT(*) as total_tasks,
    ROUND(SUM(cost), 4) as total_cost,
    ROUND(AVG(cost), 6) as avg_cost_per_task,
    COUNT(DISTINCT agent_id) as agents_used,
    COUNT(DISTINCT capability) as capabilities_used,
    ROUND(AVG(latency), 2) as avg_latency,
    MIN(timestamp) as period_start,
    MAX(timestamp) as period_end
FROM agent_costs
WHERE timestamp >= strftime('%s', 'now', '-30 days') * 1000
GROUP BY business_id;

-- Daily cost trends
CREATE VIEW IF NOT EXISTS daily_cost_trends AS
SELECT
    DATE(timestamp / 1000, 'unixepoch') as date,
    business_id,
    COUNT(*) as task_count,
    ROUND(SUM(cost), 4) as daily_cost,
    ROUND(AVG(latency), 2) as avg_latency,
    ROUND(AVG(CASE WHEN success = 1 THEN 1.0 ELSE 0.0 END) * 100, 2) as success_rate
FROM agent_costs
GROUP BY DATE(timestamp / 1000, 'unixepoch'), business_id
ORDER BY date DESC, business_id;

-- ============================================================================
-- Triggers for Data Integrity and Maintenance
-- ============================================================================

-- Update agent_costs updated_at timestamp
CREATE TRIGGER IF NOT EXISTS agent_costs_updated_at
    AFTER UPDATE ON agent_costs
    FOR EACH ROW
BEGIN
    UPDATE agent_costs
    SET created_at = strftime('%s', 'now') * 1000
    WHERE id = NEW.id;
END;

-- Clean up old health logs (keep only 30 days)
CREATE TRIGGER IF NOT EXISTS cleanup_old_health_logs
    AFTER INSERT ON agent_health_log
    FOR EACH ROW
BEGIN
    DELETE FROM agent_health_log
    WHERE timestamp < strftime('%s', 'now', '-30 days') * 1000;
END;

-- Auto-expire old conversations (keep only 90 days)
CREATE TRIGGER IF NOT EXISTS cleanup_old_conversations
    AFTER INSERT ON agent_conversations
    FOR EACH ROW
BEGIN
    DELETE FROM agent_conversations
    WHERE timestamp < strftime('%s', 'now', '-90 days') * 1000;
END;