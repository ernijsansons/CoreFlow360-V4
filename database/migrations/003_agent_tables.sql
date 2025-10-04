-- Agent System Tables for CoreFlow360 V4
-- Migration: 003_agent_tables.sql

-- Agent Registry Table
CREATE TABLE IF NOT EXISTS agent_registry (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    description TEXT,
    version TEXT DEFAULT '1.0.0',
    capabilities TEXT NOT NULL, -- JSON array
    cost_per_call REAL DEFAULT 0.001,
    max_tokens INTEGER DEFAULT 4000,
    timeout_ms INTEGER DEFAULT 30000,
    priority INTEGER DEFAULT 5,
    status TEXT DEFAULT 'active' CHECK(status IN ('active', 'inactive', 'maintenance', 'deprecated')),
    metadata TEXT, -- JSON
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Agent Messages Table
CREATE TABLE IF NOT EXISTS agent_messages (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    business_id TEXT NOT NULL,
    user_id TEXT,
    message_type TEXT CHECK(message_type IN ('request', 'response', 'error', 'system')),
    content TEXT NOT NULL,
    tokens_used INTEGER DEFAULT 0,
    cost REAL DEFAULT 0,
    latency_ms INTEGER,
    status TEXT DEFAULT 'pending' CHECK(status IN ('pending', 'processing', 'completed', 'failed', 'timeout')),
    error_message TEXT,
    metadata TEXT, -- JSON
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (agent_id) REFERENCES agent_registry(id),
    FOREIGN KEY (business_id) REFERENCES businesses(id)
);

-- Deployment Configuration Table
CREATE TABLE IF NOT EXISTS deployment_config (
    id TEXT PRIMARY KEY,
    environment TEXT NOT NULL CHECK(environment IN ('development', 'staging', 'production')),
    agent_id TEXT NOT NULL,
    worker_name TEXT NOT NULL,
    worker_url TEXT,
    bindings TEXT, -- JSON containing KV, D1, R2 bindings
    secrets TEXT, -- Encrypted JSON
    rate_limits TEXT, -- JSON
    features TEXT, -- JSON feature flags
    health_check_url TEXT,
    deployment_status TEXT DEFAULT 'pending' CHECK(deployment_status IN ('pending', 'deploying', 'active', 'failed', 'rollback')),
    deployed_at DATETIME,
    deployed_by TEXT,
    rollback_version TEXT,
    metadata TEXT, -- JSON
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (agent_id) REFERENCES agent_registry(id)
);

-- Agent Execution History
CREATE TABLE IF NOT EXISTS agent_execution_history (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    business_id TEXT NOT NULL,
    execution_time_ms INTEGER NOT NULL,
    tokens_input INTEGER DEFAULT 0,
    tokens_output INTEGER DEFAULT 0,
    total_cost REAL DEFAULT 0,
    success BOOLEAN DEFAULT TRUE,
    error_type TEXT,
    error_message TEXT,
    retry_count INTEGER DEFAULT 0,
    context TEXT, -- JSON
    result TEXT, -- JSON
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (agent_id) REFERENCES agent_registry(id),
    FOREIGN KEY (business_id) REFERENCES businesses(id)
);

-- Workflow Definitions
CREATE TABLE IF NOT EXISTS workflow_definitions (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    business_id TEXT NOT NULL,
    steps TEXT NOT NULL, -- JSON array of workflow steps
    trigger_type TEXT CHECK(trigger_type IN ('manual', 'scheduled', 'event', 'api')),
    schedule_cron TEXT,
    active BOOLEAN DEFAULT TRUE,
    version INTEGER DEFAULT 1,
    created_by TEXT,
    metadata TEXT, -- JSON
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (business_id) REFERENCES businesses(id)
);

-- Workflow Executions
CREATE TABLE IF NOT EXISTS workflow_executions (
    id TEXT PRIMARY KEY,
    workflow_id TEXT NOT NULL,
    business_id TEXT NOT NULL,
    status TEXT DEFAULT 'pending' CHECK(status IN ('pending', 'running', 'completed', 'failed', 'cancelled')),
    started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    completed_at DATETIME,
    total_duration_ms INTEGER,
    total_cost REAL DEFAULT 0,
    total_tokens INTEGER DEFAULT 0,
    current_step INTEGER DEFAULT 0,
    steps_completed TEXT, -- JSON array
    context TEXT, -- JSON
    result TEXT, -- JSON
    error_message TEXT,
    created_by TEXT,
    FOREIGN KEY (workflow_id) REFERENCES workflow_definitions(id),
    FOREIGN KEY (business_id) REFERENCES businesses(id)
);

-- Agent Capabilities Index
CREATE TABLE IF NOT EXISTS agent_capabilities (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    capability TEXT NOT NULL,
    category TEXT,
    description TEXT,
    input_schema TEXT, -- JSON schema
    output_schema TEXT, -- JSON schema
    examples TEXT, -- JSON
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (agent_id) REFERENCES agent_registry(id)
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_agent_messages_task ON agent_messages(task_id);
CREATE INDEX IF NOT EXISTS idx_agent_messages_business ON agent_messages(business_id);
CREATE INDEX IF NOT EXISTS idx_agent_messages_created ON agent_messages(created_at);
CREATE INDEX IF NOT EXISTS idx_agent_execution_business ON agent_execution_history(business_id);
CREATE INDEX IF NOT EXISTS idx_agent_execution_created ON agent_execution_history(created_at);
CREATE INDEX IF NOT EXISTS idx_workflow_executions_business ON workflow_executions(business_id);
CREATE INDEX IF NOT EXISTS idx_workflow_executions_status ON workflow_executions(status);
CREATE INDEX IF NOT EXISTS idx_deployment_config_env ON deployment_config(environment);
CREATE INDEX IF NOT EXISTS idx_agent_capabilities_agent ON agent_capabilities(agent_id);

-- Insert default agents
INSERT OR IGNORE INTO agent_registry (id, name, description, capabilities, cost_per_call, max_tokens, priority) VALUES
('task-orchestrator', 'Task Orchestrator', 'Master agent for task decomposition and coordination', '["task_planning","delegation","monitoring"]', 0.002, 4000, 10),
('security-auditor', 'Security Auditor', 'Performs security audits and compliance checks', '["security_scan","compliance_check","vulnerability_assessment"]', 0.003, 3000, 9),
('production-monitor', 'Production Monitor', 'Monitors production systems and performance', '["health_check","performance_monitoring","alerting"]', 0.001, 2000, 8),
('finance-agent', 'Finance Agent', 'Handles financial operations and reporting', '["bookkeeping","invoicing","reporting"]', 0.002, 3500, 7),
('crm-agent', 'CRM Agent', 'Manages customer relationships and communications', '["lead_management","communication","analytics"]', 0.002, 3500, 7),
('inventory-agent', 'Inventory Agent', 'Manages inventory and supply chain', '["stock_tracking","ordering","forecasting"]', 0.002, 3000, 6),
('compliance-agent', 'Compliance Agent', 'Ensures regulatory compliance', '["audit_trail","reporting","monitoring"]', 0.003, 3000, 8),
('growth-agent', 'Growth Agent', 'Predicts and plans for business growth', '["forecasting","optimization","recommendations"]', 0.003, 4000, 7);

-- Add deployment configurations for core agents
INSERT OR IGNORE INTO deployment_config (id, environment, agent_id, worker_name, deployment_status) VALUES
('prod-orchestrator', 'production', 'task-orchestrator', 'coreflow360-orchestrator', 'pending'),
('prod-security', 'production', 'security-auditor', 'coreflow360-security', 'pending'),
('prod-monitor', 'production', 'production-monitor', 'coreflow360-monitor', 'pending');