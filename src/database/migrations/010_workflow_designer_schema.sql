-- Migration: 010_workflow_designer_schema
-- Description: Ultimate Visual Workflow Designer with AI Capabilities
-- Created: 2025-09-21

-- =====================================================
-- WORKFLOW DEFINITIONS
-- =====================================================

CREATE TABLE workflow_definitions (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  business_id TEXT NOT NULL,
  name TEXT NOT NULL,
  description TEXT,
  category TEXT NOT NULL DEFAULT 'custom', -- custom, sales, finance, operations, hr, marketing
  version TEXT NOT NULL DEFAULT '1.0.0',
  parent_id TEXT, -- For versioning

  -- Visual design data
  graph_data TEXT NOT NULL, -- JSON: nodes, edges, positions
  canvas_config TEXT, -- JSON: zoom, position, viewport

  -- Execution configuration
  execution_mode TEXT NOT NULL DEFAULT 'sequential', -- sequential, parallel, adaptive
  max_parallel_nodes INTEGER DEFAULT 5,
  timeout_seconds INTEGER DEFAULT 3600,
  retry_policy TEXT, -- JSON: maxRetries, backoffStrategy, conditions

  -- AI features
  ai_optimized BOOLEAN DEFAULT FALSE,
  optimization_score REAL DEFAULT 0.0,
  cost_estimate_cents INTEGER DEFAULT 0,
  performance_tier TEXT DEFAULT 'standard', -- standard, performance, enterprise

  -- Metadata
  tags TEXT, -- JSON array
  is_template BOOLEAN DEFAULT FALSE,
  template_category TEXT,
  usage_count INTEGER DEFAULT 0,
  rating REAL DEFAULT 0.0,

  -- Security & compliance
  encryption_enabled BOOLEAN DEFAULT FALSE,
  compliance_tags TEXT, -- JSON: ['GDPR', 'HIPAA', 'SOC2']
  security_level TEXT DEFAULT 'standard', -- standard, high, critical

  -- Lifecycle
  status TEXT NOT NULL DEFAULT 'draft', -- draft, active, deprecated, archived
  published_at TIMESTAMP,
  created_by TEXT NOT NULL,
  updated_by TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

  FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
  FOREIGN KEY (parent_id) REFERENCES workflow_definitions(id),
  FOREIGN KEY (created_by) REFERENCES users(id),
  FOREIGN KEY (updated_by) REFERENCES users(id)
);

-- =====================================================
-- WORKFLOW NODES
-- =====================================================

CREATE TABLE workflow_nodes (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  workflow_id TEXT NOT NULL,
  business_id TEXT NOT NULL,

  -- Node identification
  node_key TEXT NOT NULL, -- Unique within workflow
  node_type TEXT NOT NULL, -- ai_agent, logic, integration, approval, trigger
  node_subtype TEXT, -- specific implementation type

  -- Visual properties
  position_x REAL NOT NULL DEFAULT 0,
  position_y REAL NOT NULL DEFAULT 0,
  width REAL DEFAULT 200,
  height REAL DEFAULT 100,

  -- Configuration
  config TEXT NOT NULL, -- JSON configuration specific to node type
  input_schema TEXT, -- JSON schema for inputs
  output_schema TEXT, -- JSON schema for outputs

  -- AI features
  ai_generated BOOLEAN DEFAULT FALSE,
  optimization_suggestions TEXT, -- JSON array of AI suggestions
  cost_estimate_cents INTEGER DEFAULT 0,

  -- Execution
  retry_enabled BOOLEAN DEFAULT TRUE,
  max_retries INTEGER DEFAULT 3,
  timeout_seconds INTEGER DEFAULT 300,

  -- Dependencies
  depends_on TEXT, -- JSON array of node IDs
  parallel_group TEXT, -- Nodes that can execute in parallel

  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

  FOREIGN KEY (workflow_id) REFERENCES workflow_definitions(id) ON DELETE CASCADE,
  FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,

  UNIQUE(workflow_id, node_key)
);

-- =====================================================
-- WORKFLOW EDGES (Connections)
-- =====================================================

CREATE TABLE workflow_edges (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  workflow_id TEXT NOT NULL,
  business_id TEXT NOT NULL,

  -- Connection points
  source_node_id TEXT NOT NULL,
  target_node_id TEXT NOT NULL,
  source_handle TEXT, -- Output handle ID
  target_handle TEXT, -- Input handle ID

  -- Conditional logic
  condition_type TEXT DEFAULT 'always', -- always, success, failure, conditional
  condition_expression TEXT, -- JSONPath or JavaScript expression
  condition_config TEXT, -- JSON: additional condition parameters

  -- Visual styling
  edge_type TEXT DEFAULT 'default', -- default, straight, smoothstep, step
  style_config TEXT, -- JSON: color, strokeWidth, animated

  -- Labels and annotations
  label TEXT,
  label_position REAL DEFAULT 0.5, -- Position along edge (0-1)

  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

  FOREIGN KEY (workflow_id) REFERENCES workflow_definitions(id) ON DELETE CASCADE,
  FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
  FOREIGN KEY (source_node_id) REFERENCES workflow_nodes(id) ON DELETE CASCADE,
  FOREIGN KEY (target_node_id) REFERENCES workflow_nodes(id) ON DELETE CASCADE
);

-- =====================================================
-- WORKFLOW EXECUTIONS
-- =====================================================

CREATE TABLE workflow_executions (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  workflow_id TEXT NOT NULL,
  workflow_version TEXT NOT NULL,
  business_id TEXT NOT NULL,

  -- Execution context
  triggered_by TEXT NOT NULL, -- user_id or 'system'
  trigger_type TEXT NOT NULL, -- manual, scheduled, webhook, event
  trigger_data TEXT, -- JSON: trigger-specific data

  -- Input/Output
  input_data TEXT, -- JSON: workflow inputs
  output_data TEXT, -- JSON: workflow outputs
  variables TEXT, -- JSON: workflow variables state

  -- Status tracking
  status TEXT NOT NULL DEFAULT 'pending', -- pending, running, completed, failed, cancelled
  current_node_id TEXT, -- Currently executing node
  progress_percentage REAL DEFAULT 0.0,

  -- Performance metrics
  execution_time_ms INTEGER,
  cost_cents INTEGER DEFAULT 0,
  nodes_executed INTEGER DEFAULT 0,
  nodes_failed INTEGER DEFAULT 0,

  -- Error handling
  error_message TEXT,
  error_details TEXT, -- JSON: detailed error information
  retry_count INTEGER DEFAULT 0,

  -- Timestamps
  started_at TIMESTAMP,
  completed_at TIMESTAMP,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

  FOREIGN KEY (workflow_id) REFERENCES workflow_definitions(id),
  FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
  FOREIGN KEY (current_node_id) REFERENCES workflow_nodes(id)
);

-- =====================================================
-- NODE EXECUTIONS
-- =====================================================

CREATE TABLE node_executions (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  workflow_execution_id TEXT NOT NULL,
  node_id TEXT NOT NULL,
  business_id TEXT NOT NULL,

  -- Execution details
  execution_order INTEGER NOT NULL,
  input_data TEXT, -- JSON: node inputs
  output_data TEXT, -- JSON: node outputs

  -- Status and performance
  status TEXT NOT NULL DEFAULT 'pending', -- pending, running, completed, failed, skipped
  execution_time_ms INTEGER,
  cost_cents INTEGER DEFAULT 0,

  -- AI-specific metrics
  tokens_used INTEGER DEFAULT 0,
  model_used TEXT,
  confidence_score REAL,

  -- Error handling
  error_message TEXT,
  error_details TEXT, -- JSON: detailed error information
  retry_count INTEGER DEFAULT 0,

  -- Timestamps
  started_at TIMESTAMP,
  completed_at TIMESTAMP,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

  FOREIGN KEY (workflow_execution_id) REFERENCES workflow_executions(id) ON DELETE CASCADE,
  FOREIGN KEY (node_id) REFERENCES workflow_nodes(id),
  FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE
);

-- =====================================================
-- WORKFLOW TEMPLATES
-- =====================================================

CREATE TABLE workflow_templates (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  name TEXT NOT NULL,
  description TEXT NOT NULL,
  category TEXT NOT NULL,
  industry TEXT, -- healthcare, finance, retail, etc.

  -- Template data
  template_data TEXT NOT NULL, -- JSON: complete workflow definition
  preview_image TEXT, -- Base64 or URL to preview

  -- Marketplace features
  is_public BOOLEAN DEFAULT FALSE,
  price_cents INTEGER DEFAULT 0, -- 0 = free
  creator_id TEXT,
  creator_business_id TEXT,

  -- Quality metrics
  usage_count INTEGER DEFAULT 0,
  rating REAL DEFAULT 0.0,
  review_count INTEGER DEFAULT 0,
  certification_level TEXT, -- bronze, silver, gold, platinum

  -- Versioning
  version TEXT NOT NULL DEFAULT '1.0.0',
  parent_template_id TEXT,

  -- Metadata
  tags TEXT, -- JSON array
  complexity_level TEXT DEFAULT 'beginner', -- beginner, intermediate, advanced, expert
  estimated_setup_time INTEGER, -- minutes

  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

  FOREIGN KEY (parent_template_id) REFERENCES workflow_templates(id),
  FOREIGN KEY (creator_id) REFERENCES users(id),
  FOREIGN KEY (creator_business_id) REFERENCES businesses(id)
);

-- =====================================================
-- COLLABORATION & REAL-TIME EDITING
-- =====================================================

CREATE TABLE workflow_collaborators (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  workflow_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  business_id TEXT NOT NULL,

  -- Permissions
  role TEXT NOT NULL DEFAULT 'viewer', -- owner, editor, viewer, commenter
  permissions TEXT, -- JSON: specific permissions

  -- Activity tracking
  last_seen_at TIMESTAMP,
  cursor_position TEXT, -- JSON: current cursor/selection

  -- Collaboration features
  color TEXT DEFAULT '#3b82f6', -- User color for real-time editing
  is_online BOOLEAN DEFAULT FALSE,

  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

  FOREIGN KEY (workflow_id) REFERENCES workflow_definitions(id) ON DELETE CASCADE,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,

  UNIQUE(workflow_id, user_id)
);

CREATE TABLE workflow_comments (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  workflow_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  business_id TEXT NOT NULL,

  -- Comment details
  content TEXT NOT NULL,
  comment_type TEXT DEFAULT 'general', -- general, suggestion, issue, question

  -- Positioning
  position_x REAL,
  position_y REAL,
  attached_to_node_id TEXT,

  -- Threading
  parent_comment_id TEXT,
  is_resolved BOOLEAN DEFAULT FALSE,
  resolved_by TEXT,
  resolved_at TIMESTAMP,

  -- Reactions
  reactions TEXT, -- JSON: emoji reactions with user counts

  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

  FOREIGN KEY (workflow_id) REFERENCES workflow_definitions(id) ON DELETE CASCADE,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
  FOREIGN KEY (attached_to_node_id) REFERENCES workflow_nodes(id) ON DELETE SET NULL,
  FOREIGN KEY (parent_comment_id) REFERENCES workflow_comments(id) ON DELETE CASCADE,
  FOREIGN KEY (resolved_by) REFERENCES users(id)
);

-- =====================================================
-- AI OPTIMIZATION & ANALYTICS
-- =====================================================

CREATE TABLE workflow_optimizations (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  workflow_id TEXT NOT NULL,
  business_id TEXT NOT NULL,

  -- Optimization type
  optimization_type TEXT NOT NULL, -- performance, cost, reliability, security
  ai_model_used TEXT NOT NULL,

  -- Suggestions
  suggestions TEXT NOT NULL, -- JSON array of optimization suggestions
  estimated_improvement TEXT, -- JSON: cost/time/reliability improvements
  confidence_score REAL,

  -- Implementation status
  status TEXT DEFAULT 'pending', -- pending, accepted, rejected, applied
  applied_suggestions TEXT, -- JSON: which suggestions were applied
  actual_improvement TEXT, -- JSON: measured improvements after application

  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  applied_at TIMESTAMP,

  FOREIGN KEY (workflow_id) REFERENCES workflow_definitions(id) ON DELETE CASCADE,
  FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE
);

CREATE TABLE workflow_analytics (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  workflow_id TEXT NOT NULL,
  business_id TEXT NOT NULL,

  -- Time period
  date_bucket TEXT NOT NULL, -- YYYY-MM-DD for daily rollups

  -- Execution metrics
  total_executions INTEGER DEFAULT 0,
  successful_executions INTEGER DEFAULT 0,
  failed_executions INTEGER DEFAULT 0,
  avg_execution_time_ms REAL DEFAULT 0,

  -- Cost metrics
  total_cost_cents INTEGER DEFAULT 0,
  avg_cost_per_execution_cents REAL DEFAULT 0,

  -- Performance metrics
  p50_execution_time_ms REAL,
  p95_execution_time_ms REAL,
  p99_execution_time_ms REAL,

  -- AI usage
  total_ai_calls INTEGER DEFAULT 0,
  total_tokens_used INTEGER DEFAULT 0,
  avg_tokens_per_execution REAL DEFAULT 0,

  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

  FOREIGN KEY (workflow_id) REFERENCES workflow_definitions(id) ON DELETE CASCADE,
  FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,

  UNIQUE(workflow_id, date_bucket)
);

-- =====================================================
-- APPROVAL WORKFLOWS
-- =====================================================

CREATE TABLE approval_chains (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  workflow_execution_id TEXT NOT NULL,
  node_id TEXT NOT NULL,
  business_id TEXT NOT NULL,

  -- Chain configuration
  approval_type TEXT NOT NULL, -- sequential, parallel, quorum
  required_approvals INTEGER DEFAULT 1,
  current_approvals INTEGER DEFAULT 0,

  -- Escalation
  escalation_enabled BOOLEAN DEFAULT TRUE,
  escalation_hours INTEGER DEFAULT 24,
  escalation_level INTEGER DEFAULT 0,
  max_escalation_level INTEGER DEFAULT 3,

  -- Status
  status TEXT NOT NULL DEFAULT 'pending', -- pending, approved, rejected, escalated, expired

  -- Data
  approval_data TEXT, -- JSON: data being approved

  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  expires_at TIMESTAMP,
  completed_at TIMESTAMP,

  FOREIGN KEY (workflow_execution_id) REFERENCES workflow_executions(id) ON DELETE CASCADE,
  FOREIGN KEY (node_id) REFERENCES workflow_nodes(id),
  FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE
);

CREATE TABLE approval_requests (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  approval_chain_id TEXT NOT NULL,
  business_id TEXT NOT NULL,

  -- Approver
  approver_id TEXT NOT NULL,
  approver_type TEXT DEFAULT 'user', -- user, role, department
  approval_order INTEGER DEFAULT 1,

  -- Request details
  request_message TEXT,
  approval_token TEXT, -- Secure token for email approval

  -- Response
  status TEXT NOT NULL DEFAULT 'pending', -- pending, approved, rejected, delegated
  response_message TEXT,
  approved_at TIMESTAMP,

  -- Delegation
  delegated_to TEXT,
  delegation_reason TEXT,

  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

  FOREIGN KEY (approval_chain_id) REFERENCES approval_chains(id) ON DELETE CASCADE,
  FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
  FOREIGN KEY (approver_id) REFERENCES users(id),
  FOREIGN KEY (delegated_to) REFERENCES users(id)
);

-- =====================================================
-- INDEXES FOR PERFORMANCE
-- =====================================================

-- Workflow definitions
CREATE INDEX idx_workflow_definitions_business_status ON workflow_definitions(business_id, status);
CREATE INDEX idx_workflow_definitions_template ON workflow_definitions(is_template, template_category) WHERE is_template = TRUE;
CREATE INDEX idx_workflow_definitions_usage ON workflow_definitions(usage_count DESC, rating DESC);

-- Workflow nodes
CREATE INDEX idx_workflow_nodes_workflow ON workflow_nodes(workflow_id, node_type);
CREATE INDEX idx_workflow_nodes_business ON workflow_nodes(business_id, node_type);

-- Workflow edges
CREATE INDEX idx_workflow_edges_workflow ON workflow_edges(workflow_id);
CREATE INDEX idx_workflow_edges_source ON workflow_edges(source_node_id);
CREATE INDEX idx_workflow_edges_target ON workflow_edges(target_node_id);

-- Executions
CREATE INDEX idx_workflow_executions_business_status ON workflow_executions(business_id, status, created_at DESC);
CREATE INDEX idx_workflow_executions_workflow ON workflow_executions(workflow_id, created_at DESC);
CREATE INDEX idx_workflow_executions_active ON workflow_executions(status, started_at) WHERE status IN ('pending', 'running');

-- Node executions
CREATE INDEX idx_node_executions_workflow_execution ON node_executions(workflow_execution_id, execution_order);
CREATE INDEX idx_node_executions_node ON node_executions(node_id, created_at DESC);

-- Templates
CREATE INDEX idx_workflow_templates_public ON workflow_templates(is_public, category, rating DESC) WHERE is_public = TRUE;
CREATE INDEX idx_workflow_templates_industry ON workflow_templates(industry, category);

-- Collaboration
CREATE INDEX idx_workflow_collaborators_user ON workflow_collaborators(user_id, is_online);
CREATE INDEX idx_workflow_collaborators_workflow ON workflow_collaborators(workflow_id, role);

-- Comments
CREATE INDEX idx_workflow_comments_workflow ON workflow_comments(workflow_id, created_at DESC);
CREATE INDEX idx_workflow_comments_node ON workflow_comments(attached_to_node_id);
CREATE INDEX idx_workflow_comments_thread ON workflow_comments(parent_comment_id);

-- Analytics
CREATE INDEX idx_workflow_analytics_date ON workflow_analytics(workflow_id, date_bucket DESC);
CREATE INDEX idx_workflow_analytics_business ON workflow_analytics(business_id, date_bucket DESC);

-- Approvals
CREATE INDEX idx_approval_chains_execution ON approval_chains(workflow_execution_id, status);
CREATE INDEX idx_approval_requests_approver ON approval_requests(approver_id, status);
CREATE INDEX idx_approval_requests_chain ON approval_requests(approval_chain_id, approval_order);

-- =====================================================
-- TRIGGERS FOR AUTOMATION
-- =====================================================

-- Update workflow definition updated_at
CREATE TRIGGER update_workflow_definitions_updated_at
  AFTER UPDATE ON workflow_definitions
  FOR EACH ROW
  BEGIN
    UPDATE workflow_definitions SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
  END;

-- Update workflow nodes updated_at
CREATE TRIGGER update_workflow_nodes_updated_at
  AFTER UPDATE ON workflow_nodes
  FOR EACH ROW
  BEGIN
    UPDATE workflow_nodes SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
  END;

-- Auto-increment workflow usage count
CREATE TRIGGER increment_workflow_usage
  AFTER INSERT ON workflow_executions
  FOR EACH ROW
  BEGIN
    UPDATE workflow_definitions
    SET usage_count = usage_count + 1
    WHERE id = NEW.workflow_id;
  END;

-- Update template usage count
CREATE TRIGGER increment_template_usage
  AFTER INSERT ON workflow_definitions
  FOR EACH ROW
  WHEN NEW.is_template = FALSE AND NEW.parent_id IS NOT NULL
  BEGIN
    UPDATE workflow_templates
    SET usage_count = usage_count + 1
    WHERE id = (SELECT parent_id FROM workflow_definitions WHERE id = NEW.parent_id);
  END;