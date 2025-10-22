-- Migration: Approval Workflows
-- Description: Multi-level approval system
-- Created: 2025-10-12

-- =======================
-- Workflow Definitions
-- =======================

CREATE TABLE IF NOT EXISTS approval_workflows (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  business_id TEXT NOT NULL,
  name TEXT NOT NULL,
  description TEXT,
  entity_type TEXT NOT NULL,
  trigger_condition TEXT NOT NULL,
  is_active BOOLEAN NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
  UNIQUE(business_id, name)
);

-- =======================
-- Approval Steps
-- =======================

CREATE TABLE IF NOT EXISTS approval_steps (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  workflow_id TEXT NOT NULL,
  step_order INTEGER NOT NULL,
  step_name TEXT NOT NULL,
  approver_role TEXT,
  approver_user_id TEXT,
  approval_type TEXT NOT NULL DEFAULT 'any',
  min_approvals INTEGER NOT NULL DEFAULT 1,
  auto_approve_after_hours INTEGER,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (workflow_id) REFERENCES approval_workflows(id) ON DELETE CASCADE,
  UNIQUE(workflow_id, step_order)
);

-- =======================
-- Approval Requests
-- =======================

CREATE TABLE IF NOT EXISTS approval_requests (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  workflow_id TEXT NOT NULL,
  entity_type TEXT NOT NULL,
  entity_id TEXT NOT NULL,
  requested_by TEXT NOT NULL,
  current_step INTEGER NOT NULL DEFAULT 1,
  status TEXT NOT NULL DEFAULT 'pending',
  request_data TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  completed_at TEXT,
  FOREIGN KEY (workflow_id) REFERENCES approval_workflows(id)
);

-- =======================
-- Approval Actions
-- =======================

CREATE TABLE IF NOT EXISTS approval_actions (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  request_id TEXT NOT NULL,
  step_id TEXT NOT NULL,
  approver_id TEXT NOT NULL,
  action TEXT NOT NULL,
  comments TEXT,
  action_date TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (request_id) REFERENCES approval_requests(id) ON DELETE CASCADE,
  FOREIGN KEY (step_id) REFERENCES approval_steps(id)
);

-- =======================
-- Indexes
-- =======================

CREATE INDEX idx_approval_workflows_business ON approval_workflows(business_id);
CREATE INDEX idx_approval_steps_workflow ON approval_steps(workflow_id);
CREATE INDEX idx_approval_requests_workflow ON approval_requests(workflow_id);
CREATE INDEX idx_approval_requests_status ON approval_requests(status);
CREATE INDEX idx_approval_requests_entity ON approval_requests(entity_type, entity_id);
CREATE INDEX idx_approval_actions_request ON approval_actions(request_id);
