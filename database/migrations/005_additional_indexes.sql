-- Migration: 005_additional_indexes
-- Description: Additional performance indexes and constraints
-- Created: 2024-12-01
-- Author: CoreFlow360 V4

-- Performance indexes for multi-tenant isolation
CREATE INDEX IF NOT EXISTS idx_all_tables_business_isolation ON businesses(id, status);

-- Composite indexes for common query patterns

-- User authentication and session queries
CREATE INDEX IF NOT EXISTS idx_users_auth ON users(email, password_hash, status) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_users_login ON users(email, status, locked_until) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_sessions_active ON user_sessions(user_id, business_id, expires_at) WHERE revoked_at IS NULL;

-- Business membership queries
CREATE INDEX IF NOT EXISTS idx_memberships_active_users ON business_memberships(business_id, user_id, role) WHERE status = 'active' AND deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_memberships_hierarchy ON business_memberships(business_id, reports_to_user_id) WHERE status = 'active';

-- Department and role queries
CREATE INDEX IF NOT EXISTS idx_dept_roles_active ON department_roles(business_id, department_id, user_id) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_permissions_effective ON user_permissions(business_id, user_id, permission_key) WHERE status = 'active' AND (effective_until IS NULL OR effective_until > datetime('now'));

-- Accounting performance indexes
CREATE INDEX IF NOT EXISTS idx_journal_posting ON journal_entries(business_id, status, posting_date) WHERE status IN ('approved', 'posted');
CREATE INDEX IF NOT EXISTS idx_journal_lines_period ON journal_lines(business_id, journal_entry_id) WHERE journal_entry_id IN (SELECT id FROM journal_entries WHERE status = 'posted');
CREATE INDEX IF NOT EXISTS idx_gl_current ON general_ledger(business_id, period, account_id) WHERE is_closed = 0;

-- Workflow performance indexes
CREATE INDEX IF NOT EXISTS idx_workflow_active ON workflow_instances(business_id, status, current_assignee_user_id) WHERE status IN ('active', 'waiting');
CREATE INDEX IF NOT EXISTS idx_workflow_sla ON workflow_instances(business_id, sla_deadline, status) WHERE status = 'active' AND sla_deadline IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_workflow_steps_pending ON workflow_steps(business_id, assigned_to_user_id, status) WHERE status IN ('pending', 'active');

-- Audit performance indexes
CREATE INDEX IF NOT EXISTS idx_audit_recent ON audit_logs(business_id, event_timestamp DESC) WHERE event_timestamp > datetime('now', '-30 days');
CREATE INDEX IF NOT EXISTS idx_audit_costs ON audit_logs(business_id, operation_cost) WHERE operation_cost > 0;
CREATE INDEX IF NOT EXISTS idx_audit_ai ON audit_logs(business_id, ai_model_used, ai_cost) WHERE ai_model_used IS NOT NULL;

-- Full-text search indexes (if FTS5 is available)
-- Note: These will fail silently if FTS5 is not available in D1

-- Create virtual table for business search
DROP TABLE IF EXISTS businesses_fts;
CREATE VIRTUAL TABLE IF NOT EXISTS businesses_fts USING fts5(
    name,
    legal_name,
    industry,
    content=businesses,
    content_rowid=rowid
);

-- Create triggers to keep FTS table in sync
CREATE TRIGGER IF NOT EXISTS businesses_fts_insert AFTER INSERT ON businesses BEGIN
    INSERT INTO businesses_fts(rowid, name, legal_name, industry)
    VALUES (new.rowid, new.name, new.legal_name, new.industry);
END;

CREATE TRIGGER IF NOT EXISTS businesses_fts_update AFTER UPDATE ON businesses BEGIN
    UPDATE businesses_fts
    SET name = new.name, legal_name = new.legal_name, industry = new.industry
    WHERE rowid = new.rowid;
END;

CREATE TRIGGER IF NOT EXISTS businesses_fts_delete AFTER DELETE ON businesses BEGIN
    DELETE FROM businesses_fts WHERE rowid = old.rowid;
END;

-- Create virtual table for user search
DROP TABLE IF EXISTS users_fts;
CREATE VIRTUAL TABLE IF NOT EXISTS users_fts USING fts5(
    email,
    username,
    first_name,
    last_name,
    display_name,
    content=users,
    content_rowid=rowid
);

-- Create triggers for users FTS
CREATE TRIGGER IF NOT EXISTS users_fts_insert AFTER INSERT ON users BEGIN
    INSERT INTO users_fts(rowid, email, username, first_name, last_name, display_name)
    VALUES (new.rowid, new.email, new.username, new.first_name, new.last_name, new.display_name);
END;

CREATE TRIGGER IF NOT EXISTS users_fts_update AFTER UPDATE ON users BEGIN
    UPDATE users_fts
    SET email = new.email, username = new.username, first_name = new.first_name,
        last_name = new.last_name, display_name = new.display_name
    WHERE rowid = new.rowid;
END;

CREATE TRIGGER IF NOT EXISTS users_fts_delete AFTER DELETE ON users BEGIN
    DELETE FROM users_fts WHERE rowid = old.rowid;
END;

-- Statistics tables for query optimization hints
CREATE TABLE IF NOT EXISTS table_statistics (
    table_name TEXT PRIMARY KEY,
    row_count INTEGER DEFAULT 0,
    avg_row_size INTEGER DEFAULT 0,
    index_count INTEGER DEFAULT 0,
    last_analyzed TEXT DEFAULT (datetime('now')),
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
);

-- Migration tracking table
CREATE TABLE IF NOT EXISTS schema_migrations (
    version TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    executed_at TEXT DEFAULT (datetime('now')),
    execution_time_ms INTEGER,
    checksum TEXT,
    status TEXT DEFAULT 'completed' CHECK (status IN ('pending', 'running', 'completed', 'failed', 'rolled_back')),
    error_message TEXT,
    executed_by TEXT
);

-- Insert migration records
INSERT OR IGNORE INTO schema_migrations (version, name, status) VALUES
    ('001', 'core_tenant_users', 'completed'),
    ('002', 'rbac_departments', 'completed'),
    ('003', 'double_entry_ledger', 'completed'),
    ('004', 'audit_workflows', 'completed'),
    ('005', 'additional_indexes', 'completed');