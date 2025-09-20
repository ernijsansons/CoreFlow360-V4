-- Rollback: 005_additional_indexes
-- Description: Rollback additional performance indexes
-- Created: 2024-12-01
-- Author: CoreFlow360 V4

-- Drop composite indexes
DROP INDEX IF EXISTS idx_audit_ai;
DROP INDEX IF EXISTS idx_audit_costs;
DROP INDEX IF EXISTS idx_audit_recent;
DROP INDEX IF EXISTS idx_workflow_steps_pending;
DROP INDEX IF EXISTS idx_workflow_sla;
DROP INDEX IF EXISTS idx_workflow_active;
DROP INDEX IF EXISTS idx_gl_current;
DROP INDEX IF EXISTS idx_journal_lines_period;
DROP INDEX IF EXISTS idx_journal_posting;
DROP INDEX IF EXISTS idx_permissions_effective;
DROP INDEX IF EXISTS idx_dept_roles_active;
DROP INDEX IF EXISTS idx_memberships_hierarchy;
DROP INDEX IF EXISTS idx_memberships_active_users;
DROP INDEX IF EXISTS idx_sessions_active;
DROP INDEX IF EXISTS idx_users_login;
DROP INDEX IF EXISTS idx_users_auth;
DROP INDEX IF EXISTS idx_all_tables_business_isolation;

-- Drop FTS triggers
DROP TRIGGER IF EXISTS users_fts_delete;
DROP TRIGGER IF EXISTS users_fts_update;
DROP TRIGGER IF EXISTS users_fts_insert;
DROP TRIGGER IF EXISTS businesses_fts_delete;
DROP TRIGGER IF EXISTS businesses_fts_update;
DROP TRIGGER IF EXISTS businesses_fts_insert;

-- Drop FTS virtual tables
DROP TABLE IF EXISTS users_fts;
DROP TABLE IF EXISTS businesses_fts;

-- Drop statistics and migration tracking tables
DROP TABLE IF EXISTS table_statistics;
-- Note: We keep schema_migrations table as it's needed for tracking

-- Update migration tracking
DELETE FROM schema_migrations WHERE version = '005';