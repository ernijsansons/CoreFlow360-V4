-- Rollback: 004_audit_workflows
-- Description: Rollback audit logs and workflow management
-- Created: 2024-12-01
-- Author: CoreFlow360 V4

-- Drop indexes first
DROP INDEX IF EXISTS idx_system_events_unresolved;
DROP INDEX IF EXISTS idx_system_events_category;
DROP INDEX IF EXISTS idx_system_events_severity;
DROP INDEX IF EXISTS idx_activity_logs_date;
DROP INDEX IF EXISTS idx_activity_logs_session;
DROP INDEX IF EXISTS idx_activity_logs_business_user;
DROP INDEX IF EXISTS idx_workflow_transitions_instance;
DROP INDEX IF EXISTS idx_workflow_steps_status;
DROP INDEX IF EXISTS idx_workflow_steps_assigned;
DROP INDEX IF EXISTS idx_workflow_steps_instance;
DROP INDEX IF EXISTS idx_workflow_instances_overdue;
DROP INDEX IF EXISTS idx_workflow_instances_assignee;
DROP INDEX IF EXISTS idx_workflow_instances_context;
DROP INDEX IF EXISTS idx_workflow_instances_definition;
DROP INDEX IF EXISTS idx_workflow_instances_business;
DROP INDEX IF EXISTS idx_workflow_definitions_key;
DROP INDEX IF EXISTS idx_workflow_definitions_business;
DROP INDEX IF EXISTS idx_audit_logs_timestamp;
DROP INDEX IF EXISTS idx_audit_logs_event;
DROP INDEX IF EXISTS idx_audit_logs_resource;
DROP INDEX IF EXISTS idx_audit_logs_user;
DROP INDEX IF EXISTS idx_audit_logs_business;

-- Drop tables in reverse dependency order
DROP TABLE IF EXISTS system_events;
DROP TABLE IF EXISTS activity_logs;
DROP TABLE IF EXISTS workflow_transitions;
DROP TABLE IF EXISTS workflow_steps;
DROP TABLE IF EXISTS workflow_instances;
DROP TABLE IF EXISTS workflow_definitions;
DROP TABLE IF EXISTS audit_logs;

-- Update migration tracking
DELETE FROM schema_migrations WHERE version = '004';