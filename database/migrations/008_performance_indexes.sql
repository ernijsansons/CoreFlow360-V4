-- Performance Optimization Indexes Migration
-- Adds critical indexes identified in security audit for query performance

-- ============================================================================
-- AUDIT LOG PERFORMANCE INDEXES
-- ============================================================================

-- Critical index for audit log queries by business and creation time
CREATE INDEX IF NOT EXISTS idx_audit_logs_business_created
ON audit_logs(business_id, created_at DESC);

-- Index for audit queries by user and business
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_business
ON audit_logs(user_id, business_id, created_at DESC);

-- Index for audit queries by event type and business
CREATE INDEX IF NOT EXISTS idx_audit_logs_event_business
ON audit_logs(event_type, business_id, created_at DESC);

-- Index for audit queries by resource type and ID
CREATE INDEX IF NOT EXISTS idx_audit_logs_resource
ON audit_logs(resource_type, resource_id, business_id);

-- ============================================================================
-- JOURNAL ENTRY PERFORMANCE INDEXES
-- ============================================================================

-- Critical index for journal entries by business and date
CREATE INDEX IF NOT EXISTS idx_journal_entries_business_date
ON journal_entries(business_id, date DESC);

-- Index for journal entries by business and status
CREATE INDEX IF NOT EXISTS idx_journal_entries_business_status
ON journal_entries(business_id, status, date DESC);

-- Index for journal entries by business and period
CREATE INDEX IF NOT EXISTS idx_journal_entries_business_period
ON journal_entries(business_id, period_id, date DESC);

-- Index for journal entries by business and type
CREATE INDEX IF NOT EXISTS idx_journal_entries_business_type
ON journal_entries(business_id, type, date DESC);

-- ============================================================================
-- JOURNAL LINES PERFORMANCE INDEXES
-- ============================================================================

-- Critical index for journal lines by entry and business isolation
CREATE INDEX IF NOT EXISTS idx_journal_lines_entry_business
ON journal_lines(journal_entry_id, account_id);

-- Index for journal lines by account
CREATE INDEX IF NOT EXISTS idx_journal_lines_account
ON journal_lines(account_id, journal_entry_id);

-- ============================================================================
-- BUSINESS MEMBERSHIP PERFORMANCE INDEXES
-- ============================================================================

-- Critical index for business memberships by user and status
CREATE INDEX IF NOT EXISTS idx_business_memberships_user_active
ON business_memberships(user_id, status, is_primary DESC);

-- Index for business memberships by business and status
CREATE INDEX IF NOT EXISTS idx_business_memberships_business_active
ON business_memberships(business_id, status, role);

-- Index for business membership updates
CREATE INDEX IF NOT EXISTS idx_business_memberships_updated
ON business_memberships(updated_at DESC) WHERE status = 'active';

-- ============================================================================
-- AGENT COST TRACKING INDEXES
-- ============================================================================

-- Critical index for agent costs by business and timestamp
CREATE INDEX IF NOT EXISTS idx_agent_costs_business_timestamp
ON agent_costs(business_id, timestamp DESC);

-- Index for agent costs by business and agent
CREATE INDEX IF NOT EXISTS idx_agent_costs_business_agent
ON agent_costs(business_id, agent_id, timestamp DESC);

-- Index for agent costs by business and capability
CREATE INDEX IF NOT EXISTS idx_agent_costs_business_capability
ON agent_costs(business_id, capability, timestamp DESC);

-- Index for agent costs by business and success status
CREATE INDEX IF NOT EXISTS idx_agent_costs_business_success
ON agent_costs(business_id, success, timestamp DESC);

-- ============================================================================
-- CRM PERFORMANCE INDEXES
-- ============================================================================

-- Index for companies by business
CREATE INDEX IF NOT EXISTS idx_companies_business
ON companies(business_id, created_at DESC);

-- Index for contacts by business and email
CREATE INDEX IF NOT EXISTS idx_contacts_business_email
ON contacts(business_id, email);

-- Index for contacts by business and company
CREATE INDEX IF NOT EXISTS idx_contacts_business_company
ON contacts(business_id, company_id, created_at DESC);

-- Index for leads by business and status
CREATE INDEX IF NOT EXISTS idx_leads_business_status
ON leads(business_id, status, created_at DESC);

-- Index for leads by business and assigned user
CREATE INDEX IF NOT EXISTS idx_leads_business_assigned
ON leads(business_id, assigned_to, status);

-- ============================================================================
-- ALERTS AND MONITORING INDEXES
-- ============================================================================

-- Index for alerts by business and trigger time
CREATE INDEX IF NOT EXISTS idx_alerts_business_triggered
ON alerts(business_id, triggered_at DESC);

-- Index for alerts by business and status
CREATE INDEX IF NOT EXISTS idx_alerts_business_status
ON alerts(business_id, status, triggered_at DESC);

-- Index for alerts by fingerprint for deduplication
CREATE INDEX IF NOT EXISTS idx_alerts_fingerprint
ON alerts(fingerprint, triggered_at DESC);

-- ============================================================================
-- SELF-HEALING MONITORING INDEXES
-- ============================================================================

-- Index for self-healing monitoring by check time
CREATE INDEX IF NOT EXISTS idx_self_healing_monitoring_check
ON self_healing_monitoring(check_at ASC, status);

-- Index for self-healing monitoring by business and status
CREATE INDEX IF NOT EXISTS idx_self_healing_monitoring_business
ON self_healing_monitoring(business_id, status, check_at ASC);

-- ============================================================================
-- USER AND SESSION INDEXES
-- ============================================================================

-- Index for users by email (unique constraint already exists)
-- Index for users by business context
CREATE INDEX IF NOT EXISTS idx_users_status_created
ON users(status, created_at DESC) WHERE status != 'deleted';

-- Index for password reset tokens
CREATE INDEX IF NOT EXISTS idx_users_reset_token
ON users(password_reset_token) WHERE password_reset_token IS NOT NULL;

-- ============================================================================
-- WORKFLOW AND TASK INDEXES
-- ============================================================================

-- Index for AI tasks by business and status
CREATE INDEX IF NOT EXISTS idx_ai_tasks_business_status
ON ai_tasks(business_id, status, priority DESC, created_at ASC);

-- Index for AI tasks by type and business
CREATE INDEX IF NOT EXISTS idx_ai_tasks_type_business
ON ai_tasks(type, business_id, status);

-- Index for AI tasks by scheduled execution time
CREATE INDEX IF NOT EXISTS idx_ai_tasks_scheduled
ON ai_tasks(scheduled_at ASC) WHERE status = 'scheduled';

-- ============================================================================
-- FINANCIAL LEDGER INDEXES
-- ============================================================================

-- Index for ledger transactions by account and date
CREATE INDEX IF NOT EXISTS idx_ledger_transactions_account_date
ON ledger_transactions(account_id, date DESC, business_id);

-- Index for ledger transactions by business and date
CREATE INDEX IF NOT EXISTS idx_ledger_transactions_business_date
ON ledger_transactions(business_id, date DESC);

-- Index for general ledger by account and business
CREATE INDEX IF NOT EXISTS idx_general_ledger_account_business
ON general_ledger(account_id, business_id);

-- ============================================================================
-- CHART OF ACCOUNTS INDEXES
-- ============================================================================

-- Index for accounts by business and status
CREATE INDEX IF NOT EXISTS idx_accounts_business_status
ON accounts(business_id, status, code);

-- Index for accounts by business and type
CREATE INDEX IF NOT EXISTS idx_accounts_business_type
ON accounts(business_id, account_type, code);

-- ============================================================================
-- PERFORMANCE MONITORING INDEXES
-- ============================================================================

-- Index for telemetry data by business and timestamp
CREATE INDEX IF NOT EXISTS idx_telemetry_business_timestamp
ON telemetry_data(business_id, timestamp DESC) WHERE business_id IS NOT NULL;

-- Index for telemetry data by module and capability
CREATE INDEX IF NOT EXISTS idx_telemetry_module_capability
ON telemetry_data(module, capability, timestamp DESC);

-- Index for telemetry data by trace ID for distributed tracing
CREATE INDEX IF NOT EXISTS idx_telemetry_trace_id
ON telemetry_data(trace_id, span_id) WHERE trace_id IS NOT NULL;

-- ============================================================================
-- COMPOSITE INDEXES FOR COMMON QUERY PATTERNS
-- ============================================================================

-- Composite index for audit log security queries
CREATE INDEX IF NOT EXISTS idx_audit_logs_security_pattern
ON audit_logs(business_id, user_id, event_type, created_at DESC);

-- Composite index for journal entry financial reporting
CREATE INDEX IF NOT EXISTS idx_journal_entries_reporting_pattern
ON journal_entries(business_id, period_id, status, date DESC);

-- Composite index for agent cost analytics
CREATE INDEX IF NOT EXISTS idx_agent_costs_analytics_pattern
ON agent_costs(business_id, agent_id, capability, timestamp DESC);

-- Composite index for CRM lead pipeline queries
CREATE INDEX IF NOT EXISTS idx_leads_pipeline_pattern
ON leads(business_id, status, assigned_to, ai_qualification_score DESC);

-- ============================================================================
-- PARTIAL INDEXES FOR ACTIVE RECORDS
-- ============================================================================

-- Partial index for active business memberships only
CREATE INDEX IF NOT EXISTS idx_business_memberships_active_only
ON business_memberships(user_id, business_id, role)
WHERE status = 'active';

-- Partial index for active users only
CREATE INDEX IF NOT EXISTS idx_users_active_only
ON users(email, created_at DESC)
WHERE status = 'active';

-- Partial index for posted journal entries only
CREATE INDEX IF NOT EXISTS idx_journal_entries_posted_only
ON journal_entries(business_id, date DESC, period_id)
WHERE status = 'posted';

-- Partial index for open leads only
CREATE INDEX IF NOT EXISTS idx_leads_open_only
ON leads(business_id, assigned_to, ai_qualification_score DESC)
WHERE status NOT IN ('closed_won', 'closed_lost', 'unqualified');

-- ============================================================================
-- COVERING INDEXES FOR COMMON SELECT PATTERNS
-- ============================================================================

-- Covering index for audit log list queries
CREATE INDEX IF NOT EXISTS idx_audit_logs_covering_list
ON audit_logs(business_id, created_at DESC)
INCLUDE (id, user_id, event_type, event_name, status);

-- Covering index for journal entry list queries
CREATE INDEX IF NOT EXISTS idx_journal_entries_covering_list
ON journal_entries(business_id, date DESC)
INCLUDE (id, entry_number, description, status, type);

-- Covering index for lead list queries
CREATE INDEX IF NOT EXISTS idx_leads_covering_list
ON leads(business_id, status, created_at DESC)
INCLUDE (id, contact_id, company_id, source, assigned_to, ai_qualification_score);

-- ============================================================================
-- UPDATE MIGRATION TRACKING
-- ============================================================================

INSERT INTO schema_migrations (version, applied_at)
VALUES ('008', datetime('now'));