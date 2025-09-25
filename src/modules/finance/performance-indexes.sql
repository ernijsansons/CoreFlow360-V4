-- ============================================================================
-- PERFORMANCE OPTIMIZATION INDEXES
-- Critical indexes for financial reporting performance improvements
-- ============================================================================

-- Additional indexes for aging reports and date-based queries
CREATE INDEX IF NOT EXISTS idx_invoices_issue_date_business
ON invoices (business_id, issue_date);

CREATE INDEX IF NOT EXISTS idx_invoices_status_balance_business
ON invoices (business_id, status, balance_due) WHERE balance_due > 0;

CREATE INDEX IF NOT EXISTS idx_invoice_payments_date_business
ON invoice_payments (business_id, payment_date);

CREATE INDEX IF NOT EXISTS idx_invoice_payments_invoice_amount
ON invoice_payments (invoice_id, amount, payment_date);

-- Journal entries performance indexes for financial statements
CREATE INDEX IF NOT EXISTS idx_journal_lines_account_date_business
ON journal_lines (account_id, journal_entry_id)
INNER JOIN journal_entries ON journal_lines.journal_entry_id = journal_entries.id
WHERE journal_entries.business_id = ? AND journal_entries.status = 'POSTED';

-- Alternative approach for journal lines with business_id denormalization
-- Note: This would require schema change to add business_id to journal_lines
-- CREATE INDEX IF NOT EXISTS idx_journal_lines_business_account_date
-- ON journal_lines (business_id, account_id, date) WHERE status = 'POSTED';

-- General ledger performance for balance sheet queries
CREATE INDEX IF NOT EXISTS idx_general_ledger_business_account
ON general_ledger (business_id, account_id, period_id);

CREATE INDEX IF NOT EXISTS idx_general_ledger_closing_balance
ON general_ledger (business_id, period_id, closing_balance) WHERE closing_balance != 0;

-- Ledger transactions for cash flow analysis
CREATE INDEX IF NOT EXISTS idx_ledger_transactions_cash_accounts
ON ledger_transactions (business_id, account_id, date)
INNER JOIN chart_of_accounts ON ledger_transactions.account_id = chart_of_accounts.id
WHERE chart_of_accounts.is_cash_account = 1;

-- Financial reports query optimization
CREATE INDEX IF NOT EXISTS idx_financial_reports_type_date
ON financial_reports (business_id, type, generated_at DESC);

CREATE INDEX IF NOT EXISTS idx_financial_reports_parameters_hash
ON financial_reports (business_id, type, parameters) WHERE status = 'COMPLETED';

-- Custom report definitions optimization
CREATE INDEX IF NOT EXISTS idx_custom_report_definitions_public
ON custom_report_definitions (business_id, is_public, is_template, name);

CREATE INDEX IF NOT EXISTS idx_custom_report_definitions_data_source
ON custom_report_definitions (business_id, data_source, created_at DESC);

-- Chart of accounts hierarchy queries
CREATE INDEX IF NOT EXISTS idx_chart_accounts_hierarchy
ON chart_of_accounts (business_id, parent_id, type, is_active);

-- Invoice aging specific indexes
CREATE INDEX IF NOT EXISTS idx_invoices_aging_query
ON invoices (business_id, status, due_date, balance_due)
WHERE status IN ('SENT', 'VIEWED', 'PARTIALLY_PAID', 'OVERDUE') AND balance_due > 0;

-- Customer payment history for credit analysis
CREATE INDEX IF NOT EXISTS idx_invoice_payments_customer_history
ON invoice_payments (business_id, created_at DESC)
INNER JOIN invoices ON invoice_payments.invoice_id = invoices.id;

-- Accounting periods for date range queries
CREATE INDEX IF NOT EXISTS idx_accounting_periods_date_range
ON accounting_periods (business_id, start_date, end_date, status) WHERE status = 'OPEN';

-- Multi-currency support indexes
CREATE INDEX IF NOT EXISTS idx_exchange_rates_effective_date
ON exchange_rates (from_currency, to_currency, effective_date DESC);

-- Audit trail performance
CREATE INDEX IF NOT EXISTS idx_audit_logs_business_date
ON audit_logs (business_id, created_at DESC, table_name);

CREATE INDEX IF NOT EXISTS idx_audit_logs_record_changes
ON audit_logs (table_name, record_id, created_at DESC);

-- Department and project reporting
CREATE INDEX IF NOT EXISTS idx_journal_lines_department_project
ON journal_lines (department_id, project_id, journal_entry_id)
WHERE department_id IS NOT NULL OR project_id IS NOT NULL;

-- Reconciliation performance
CREATE INDEX IF NOT EXISTS idx_ledger_transactions_reconciliation
ON ledger_transactions (account_id, reconciled, date)
INNER JOIN chart_of_accounts ON ledger_transactions.account_id = chart_of_accounts.id
WHERE chart_of_accounts.is_reconcilable = 1;

-- Report export tracking
CREATE INDEX IF NOT EXISTS idx_report_exports_business_date
ON report_exports (business_id, exported_at DESC, status);

-- Scheduled reports performance
CREATE INDEX IF NOT EXISTS idx_report_schedules_next_run
ON report_schedules (business_id, is_active, next_run_at) WHERE is_active = 1;

-- User permissions for reports
CREATE INDEX IF NOT EXISTS idx_report_permissions_user_business
ON report_permissions (user_id, business_id, permission_level);

-- ============================================================================
-- COMPOSITE INDEXES FOR COMPLEX QUERIES
-- ============================================================================

-- Profit & Loss statement optimization
CREATE INDEX IF NOT EXISTS idx_pl_statement_query
ON journal_lines (journal_entry_id, account_id, debit, credit)
INNER JOIN journal_entries ON journal_lines.journal_entry_id = journal_entries.id
INNER JOIN chart_of_accounts ON journal_lines.account_id = chart_of_accounts.id
WHERE journal_entries.business_id = ?
AND journal_entries.status = 'POSTED'
AND chart_of_accounts.type IN ('REVENUE', 'EXPENSE')
AND journal_entries.date BETWEEN ? AND ?;

-- Balance sheet optimization
CREATE INDEX IF NOT EXISTS idx_balance_sheet_query
ON general_ledger (business_id, period_id, account_id, closing_balance)
INNER JOIN chart_of_accounts ON general_ledger.account_id = chart_of_accounts.id
WHERE chart_of_accounts.type IN ('ASSET', 'LIABILITY', 'EQUITY')
AND general_ledger.closing_balance != 0;

-- Cash flow statement optimization
CREATE INDEX IF NOT EXISTS idx_cash_flow_query
ON ledger_transactions (business_id, date, account_id, debit, credit)
INNER JOIN chart_of_accounts ON ledger_transactions.account_id = chart_of_accounts.id
WHERE chart_of_accounts.is_cash_account = 1
ORDER BY date;

-- ============================================================================
-- PERFORMANCE STATISTICS AND MONITORING
-- ============================================================================

-- Enable query plan analysis
PRAGMA query_planner = ON;

-- Analyze tables for better query optimization
ANALYZE chart_of_accounts;
ANALYZE journal_entries;
ANALYZE journal_lines;
ANALYZE general_ledger;
ANALYZE ledger_transactions;
ANALYZE invoices;
ANALYZE invoice_payments;
ANALYZE financial_reports;
ANALYZE custom_report_definitions;

-- ============================================================================
-- INDEX MAINTENANCE NOTES
-- ============================================================================

/*
Performance Monitoring Recommendations:

1. Monitor slow query log for queries taking > 100ms
2. Use EXPLAIN QUERY PLAN to analyze query performance
3. Consider partitioning large tables by business_id for multi-tenant isolation
4. Implement query result caching for frequently accessed reports
5. Use connection pooling for database connections
6. Consider read replicas for reporting queries

Critical Query Patterns to Monitor:
- Aging reports: business_id + status + due_date + balance_due
- P&L statements: business_id + account_type + date_range
- Balance sheets: business_id + period + account_type + balance
- Cash flow: business_id + cash_accounts + date_range
- Custom reports: business_id + data_source + filters

Index Usage Analysis:
Run periodically: SELECT name, sql FROM sqlite_master WHERE type='index' AND name LIKE 'idx_%';
Check unused indexes: PRAGMA index_info(index_name);
*/