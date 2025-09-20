-- Rollback: 003_double_entry_ledger
-- Description: Rollback double-entry accounting system
-- Created: 2024-12-01
-- Author: CoreFlow360 V4

-- Drop indexes first
DROP INDEX IF EXISTS idx_accounting_periods_dates;
DROP INDEX IF EXISTS idx_accounting_periods_business;
DROP INDEX IF EXISTS idx_trial_balance_lines_balance;
DROP INDEX IF EXISTS idx_trial_balance_business;
DROP INDEX IF EXISTS idx_general_ledger_business_period;
DROP INDEX IF EXISTS idx_general_ledger_account;
DROP INDEX IF EXISTS idx_journal_lines_reconciliation;
DROP INDEX IF EXISTS idx_journal_lines_department;
DROP INDEX IF EXISTS idx_journal_lines_account;
DROP INDEX IF EXISTS idx_journal_lines_entry;
DROP INDEX IF EXISTS idx_journal_entries_source;
DROP INDEX IF EXISTS idx_journal_entries_period;
DROP INDEX IF EXISTS idx_journal_entries_date;
DROP INDEX IF EXISTS idx_journal_entries_number;
DROP INDEX IF EXISTS idx_journal_entries_business;
DROP INDEX IF EXISTS idx_accounts_parent;
DROP INDEX IF EXISTS idx_accounts_type;
DROP INDEX IF EXISTS idx_accounts_number;
DROP INDEX IF EXISTS idx_accounts_business;

-- Drop tables in reverse dependency order
DROP TABLE IF EXISTS accounting_periods;
DROP TABLE IF EXISTS trial_balance_lines;
DROP TABLE IF EXISTS trial_balance;
DROP TABLE IF EXISTS general_ledger;
DROP TABLE IF EXISTS journal_lines;
DROP TABLE IF EXISTS journal_entries;
DROP TABLE IF EXISTS accounts;

-- Update migration tracking
DELETE FROM schema_migrations WHERE version = '003';