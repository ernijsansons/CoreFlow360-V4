-- Migration 031: Account Reconciliation System
-- Creates tables for bank/credit card account reconciliation

-- Accounts table (if not exists - for reconciliation targets)
CREATE TABLE IF NOT EXISTS accounts (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  business_id TEXT NOT NULL,
  account_name TEXT NOT NULL,
  account_type TEXT NOT NULL CHECK (account_type IN ('bank', 'credit_card', 'cash', 'other')),
  account_number TEXT,
  institution_name TEXT,
  current_balance REAL NOT NULL DEFAULT 0,
  currency TEXT NOT NULL DEFAULT 'USD',
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'closed')),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE
);

-- Reconciliations table (main reconciliation records)
CREATE TABLE IF NOT EXISTS reconciliations (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  business_id TEXT NOT NULL,
  account_id TEXT NOT NULL,
  statement_date TEXT NOT NULL,
  statement_balance REAL NOT NULL,
  book_balance REAL NOT NULL,
  difference REAL NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'in_progress' CHECK (status IN ('in_progress', 'completed', 'review_required')),
  statement_file_url TEXT,
  notes TEXT,
  reconciled_by TEXT,
  reconciled_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
  FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE,
  FOREIGN KEY (reconciled_by) REFERENCES users(id) ON DELETE SET NULL
);

-- Reconciliation items (individual transaction matches)
CREATE TABLE IF NOT EXISTS reconciliation_items (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  reconciliation_id TEXT NOT NULL,
  transaction_id TEXT,
  statement_transaction_id TEXT,
  transaction_date TEXT NOT NULL,
  description TEXT NOT NULL,
  amount REAL NOT NULL,
  matched BOOLEAN NOT NULL DEFAULT 0,
  match_confidence INTEGER DEFAULT 0,
  match_type TEXT CHECK (match_type IN ('auto', 'manual', 'suggested', 'unmatched')),
  matched_at TEXT,
  matched_by TEXT,
  notes TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (reconciliation_id) REFERENCES reconciliations(id) ON DELETE CASCADE,
  FOREIGN KEY (transaction_id) REFERENCES ledger_entries(id) ON DELETE SET NULL,
  FOREIGN KEY (matched_by) REFERENCES users(id) ON DELETE SET NULL
);

-- Statement transactions (imported from bank statements)
CREATE TABLE IF NOT EXISTS statement_transactions (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  reconciliation_id TEXT NOT NULL,
  transaction_date TEXT NOT NULL,
  description TEXT NOT NULL,
  amount REAL NOT NULL,
  reference_number TEXT,
  check_number TEXT,
  matched BOOLEAN NOT NULL DEFAULT 0,
  matched_item_id TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (reconciliation_id) REFERENCES reconciliations(id) ON DELETE CASCADE,
  FOREIGN KEY (matched_item_id) REFERENCES reconciliation_items(id) ON DELETE SET NULL
);

-- Reconciliation rules (auto-match rules)
CREATE TABLE IF NOT EXISTS reconciliation_rules (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  business_id TEXT NOT NULL,
  account_id TEXT,
  rule_name TEXT NOT NULL,
  rule_type TEXT NOT NULL CHECK (rule_type IN ('exact_match', 'amount_match', 'description_match', 'date_range')),
  conditions TEXT NOT NULL, -- JSON: {field: 'amount', operator: 'equals', value: 100}
  auto_apply BOOLEAN NOT NULL DEFAULT 0,
  priority INTEGER NOT NULL DEFAULT 0,
  active BOOLEAN NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
  FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
);

-- Discrepancies table (unreconciled items requiring attention)
CREATE TABLE IF NOT EXISTS reconciliation_discrepancies (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  reconciliation_id TEXT NOT NULL,
  discrepancy_type TEXT NOT NULL CHECK (discrepancy_type IN ('missing_transaction', 'duplicate', 'amount_mismatch', 'timing_difference')),
  description TEXT NOT NULL,
  amount REAL,
  statement_transaction_id TEXT,
  book_transaction_id TEXT,
  resolution TEXT CHECK (resolution IN ('pending', 'resolved', 'ignored')),
  resolution_notes TEXT,
  resolved_by TEXT,
  resolved_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (reconciliation_id) REFERENCES reconciliations(id) ON DELETE CASCADE,
  FOREIGN KEY (statement_transaction_id) REFERENCES statement_transactions(id) ON DELETE SET NULL,
  FOREIGN KEY (resolved_by) REFERENCES users(id) ON DELETE SET NULL
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_accounts_business ON accounts(business_id);
CREATE INDEX IF NOT EXISTS idx_accounts_status ON accounts(business_id, status);

CREATE INDEX IF NOT EXISTS idx_reconciliations_business ON reconciliations(business_id);
CREATE INDEX IF NOT EXISTS idx_reconciliations_account ON reconciliations(account_id);
CREATE INDEX IF NOT EXISTS idx_reconciliations_status ON reconciliations(business_id, status);
CREATE INDEX IF NOT EXISTS idx_reconciliations_date ON reconciliations(business_id, statement_date DESC);

CREATE INDEX IF NOT EXISTS idx_reconciliation_items_reconciliation ON reconciliation_items(reconciliation_id);
CREATE INDEX IF NOT EXISTS idx_reconciliation_items_transaction ON reconciliation_items(transaction_id);
CREATE INDEX IF NOT EXISTS idx_reconciliation_items_matched ON reconciliation_items(reconciliation_id, matched);

CREATE INDEX IF NOT EXISTS idx_statement_transactions_reconciliation ON statement_transactions(reconciliation_id);
CREATE INDEX IF NOT EXISTS idx_statement_transactions_matched ON statement_transactions(reconciliation_id, matched);

CREATE INDEX IF NOT EXISTS idx_reconciliation_rules_business ON reconciliation_rules(business_id);
CREATE INDEX IF NOT EXISTS idx_reconciliation_rules_account ON reconciliation_rules(account_id);
CREATE INDEX IF NOT EXISTS idx_reconciliation_rules_active ON reconciliation_rules(business_id, active);

CREATE INDEX IF NOT EXISTS idx_discrepancies_reconciliation ON reconciliation_discrepancies(reconciliation_id);
CREATE INDEX IF NOT EXISTS idx_discrepancies_resolution ON reconciliation_discrepancies(reconciliation_id, resolution);

-- Sample data for testing (can be removed in production)
-- Sample account
INSERT INTO accounts (id, business_id, account_name, account_type, account_number, institution_name, current_balance)
VALUES ('acc_sample_001', 'business_001', 'Business Checking', 'bank', '****1234', 'Chase Bank', 15000.00);

-- Sample reconciliation rule
INSERT INTO reconciliation_rules (business_id, account_id, rule_name, rule_type, conditions, auto_apply, priority)
VALUES (
  'business_001',
  'acc_sample_001',
  'Exact amount and date match',
  'exact_match',
  '{"fields": ["amount", "transaction_date"], "tolerance_days": 0, "tolerance_amount": 0}',
  1,
  1
);
