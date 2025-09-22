-- ============================================================================
-- FINANCE MODULE DATABASE SCHEMA
-- Complete double-entry bookkeeping system with audit trails and invoicing
-- ============================================================================

-- Chart of Accounts
CREATE TABLE IF NOT EXISTS chart_of_accounts (
  id TEXT PRIMARY KEY,
  code TEXT NOT NULL,
  name TEXT NOT NULL,
  type TEXT NOT NULL, -- ASSET, LIABILITY, EQUITY, REVENUE, EXPENSE, CONTRA_*
  category TEXT NOT NULL, -- CURRENT_ASSET, FIXED_ASSET, etc.
  parent_id TEXT,
  description TEXT,
  currency TEXT NOT NULL DEFAULT 'USD',
  normal_balance TEXT NOT NULL, -- 'debit' or 'credit'
  is_active INTEGER NOT NULL DEFAULT 1,
  is_system_account INTEGER NOT NULL DEFAULT 0,
  is_reconcilable INTEGER NOT NULL DEFAULT 0,
  is_cash_account INTEGER NOT NULL DEFAULT 0,
  metadata TEXT DEFAULT '{}',
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  business_id TEXT NOT NULL,

  UNIQUE (code, business_id),
  FOREIGN KEY (parent_id) REFERENCES chart_of_accounts(id),
  INDEX idx_accounts_business_type (business_id, type),
  INDEX idx_accounts_business_code (business_id, code),
  INDEX idx_accounts_parent (parent_id),
  INDEX idx_accounts_active (business_id, is_active) WHERE is_active = 1
);

-- Accounting Periods
CREATE TABLE IF NOT EXISTS accounting_periods (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  start_date INTEGER NOT NULL,
  end_date INTEGER NOT NULL,
  fiscal_year INTEGER NOT NULL,
  fiscal_period INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'FUTURE', -- FUTURE, OPEN, CLOSING, CLOSED, LOCKED
  closed_at INTEGER,
  closed_by TEXT,
  locked_at INTEGER,
  locked_by TEXT,
  business_id TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  created_by TEXT NOT NULL,

  INDEX idx_periods_business_fiscal (business_id, fiscal_year, fiscal_period),
  INDEX idx_periods_business_dates (business_id, start_date, end_date),
  INDEX idx_periods_status (business_id, status)
);

-- Journal Entries
CREATE TABLE IF NOT EXISTS journal_entries (
  id TEXT PRIMARY KEY,
  entry_number TEXT NOT NULL,
  date INTEGER NOT NULL,
  description TEXT NOT NULL,
  reference TEXT,
  type TEXT NOT NULL DEFAULT 'STANDARD', -- STANDARD, ADJUSTING, CLOSING, REVERSING, OPENING, SYSTEM
  status TEXT NOT NULL DEFAULT 'DRAFT', -- DRAFT, PENDING_APPROVAL, APPROVED, POSTED, REVERSED, VOIDED
  period_id TEXT NOT NULL,
  reversal_of TEXT,
  reversed_by TEXT,
  posted_at INTEGER,
  posted_by TEXT,
  created_at INTEGER NOT NULL,
  created_by TEXT NOT NULL,
  updated_at INTEGER NOT NULL,
  updated_by TEXT,
  business_id TEXT NOT NULL,
  metadata TEXT DEFAULT '{}',

  UNIQUE (entry_number, business_id),
  FOREIGN KEY (period_id) REFERENCES accounting_periods(id),
  FOREIGN KEY (reversal_of) REFERENCES journal_entries(id),
  FOREIGN KEY (reversed_by) REFERENCES journal_entries(id),
  INDEX idx_journal_entries_business_date (business_id, date),
  INDEX idx_journal_entries_business_status (business_id, status),
  INDEX idx_journal_entries_period (period_id),
  INDEX idx_journal_entries_type (business_id, type),
  INDEX idx_journal_entries_posted (business_id, posted_at) WHERE status = 'POSTED'
);

-- Journal Lines (Double-entry details)
CREATE TABLE IF NOT EXISTS journal_lines (
  id TEXT PRIMARY KEY,
  journal_entry_id TEXT NOT NULL,
  account_id TEXT NOT NULL,
  account_code TEXT NOT NULL,
  account_name TEXT NOT NULL,
  debit REAL NOT NULL DEFAULT 0,
  credit REAL NOT NULL DEFAULT 0,
  currency TEXT NOT NULL DEFAULT 'USD',
  exchange_rate REAL NOT NULL DEFAULT 1.0,
  base_debit REAL NOT NULL DEFAULT 0, -- In base currency
  base_credit REAL NOT NULL DEFAULT 0, -- In base currency
  description TEXT,
  department_id TEXT,
  project_id TEXT,
  customer_id TEXT,
  vendor_id TEXT,
  employee_id TEXT,
  metadata TEXT DEFAULT '{}',

  FOREIGN KEY (journal_entry_id) REFERENCES journal_entries(id) ON DELETE CASCADE,
  FOREIGN KEY (account_id) REFERENCES chart_of_accounts(id),
  INDEX idx_journal_lines_entry (journal_entry_id),
  INDEX idx_journal_lines_account (account_id),
  INDEX idx_journal_lines_department (department_id),
  INDEX idx_journal_lines_project (project_id),

  -- Ensure either debit or credit, but not both
  CHECK ((debit > 0 AND credit = 0) OR (credit > 0 AND debit = 0)),
  CHECK (debit >= 0 AND credit >= 0),
  CHECK (base_debit >= 0 AND base_credit >= 0),
  CHECK (exchange_rate > 0)
);

-- General Ledger (Account balances by period)
CREATE TABLE IF NOT EXISTS general_ledger (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL,
  period_id TEXT NOT NULL,
  opening_balance REAL NOT NULL DEFAULT 0,
  debits REAL NOT NULL DEFAULT 0,
  credits REAL NOT NULL DEFAULT 0,
  closing_balance REAL NOT NULL DEFAULT 0,
  currency TEXT NOT NULL DEFAULT 'USD',
  transaction_count INTEGER NOT NULL DEFAULT 0,
  last_transaction_date INTEGER,
  business_id TEXT NOT NULL,

  UNIQUE (account_id, period_id),
  FOREIGN KEY (account_id) REFERENCES chart_of_accounts(id),
  FOREIGN KEY (period_id) REFERENCES accounting_periods(id),
  INDEX idx_general_ledger_account (account_id),
  INDEX idx_general_ledger_period (period_id),
  INDEX idx_general_ledger_business (business_id)
);

-- Ledger Transactions (Detailed transaction history)
CREATE TABLE IF NOT EXISTS ledger_transactions (
  id TEXT PRIMARY KEY,
  journal_entry_id TEXT NOT NULL,
  account_id TEXT NOT NULL,
  date INTEGER NOT NULL,
  debit REAL NOT NULL DEFAULT 0,
  credit REAL NOT NULL DEFAULT 0,
  balance REAL NOT NULL, -- Running balance
  currency TEXT NOT NULL DEFAULT 'USD',
  exchange_rate REAL NOT NULL DEFAULT 1.0,
  base_debit REAL NOT NULL DEFAULT 0,
  base_credit REAL NOT NULL DEFAULT 0,
  base_balance REAL NOT NULL, -- Running balance in base currency
  description TEXT NOT NULL,
  reference TEXT,
  reconciled INTEGER NOT NULL DEFAULT 0,
  reconciled_date INTEGER,
  business_id TEXT NOT NULL,

  FOREIGN KEY (journal_entry_id) REFERENCES journal_entries(id),
  FOREIGN KEY (account_id) REFERENCES chart_of_accounts(id),
  INDEX idx_ledger_transactions_account_date (account_id, date),
  INDEX idx_ledger_transactions_journal (journal_entry_id),
  INDEX idx_ledger_transactions_business_date (business_id, date),
  INDEX idx_ledger_transactions_reconciled (account_id, reconciled),

  CHECK (debit >= 0 AND credit >= 0),
  CHECK (base_debit >= 0 AND base_credit >= 0),
  CHECK (exchange_rate > 0)
);

-- Currencies
CREATE TABLE IF NOT EXISTS currencies (
  code TEXT PRIMARY KEY, -- ISO 4217 code
  name TEXT NOT NULL,
  symbol TEXT NOT NULL,
  decimal_places INTEGER NOT NULL DEFAULT 2,
  is_base_currency INTEGER NOT NULL DEFAULT 0,
  added_by TEXT,
  business_id TEXT,
  created_at INTEGER DEFAULT (strftime('%s', 'now') * 1000),

  CHECK (decimal_places >= 0 AND decimal_places <= 4)
);

-- Exchange Rates
CREATE TABLE IF NOT EXISTS exchange_rates (
  id TEXT PRIMARY KEY,
  from_currency TEXT NOT NULL,
  to_currency TEXT NOT NULL,
  rate REAL NOT NULL,
  effective_date INTEGER NOT NULL,
  expiry_date INTEGER,
  source TEXT NOT NULL DEFAULT 'manual',
  is_automatic INTEGER NOT NULL DEFAULT 0,
  business_id TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  created_by TEXT NOT NULL,

  FOREIGN KEY (from_currency) REFERENCES currencies(code),
  FOREIGN KEY (to_currency) REFERENCES currencies(code),
  INDEX idx_exchange_rates_currencies_date (from_currency, to_currency, effective_date),
  INDEX idx_exchange_rates_business (business_id),
  INDEX idx_exchange_rates_effective (effective_date),
  INDEX idx_exchange_rates_expiry (expiry_date) WHERE expiry_date IS NOT NULL,

  CHECK (rate > 0)
);

-- Finance Configuration
CREATE TABLE IF NOT EXISTS finance_config (
  business_id TEXT PRIMARY KEY,
  base_currency TEXT NOT NULL DEFAULT 'USD',
  fiscal_year_start INTEGER NOT NULL DEFAULT 1, -- Month 1-12
  period_type TEXT NOT NULL DEFAULT 'monthly', -- monthly, quarterly
  allow_negative_inventory INTEGER NOT NULL DEFAULT 0,
  require_approval INTEGER NOT NULL DEFAULT 0,
  approval_threshold REAL NOT NULL DEFAULT 1000,
  retained_earnings_account_id TEXT,
  income_summary_account_id TEXT,
  rounding_account_id TEXT,
  currency_gain_loss_account_id TEXT,
  opening_balance_account_id TEXT,
  updated_at INTEGER DEFAULT (strftime('%s', 'now') * 1000),
  updated_by TEXT,

  FOREIGN KEY (base_currency) REFERENCES currencies(code),
  FOREIGN KEY (retained_earnings_account_id) REFERENCES chart_of_accounts(id),
  FOREIGN KEY (income_summary_account_id) REFERENCES chart_of_accounts(id),
  FOREIGN KEY (rounding_account_id) REFERENCES chart_of_accounts(id),
  FOREIGN KEY (currency_gain_loss_account_id) REFERENCES chart_of_accounts(id),
  FOREIGN KEY (opening_balance_account_id) REFERENCES chart_of_accounts(id),

  CHECK (fiscal_year_start BETWEEN 1 AND 12),
  CHECK (approval_threshold >= 0)
);

-- Financial Audit Log
CREATE TABLE IF NOT EXISTS finance_audit_log (
  id TEXT PRIMARY KEY,
  entity_type TEXT NOT NULL, -- 'account', 'journal', 'period', 'ledger'
  entity_id TEXT NOT NULL,
  action TEXT NOT NULL, -- CREATE, UPDATE, DELETE, POST, REVERSE, etc.
  changes TEXT, -- JSON of changes
  performed_by TEXT NOT NULL,
  performed_at INTEGER NOT NULL,
  ip_address TEXT,
  user_agent TEXT,
  business_id TEXT NOT NULL,
  previous_hash TEXT,
  current_hash TEXT NOT NULL,

  INDEX idx_finance_audit_business_date (business_id, performed_at),
  INDEX idx_finance_audit_entity (entity_type, entity_id),
  INDEX idx_finance_audit_user (performed_by, performed_at),
  INDEX idx_finance_audit_action (business_id, action),
  INDEX idx_finance_audit_hash (business_id, current_hash)
);

-- Account Reconciliation
CREATE TABLE IF NOT EXISTS account_reconciliation (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL,
  statement_date INTEGER NOT NULL,
  statement_balance REAL NOT NULL,
  book_balance REAL NOT NULL,
  difference REAL NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending', -- pending, in_progress, completed
  reconciled_by TEXT,
  reconciled_at INTEGER,
  notes TEXT,
  business_id TEXT NOT NULL,
  created_at INTEGER NOT NULL,

  FOREIGN KEY (account_id) REFERENCES chart_of_accounts(id),
  INDEX idx_reconciliation_account_date (account_id, statement_date),
  INDEX idx_reconciliation_business_status (business_id, status),
  INDEX idx_reconciliation_date (statement_date)
);

-- Reconciliation Items
CREATE TABLE IF NOT EXISTS reconciliation_items (
  id TEXT PRIMARY KEY,
  reconciliation_id TEXT NOT NULL,
  transaction_id TEXT,
  statement_date INTEGER NOT NULL,
  statement_amount REAL NOT NULL,
  book_amount REAL NOT NULL,
  difference REAL NOT NULL,
  status TEXT NOT NULL DEFAULT 'unmatched', -- matched, unmatched, partial
  reconciled_by TEXT,
  reconciled_at INTEGER,
  notes TEXT,
  business_id TEXT NOT NULL,

  FOREIGN KEY (reconciliation_id) REFERENCES account_reconciliation(id),
  FOREIGN KEY (transaction_id) REFERENCES ledger_transactions(id),
  INDEX idx_reconciliation_items_reconciliation (reconciliation_id),
  INDEX idx_reconciliation_items_transaction (transaction_id),
  INDEX idx_reconciliation_items_status (status),
  INDEX idx_reconciliation_items_business (business_id)
);

-- Budget Lines
CREATE TABLE IF NOT EXISTS budget_lines (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL,
  period_id TEXT NOT NULL,
  budget_amount REAL NOT NULL DEFAULT 0,
  actual_amount REAL NOT NULL DEFAULT 0,
  variance REAL NOT NULL DEFAULT 0,
  variance_percentage REAL NOT NULL DEFAULT 0,
  notes TEXT,
  business_id TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,

  UNIQUE (account_id, period_id),
  FOREIGN KEY (account_id) REFERENCES chart_of_accounts(id),
  FOREIGN KEY (period_id) REFERENCES accounting_periods(id),
  INDEX idx_budget_lines_account (account_id),
  INDEX idx_budget_lines_period (period_id),
  INDEX idx_budget_lines_business (business_id)
);

-- Closing Entries (Track period closing process)
CREATE TABLE IF NOT EXISTS closing_entries (
  id TEXT PRIMARY KEY,
  period_id TEXT NOT NULL,
  type TEXT NOT NULL, -- 'revenue', 'expense', 'dividend', 'summary'
  source_accounts TEXT NOT NULL, -- JSON array of account IDs
  target_account TEXT NOT NULL,
  amount REAL NOT NULL,
  journal_entry_id TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  business_id TEXT NOT NULL,

  FOREIGN KEY (period_id) REFERENCES accounting_periods(id),
  FOREIGN KEY (target_account) REFERENCES chart_of_accounts(id),
  FOREIGN KEY (journal_entry_id) REFERENCES journal_entries(id),
  INDEX idx_closing_entries_period (period_id),
  INDEX idx_closing_entries_journal (journal_entry_id),
  INDEX idx_closing_entries_business (business_id)
);

-- Financial Statements Cache
CREATE TABLE IF NOT EXISTS financial_statements (
  id TEXT PRIMARY KEY,
  type TEXT NOT NULL, -- BALANCE_SHEET, INCOME_STATEMENT, CASH_FLOW, EQUITY_STATEMENT
  period_id TEXT NOT NULL,
  start_date INTEGER NOT NULL,
  end_date INTEGER NOT NULL,
  currency TEXT NOT NULL,
  data TEXT NOT NULL, -- JSON statement data
  generated_at INTEGER NOT NULL,
  generated_by TEXT NOT NULL,
  business_id TEXT NOT NULL,

  FOREIGN KEY (period_id) REFERENCES accounting_periods(id),
  INDEX idx_financial_statements_business_type (business_id, type),
  INDEX idx_financial_statements_period (period_id),
  INDEX idx_financial_statements_dates (start_date, end_date)
);

-- Validation Rules
CREATE TABLE IF NOT EXISTS validation_rules (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  type TEXT NOT NULL, -- 'account', 'journal', 'period'
  condition TEXT NOT NULL, -- Expression to evaluate
  error_message TEXT NOT NULL,
  severity TEXT NOT NULL DEFAULT 'error', -- 'error', 'warning'
  is_active INTEGER NOT NULL DEFAULT 1,
  business_id TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,

  INDEX idx_validation_rules_type (type, is_active),
  INDEX idx_validation_rules_business (business_id, is_active)
);

-- ============================================================================
-- TRIGGERS FOR DATA INTEGRITY
-- ============================================================================

-- Update journal entry timestamp when lines change
CREATE TRIGGER IF NOT EXISTS update_journal_entry_timestamp
AFTER INSERT ON journal_lines
FOR EACH ROW
BEGIN
  UPDATE journal_entries
  SET updated_at = strftime('%s', 'now') * 1000
  WHERE id = NEW.journal_entry_id;
END;

-- Validate journal entry balance
CREATE TRIGGER IF NOT EXISTS validate_journal_balance
AFTER INSERT ON journal_lines
FOR EACH ROW
BEGIN
  -- Check if journal entry is balanced after this insert
  SELECT CASE
    WHEN ABS(
      (SELECT COALESCE(SUM(base_debit), 0) FROM journal_lines WHERE journal_entry_id = NEW.journal_entry_id) -
      (SELECT COALESCE(SUM(base_credit), 0) FROM journal_lines WHERE journal_entry_id = NEW.journal_entry_id)
    ) > 0.01 THEN
      RAISE(FAIL, 'Journal entry must be balanced (debits = credits)')
  END;
END;

-- Prevent modification of posted entries
CREATE TRIGGER IF NOT EXISTS prevent_posted_entry_modification
BEFORE UPDATE ON journal_entries
FOR EACH ROW
WHEN OLD.status = 'POSTED' AND NEW.status != OLD.status
BEGIN
  SELECT RAISE(FAIL, 'Cannot modify posted journal entries');
END;

-- Prevent deletion of posted entries
CREATE TRIGGER IF NOT EXISTS prevent_posted_entry_deletion
BEFORE DELETE ON journal_entries
FOR EACH ROW
WHEN OLD.status = 'POSTED'
BEGIN
  SELECT RAISE(FAIL, 'Cannot delete posted journal entries');
END;

-- Update general ledger on transaction posting
CREATE TRIGGER IF NOT EXISTS update_general_ledger
AFTER UPDATE ON journal_entries
FOR EACH ROW
WHEN NEW.status = 'POSTED' AND OLD.status != 'POSTED'
BEGIN
  -- Update general ledger balances for all accounts in this entry
  INSERT OR REPLACE INTO general_ledger (
    id, account_id, period_id, opening_balance, debits, credits,
    closing_balance, currency, transaction_count, last_transaction_date, business_id
  )
  SELECT
    COALESCE(gl.id, 'gl_' || jl.account_id || '_' || NEW.period_id),
    jl.account_id,
    NEW.period_id,
    COALESCE(gl.opening_balance, 0),
    COALESCE(gl.debits, 0) + COALESCE(jl_sum.total_debit, 0),
    COALESCE(gl.credits, 0) + COALESCE(jl_sum.total_credit, 0),
    COALESCE(gl.opening_balance, 0) +
    COALESCE(gl.debits, 0) + COALESCE(jl_sum.total_debit, 0) -
    COALESCE(gl.credits, 0) - COALESCE(jl_sum.total_credit, 0),
    COALESCE(gl.currency, 'USD'),
    COALESCE(gl.transaction_count, 0) + 1,
    NEW.date,
    NEW.business_id
  FROM (
    SELECT account_id, SUM(base_debit) as total_debit, SUM(base_credit) as total_credit
    FROM journal_lines
    WHERE journal_entry_id = NEW.id
    GROUP BY account_id
  ) jl_sum
  LEFT JOIN general_ledger gl ON gl.account_id = jl_sum.account_id AND gl.period_id = NEW.period_id;
END;

-- Prevent period modification after closing
CREATE TRIGGER IF NOT EXISTS prevent_closed_period_modification
BEFORE UPDATE ON accounting_periods
FOR EACH ROW
WHEN OLD.status IN ('CLOSED', 'LOCKED') AND NEW.status != OLD.status
BEGIN
  SELECT CASE
    WHEN OLD.status = 'LOCKED' THEN
      RAISE(FAIL, 'Cannot modify locked periods')
    WHEN OLD.status = 'CLOSED' AND NEW.status != 'LOCKED' THEN
      RAISE(FAIL, 'Closed periods can only be locked')
  END;
END;

-- ============================================================================
-- INVOICE SYSTEM TABLES
-- ============================================================================

-- Customers
CREATE TABLE IF NOT EXISTS customers (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  email TEXT,
  phone TEXT,
  website TEXT,
  tax_id TEXT,
  currency TEXT NOT NULL DEFAULT 'USD',
  payment_terms TEXT NOT NULL, -- JSON serialized PaymentTerms
  credit_limit REAL,
  billing_address TEXT, -- JSON serialized InvoiceAddress
  shipping_address TEXT, -- JSON serialized InvoiceAddress
  contacts TEXT, -- JSON serialized CustomerContact[]
  is_active INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  business_id TEXT NOT NULL,
  metadata TEXT DEFAULT '{}',

  INDEX idx_customers_business (business_id),
  INDEX idx_customers_business_active (business_id, is_active) WHERE is_active = 1,
  INDEX idx_customers_email (business_id, email) WHERE email IS NOT NULL
);

-- Tax Rates
CREATE TABLE IF NOT EXISTS tax_rates (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  rate REAL NOT NULL,
  type TEXT NOT NULL, -- SALES_TAX, VAT, GST, EXCISE_TAX, CUSTOM
  jurisdiction TEXT NOT NULL,
  account_id TEXT NOT NULL,
  is_active INTEGER NOT NULL DEFAULT 1,
  effective_date INTEGER NOT NULL,
  expiry_date INTEGER,
  business_id TEXT NOT NULL,

  FOREIGN KEY (account_id) REFERENCES chart_of_accounts(id),
  INDEX idx_tax_rates_business (business_id),
  INDEX idx_tax_rates_business_active (business_id, is_active) WHERE is_active = 1,
  INDEX idx_tax_rates_jurisdiction (business_id, jurisdiction)
);

-- Tax Jurisdictions
CREATE TABLE IF NOT EXISTS tax_jurisdictions (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  code TEXT NOT NULL,
  type TEXT NOT NULL, -- country, state, province, city, district
  parent_id TEXT,
  business_id TEXT NOT NULL,

  FOREIGN KEY (parent_id) REFERENCES tax_jurisdictions(id),
  INDEX idx_tax_jurisdictions_business (business_id),
  INDEX idx_tax_jurisdictions_code (business_id, code)
);

-- Invoices
CREATE TABLE IF NOT EXISTS invoices (
  id TEXT PRIMARY KEY,
  invoice_number TEXT NOT NULL,
  customer_id TEXT NOT NULL,
  customer_name TEXT NOT NULL,
  customer_email TEXT,
  customer_address TEXT, -- JSON serialized InvoiceAddress
  bill_to_address TEXT, -- JSON serialized InvoiceAddress
  ship_to_address TEXT, -- JSON serialized InvoiceAddress
  issue_date INTEGER NOT NULL,
  due_date INTEGER NOT NULL,
  currency TEXT NOT NULL DEFAULT 'USD',
  exchange_rate REAL NOT NULL DEFAULT 1.0,
  subtotal REAL NOT NULL DEFAULT 0,
  tax_total REAL NOT NULL DEFAULT 0,
  discount_total REAL NOT NULL DEFAULT 0,
  total REAL NOT NULL DEFAULT 0,
  balance_due REAL NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'DRAFT', -- DRAFT, PENDING_APPROVAL, SENT, VIEWED, PARTIALLY_PAID, PAID, OVERDUE, CANCELLED, VOIDED
  terms TEXT NOT NULL, -- JSON serialized PaymentTerms
  lines TEXT NOT NULL, -- JSON serialized InvoiceLine[]
  tax_lines TEXT, -- JSON serialized TaxLine[]
  discounts TEXT, -- JSON serialized InvoiceDiscount[]
  notes TEXT,
  internal_notes TEXT,
  reference_number TEXT,
  po_number TEXT,
  approval_required INTEGER NOT NULL DEFAULT 0,
  approval_status TEXT, -- PENDING, APPROVED, REJECTED
  approvals TEXT, -- JSON serialized InvoiceApproval[]
  pdf_url TEXT,
  sent_at INTEGER,
  sent_by TEXT,
  last_reminder_sent INTEGER,
  journal_entry_id TEXT,
  created_at INTEGER NOT NULL,
  created_by TEXT NOT NULL,
  updated_at INTEGER NOT NULL,
  updated_by TEXT,
  business_id TEXT NOT NULL,
  metadata TEXT DEFAULT '{}',

  UNIQUE (invoice_number, business_id),
  FOREIGN KEY (customer_id) REFERENCES customers(id),
  FOREIGN KEY (journal_entry_id) REFERENCES journal_entries(id),
  INDEX idx_invoices_business (business_id),
  INDEX idx_invoices_business_status (business_id, status),
  INDEX idx_invoices_customer (customer_id),
  INDEX idx_invoices_due_date (business_id, due_date),
  INDEX idx_invoices_balance_due (business_id, balance_due) WHERE balance_due > 0,
  INDEX idx_invoices_sent (business_id, sent_at) WHERE sent_at IS NOT NULL
);

-- Invoice Payments
CREATE TABLE IF NOT EXISTS invoice_payments (
  id TEXT PRIMARY KEY,
  invoice_id TEXT NOT NULL,
  payment_date INTEGER NOT NULL,
  amount REAL NOT NULL,
  currency TEXT NOT NULL DEFAULT 'USD',
  exchange_rate REAL NOT NULL DEFAULT 1.0,
  base_amount REAL NOT NULL,
  payment_method TEXT NOT NULL, -- CASH, CHECK, CREDIT_CARD, BANK_TRANSFER, etc.
  reference TEXT,
  notes TEXT,
  journal_entry_id TEXT,
  created_at INTEGER NOT NULL,
  created_by TEXT NOT NULL,
  business_id TEXT NOT NULL,

  FOREIGN KEY (invoice_id) REFERENCES invoices(id),
  FOREIGN KEY (journal_entry_id) REFERENCES journal_entries(id),
  INDEX idx_invoice_payments_invoice (invoice_id),
  INDEX idx_invoice_payments_business (business_id),
  INDEX idx_invoice_payments_date (business_id, payment_date)
);

-- Invoice Approvals
CREATE TABLE IF NOT EXISTS invoice_approvals (
  id TEXT PRIMARY KEY,
  invoice_id TEXT NOT NULL,
  approver_user_id TEXT NOT NULL,
  approver_name TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'PENDING', -- PENDING, APPROVED, REJECTED, CANCELLED
  level INTEGER NOT NULL,
  comments TEXT,
  approved_at INTEGER,
  rejected_at INTEGER,

  FOREIGN KEY (invoice_id) REFERENCES invoices(id),
  INDEX idx_invoice_approvals_invoice (invoice_id),
  INDEX idx_invoice_approvals_approver (approver_user_id),
  INDEX idx_invoice_approvals_status (status),
  INDEX idx_invoice_approvals_level (invoice_id, level)
);

-- Invoice Approval Configuration
CREATE TABLE IF NOT EXISTS invoice_approval_config (
  business_id TEXT PRIMARY KEY,
  is_enabled INTEGER NOT NULL DEFAULT 1,
  default_threshold REAL NOT NULL DEFAULT 1000,
  max_approval_levels INTEGER NOT NULL DEFAULT 3,
  auto_approve_small_amounts INTEGER NOT NULL DEFAULT 0,
  small_amount_threshold REAL NOT NULL DEFAULT 100,
  require_comments_on_rejection INTEGER NOT NULL DEFAULT 1,
  notify_on_pending_approval INTEGER NOT NULL DEFAULT 1,
  escalation_days INTEGER NOT NULL DEFAULT 3
);

-- Invoice Approval Rules
CREATE TABLE IF NOT EXISTS invoice_approval_rules (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT,
  threshold_amount REAL NOT NULL,
  currency TEXT NOT NULL DEFAULT 'USD',
  required_approvers TEXT NOT NULL, -- JSON serialized ApprovalLevel[]
  is_active INTEGER NOT NULL DEFAULT 1,
  business_id TEXT NOT NULL,

  INDEX idx_approval_rules_business (business_id),
  INDEX idx_approval_rules_business_active (business_id, is_active) WHERE is_active = 1,
  INDEX idx_approval_rules_threshold (business_id, threshold_amount)
);

-- Invoice Templates
CREATE TABLE IF NOT EXISTS invoice_templates (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  is_default INTEGER NOT NULL DEFAULT 0,
  logo_url TEXT,
  colors TEXT, -- JSON serialized color scheme
  layout TEXT NOT NULL DEFAULT 'standard', -- standard, modern, minimal
  show_tax_column INTEGER NOT NULL DEFAULT 1,
  show_discount_column INTEGER NOT NULL DEFAULT 1,
  footer_text TEXT,
  business_id TEXT NOT NULL,

  INDEX idx_invoice_templates_business (business_id),
  INDEX idx_invoice_templates_default (business_id, is_default) WHERE is_default = 1
);

-- Finance Configuration (Extended for Invoice System)
CREATE TABLE IF NOT EXISTS finance_config (
  business_id TEXT PRIMARY KEY,
  base_currency TEXT NOT NULL DEFAULT 'USD',
  fiscal_year_start INTEGER NOT NULL DEFAULT 1, -- Month (1-12)
  period_type TEXT NOT NULL DEFAULT 'monthly', -- monthly, quarterly, yearly
  allow_negative_inventory INTEGER NOT NULL DEFAULT 0,
  require_approval INTEGER NOT NULL DEFAULT 1,
  approval_threshold REAL NOT NULL DEFAULT 1000,

  -- Account IDs for automatic posting
  retained_earnings_account_id TEXT,
  income_summary_account_id TEXT,
  rounding_account_id TEXT,
  currency_gain_loss_account_id TEXT,
  opening_balance_account_id TEXT,
  accounts_receivable_id TEXT,
  sales_tax_payable_id TEXT,
  default_revenue_account_id TEXT,
  discount_allowed_account_id TEXT,
  bad_debt_account_id TEXT,
  unallocated_cash_account_id TEXT,
  cash_account_id TEXT,

  -- Tax Configuration
  default_tax_rate_id TEXT,
  tax_calculation_method TEXT NOT NULL DEFAULT 'line', -- line, total
  tax_rounding_method TEXT NOT NULL DEFAULT 'standard', -- standard, up, down

  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,

  FOREIGN KEY (retained_earnings_account_id) REFERENCES chart_of_accounts(id),
  FOREIGN KEY (income_summary_account_id) REFERENCES chart_of_accounts(id),
  FOREIGN KEY (accounts_receivable_id) REFERENCES chart_of_accounts(id),
  FOREIGN KEY (default_revenue_account_id) REFERENCES chart_of_accounts(id),
  FOREIGN KEY (default_tax_rate_id) REFERENCES tax_rates(id)
);

-- ============================================================================
-- INVOICE SYSTEM TRIGGERS
-- ============================================================================

-- Update invoice balance when payment is added
CREATE TRIGGER IF NOT EXISTS update_invoice_balance_on_payment
AFTER INSERT ON invoice_payments
FOR EACH ROW
BEGIN
  UPDATE invoices
  SET
    balance_due = balance_due - NEW.amount,
    status = CASE
      WHEN balance_due - NEW.amount <= 0.01 THEN 'PAID'
      WHEN balance_due - NEW.amount < total THEN 'PARTIALLY_PAID'
      ELSE status
    END,
    updated_at = NEW.created_at
  WHERE id = NEW.invoice_id;
END;

-- Auto-generate invoice numbers
CREATE TRIGGER IF NOT EXISTS auto_generate_invoice_number
BEFORE INSERT ON invoices
FOR EACH ROW
WHEN NEW.invoice_number IS NULL OR NEW.invoice_number = ''
BEGIN
  UPDATE invoices SET invoice_number = (
    SELECT printf('INV-%04d-%06d',
      strftime('%Y', datetime(NEW.issue_date / 1000, 'unixepoch')),
      COALESCE(MAX(CAST(substr(invoice_number, -6) AS INTEGER)), 0) + 1
    )
    FROM invoices
    WHERE business_id = NEW.business_id
    AND strftime('%Y', datetime(issue_date / 1000, 'unixepoch')) = strftime('%Y', datetime(NEW.issue_date / 1000, 'unixepoch'))
  )
  WHERE id = NEW.id;
END;

-- Update overdue status
CREATE TRIGGER IF NOT EXISTS update_overdue_status
AFTER UPDATE ON invoices
FOR EACH ROW
WHEN NEW.due_date < (strftime('%s', 'now') * 1000)
AND NEW.balance_due > 0
AND NEW.status IN ('SENT', 'VIEWED', 'PARTIALLY_PAID')
BEGIN
  UPDATE invoices
  SET status = 'OVERDUE', updated_at = (strftime('%s', 'now') * 1000)
  WHERE id = NEW.id;
END;

-- ============================================================================
-- VIEWS FOR COMMON QUERIES
-- ============================================================================

-- Account Balances View
CREATE VIEW IF NOT EXISTS account_balances AS
SELECT
  coa.id as account_id,
  coa.code as account_code,
  coa.name as account_name,
  coa.type as account_type,
  coa.currency,
  coa.business_id,
  COALESCE(SUM(CASE WHEN lt.debit > 0 THEN lt.base_debit ELSE 0 END), 0) as total_debits,
  COALESCE(SUM(CASE WHEN lt.credit > 0 THEN lt.base_credit ELSE 0 END), 0) as total_credits,
  CASE
    WHEN coa.normal_balance = 'debit' THEN
      COALESCE(SUM(lt.base_debit - lt.base_credit), 0)
    ELSE
      COALESCE(SUM(lt.base_credit - lt.base_debit), 0)
  END as balance,
  MAX(lt.date) as last_transaction_date
FROM chart_of_accounts coa
LEFT JOIN ledger_transactions lt ON coa.id = lt.account_id
WHERE coa.is_active = 1
GROUP BY coa.id, coa.code, coa.name, coa.type, coa.currency, coa.business_id, coa.normal_balance;

-- Trial Balance View
CREATE VIEW IF NOT EXISTS trial_balance AS
SELECT
  ap.id as period_id,
  ap.name as period_name,
  ab.account_id,
  ab.account_code,
  ab.account_name,
  ab.account_type,
  CASE WHEN ab.balance >= 0 AND ab.account_type IN ('ASSET', 'EXPENSE') THEN ab.balance ELSE 0 END as debit_balance,
  CASE WHEN ab.balance >= 0 AND ab.account_type IN ('LIABILITY', 'EQUITY', 'REVENUE') THEN ab.balance ELSE 0 END as credit_balance,
  ab.business_id
FROM account_balances ab
CROSS JOIN accounting_periods ap
WHERE ab.business_id = ap.business_id
AND ab.last_transaction_date BETWEEN ap.start_date AND ap.end_date;

-- ============================================================================
-- FINANCIAL REPORTING TABLES
-- ============================================================================

-- Financial Reports Storage
CREATE TABLE IF NOT EXISTS financial_reports (
  id TEXT PRIMARY KEY,
  type TEXT NOT NULL, -- PROFIT_AND_LOSS, BALANCE_SHEET, CASH_FLOW, etc.
  name TEXT NOT NULL,
  description TEXT,
  parameters TEXT NOT NULL, -- JSON serialized ReportParameters
  generated_at INTEGER NOT NULL,
  generated_by TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'GENERATING', -- GENERATING, COMPLETED, FAILED, EXPIRED
  data TEXT, -- JSON serialized report data
  export_urls TEXT, -- JSON serialized export URLs
  business_id TEXT NOT NULL,

  INDEX idx_financial_reports_business (business_id),
  INDEX idx_financial_reports_type (business_id, type),
  INDEX idx_financial_reports_generated (business_id, generated_at),
  INDEX idx_financial_reports_status (business_id, status)
);

-- Custom Report Definitions
CREATE TABLE IF NOT EXISTS custom_report_definitions (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT,
  data_source TEXT NOT NULL, -- CHART_OF_ACCOUNTS, JOURNAL_ENTRIES, etc.
  columns TEXT NOT NULL, -- JSON serialized ReportColumn[]
  filters TEXT NOT NULL, -- JSON serialized ReportFilter[]
  sorting TEXT NOT NULL, -- JSON serialized ReportSort[]
  grouping TEXT, -- JSON serialized ReportGrouping[]
  aggregations TEXT, -- JSON serialized ReportAggregation[]
  formatting TEXT, -- JSON serialized ReportFormatting
  is_template INTEGER NOT NULL DEFAULT 0,
  is_public INTEGER NOT NULL DEFAULT 0,
  created_by TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  business_id TEXT NOT NULL,

  INDEX idx_custom_reports_business (business_id),
  INDEX idx_custom_reports_public (is_public) WHERE is_public = 1,
  INDEX idx_custom_reports_creator (created_by),
  INDEX idx_custom_reports_name (business_id, name)
);

-- Report Templates (Pre-built report definitions)
CREATE TABLE IF NOT EXISTS report_templates (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT,
  category TEXT NOT NULL, -- Financial, Operational, Custom
  report_type TEXT NOT NULL,
  definition TEXT NOT NULL, -- JSON serialized report definition
  preview_data TEXT, -- JSON serialized sample data
  is_system INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,

  INDEX idx_report_templates_category (category),
  INDEX idx_report_templates_type (report_type)
);

-- Report Schedules (For automated report generation)
CREATE TABLE IF NOT EXISTS report_schedules (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  report_definition_id TEXT,
  report_type TEXT,
  parameters TEXT NOT NULL, -- JSON serialized parameters
  schedule_cron TEXT NOT NULL, -- Cron expression
  export_formats TEXT, -- JSON array of export formats
  email_recipients TEXT, -- JSON array of email addresses
  is_active INTEGER NOT NULL DEFAULT 1,
  last_run_at INTEGER,
  next_run_at INTEGER,
  created_by TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  business_id TEXT NOT NULL,

  INDEX idx_report_schedules_business (business_id),
  INDEX idx_report_schedules_next_run (next_run_at) WHERE is_active = 1,
  INDEX idx_report_schedules_active (business_id, is_active) WHERE is_active = 1
);

-- Report Access Control
CREATE TABLE IF NOT EXISTS report_permissions (
  id TEXT PRIMARY KEY,
  report_id TEXT,
  report_definition_id TEXT,
  user_id TEXT NOT NULL,
  permission_type TEXT NOT NULL, -- VIEW, EDIT, DELETE, EXPORT
  granted_by TEXT NOT NULL,
  granted_at INTEGER NOT NULL,
  business_id TEXT NOT NULL,

  FOREIGN KEY (report_id) REFERENCES financial_reports(id),
  FOREIGN KEY (report_definition_id) REFERENCES custom_report_definitions(id),
  INDEX idx_report_permissions_user (user_id),
  INDEX idx_report_permissions_business (business_id),
  INDEX idx_report_permissions_report (report_id),
  INDEX idx_report_permissions_definition (report_definition_id)
);

-- ============================================================================
-- GDPR DATA EXPORT COMPLIANCE
-- ============================================================================

-- GDPR Export Requests
CREATE TABLE IF NOT EXISTS gdpr_export_requests (
  id TEXT PRIMARY KEY,
  business_id TEXT NOT NULL,
  requested_by TEXT NOT NULL,
  requested_at INTEGER NOT NULL,
  purpose TEXT NOT NULL, -- user_request, legal_obligation, compliance_audit
  include_personal_data INTEGER NOT NULL DEFAULT 0,
  include_financial_data INTEGER NOT NULL DEFAULT 0,
  include_audit_trails INTEGER NOT NULL DEFAULT 0,
  date_range_start INTEGER,
  date_range_end INTEGER,
  export_format TEXT NOT NULL, -- JSON, CSV, XML
  delivery_method TEXT NOT NULL, -- download, email, secure_link
  retention_days INTEGER NOT NULL DEFAULT 30,
  status TEXT NOT NULL DEFAULT 'generating', -- generating, completed, failed, expired
  created_at INTEGER NOT NULL,
  completed_at INTEGER,
  download_url TEXT,
  file_size INTEGER,
  expires_at INTEGER,
  personal_data_count INTEGER DEFAULT 0,
  financial_data_count INTEGER DEFAULT 0,
  audit_trail_count INTEGER DEFAULT 0,
  error_message TEXT,

  INDEX idx_gdpr_exports_business (business_id),
  INDEX idx_gdpr_exports_status (business_id, status),
  INDEX idx_gdpr_exports_requested_by (requested_by),
  INDEX idx_gdpr_exports_expires (expires_at) WHERE status = 'completed'
);

-- ============================================================================
-- FINANCIAL REPORTING TRIGGERS
-- ============================================================================

-- Auto-cleanup expired reports
CREATE TRIGGER IF NOT EXISTS cleanup_expired_reports
AFTER UPDATE ON financial_reports
FOR EACH ROW
WHEN NEW.status = 'EXPIRED'
BEGIN
  -- In a real implementation, this would trigger cleanup of export files
  UPDATE financial_reports
  SET export_urls = NULL
  WHERE id = NEW.id;
END;

-- Update report schedule next run time
CREATE TRIGGER IF NOT EXISTS update_next_run_time
AFTER UPDATE ON report_schedules
FOR EACH ROW
WHEN NEW.last_run_at > OLD.last_run_at
BEGIN
  -- This would calculate next run time based on cron expression
  -- For now, just set it to 24 hours later
  UPDATE report_schedules
  SET next_run_at = NEW.last_run_at + (24 * 60 * 60 * 1000)
  WHERE id = NEW.id;
END;

-- ============================================================================
-- ADDITIONAL VIEWS FOR REPORTING
-- ============================================================================

-- Profit & Loss Summary View
CREATE VIEW IF NOT EXISTS profit_loss_summary AS
SELECT
  je.business_id,
  strftime('%Y-%m', datetime(je.date / 1000, 'unixepoch')) as period,
  SUM(CASE
    WHEN coa.type = 'REVENUE' THEN -(jl.base_debit - jl.base_credit)
    ELSE 0
  END) as total_revenue,
  SUM(CASE
    WHEN coa.category = 'COST_OF_GOODS_SOLD' THEN (jl.base_debit - jl.base_credit)
    ELSE 0
  END) as total_cogs,
  SUM(CASE
    WHEN coa.type = 'EXPENSE' AND coa.category = 'OPERATING_EXPENSE' THEN (jl.base_debit - jl.base_credit)
    ELSE 0
  END) as total_operating_expenses,
  SUM(CASE
    WHEN coa.type = 'REVENUE' THEN -(jl.base_debit - jl.base_credit)
    WHEN coa.type = 'EXPENSE' OR coa.category IN ('COST_OF_GOODS_SOLD', 'TAX_EXPENSE') THEN (jl.base_debit - jl.base_credit)
    ELSE 0
  END) as net_income
FROM journal_entries je
INNER JOIN journal_lines jl ON je.id = jl.journal_entry_id
INNER JOIN chart_of_accounts coa ON jl.account_id = coa.id
WHERE je.status = 'POSTED'
GROUP BY je.business_id, strftime('%Y-%m', datetime(je.date / 1000, 'unixepoch'));

-- Cash Flow Summary View
CREATE VIEW IF NOT EXISTS cash_flow_summary AS
SELECT
  coa.business_id,
  strftime('%Y-%m', datetime(je.date / 1000, 'unixepoch')) as period,
  SUM(CASE
    WHEN coa.is_cash_account = 1 THEN (jl.base_debit - jl.base_credit)
    ELSE 0
  END) as net_cash_flow,
  SUM(CASE
    WHEN coa.is_cash_account = 1 AND coa.category = 'CURRENT_ASSET' THEN (jl.base_debit - jl.base_credit)
    ELSE 0
  END) as operating_cash_flow
FROM journal_entries je
INNER JOIN journal_lines jl ON je.id = jl.journal_entry_id
INNER JOIN chart_of_accounts coa ON jl.account_id = coa.id
WHERE je.status = 'POSTED'
GROUP BY coa.business_id, strftime('%Y-%m', datetime(je.date / 1000, 'unixepoch'));

-- ============================================================================
-- SAMPLE DATA SETUP (Optional - for testing)
-- ============================================================================

-- Insert standard currencies
INSERT OR IGNORE INTO currencies (code, name, symbol, decimal_places, is_base_currency) VALUES
('USD', 'US Dollar', '$', 2, 1),
('EUR', 'Euro', '€', 2, 0),
('GBP', 'British Pound', '£', 2, 0),
('JPY', 'Japanese Yen', '¥', 0, 0),
('CAD', 'Canadian Dollar', 'C$', 2, 0),
('AUD', 'Australian Dollar', 'A$', 2, 0);

-- ============================================================================
-- PERFORMANCE OPTIMIZATION INDEXES
-- ============================================================================

-- Additional indexes for better performance
CREATE INDEX IF NOT EXISTS idx_journal_entries_date_status ON journal_entries(date, status);
CREATE INDEX IF NOT EXISTS idx_journal_lines_amounts ON journal_lines(base_debit, base_credit) WHERE base_debit > 0 OR base_credit > 0;
CREATE INDEX IF NOT EXISTS idx_ledger_transactions_balance ON ledger_transactions(account_id, date, balance);
CREATE INDEX IF NOT EXISTS idx_general_ledger_closing ON general_ledger(period_id, closing_balance) WHERE closing_balance != 0;

-- Partial indexes for common queries
CREATE INDEX IF NOT EXISTS idx_active_accounts ON chart_of_accounts(business_id, type, code) WHERE is_active = 1;
CREATE INDEX IF NOT EXISTS idx_posted_entries ON journal_entries(business_id, date, period_id) WHERE status = 'POSTED';
CREATE INDEX IF NOT EXISTS idx_open_periods ON accounting_periods(business_id, start_date, end_date) WHERE status = 'OPEN';

-- ============================================================================
-- DATA RETENTION AND CLEANUP
-- ============================================================================

-- Audit log cleanup (keep last 2 years)
-- Note: This would be handled by a separate cleanup process

-- ============================================================================
-- SCHEMA VERSION TRACKING
-- ============================================================================

INSERT OR REPLACE INTO schema_versions (module, version, applied_at)
VALUES ('finance', '1.0.0', strftime('%s', 'now') * 1000);