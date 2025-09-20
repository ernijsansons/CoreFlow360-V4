-- Migration: 003_double_entry_ledger
-- Description: Double-entry accounting system with Chart of Accounts, Journal Entries, and Ledgers
-- Created: 2024-12-01
-- Author: CoreFlow360 V4

-- Chart of Accounts table
CREATE TABLE IF NOT EXISTS accounts (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT NOT NULL,

    -- Account Information
    account_number TEXT NOT NULL,
    account_name TEXT NOT NULL,
    description TEXT,

    -- Account Classification (follows standard accounting)
    account_type TEXT NOT NULL CHECK (account_type IN (
        'asset',
        'liability',
        'equity',
        'revenue',
        'expense',
        'contra_asset',
        'contra_liability',
        'contra_equity',
        'contra_revenue',
        'contra_expense'
    )),

    -- Account Categories for detailed classification
    category TEXT NOT NULL CHECK (category IN (
        -- Assets
        'cash', 'bank', 'accounts_receivable', 'inventory', 'prepaid_expenses',
        'fixed_assets', 'accumulated_depreciation', 'intangible_assets', 'investments',
        -- Liabilities
        'accounts_payable', 'accrued_expenses', 'unearned_revenue', 'notes_payable',
        'current_liabilities', 'long_term_liabilities', 'taxes_payable',
        -- Equity
        'owners_equity', 'retained_earnings', 'common_stock', 'dividends',
        -- Revenue
        'sales_revenue', 'service_revenue', 'interest_income', 'other_income',
        -- Expenses
        'cost_of_goods_sold', 'salaries_expense', 'rent_expense', 'utilities_expense',
        'depreciation_expense', 'interest_expense', 'tax_expense', 'other_expense'
    )),

    -- Account Properties
    normal_balance TEXT NOT NULL CHECK (normal_balance IN ('debit', 'credit')),
    is_control_account INTEGER DEFAULT 0,
    parent_account_id TEXT,
    account_level INTEGER DEFAULT 0,

    -- Currency and Tax
    currency TEXT DEFAULT 'USD',
    tax_rate REAL DEFAULT 0,
    tax_code TEXT,

    -- Balance Tracking
    opening_balance REAL DEFAULT 0,
    opening_balance_date TEXT,
    current_balance REAL DEFAULT 0,
    ytd_debit REAL DEFAULT 0,
    ytd_credit REAL DEFAULT 0,

    -- Bank Integration
    is_bank_account INTEGER DEFAULT 0,
    bank_account_number TEXT,
    bank_name TEXT,
    bank_branch TEXT,
    last_reconciled_date TEXT,
    last_reconciled_balance REAL,

    -- Status and Control
    status TEXT DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'closed', 'deleted')),
    is_system_account INTEGER DEFAULT 0, -- System accounts cannot be deleted
    requires_department INTEGER DEFAULT 0,
    requires_project INTEGER DEFAULT 0,

    -- Timestamps
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now')),
    closed_at TEXT,
    deleted_at TEXT,

    -- Foreign Keys
    FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
    FOREIGN KEY (parent_account_id) REFERENCES accounts(id) ON DELETE SET NULL,

    -- Constraints
    UNIQUE(business_id, account_number),
    CHECK (deleted_at IS NULL OR status = 'deleted'),
    CHECK (closed_at IS NULL OR status = 'closed')
);

-- Journal Entries (Header) table
CREATE TABLE IF NOT EXISTS journal_entries (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT NOT NULL,

    -- Entry Information
    entry_number TEXT NOT NULL,
    entry_date TEXT NOT NULL,
    posting_date TEXT,
    period TEXT NOT NULL, -- Format: YYYY-MM
    fiscal_year INTEGER NOT NULL,

    -- Entry Type
    entry_type TEXT NOT NULL CHECK (entry_type IN (
        'standard',
        'adjusting',
        'closing',
        'reversing',
        'recurring',
        'opening',
        'correction'
    )),

    -- Source and Reference
    source_type TEXT CHECK (source_type IN (
        'manual',
        'invoice',
        'bill',
        'payment',
        'receipt',
        'payroll',
        'inventory',
        'depreciation',
        'system'
    )),
    source_document_id TEXT,
    reference_number TEXT,
    external_reference TEXT,

    -- Description
    description TEXT NOT NULL,
    notes TEXT,

    -- Amounts (for validation)
    total_debit REAL NOT NULL DEFAULT 0,
    total_credit REAL NOT NULL DEFAULT 0,

    -- Approval Workflow
    status TEXT DEFAULT 'draft' CHECK (status IN (
        'draft',
        'pending_approval',
        'approved',
        'posted',
        'reversed',
        'voided'
    )),
    approved_by_user_id TEXT,
    approved_at TEXT,
    posted_by_user_id TEXT,
    posted_at TEXT,

    -- Reversal Information
    is_reversal INTEGER DEFAULT 0,
    reversed_entry_id TEXT,
    reversal_entry_id TEXT,
    reversed_at TEXT,
    reversal_reason TEXT,

    -- Recurring Entry
    is_recurring INTEGER DEFAULT 0,
    recurring_template_id TEXT,

    -- Created By
    created_by_user_id TEXT NOT NULL,

    -- Timestamps
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now')),
    voided_at TEXT,

    -- Foreign Keys
    FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
    FOREIGN KEY (created_by_user_id) REFERENCES users(id),
    FOREIGN KEY (approved_by_user_id) REFERENCES users(id),
    FOREIGN KEY (posted_by_user_id) REFERENCES users(id),
    FOREIGN KEY (reversed_entry_id) REFERENCES journal_entries(id),
    FOREIGN KEY (reversal_entry_id) REFERENCES journal_entries(id),

    -- Constraints
    UNIQUE(business_id, entry_number),
    CHECK (total_debit = total_credit), -- Double-entry balance check
    CHECK (total_debit >= 0),
    CHECK (voided_at IS NULL OR status = 'voided')
);

-- Journal Entry Lines (Detail) table
CREATE TABLE IF NOT EXISTS journal_lines (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT NOT NULL,
    journal_entry_id TEXT NOT NULL,

    -- Line Information
    line_number INTEGER NOT NULL,
    account_id TEXT NOT NULL,

    -- Amounts (only one should be non-zero)
    debit_amount REAL DEFAULT 0,
    credit_amount REAL DEFAULT 0,

    -- Description and Reference
    description TEXT,
    reference TEXT,

    -- Dimensions (for analytical accounting)
    department_id TEXT,
    project_id TEXT,
    cost_center_id TEXT,
    customer_id TEXT,
    vendor_id TEXT,
    employee_id TEXT,

    -- Tax Information
    tax_amount REAL DEFAULT 0,
    tax_code TEXT,
    tax_rate REAL DEFAULT 0,

    -- Currency (for multi-currency support)
    currency TEXT DEFAULT 'USD',
    exchange_rate REAL DEFAULT 1.0,
    base_debit_amount REAL DEFAULT 0, -- In base currency
    base_credit_amount REAL DEFAULT 0, -- In base currency

    -- Reconciliation
    is_reconciled INTEGER DEFAULT 0,
    reconciled_date TEXT,
    reconciliation_id TEXT,

    -- Analysis
    quantity REAL,
    unit_price REAL,
    tags TEXT, -- JSON array of tags

    -- Timestamps
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now')),

    -- Foreign Keys
    FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
    FOREIGN KEY (journal_entry_id) REFERENCES journal_entries(id) ON DELETE CASCADE,
    FOREIGN KEY (account_id) REFERENCES accounts(id),
    FOREIGN KEY (department_id) REFERENCES departments(id),

    -- Constraints
    CHECK ((debit_amount > 0 AND credit_amount = 0) OR (credit_amount > 0 AND debit_amount = 0)),
    CHECK (base_debit_amount >= 0),
    CHECK (base_credit_amount >= 0)
);

-- General Ledger (account balances by period) table
CREATE TABLE IF NOT EXISTS general_ledger (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT NOT NULL,
    account_id TEXT NOT NULL,

    -- Period Information
    period TEXT NOT NULL, -- Format: YYYY-MM
    fiscal_year INTEGER NOT NULL,

    -- Opening Balance
    opening_balance REAL DEFAULT 0,

    -- Period Movements
    period_debit REAL DEFAULT 0,
    period_credit REAL DEFAULT 0,

    -- Closing Balance
    closing_balance REAL DEFAULT 0,

    -- Transaction Count
    transaction_count INTEGER DEFAULT 0,

    -- YTD Balances
    ytd_debit REAL DEFAULT 0,
    ytd_credit REAL DEFAULT 0,
    ytd_balance REAL DEFAULT 0,

    -- Status
    is_closed INTEGER DEFAULT 0,
    closed_at TEXT,

    -- Timestamps
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now')),

    -- Foreign Keys
    FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
    FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE,

    -- Constraints
    UNIQUE(business_id, account_id, period),
    CHECK (closing_balance = opening_balance + period_debit - period_credit OR
           closing_balance = opening_balance - period_debit + period_credit)
);

-- Trial Balance table
CREATE TABLE IF NOT EXISTS trial_balance (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT NOT NULL,

    -- Period
    period TEXT NOT NULL, -- Format: YYYY-MM
    fiscal_year INTEGER NOT NULL,
    as_of_date TEXT NOT NULL,

    -- Totals
    total_debit REAL NOT NULL DEFAULT 0,
    total_credit REAL NOT NULL DEFAULT 0,

    -- Status
    is_balanced INTEGER DEFAULT 0,
    generated_at TEXT DEFAULT (datetime('now')),
    generated_by_user_id TEXT,

    -- Timestamps
    created_at TEXT DEFAULT (datetime('now')),

    -- Foreign Keys
    FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
    FOREIGN KEY (generated_by_user_id) REFERENCES users(id),

    -- Constraints
    UNIQUE(business_id, period, as_of_date),
    CHECK (is_balanced = 0 OR total_debit = total_credit)
);

-- Trial Balance Lines table
CREATE TABLE IF NOT EXISTS trial_balance_lines (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    trial_balance_id TEXT NOT NULL,
    business_id TEXT NOT NULL,
    account_id TEXT NOT NULL,

    -- Balances
    debit_balance REAL DEFAULT 0,
    credit_balance REAL DEFAULT 0,

    -- YTD Amounts
    ytd_debit REAL DEFAULT 0,
    ytd_credit REAL DEFAULT 0,

    -- Transaction Count
    transaction_count INTEGER DEFAULT 0,

    -- Timestamps
    created_at TEXT DEFAULT (datetime('now')),

    -- Foreign Keys
    FOREIGN KEY (trial_balance_id) REFERENCES trial_balance(id) ON DELETE CASCADE,
    FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
    FOREIGN KEY (account_id) REFERENCES accounts(id),

    -- Constraints
    CHECK ((debit_balance > 0 AND credit_balance = 0) OR (credit_balance > 0 AND debit_balance = 0) OR (debit_balance = 0 AND credit_balance = 0))
);

-- Accounting Periods table
CREATE TABLE IF NOT EXISTS accounting_periods (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT NOT NULL,

    -- Period Information
    period_name TEXT NOT NULL,
    period TEXT NOT NULL, -- Format: YYYY-MM
    fiscal_year INTEGER NOT NULL,
    quarter INTEGER NOT NULL CHECK (quarter IN (1, 2, 3, 4)),

    -- Dates
    start_date TEXT NOT NULL,
    end_date TEXT NOT NULL,

    -- Status
    status TEXT DEFAULT 'open' CHECK (status IN ('open', 'closed', 'locked')),
    closed_by_user_id TEXT,
    closed_at TEXT,
    locked_by_user_id TEXT,
    locked_at TEXT,

    -- Timestamps
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now')),

    -- Foreign Keys
    FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
    FOREIGN KEY (closed_by_user_id) REFERENCES users(id),
    FOREIGN KEY (locked_by_user_id) REFERENCES users(id),

    -- Constraints
    UNIQUE(business_id, period),
    CHECK (end_date > start_date)
);

-- Create indexes for accounting tables
CREATE INDEX idx_accounts_business ON accounts(business_id, status);
CREATE INDEX idx_accounts_number ON accounts(business_id, account_number);
CREATE INDEX idx_accounts_type ON accounts(account_type, category);
CREATE INDEX idx_accounts_parent ON accounts(parent_account_id);

CREATE INDEX idx_journal_entries_business ON journal_entries(business_id, status);
CREATE INDEX idx_journal_entries_number ON journal_entries(business_id, entry_number);
CREATE INDEX idx_journal_entries_date ON journal_entries(entry_date, posting_date);
CREATE INDEX idx_journal_entries_period ON journal_entries(business_id, period, fiscal_year);
CREATE INDEX idx_journal_entries_source ON journal_entries(source_type, source_document_id);

CREATE INDEX idx_journal_lines_entry ON journal_lines(journal_entry_id);
CREATE INDEX idx_journal_lines_account ON journal_lines(account_id);
CREATE INDEX idx_journal_lines_department ON journal_lines(department_id) WHERE department_id IS NOT NULL;
CREATE INDEX idx_journal_lines_reconciliation ON journal_lines(reconciliation_id) WHERE is_reconciled = 1;

CREATE INDEX idx_general_ledger_account ON general_ledger(account_id, period);
CREATE INDEX idx_general_ledger_business_period ON general_ledger(business_id, period);

CREATE INDEX idx_trial_balance_business ON trial_balance(business_id, period);
CREATE INDEX idx_trial_balance_lines_balance ON trial_balance_lines(trial_balance_id);

CREATE INDEX idx_accounting_periods_business ON accounting_periods(business_id, status);
CREATE INDEX idx_accounting_periods_dates ON accounting_periods(start_date, end_date);