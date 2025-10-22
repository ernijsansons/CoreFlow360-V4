-- Migration 090: Autonomous Finance Agent Infrastructure
-- Description: Complete database schema for Finance Agent (Agent 6 - Priority 100/100)
-- Purpose: Double-entry bookkeeping, bank reconciliation, invoicing, expense categorization,
--          financial reporting, tax calculation, audit trails, cash flow forecasting,
--          anomaly detection, and multi-currency management
-- Created: 2025-10-20
-- Status: Production-ready

-- ============================================================================
-- CORE ACCOUNTING TABLES
-- ============================================================================

-- Chart of Accounts (COA)
CREATE TABLE IF NOT EXISTS chart_of_accounts (
    id TEXT PRIMARY KEY,
    business_id TEXT NOT NULL,
    account_code TEXT NOT NULL,
    account_name TEXT NOT NULL,
    account_type TEXT NOT NULL CHECK (account_type IN ('asset', 'liability', 'equity', 'revenue', 'expense')),
    account_subtype TEXT, -- 'current_asset', 'fixed_asset', 'current_liability', etc.
    parent_account_id TEXT, -- For hierarchical COA
    is_active INTEGER DEFAULT 1,
    requires_reconciliation INTEGER DEFAULT 0, -- For bank accounts
    tax_code TEXT, -- For tax-related accounts
    description TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (business_id) REFERENCES businesses(id),
    FOREIGN KEY (parent_account_id) REFERENCES chart_of_accounts(id),
    UNIQUE(business_id, account_code)
);

CREATE INDEX idx_coa_business ON chart_of_accounts(business_id);
CREATE INDEX idx_coa_type ON chart_of_accounts(account_type);
CREATE INDEX idx_coa_active ON chart_of_accounts(is_active);

-- Journal Entries (Double-Entry Bookkeeping)
CREATE TABLE IF NOT EXISTS journal_entries (
    id TEXT PRIMARY KEY,
    business_id TEXT NOT NULL,
    entry_number TEXT NOT NULL,
    entry_date TEXT NOT NULL,
    entry_type TEXT NOT NULL CHECK (entry_type IN ('manual', 'automatic', 'adjustment', 'closing')),
    reference_type TEXT, -- 'invoice', 'payment', 'expense', 'adjustment', etc.
    reference_id TEXT, -- ID of the related entity
    description TEXT NOT NULL,
    status TEXT DEFAULT 'draft' CHECK (status IN ('draft', 'posted', 'voided')),
    posted_at TEXT,
    posted_by TEXT, -- user_id or 'finance-agent' for automated entries
    created_by TEXT NOT NULL, -- user_id or 'finance-agent'
    reviewed_by TEXT, -- user_id for manual review
    notes TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (business_id) REFERENCES businesses(id),
    UNIQUE(business_id, entry_number)
);

CREATE INDEX idx_journal_business ON journal_entries(business_id);
CREATE INDEX idx_journal_date ON journal_entries(entry_date);
CREATE INDEX idx_journal_status ON journal_entries(status);
CREATE INDEX idx_journal_type ON journal_entries(entry_type);
CREATE INDEX idx_journal_reference ON journal_entries(reference_type, reference_id);

-- Journal Entry Lines (Debits and Credits)
CREATE TABLE IF NOT EXISTS journal_entry_lines (
    id TEXT PRIMARY KEY,
    journal_entry_id TEXT NOT NULL,
    account_id TEXT NOT NULL,
    line_type TEXT NOT NULL CHECK (line_type IN ('debit', 'credit')),
    amount REAL NOT NULL CHECK (amount >= 0),
    currency TEXT DEFAULT 'USD',
    exchange_rate REAL DEFAULT 1.0,
    amount_base_currency REAL NOT NULL, -- Amount in business base currency
    description TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (journal_entry_id) REFERENCES journal_entries(id) ON DELETE CASCADE,
    FOREIGN KEY (account_id) REFERENCES chart_of_accounts(id)
);

CREATE INDEX idx_journal_lines_entry ON journal_entry_lines(journal_entry_id);
CREATE INDEX idx_journal_lines_account ON journal_entry_lines(account_id);
CREATE INDEX idx_journal_lines_type ON journal_entry_lines(line_type);

-- ============================================================================
-- INVOICING & RECEIVABLES
-- ============================================================================

-- Invoices (Enhanced from existing schema)
CREATE TABLE IF NOT EXISTS invoices (
    id TEXT PRIMARY KEY,
    business_id TEXT NOT NULL,
    customer_id TEXT NOT NULL,
    invoice_number TEXT UNIQUE NOT NULL,
    invoice_date TEXT NOT NULL,
    due_date TEXT NOT NULL,
    status TEXT DEFAULT 'draft' CHECK (status IN ('draft', 'sent', 'viewed', 'paid', 'overdue', 'partially_paid', 'cancelled')),
    subtotal REAL NOT NULL,
    tax_amount REAL DEFAULT 0,
    discount_amount REAL DEFAULT 0,
    total_amount REAL NOT NULL,
    amount_paid REAL DEFAULT 0,
    amount_due REAL NOT NULL,
    currency TEXT DEFAULT 'USD',
    payment_terms TEXT, -- 'net_30', 'net_60', 'due_on_receipt', etc.
    notes TEXT,
    sent_at TEXT,
    viewed_at TEXT,
    paid_at TEXT,
    journal_entry_id TEXT, -- Link to accounting entry
    pdf_url TEXT, -- R2 storage URL
    created_by TEXT, -- user_id or 'finance-agent'
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (business_id) REFERENCES businesses(id),
    FOREIGN KEY (customer_id) REFERENCES customers(id),
    FOREIGN KEY (journal_entry_id) REFERENCES journal_entries(id)
);

CREATE INDEX idx_invoices_business ON invoices(business_id);
CREATE INDEX idx_invoices_customer ON invoices(customer_id);
CREATE INDEX idx_invoices_status ON invoices(status);
CREATE INDEX idx_invoices_due_date ON invoices(due_date);
CREATE INDEX idx_invoices_date ON invoices(invoice_date);

-- Invoice Line Items
CREATE TABLE IF NOT EXISTS invoice_line_items (
    id TEXT PRIMARY KEY,
    invoice_id TEXT NOT NULL,
    product_id TEXT,
    description TEXT NOT NULL,
    quantity REAL NOT NULL,
    unit_price REAL NOT NULL,
    tax_rate REAL DEFAULT 0,
    discount_percent REAL DEFAULT 0,
    line_total REAL NOT NULL,
    account_id TEXT, -- Revenue account
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (invoice_id) REFERENCES invoices(id) ON DELETE CASCADE,
    FOREIGN KEY (product_id) REFERENCES products(id),
    FOREIGN KEY (account_id) REFERENCES chart_of_accounts(id)
);

CREATE INDEX idx_invoice_lines_invoice ON invoice_line_items(invoice_id);
CREATE INDEX idx_invoice_lines_product ON invoice_line_items(product_id);

-- ============================================================================
-- EXPENSES & PAYABLES
-- ============================================================================

-- Expenses (Enhanced tracking)
CREATE TABLE IF NOT EXISTS expenses (
    id TEXT PRIMARY KEY,
    business_id TEXT NOT NULL,
    vendor_id TEXT,
    expense_number TEXT NOT NULL,
    expense_date TEXT NOT NULL,
    category TEXT NOT NULL, -- ML-categorized
    subcategory TEXT,
    amount REAL NOT NULL,
    currency TEXT DEFAULT 'USD',
    exchange_rate REAL DEFAULT 1.0,
    amount_base_currency REAL NOT NULL,
    description TEXT,
    payment_method TEXT CHECK (payment_method IN ('cash', 'credit_card', 'debit_card', 'bank_transfer', 'check')),
    payment_status TEXT DEFAULT 'unpaid' CHECK (payment_status IN ('unpaid', 'paid', 'partially_paid')),
    receipt_url TEXT, -- R2 storage URL
    is_reimbursable INTEGER DEFAULT 0,
    reimbursed_at TEXT,
    account_id TEXT, -- Expense account from COA
    journal_entry_id TEXT,
    confidence_score REAL, -- ML categorization confidence (0-1)
    requires_review INTEGER DEFAULT 0, -- Flag for low confidence
    reviewed_by TEXT,
    reviewed_at TEXT,
    created_by TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (business_id) REFERENCES businesses(id),
    FOREIGN KEY (vendor_id) REFERENCES vendors(id),
    FOREIGN KEY (account_id) REFERENCES chart_of_accounts(id),
    FOREIGN KEY (journal_entry_id) REFERENCES journal_entries(id),
    UNIQUE(business_id, expense_number)
);

CREATE INDEX idx_expenses_business ON expenses(business_id);
CREATE INDEX idx_expenses_vendor ON expenses(vendor_id);
CREATE INDEX idx_expenses_date ON expenses(expense_date);
CREATE INDEX idx_expenses_category ON expenses(category);
CREATE INDEX idx_expenses_status ON expenses(payment_status);
CREATE INDEX idx_expenses_review ON expenses(requires_review);

-- Expense Categories (ML Training Data)
CREATE TABLE IF NOT EXISTS expense_categories (
    id TEXT PRIMARY KEY,
    business_id TEXT NOT NULL,
    category_name TEXT NOT NULL,
    parent_category TEXT,
    default_account_id TEXT, -- Default COA account for this category
    keywords TEXT, -- JSON array of keywords for ML
    is_active INTEGER DEFAULT 1,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (business_id) REFERENCES businesses(id),
    FOREIGN KEY (default_account_id) REFERENCES chart_of_accounts(id),
    UNIQUE(business_id, category_name)
);

CREATE INDEX idx_expense_categories_business ON expense_categories(business_id);

-- ============================================================================
-- BANK RECONCILIATION
-- ============================================================================

-- Bank Accounts
CREATE TABLE IF NOT EXISTS bank_accounts (
    id TEXT PRIMARY KEY,
    business_id TEXT NOT NULL,
    account_name TEXT NOT NULL,
    bank_name TEXT NOT NULL,
    account_number TEXT NOT NULL, -- Last 4 digits only
    account_type TEXT CHECK (account_type IN ('checking', 'savings', 'credit_card', 'line_of_credit')),
    currency TEXT DEFAULT 'USD',
    current_balance REAL DEFAULT 0,
    reconciled_balance REAL DEFAULT 0,
    last_reconciled_date TEXT,
    coa_account_id TEXT NOT NULL, -- Link to chart of accounts
    is_active INTEGER DEFAULT 1,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (business_id) REFERENCES businesses(id),
    FOREIGN KEY (coa_account_id) REFERENCES chart_of_accounts(id)
);

CREATE INDEX idx_bank_accounts_business ON bank_accounts(business_id);
CREATE INDEX idx_bank_accounts_active ON bank_accounts(is_active);

-- Bank Transactions (Imported from bank feeds)
CREATE TABLE IF NOT EXISTS bank_transactions (
    id TEXT PRIMARY KEY,
    bank_account_id TEXT NOT NULL,
    transaction_date TEXT NOT NULL,
    posted_date TEXT NOT NULL,
    description TEXT NOT NULL,
    amount REAL NOT NULL, -- Positive for credits, negative for debits
    transaction_type TEXT CHECK (transaction_type IN ('debit', 'credit', 'fee', 'interest')),
    reference_number TEXT,
    payee TEXT,
    category TEXT, -- Bank's category
    balance_after REAL,
    is_reconciled INTEGER DEFAULT 0,
    matched_transaction_id TEXT, -- Link to ledger transaction
    match_confidence REAL, -- ML matching confidence (0-1)
    reconciled_at TEXT,
    reconciled_by TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (bank_account_id) REFERENCES bank_accounts(id)
);

CREATE INDEX idx_bank_txns_account ON bank_transactions(bank_account_id);
CREATE INDEX idx_bank_txns_date ON bank_transactions(transaction_date);
CREATE INDEX idx_bank_txns_reconciled ON bank_transactions(is_reconciled);

-- Bank Reconciliation Sessions
CREATE TABLE IF NOT EXISTS bank_reconciliations (
    id TEXT PRIMARY KEY,
    business_id TEXT NOT NULL,
    bank_account_id TEXT NOT NULL,
    reconciliation_date TEXT NOT NULL,
    statement_date TEXT NOT NULL,
    opening_balance REAL NOT NULL,
    closing_balance REAL NOT NULL,
    statement_balance REAL NOT NULL,
    difference REAL, -- Should be 0 when reconciled
    status TEXT DEFAULT 'in_progress' CHECK (status IN ('in_progress', 'completed', 'reviewed')),
    transactions_matched INTEGER DEFAULT 0,
    transactions_unmatched INTEGER DEFAULT 0,
    auto_match_rate REAL, -- Percentage auto-matched
    completed_at TEXT,
    completed_by TEXT,
    notes TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (business_id) REFERENCES businesses(id),
    FOREIGN KEY (bank_account_id) REFERENCES bank_accounts(id)
);

CREATE INDEX idx_bank_recon_business ON bank_reconciliations(business_id);
CREATE INDEX idx_bank_recon_account ON bank_reconciliations(bank_account_id);
CREATE INDEX idx_bank_recon_date ON bank_reconciliations(reconciliation_date);

-- ============================================================================
-- TAX MANAGEMENT
-- ============================================================================

-- Tax Rates
CREATE TABLE IF NOT EXISTS tax_rates (
    id TEXT PRIMARY KEY,
    business_id TEXT NOT NULL,
    jurisdiction TEXT NOT NULL, -- 'US-CA', 'US-NY', 'UK', etc.
    tax_type TEXT NOT NULL CHECK (tax_type IN ('sales_tax', 'vat', 'income_tax', 'payroll_tax')),
    tax_name TEXT NOT NULL,
    rate REAL NOT NULL CHECK (rate >= 0 AND rate <= 100), -- Percentage
    is_active INTEGER DEFAULT 1,
    effective_from TEXT NOT NULL,
    effective_to TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (business_id) REFERENCES businesses(id)
);

CREATE INDEX idx_tax_rates_business ON tax_rates(business_id);
CREATE INDEX idx_tax_rates_jurisdiction ON tax_rates(jurisdiction);
CREATE INDEX idx_tax_rates_active ON tax_rates(is_active);

-- Tax Calculations (Per Transaction)
CREATE TABLE IF NOT EXISTS tax_calculations (
    id TEXT PRIMARY KEY,
    business_id TEXT NOT NULL,
    transaction_type TEXT NOT NULL, -- 'invoice', 'expense', 'payment'
    transaction_id TEXT NOT NULL,
    jurisdiction TEXT NOT NULL,
    tax_type TEXT NOT NULL,
    taxable_amount REAL NOT NULL,
    tax_rate REAL NOT NULL,
    tax_amount REAL NOT NULL,
    calculation_date TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (business_id) REFERENCES businesses(id)
);

CREATE INDEX idx_tax_calc_business ON tax_calculations(business_id);
CREATE INDEX idx_tax_calc_transaction ON tax_calculations(transaction_type, transaction_id);
CREATE INDEX idx_tax_calc_jurisdiction ON tax_calculations(jurisdiction);

-- ============================================================================
-- CASH FLOW FORECASTING
-- ============================================================================

-- Cash Flow Forecasts
CREATE TABLE IF NOT EXISTS cash_flow_forecasts (
    id TEXT PRIMARY KEY,
    business_id TEXT NOT NULL,
    forecast_date TEXT NOT NULL,
    forecast_period_days INTEGER NOT NULL, -- Usually 90
    opening_balance REAL NOT NULL,
    projected_inflows REAL NOT NULL,
    projected_outflows REAL NOT NULL,
    closing_balance REAL NOT NULL,
    scenario TEXT DEFAULT 'base' CHECK (scenario IN ('best', 'base', 'worst')),
    confidence_level REAL, -- ML model confidence
    forecast_method TEXT, -- 'ml_model', 'historical_average', 'linear_regression'
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (business_id) REFERENCES businesses(id)
);

CREATE INDEX idx_cashflow_forecast_business ON cash_flow_forecasts(business_id);
CREATE INDEX idx_cashflow_forecast_date ON cash_flow_forecasts(forecast_date);

-- Daily Cash Flow Projections
CREATE TABLE IF NOT EXISTS cash_flow_projections (
    id TEXT PRIMARY KEY,
    forecast_id TEXT NOT NULL,
    projection_date TEXT NOT NULL,
    day_number INTEGER NOT NULL, -- 1-90
    opening_balance REAL NOT NULL,
    expected_inflows REAL NOT NULL,
    expected_outflows REAL NOT NULL,
    closing_balance REAL NOT NULL,
    inflow_sources TEXT, -- JSON: breakdown by source
    outflow_categories TEXT, -- JSON: breakdown by category
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (forecast_id) REFERENCES cash_flow_forecasts(id) ON DELETE CASCADE
);

CREATE INDEX idx_cashflow_proj_forecast ON cash_flow_projections(forecast_id);
CREATE INDEX idx_cashflow_proj_date ON cash_flow_projections(projection_date);

-- ============================================================================
-- ANOMALY DETECTION
-- ============================================================================

-- Financial Anomalies
CREATE TABLE IF NOT EXISTS financial_anomalies (
    id TEXT PRIMARY KEY,
    business_id TEXT NOT NULL,
    anomaly_type TEXT NOT NULL CHECK (anomaly_type IN ('unusual_transaction', 'duplicate_transaction', 'fraud_risk', 'data_inconsistency', 'unusual_pattern')),
    severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    entity_type TEXT NOT NULL, -- 'invoice', 'expense', 'journal_entry', 'bank_transaction'
    entity_id TEXT NOT NULL,
    detected_at TEXT NOT NULL,
    detection_method TEXT, -- 'ml_model', 'rule_based', 'statistical'
    anomaly_score REAL NOT NULL CHECK (anomaly_score >= 0 AND anomaly_score <= 1),
    description TEXT NOT NULL,
    expected_value REAL,
    actual_value REAL,
    deviation_percent REAL,
    status TEXT DEFAULT 'open' CHECK (status IN ('open', 'investigating', 'resolved', 'false_positive')),
    investigated_by TEXT,
    investigated_at TEXT,
    resolution_notes TEXT,
    resolved_at TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (business_id) REFERENCES businesses(id)
);

CREATE INDEX idx_anomalies_business ON financial_anomalies(business_id);
CREATE INDEX idx_anomalies_type ON financial_anomalies(anomaly_type);
CREATE INDEX idx_anomalies_severity ON financial_anomalies(severity);
CREATE INDEX idx_anomalies_status ON financial_anomalies(status);
CREATE INDEX idx_anomalies_entity ON financial_anomalies(entity_type, entity_id);

-- ============================================================================
-- MULTI-CURRENCY SUPPORT
-- ============================================================================

-- Exchange Rates
CREATE TABLE IF NOT EXISTS exchange_rates (
    id TEXT PRIMARY KEY,
    base_currency TEXT NOT NULL,
    target_currency TEXT NOT NULL,
    rate REAL NOT NULL CHECK (rate > 0),
    rate_date TEXT NOT NULL,
    source TEXT, -- 'api', 'manual', 'central_bank'
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(base_currency, target_currency, rate_date)
);

CREATE INDEX idx_exchange_rates_currencies ON exchange_rates(base_currency, target_currency);
CREATE INDEX idx_exchange_rates_date ON exchange_rates(rate_date);

-- Currency Revaluation (For unrealized gains/losses)
CREATE TABLE IF NOT EXISTS currency_revaluations (
    id TEXT PRIMARY KEY,
    business_id TEXT NOT NULL,
    revaluation_date TEXT NOT NULL,
    account_id TEXT NOT NULL,
    original_currency TEXT NOT NULL,
    original_amount REAL NOT NULL,
    base_currency TEXT NOT NULL,
    old_rate REAL NOT NULL,
    new_rate REAL NOT NULL,
    old_base_amount REAL NOT NULL,
    new_base_amount REAL NOT NULL,
    gain_loss REAL NOT NULL, -- Positive for gain, negative for loss
    journal_entry_id TEXT, -- Revaluation journal entry
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (business_id) REFERENCES businesses(id),
    FOREIGN KEY (account_id) REFERENCES chart_of_accounts(id),
    FOREIGN KEY (journal_entry_id) REFERENCES journal_entries(id)
);

CREATE INDEX idx_revaluations_business ON currency_revaluations(business_id);
CREATE INDEX idx_revaluations_date ON currency_revaluations(revaluation_date);

-- ============================================================================
-- FINANCIAL REPORTING
-- ============================================================================

-- Saved Reports
CREATE TABLE IF NOT EXISTS financial_reports (
    id TEXT PRIMARY KEY,
    business_id TEXT NOT NULL,
    report_type TEXT NOT NULL CHECK (report_type IN ('balance_sheet', 'income_statement', 'cash_flow_statement', 'trial_balance', 'general_ledger', 'aged_receivables', 'aged_payables')),
    report_name TEXT NOT NULL,
    period_start TEXT NOT NULL,
    period_end TEXT NOT NULL,
    report_data TEXT NOT NULL, -- JSON: full report structure
    pdf_url TEXT, -- R2 storage URL
    generated_at TEXT NOT NULL,
    generated_by TEXT, -- user_id or 'finance-agent'
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (business_id) REFERENCES businesses(id)
);

CREATE INDEX idx_reports_business ON financial_reports(business_id);
CREATE INDEX idx_reports_type ON financial_reports(report_type);
CREATE INDEX idx_reports_date ON financial_reports(period_end);

-- ============================================================================
-- FINANCE AGENT TASKS
-- ============================================================================

-- Finance Agent Task Queue
CREATE TABLE IF NOT EXISTS finance_agent_tasks (
    id TEXT PRIMARY KEY,
    business_id TEXT NOT NULL,
    task_type TEXT NOT NULL CHECK (task_type IN (
        'categorize_expense',
        'match_bank_transaction',
        'generate_invoice',
        'create_journal_entry',
        'calculate_tax',
        'forecast_cash_flow',
        'detect_anomaly',
        'generate_report',
        'reconcile_account',
        'update_exchange_rates'
    )),
    priority TEXT DEFAULT 'normal' CHECK (priority IN ('low', 'normal', 'high', 'critical')),
    status TEXT DEFAULT 'pending' CHECK (status IN ('pending', 'processing', 'completed', 'failed', 'requires_review')),
    input_data TEXT NOT NULL, -- JSON: task parameters
    output_data TEXT, -- JSON: task results
    confidence_score REAL, -- ML confidence (0-1)
    requires_human_review INTEGER DEFAULT 0,
    error_message TEXT,
    started_at TEXT,
    completed_at TEXT,
    execution_time_ms INTEGER, -- Performance tracking
    tokens_used INTEGER, -- AI token usage
    cost REAL, -- Task cost in USD
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (business_id) REFERENCES businesses(id)
);

CREATE INDEX idx_finance_tasks_business ON finance_agent_tasks(business_id);
CREATE INDEX idx_finance_tasks_status ON finance_agent_tasks(status);
CREATE INDEX idx_finance_tasks_type ON finance_agent_tasks(task_type);
CREATE INDEX idx_finance_tasks_review ON finance_agent_tasks(requires_human_review);
CREATE INDEX idx_finance_tasks_priority ON finance_agent_tasks(priority);

-- ============================================================================
-- AUDIT TRAIL
-- ============================================================================

-- Finance Audit Log (Immutable)
CREATE TABLE IF NOT EXISTS finance_audit_log (
    id TEXT PRIMARY KEY,
    business_id TEXT NOT NULL,
    entity_type TEXT NOT NULL, -- 'journal_entry', 'invoice', 'expense', etc.
    entity_id TEXT NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('created', 'updated', 'deleted', 'posted', 'voided', 'reconciled', 'approved', 'rejected')),
    performed_by TEXT NOT NULL, -- user_id or 'finance-agent'
    performed_at TEXT NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    old_values TEXT, -- JSON: state before change
    new_values TEXT, -- JSON: state after change
    reason TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (business_id) REFERENCES businesses(id)
);

CREATE INDEX idx_audit_business ON finance_audit_log(business_id);
CREATE INDEX idx_audit_entity ON finance_audit_log(entity_type, entity_id);
CREATE INDEX idx_audit_date ON finance_audit_log(performed_at);
CREATE INDEX idx_audit_user ON finance_audit_log(performed_by);

-- ============================================================================
-- AGENT PERFORMANCE METRICS
-- ============================================================================

-- Finance Agent Performance
CREATE TABLE IF NOT EXISTS finance_agent_metrics (
    id TEXT PRIMARY KEY,
    business_id TEXT NOT NULL,
    metric_date TEXT NOT NULL,
    tasks_completed INTEGER DEFAULT 0,
    tasks_failed INTEGER DEFAULT 0,
    avg_confidence_score REAL,
    avg_execution_time_ms INTEGER,
    human_review_rate REAL, -- Percentage requiring review
    accuracy_rate REAL, -- When human validates
    cost_per_task REAL,
    total_cost REAL,
    total_tokens_used INTEGER,
    errors_detected INTEGER,
    anomalies_found INTEGER,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (business_id) REFERENCES businesses(id),
    UNIQUE(business_id, metric_date)
);

CREATE INDEX idx_metrics_business ON finance_agent_metrics(business_id);
CREATE INDEX idx_metrics_date ON finance_agent_metrics(metric_date);

-- ============================================================================
-- INITIAL DATA: Default Chart of Accounts
-- ============================================================================

-- Note: Default COA will be inserted via application code based on business type
-- This ensures flexibility for different industries (e-commerce, SaaS, consulting, etc.)

-- ============================================================================
-- MIGRATION COMPLETE
-- ============================================================================

-- Migration validation
SELECT 'Migration 090_finance_agent.sql completed successfully' as status;
