-- Migration: Revenue Recognition (ASC 606)
-- Description: Compliant revenue recognition with performance obligations
-- Created: 2025-10-12

-- =======================
-- Contracts
-- =======================

-- Customer contracts
CREATE TABLE IF NOT EXISTS revenue_contracts (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  business_id TEXT NOT NULL,
  customer_id TEXT NOT NULL,
  contract_number TEXT NOT NULL,
  contract_date TEXT NOT NULL,
  start_date TEXT NOT NULL,
  end_date TEXT,
  total_contract_value REAL NOT NULL,
  currency TEXT NOT NULL DEFAULT 'USD',
  status TEXT NOT NULL DEFAULT 'active', -- active, completed, cancelled, amended
  parent_contract_id TEXT, -- For amendments
  recognition_method TEXT NOT NULL DEFAULT 'over_time', -- over_time, point_in_time
  metadata TEXT, -- JSON
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
  FOREIGN KEY (parent_contract_id) REFERENCES revenue_contracts(id),
  FOREIGN KEY (currency) REFERENCES currencies(code),
  UNIQUE(business_id, contract_number)
);

-- =======================
-- Performance Obligations
-- =======================

-- ASC 606 Step 2: Identify performance obligations
CREATE TABLE IF NOT EXISTS performance_obligations (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  contract_id TEXT NOT NULL,
  obligation_number INTEGER NOT NULL,
  description TEXT NOT NULL,
  standalone_selling_price REAL NOT NULL, -- Step 3: Transaction price allocation
  allocated_amount REAL NOT NULL,
  status TEXT NOT NULL DEFAULT 'unsatisfied', -- unsatisfied, partially_satisfied, satisfied
  satisfaction_type TEXT NOT NULL DEFAULT 'over_time', -- over_time, point_in_time
  start_date TEXT NOT NULL,
  end_date TEXT,
  percent_complete REAL NOT NULL DEFAULT 0,
  recognition_method TEXT NOT NULL DEFAULT 'straight_line', -- straight_line, units_of_delivery, milestones
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (contract_id) REFERENCES revenue_contracts(id) ON DELETE CASCADE,
  UNIQUE(contract_id, obligation_number)
);

-- Milestones for milestone-based recognition
CREATE TABLE IF NOT EXISTS obligation_milestones (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  obligation_id TEXT NOT NULL,
  milestone_name TEXT NOT NULL,
  milestone_date TEXT,
  expected_date TEXT NOT NULL,
  revenue_amount REAL NOT NULL,
  is_achieved BOOLEAN NOT NULL DEFAULT 0,
  achieved_date TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (obligation_id) REFERENCES performance_obligations(id) ON DELETE CASCADE
);

-- Units of delivery tracking
CREATE TABLE IF NOT EXISTS obligation_units (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  obligation_id TEXT NOT NULL,
  unit_type TEXT NOT NULL, -- hours, units, licenses, etc.
  total_units REAL NOT NULL,
  delivered_units REAL NOT NULL DEFAULT 0,
  unit_price REAL NOT NULL,
  delivery_date TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (obligation_id) REFERENCES performance_obligations(id) ON DELETE CASCADE
);

-- =======================
-- Revenue Recognition Schedule
-- =======================

-- Recognized revenue transactions
CREATE TABLE IF NOT EXISTS recognized_revenue (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  business_id TEXT NOT NULL,
  contract_id TEXT NOT NULL,
  obligation_id TEXT,
  recognition_date TEXT NOT NULL,
  amount REAL NOT NULL,
  currency TEXT NOT NULL DEFAULT 'USD',
  recognition_basis TEXT NOT NULL, -- time_elapsed, milestone, units_delivered
  ledger_entry_id TEXT, -- Link to actual journal entry
  is_reversed BOOLEAN NOT NULL DEFAULT 0,
  reversal_reason TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
  FOREIGN KEY (contract_id) REFERENCES revenue_contracts(id),
  FOREIGN KEY (obligation_id) REFERENCES performance_obligations(id),
  FOREIGN KEY (ledger_entry_id) REFERENCES ledger_entries(id),
  FOREIGN KEY (currency) REFERENCES currencies(code)
);

-- Future recognition schedule
CREATE TABLE IF NOT EXISTS revenue_schedule (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  obligation_id TEXT NOT NULL,
  scheduled_date TEXT NOT NULL,
  scheduled_amount REAL NOT NULL,
  is_recognized BOOLEAN NOT NULL DEFAULT 0,
  recognized_date TEXT,
  recognized_revenue_id TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (obligation_id) REFERENCES performance_obligations(id) ON DELETE CASCADE,
  FOREIGN KEY (recognized_revenue_id) REFERENCES recognized_revenue(id)
);

-- =======================
-- Contract Modifications
-- =======================

-- Track contract amendments and modifications
CREATE TABLE IF NOT EXISTS contract_modifications (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  original_contract_id TEXT NOT NULL,
  new_contract_id TEXT NOT NULL,
  modification_date TEXT NOT NULL,
  modification_type TEXT NOT NULL, -- amendment, termination, extension
  reason TEXT NOT NULL,
  impact_on_revenue REAL NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (original_contract_id) REFERENCES revenue_contracts(id),
  FOREIGN KEY (new_contract_id) REFERENCES revenue_contracts(id)
);

-- =======================
-- Variable Consideration
-- =======================

-- ASC 606 Step 3: Variable consideration (discounts, rebates, refunds, etc.)
CREATE TABLE IF NOT EXISTS variable_consideration (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  contract_id TEXT NOT NULL,
  obligation_id TEXT,
  consideration_type TEXT NOT NULL, -- discount, rebate, bonus, penalty, refund
  estimated_amount REAL NOT NULL,
  actual_amount REAL,
  constraint_method TEXT NOT NULL DEFAULT 'most_likely', -- most_likely, expected_value
  is_constrained BOOLEAN NOT NULL DEFAULT 0,
  recognition_date TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (contract_id) REFERENCES revenue_contracts(id) ON DELETE CASCADE,
  FOREIGN KEY (obligation_id) REFERENCES performance_obligations(id)
);

-- =======================
-- Contract Costs
-- =======================

-- Costs to obtain and fulfill contracts (ASC 340-40)
CREATE TABLE IF NOT EXISTS contract_costs (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  business_id TEXT NOT NULL,
  contract_id TEXT NOT NULL,
  cost_type TEXT NOT NULL, -- obtain, fulfill
  cost_category TEXT NOT NULL, -- sales_commission, setup, onboarding, etc.
  total_cost REAL NOT NULL,
  amortization_period_months INTEGER NOT NULL,
  amortized_amount REAL NOT NULL DEFAULT 0,
  remaining_amount REAL NOT NULL,
  start_date TEXT NOT NULL,
  end_date TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
  FOREIGN KEY (contract_id) REFERENCES revenue_contracts(id)
);

-- Amortization schedule for contract costs
CREATE TABLE IF NOT EXISTS contract_cost_amortization (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  contract_cost_id TEXT NOT NULL,
  period_date TEXT NOT NULL,
  amortization_amount REAL NOT NULL,
  is_recorded BOOLEAN NOT NULL DEFAULT 0,
  ledger_entry_id TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (contract_cost_id) REFERENCES contract_costs(id) ON DELETE CASCADE,
  FOREIGN KEY (ledger_entry_id) REFERENCES ledger_entries(id)
);

-- =======================
-- Disclosure Requirements
-- =======================

-- ASC 606 disclosure data
CREATE TABLE IF NOT EXISTS revenue_disclosures (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  business_id TEXT NOT NULL,
  disclosure_period TEXT NOT NULL, -- YYYY-MM format
  revenue_by_category TEXT NOT NULL, -- JSON: revenue breakdown
  remaining_performance_obligations REAL NOT NULL,
  contract_balances TEXT NOT NULL, -- JSON: contract assets/liabilities
  significant_judgments TEXT, -- JSON: judgment disclosures
  costs_to_obtain_fulfill REAL NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
  UNIQUE(business_id, disclosure_period)
);

-- =======================
-- Indexes for Performance
-- =======================

-- Contracts
CREATE INDEX idx_revenue_contracts_business ON revenue_contracts(business_id);
CREATE INDEX idx_revenue_contracts_customer ON revenue_contracts(customer_id);
CREATE INDEX idx_revenue_contracts_status ON revenue_contracts(status);
CREATE INDEX idx_revenue_contracts_dates ON revenue_contracts(start_date, end_date);

-- Performance obligations
CREATE INDEX idx_performance_obligations_contract ON performance_obligations(contract_id);
CREATE INDEX idx_performance_obligations_status ON performance_obligations(status);
CREATE INDEX idx_performance_obligations_dates ON performance_obligations(start_date, end_date);

-- Recognized revenue
CREATE INDEX idx_recognized_revenue_business ON recognized_revenue(business_id);
CREATE INDEX idx_recognized_revenue_contract ON recognized_revenue(contract_id);
CREATE INDEX idx_recognized_revenue_obligation ON recognized_revenue(obligation_id);
CREATE INDEX idx_recognized_revenue_date ON recognized_revenue(recognition_date);

-- Revenue schedule
CREATE INDEX idx_revenue_schedule_obligation ON revenue_schedule(obligation_id);
CREATE INDEX idx_revenue_schedule_date ON revenue_schedule(scheduled_date);
CREATE INDEX idx_revenue_schedule_pending ON revenue_schedule(scheduled_date, is_recognized)
  WHERE is_recognized = 0;

-- Variable consideration
CREATE INDEX idx_variable_consideration_contract ON variable_consideration(contract_id);
CREATE INDEX idx_variable_consideration_obligation ON variable_consideration(obligation_id);

-- Contract costs
CREATE INDEX idx_contract_costs_business ON contract_costs(business_id);
CREATE INDEX idx_contract_costs_contract ON contract_costs(contract_id);
CREATE INDEX idx_contract_costs_dates ON contract_costs(start_date, end_date);

-- Cost amortization
CREATE INDEX idx_contract_cost_amortization_cost ON contract_cost_amortization(contract_cost_id);
CREATE INDEX idx_contract_cost_amortization_date ON contract_cost_amortization(period_date);
CREATE INDEX idx_contract_cost_amortization_pending ON contract_cost_amortization(period_date, is_recorded)
  WHERE is_recorded = 0;

-- Disclosures
CREATE INDEX idx_revenue_disclosures_business ON revenue_disclosures(business_id);
CREATE INDEX idx_revenue_disclosures_period ON revenue_disclosures(disclosure_period);
