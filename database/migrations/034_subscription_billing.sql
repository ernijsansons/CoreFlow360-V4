-- Migration: Subscription Billing
-- Description: Recurring revenue management and subscription billing
-- Created: 2025-10-12

-- =======================
-- Subscription Plans
-- =======================

-- Subscription plan templates
CREATE TABLE IF NOT EXISTS subscription_plans (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  business_id TEXT NOT NULL,
  name TEXT NOT NULL,
  description TEXT,
  billing_period TEXT NOT NULL, -- monthly, quarterly, annually, custom
  billing_interval INTEGER NOT NULL DEFAULT 1, -- e.g., 2 for bi-monthly
  amount REAL NOT NULL,
  currency TEXT NOT NULL DEFAULT 'USD',
  trial_period_days INTEGER DEFAULT 0,
  setup_fee REAL DEFAULT 0,
  is_active BOOLEAN NOT NULL DEFAULT 1,
  metadata TEXT, -- JSON: {features, limits, etc}
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
  FOREIGN KEY (currency) REFERENCES currencies(code)
);

-- Plan pricing tiers (for usage-based billing)
CREATE TABLE IF NOT EXISTS subscription_plan_tiers (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  plan_id TEXT NOT NULL,
  tier_name TEXT NOT NULL,
  min_quantity INTEGER NOT NULL,
  max_quantity INTEGER, -- NULL for unlimited
  unit_price REAL NOT NULL,
  flat_fee REAL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (plan_id) REFERENCES subscription_plans(id) ON DELETE CASCADE
);

-- =======================
-- Subscriptions
-- =======================

-- Active subscriptions
CREATE TABLE IF NOT EXISTS subscriptions (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  business_id TEXT NOT NULL,
  customer_id TEXT NOT NULL, -- Reference to contacts/customers
  plan_id TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active', -- active, paused, cancelled, expired, trial
  current_period_start TEXT NOT NULL,
  current_period_end TEXT NOT NULL,
  trial_start TEXT,
  trial_end TEXT,
  cancelled_at TEXT,
  cancellation_reason TEXT,
  billing_day INTEGER, -- Day of month for billing (1-31)
  amount REAL NOT NULL,
  currency TEXT NOT NULL DEFAULT 'USD',
  quantity INTEGER NOT NULL DEFAULT 1, -- For seat-based or quantity-based pricing
  discount_percentage REAL DEFAULT 0,
  discount_amount REAL DEFAULT 0,
  tax_percentage REAL DEFAULT 0,
  metadata TEXT, -- JSON: custom fields
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
  FOREIGN KEY (plan_id) REFERENCES subscription_plans(id),
  FOREIGN KEY (currency) REFERENCES currencies(code)
);

-- Subscription add-ons (optional features/services)
CREATE TABLE IF NOT EXISTS subscription_addons (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  subscription_id TEXT NOT NULL,
  name TEXT NOT NULL,
  description TEXT,
  amount REAL NOT NULL,
  quantity INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (subscription_id) REFERENCES subscriptions(id) ON DELETE CASCADE
);

-- =======================
-- Subscription Invoices
-- =======================

-- Subscription-generated invoices
CREATE TABLE IF NOT EXISTS subscription_invoices (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  business_id TEXT NOT NULL,
  subscription_id TEXT NOT NULL,
  invoice_number TEXT NOT NULL,
  invoice_date TEXT NOT NULL,
  due_date TEXT NOT NULL,
  period_start TEXT NOT NULL,
  period_end TEXT NOT NULL,
  subtotal REAL NOT NULL,
  tax_amount REAL NOT NULL DEFAULT 0,
  discount_amount REAL NOT NULL DEFAULT 0,
  total REAL NOT NULL,
  currency TEXT NOT NULL DEFAULT 'USD',
  status TEXT NOT NULL DEFAULT 'draft', -- draft, sent, paid, overdue, void
  paid_at TEXT,
  payment_method TEXT, -- stripe, paypal, bank_transfer, etc
  payment_reference TEXT,
  metadata TEXT, -- JSON
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
  FOREIGN KEY (subscription_id) REFERENCES subscriptions(id),
  FOREIGN KEY (currency) REFERENCES currencies(code),
  UNIQUE(business_id, invoice_number)
);

-- Invoice line items
CREATE TABLE IF NOT EXISTS subscription_invoice_items (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  invoice_id TEXT NOT NULL,
  description TEXT NOT NULL,
  quantity REAL NOT NULL DEFAULT 1,
  unit_price REAL NOT NULL,
  amount REAL NOT NULL,
  is_addon BOOLEAN NOT NULL DEFAULT 0,
  period_start TEXT,
  period_end TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (invoice_id) REFERENCES subscription_invoices(id) ON DELETE CASCADE
);

-- =======================
-- Usage Tracking (for metered billing)
-- =======================

-- Usage records for metered features
CREATE TABLE IF NOT EXISTS subscription_usage (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  subscription_id TEXT NOT NULL,
  feature_name TEXT NOT NULL, -- e.g., "api_calls", "storage_gb", "users"
  usage_quantity REAL NOT NULL,
  usage_date TEXT NOT NULL,
  metadata TEXT, -- JSON: additional context
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (subscription_id) REFERENCES subscriptions(id) ON DELETE CASCADE
);

-- Aggregated usage summaries
CREATE TABLE IF NOT EXISTS subscription_usage_summary (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  subscription_id TEXT NOT NULL,
  feature_name TEXT NOT NULL,
  period_start TEXT NOT NULL,
  period_end TEXT NOT NULL,
  total_usage REAL NOT NULL,
  billable_amount REAL NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (subscription_id) REFERENCES subscriptions(id) ON DELETE CASCADE,
  UNIQUE(subscription_id, feature_name, period_start, period_end)
);

-- =======================
-- Revenue Recognition
-- =======================

-- Deferred revenue tracking
CREATE TABLE IF NOT EXISTS deferred_revenue (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  business_id TEXT NOT NULL,
  subscription_id TEXT,
  invoice_id TEXT,
  total_amount REAL NOT NULL,
  recognized_amount REAL NOT NULL DEFAULT 0,
  remaining_amount REAL NOT NULL,
  start_date TEXT NOT NULL,
  end_date TEXT NOT NULL,
  recognition_method TEXT NOT NULL DEFAULT 'straight_line', -- straight_line, usage_based
  currency TEXT NOT NULL DEFAULT 'USD',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
  FOREIGN KEY (subscription_id) REFERENCES subscriptions(id),
  FOREIGN KEY (invoice_id) REFERENCES subscription_invoices(id),
  FOREIGN KEY (currency) REFERENCES currencies(code)
);

-- Revenue recognition schedule
CREATE TABLE IF NOT EXISTS revenue_recognition_schedule (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  deferred_revenue_id TEXT NOT NULL,
  recognition_date TEXT NOT NULL,
  amount REAL NOT NULL,
  is_recognized BOOLEAN NOT NULL DEFAULT 0,
  ledger_entry_id TEXT, -- Link to actual ledger entry when recognized
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (deferred_revenue_id) REFERENCES deferred_revenue(id) ON DELETE CASCADE,
  FOREIGN KEY (ledger_entry_id) REFERENCES ledger_entries(id)
);

-- =======================
-- Metrics & Analytics
-- =======================

-- MRR/ARR snapshots
CREATE TABLE IF NOT EXISTS recurring_revenue_metrics (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  business_id TEXT NOT NULL,
  metric_date TEXT NOT NULL,
  mrr REAL NOT NULL DEFAULT 0, -- Monthly Recurring Revenue
  arr REAL NOT NULL DEFAULT 0, -- Annual Recurring Revenue
  active_subscriptions INTEGER NOT NULL DEFAULT 0,
  new_mrr REAL NOT NULL DEFAULT 0,
  expansion_mrr REAL NOT NULL DEFAULT 0,
  contraction_mrr REAL NOT NULL DEFAULT 0,
  churned_mrr REAL NOT NULL DEFAULT 0,
  reactivation_mrr REAL NOT NULL DEFAULT 0,
  currency TEXT NOT NULL DEFAULT 'USD',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
  FOREIGN KEY (currency) REFERENCES currencies(code),
  UNIQUE(business_id, metric_date, currency)
);

-- Customer lifetime value tracking
CREATE TABLE IF NOT EXISTS subscription_ltv (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  business_id TEXT NOT NULL,
  customer_id TEXT NOT NULL,
  total_revenue REAL NOT NULL DEFAULT 0,
  average_monthly_revenue REAL NOT NULL DEFAULT 0,
  lifetime_months INTEGER NOT NULL DEFAULT 0,
  predicted_ltv REAL NOT NULL DEFAULT 0,
  churn_probability REAL NOT NULL DEFAULT 0,
  calculation_date TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
  UNIQUE(business_id, customer_id, calculation_date)
);

-- =======================
-- Indexes for Performance
-- =======================

-- Subscription plans
CREATE INDEX idx_subscription_plans_business ON subscription_plans(business_id);
CREATE INDEX idx_subscription_plans_active ON subscription_plans(is_active);

-- Subscriptions
CREATE INDEX idx_subscriptions_business ON subscriptions(business_id);
CREATE INDEX idx_subscriptions_customer ON subscriptions(customer_id);
CREATE INDEX idx_subscriptions_plan ON subscriptions(plan_id);
CREATE INDEX idx_subscriptions_status ON subscriptions(status);
CREATE INDEX idx_subscriptions_period_end ON subscriptions(current_period_end);
CREATE INDEX idx_subscriptions_active ON subscriptions(business_id, status)
  WHERE status = 'active';

-- Invoices
CREATE INDEX idx_subscription_invoices_business ON subscription_invoices(business_id);
CREATE INDEX idx_subscription_invoices_subscription ON subscription_invoices(subscription_id);
CREATE INDEX idx_subscription_invoices_status ON subscription_invoices(status);
CREATE INDEX idx_subscription_invoices_due_date ON subscription_invoices(due_date);
CREATE INDEX idx_subscription_invoices_unpaid ON subscription_invoices(business_id, status)
  WHERE status IN ('sent', 'overdue');

-- Usage tracking
CREATE INDEX idx_subscription_usage_subscription ON subscription_usage(subscription_id);
CREATE INDEX idx_subscription_usage_date ON subscription_usage(usage_date);
CREATE INDEX idx_subscription_usage_feature ON subscription_usage(feature_name);

-- Deferred revenue
CREATE INDEX idx_deferred_revenue_business ON deferred_revenue(business_id);
CREATE INDEX idx_deferred_revenue_subscription ON deferred_revenue(subscription_id);
CREATE INDEX idx_deferred_revenue_dates ON deferred_revenue(start_date, end_date);

-- Revenue recognition schedule
CREATE INDEX idx_revenue_schedule_deferred ON revenue_recognition_schedule(deferred_revenue_id);
CREATE INDEX idx_revenue_schedule_date ON revenue_recognition_schedule(recognition_date);
CREATE INDEX idx_revenue_schedule_pending ON revenue_recognition_schedule(recognition_date, is_recognized)
  WHERE is_recognized = 0;

-- Metrics
CREATE INDEX idx_recurring_revenue_metrics_business ON recurring_revenue_metrics(business_id);
CREATE INDEX idx_recurring_revenue_metrics_date ON recurring_revenue_metrics(metric_date);
