-- ============================================================================
-- PAYMENT METHOD ACCOUNTS MAPPING SCHEMA
-- Tables to support mapping different payment methods to specific cash accounts
-- ============================================================================

-- Payment Methods Configuration
CREATE TABLE IF NOT EXISTS payment_methods_config (
  id TEXT PRIMARY KEY,
  method_type TEXT NOT NULL, -- 'CASH', 'CHECK', 'CREDIT_CARD', 'BANK_TRANSFER', etc.
  display_name TEXT NOT NULL,
  description TEXT,
  is_active INTEGER NOT NULL DEFAULT 1,
  requires_reference INTEGER NOT NULL DEFAULT 0, -- Whether this method requires a reference number
  processing_time_hours INTEGER DEFAULT 0, -- Expected processing time
  fees_percentage REAL DEFAULT 0, -- Processing fees as percentage
  fees_fixed_amount REAL DEFAULT 0, -- Fixed processing fees
  business_id TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,

  INDEX idx_payment_methods_business (business_id),
  INDEX idx_payment_methods_business_active (business_id, is_active) WHERE is_active = 1,
  INDEX idx_payment_methods_type (business_id, method_type)
);

-- Payment Method Account Mapping
CREATE TABLE IF NOT EXISTS payment_method_accounts (
  id TEXT PRIMARY KEY,
  payment_method_id TEXT NOT NULL,
  account_id TEXT NOT NULL, -- Points to chart_of_accounts
  is_primary INTEGER NOT NULL DEFAULT 0, -- Primary account for this payment method
  is_fees_account INTEGER NOT NULL DEFAULT 0, -- Account for processing fees
  effective_date INTEGER NOT NULL,
  expiry_date INTEGER,
  created_at INTEGER NOT NULL,
  business_id TEXT NOT NULL,

  FOREIGN KEY (payment_method_id) REFERENCES payment_methods_config(id),
  FOREIGN KEY (account_id) REFERENCES chart_of_accounts(id),
  INDEX idx_payment_method_accounts_method (payment_method_id),
  INDEX idx_payment_method_accounts_account (account_id),
  INDEX idx_payment_method_accounts_business (business_id),
  INDEX idx_payment_method_accounts_primary (payment_method_id, is_primary) WHERE is_primary = 1,
  INDEX idx_payment_method_accounts_effective (effective_date, expiry_date)
);

-- Payment Processing Rules
CREATE TABLE IF NOT EXISTS payment_processing_rules (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  payment_method_id TEXT NOT NULL,
  condition_type TEXT NOT NULL, -- 'amount_range', 'customer_type', 'currency', 'time_based'
  conditions TEXT NOT NULL, -- JSON with rule conditions
  target_account_id TEXT NOT NULL, -- Override account for this rule
  fees_account_id TEXT, -- Override fees account
  priority INTEGER NOT NULL DEFAULT 0, -- Higher priority rules are evaluated first
  is_active INTEGER NOT NULL DEFAULT 1,
  effective_date INTEGER NOT NULL,
  expiry_date INTEGER,
  created_at INTEGER NOT NULL,
  business_id TEXT NOT NULL,

  FOREIGN KEY (payment_method_id) REFERENCES payment_methods_config(id),
  FOREIGN KEY (target_account_id) REFERENCES chart_of_accounts(id),
  FOREIGN KEY (fees_account_id) REFERENCES chart_of_accounts(id),
  INDEX idx_payment_processing_rules_method (payment_method_id),
  INDEX idx_payment_processing_rules_business (business_id),
  INDEX idx_payment_processing_rules_priority (business_id, priority),
  INDEX idx_payment_processing_rules_active (business_id, is_active) WHERE is_active = 1,
  INDEX idx_payment_processing_rules_effective (effective_date, expiry_date)
);

-- Payment Gateway Configuration (for online payments)
CREATE TABLE IF NOT EXISTS payment_gateways (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL, -- 'Stripe', 'PayPal', 'Square', etc.
  gateway_type TEXT NOT NULL,
  api_endpoint TEXT,
  merchant_id TEXT,
  is_sandbox INTEGER NOT NULL DEFAULT 0,
  supported_methods TEXT NOT NULL, -- JSON array of supported payment methods
  default_account_id TEXT NOT NULL, -- Default cash account for this gateway
  fees_account_id TEXT, -- Account for gateway fees
  settlement_account_id TEXT, -- Account for settlement differences
  currency_codes TEXT, -- JSON array of supported currencies
  is_active INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  business_id TEXT NOT NULL,

  FOREIGN KEY (default_account_id) REFERENCES chart_of_accounts(id),
  FOREIGN KEY (fees_account_id) REFERENCES chart_of_accounts(id),
  FOREIGN KEY (settlement_account_id) REFERENCES chart_of_accounts(id),
  INDEX idx_payment_gateways_business (business_id),
  INDEX idx_payment_gateways_business_active (business_id, is_active) WHERE is_active = 1,
  INDEX idx_payment_gateways_type (business_id, gateway_type)
);

-- Payment Method Gateway Mapping
CREATE TABLE IF NOT EXISTS payment_method_gateways (
  id TEXT PRIMARY KEY,
  payment_method_id TEXT NOT NULL,
  gateway_id TEXT NOT NULL,
  gateway_method_code TEXT NOT NULL, -- Gateway-specific method identifier
  account_id TEXT, -- Override account for this gateway/method combination
  fees_percentage REAL DEFAULT 0, -- Gateway-specific fees
  fees_fixed_amount REAL DEFAULT 0,
  is_active INTEGER NOT NULL DEFAULT 1,
  business_id TEXT NOT NULL,

  FOREIGN KEY (payment_method_id) REFERENCES payment_methods_config(id),
  FOREIGN KEY (gateway_id) REFERENCES payment_gateways(id),
  FOREIGN KEY (account_id) REFERENCES chart_of_accounts(id),
  INDEX idx_payment_method_gateways_method (payment_method_id),
  INDEX idx_payment_method_gateways_gateway (gateway_id),
  INDEX idx_payment_method_gateways_business (business_id),
  INDEX idx_payment_method_gateways_active (business_id, is_active) WHERE is_active = 1,

  UNIQUE (payment_method_id, gateway_id, business_id)
);

-- Bank Account Configuration (for bank transfers and ACH)
CREATE TABLE IF NOT EXISTS bank_accounts (
  id TEXT PRIMARY KEY,
  account_name TEXT NOT NULL,
  bank_name TEXT NOT NULL,
  account_number TEXT NOT NULL, -- Encrypted/masked
  routing_number TEXT, -- For US accounts
  iban TEXT, -- For international accounts
  swift_code TEXT, -- For international accounts
  account_type TEXT NOT NULL, -- 'checking', 'savings', 'business'
  currency TEXT NOT NULL DEFAULT 'USD',
  chart_account_id TEXT NOT NULL, -- Linked chart of accounts entry
  is_primary INTEGER NOT NULL DEFAULT 0,
  is_active INTEGER NOT NULL DEFAULT 1,
  last_reconciliation_date INTEGER,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  business_id TEXT NOT NULL,

  FOREIGN KEY (chart_account_id) REFERENCES chart_of_accounts(id),
  INDEX idx_bank_accounts_business (business_id),
  INDEX idx_bank_accounts_business_active (business_id, is_active) WHERE is_active = 1,
  INDEX idx_bank_accounts_chart_account (chart_account_id),
  INDEX idx_bank_accounts_primary (business_id, is_primary) WHERE is_primary = 1,
  INDEX idx_bank_accounts_currency (business_id, currency)
);

-- ============================================================================
-- SAMPLE DATA FOR COMMON PAYMENT METHODS
-- ============================================================================

-- Insert standard payment methods (these can be customized per business)
INSERT OR IGNORE INTO payment_methods_config (
  id, method_type, display_name, description, is_active, requires_reference,
  processing_time_hours, fees_percentage, fees_fixed_amount, business_id,
  created_at, updated_at
) VALUES
  ('pm_cash', 'CASH', 'Cash', 'Cash payments', 1, 0, 0, 0, 0, 'system', strftime('%s', 'now') * 1000, strftime('%s', 'now') * 1000),
  ('pm_check', 'CHECK', 'Check', 'Check payments', 1, 1, 72, 0, 0, 'system', strftime('%s', 'now') * 1000, strftime('%s', 'now') * 1000),
  ('pm_credit_card', 'CREDIT_CARD', 'Credit Card', 'Credit card payments', 1, 1, 1, 2.9, 0.30, 'system', strftime('%s', 'now') * 1000, strftime('%s', 'now') * 1000),
  ('pm_debit_card', 'DEBIT_CARD', 'Debit Card', 'Debit card payments', 1, 1, 1, 1.9, 0.25, 'system', strftime('%s', 'now') * 1000, strftime('%s', 'now') * 1000),
  ('pm_bank_transfer', 'BANK_TRANSFER', 'Bank Transfer', 'Bank wire transfers', 1, 1, 24, 0, 25.00, 'system', strftime('%s', 'now') * 1000, strftime('%s', 'now') * 1000),
  ('pm_ach', 'ACH', 'ACH Transfer', 'ACH electronic transfers', 1, 1, 48, 0.5, 0, 'system', strftime('%s', 'now') * 1000, strftime('%s', 'now') * 1000),
  ('pm_paypal', 'PAYPAL', 'PayPal', 'PayPal payments', 1, 1, 1, 3.49, 0.49, 'system', strftime('%s', 'now') * 1000, strftime('%s', 'now') * 1000),
  ('pm_cryptocurrency', 'CRYPTOCURRENCY', 'Cryptocurrency', 'Digital currency payments', 1, 1, 24, 1.0, 0, 'system', strftime('%s', 'now') * 1000, strftime('%s', 'now') * 1000);

-- ============================================================================
-- TRIGGERS FOR DATA INTEGRITY
-- ============================================================================

-- Ensure only one primary account per payment method
CREATE TRIGGER IF NOT EXISTS ensure_one_primary_payment_account
BEFORE INSERT ON payment_method_accounts
FOR EACH ROW
WHEN NEW.is_primary = 1
BEGIN
  UPDATE payment_method_accounts
  SET is_primary = 0
  WHERE payment_method_id = NEW.payment_method_id
  AND business_id = NEW.business_id
  AND is_primary = 1;
END;

-- Ensure only one primary bank account per business
CREATE TRIGGER IF NOT EXISTS ensure_one_primary_bank_account
BEFORE INSERT ON bank_accounts
FOR EACH ROW
WHEN NEW.is_primary = 1
BEGIN
  UPDATE bank_accounts
  SET is_primary = 0
  WHERE business_id = NEW.business_id
  AND is_primary = 1;
END;

-- Update payment method config timestamp when accounts change
CREATE TRIGGER IF NOT EXISTS update_payment_method_on_account_change
AFTER INSERT ON payment_method_accounts
FOR EACH ROW
BEGIN
  UPDATE payment_methods_config
  SET updated_at = strftime('%s', 'now') * 1000
  WHERE id = NEW.payment_method_id;
END;

-- Validate payment processing rules JSON
CREATE TRIGGER IF NOT EXISTS validate_payment_rule_conditions
BEFORE INSERT ON payment_processing_rules
FOR EACH ROW
BEGIN
  SELECT CASE
    WHEN json_valid(NEW.conditions) = 0 THEN
      RAISE(FAIL, 'Payment processing rule conditions must be valid JSON')
  END;
END;

-- ============================================================================
-- VIEWS FOR COMMON QUERIES
-- ============================================================================

-- Payment Method Summary View
CREATE VIEW IF NOT EXISTS payment_method_summary AS
SELECT
  pmc.id as method_id,
  pmc.method_type,
  pmc.display_name,
  pmc.is_active,
  COUNT(pma.id) as mapped_accounts,
  COUNT(CASE WHEN pma.is_primary = 1 THEN 1 END) as primary_accounts,
  pmc.fees_percentage,
  pmc.fees_fixed_amount,
  pmc.business_id
FROM payment_methods_config pmc
LEFT JOIN payment_method_accounts pma ON pmc.id = pma.payment_method_id
GROUP BY pmc.id, pmc.method_type, pmc.display_name, pmc.is_active,
         pmc.fees_percentage, pmc.fees_fixed_amount, pmc.business_id;

-- Payment Account Details View
CREATE VIEW IF NOT EXISTS payment_account_details AS
SELECT
  pma.id as mapping_id,
  pmc.method_type,
  pmc.display_name as method_name,
  coa.code as account_code,
  coa.name as account_name,
  coa.type as account_type,
  pma.is_primary,
  pma.is_fees_account,
  pma.effective_date,
  pma.expiry_date,
  pma.business_id
FROM payment_method_accounts pma
INNER JOIN payment_methods_config pmc ON pma.payment_method_id = pmc.id
INNER JOIN chart_of_accounts coa ON pma.account_id = coa.id
WHERE pma.effective_date <= strftime('%s', 'now') * 1000
AND (pma.expiry_date IS NULL OR pma.expiry_date > strftime('%s', 'now') * 1000);

-- ============================================================================
-- SCHEMA VERSION TRACKING
-- ============================================================================

INSERT OR REPLACE INTO schema_versions (module, version, applied_at)
VALUES ('finance_payment_method_accounts', '1.0.0', strftime('%s', 'now') * 1000);