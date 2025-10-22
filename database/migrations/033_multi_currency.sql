-- Migration: Multi-Currency Accounting
-- Description: Support for multiple currencies with real-time exchange rates
-- Created: 2025-10-12

-- =======================
-- Currency Configuration
-- =======================

-- Supported currencies
CREATE TABLE IF NOT EXISTS currencies (
  code TEXT PRIMARY KEY,  -- ISO 4217 (USD, EUR, GBP, etc.)
  name TEXT NOT NULL,
  symbol TEXT NOT NULL,
  decimal_places INTEGER NOT NULL DEFAULT 2,
  is_active BOOLEAN NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Business currency preferences
CREATE TABLE IF NOT EXISTS business_currencies (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  business_id TEXT NOT NULL,
  base_currency TEXT NOT NULL DEFAULT 'USD',  -- Reporting currency
  functional_currency TEXT NOT NULL DEFAULT 'USD',  -- Operating currency
  allowed_currencies TEXT NOT NULL DEFAULT '["USD"]',  -- JSON array of allowed currencies
  auto_conversion BOOLEAN NOT NULL DEFAULT 1,  -- Auto-convert to base currency
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
  FOREIGN KEY (base_currency) REFERENCES currencies(code),
  FOREIGN KEY (functional_currency) REFERENCES currencies(code),
  UNIQUE(business_id)
);

-- =======================
-- Exchange Rates
-- =======================

-- Real-time exchange rates
CREATE TABLE IF NOT EXISTS exchange_rates (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  from_currency TEXT NOT NULL,
  to_currency TEXT NOT NULL,
  rate REAL NOT NULL,
  inverse_rate REAL NOT NULL,  -- Cached inverse for performance
  source TEXT NOT NULL,  -- API source (ecb, openexchangerates, etc.)
  valid_from TEXT NOT NULL,
  valid_to TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (from_currency) REFERENCES currencies(code),
  FOREIGN KEY (to_currency) REFERENCES currencies(code),
  UNIQUE(from_currency, to_currency, valid_from)
);

-- Historical exchange rates for audit trail
CREATE TABLE IF NOT EXISTS exchange_rate_history (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  from_currency TEXT NOT NULL,
  to_currency TEXT NOT NULL,
  rate REAL NOT NULL,
  rate_date TEXT NOT NULL,
  source TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (from_currency) REFERENCES currencies(code),
  FOREIGN KEY (to_currency) REFERENCES currencies(code)
);

-- =======================
-- Multi-Currency Transactions
-- =======================

-- Enhanced ledger entries with currency support
-- (Extends existing ledger_entries table)
ALTER TABLE ledger_entries ADD COLUMN currency TEXT DEFAULT 'USD';
ALTER TABLE ledger_entries ADD COLUMN original_amount REAL;
ALTER TABLE ledger_entries ADD COLUMN original_currency TEXT;
ALTER TABLE ledger_entries ADD COLUMN exchange_rate REAL;
ALTER TABLE ledger_entries ADD COLUMN exchange_rate_date TEXT;

-- Multi-currency transaction amounts
CREATE TABLE IF NOT EXISTS multi_currency_amounts (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  ledger_entry_id TEXT NOT NULL,
  currency TEXT NOT NULL,
  amount REAL NOT NULL,
  exchange_rate REAL NOT NULL,
  base_currency_amount REAL NOT NULL,  -- Converted to base currency
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (ledger_entry_id) REFERENCES ledger_entries(id) ON DELETE CASCADE,
  FOREIGN KEY (currency) REFERENCES currencies(code)
);

-- Currency gains/losses tracking
CREATE TABLE IF NOT EXISTS currency_gains_losses (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  business_id TEXT NOT NULL,
  ledger_entry_id TEXT,
  currency TEXT NOT NULL,
  realized_gain_loss REAL NOT NULL DEFAULT 0,  -- Actual gain/loss on settlement
  unrealized_gain_loss REAL NOT NULL DEFAULT 0,  -- Valuation gain/loss
  calculation_date TEXT NOT NULL,
  original_rate REAL NOT NULL,
  current_rate REAL NOT NULL,
  original_amount REAL NOT NULL,
  description TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
  FOREIGN KEY (ledger_entry_id) REFERENCES ledger_entries(id) ON DELETE SET NULL,
  FOREIGN KEY (currency) REFERENCES currencies(code)
);

-- =======================
-- Multi-Currency Accounts
-- =======================

-- Enhanced accounts table for currency support
ALTER TABLE accounts ADD COLUMN currency TEXT DEFAULT 'USD';
ALTER TABLE accounts ADD COLUMN is_multi_currency BOOLEAN DEFAULT 0;
ALTER TABLE accounts ADD COLUMN allowed_currencies TEXT;  -- JSON array

-- Account balance snapshots in multiple currencies
CREATE TABLE IF NOT EXISTS account_balance_multi_currency (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  account_id TEXT NOT NULL,
  currency TEXT NOT NULL,
  balance REAL NOT NULL,
  base_currency_balance REAL NOT NULL,  -- Converted to base currency
  exchange_rate REAL NOT NULL,
  snapshot_date TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE,
  FOREIGN KEY (currency) REFERENCES currencies(code),
  UNIQUE(account_id, currency, snapshot_date)
);

-- =======================
-- Indexes for Performance
-- =======================

-- Currency configuration
CREATE INDEX idx_currencies_active ON currencies(is_active);

-- Business currencies
CREATE INDEX idx_business_currencies_business ON business_currencies(business_id);
CREATE INDEX idx_business_currencies_base ON business_currencies(base_currency);

-- Exchange rates
CREATE INDEX idx_exchange_rates_pair ON exchange_rates(from_currency, to_currency);
CREATE INDEX idx_exchange_rates_valid_from ON exchange_rates(valid_from);
CREATE INDEX idx_exchange_rates_current ON exchange_rates(from_currency, to_currency, valid_from)
  WHERE valid_to IS NULL;

-- Exchange rate history
CREATE INDEX idx_exchange_rate_history_pair ON exchange_rate_history(from_currency, to_currency);
CREATE INDEX idx_exchange_rate_history_date ON exchange_rate_history(rate_date);

-- Multi-currency amounts
CREATE INDEX idx_multi_currency_amounts_entry ON multi_currency_amounts(ledger_entry_id);
CREATE INDEX idx_multi_currency_amounts_currency ON multi_currency_amounts(currency);

-- Currency gains/losses
CREATE INDEX idx_currency_gains_losses_business ON currency_gains_losses(business_id);
CREATE INDEX idx_currency_gains_losses_entry ON currency_gains_losses(ledger_entry_id);
CREATE INDEX idx_currency_gains_losses_date ON currency_gains_losses(calculation_date);
CREATE INDEX idx_currency_gains_losses_currency ON currency_gains_losses(currency);

-- Account balances
CREATE INDEX idx_account_balance_mc_account ON account_balance_multi_currency(account_id);
CREATE INDEX idx_account_balance_mc_currency ON account_balance_multi_currency(currency);
CREATE INDEX idx_account_balance_mc_date ON account_balance_multi_currency(snapshot_date);

-- =======================
-- Seed Data: Common Currencies
-- =======================

INSERT INTO currencies (code, name, symbol, decimal_places) VALUES
  ('USD', 'US Dollar', '$', 2),
  ('EUR', 'Euro', '€', 2),
  ('GBP', 'British Pound', '£', 2),
  ('JPY', 'Japanese Yen', '¥', 0),
  ('CAD', 'Canadian Dollar', 'CA$', 2),
  ('AUD', 'Australian Dollar', 'A$', 2),
  ('CHF', 'Swiss Franc', 'CHF', 2),
  ('CNY', 'Chinese Yuan', '¥', 2),
  ('INR', 'Indian Rupee', '₹', 2),
  ('MXN', 'Mexican Peso', 'MX$', 2),
  ('BRL', 'Brazilian Real', 'R$', 2),
  ('ZAR', 'South African Rand', 'R', 2),
  ('SGD', 'Singapore Dollar', 'S$', 2),
  ('HKD', 'Hong Kong Dollar', 'HK$', 2),
  ('NZD', 'New Zealand Dollar', 'NZ$', 2),
  ('SEK', 'Swedish Krona', 'kr', 2),
  ('NOK', 'Norwegian Krone', 'kr', 2),
  ('DKK', 'Danish Krone', 'kr', 2),
  ('PLN', 'Polish Zloty', 'zł', 2),
  ('THB', 'Thai Baht', '฿', 2),
  ('IDR', 'Indonesian Rupiah', 'Rp', 0),
  ('MYR', 'Malaysian Ringgit', 'RM', 2),
  ('PHP', 'Philippine Peso', '₱', 2),
  ('KRW', 'South Korean Won', '₩', 0),
  ('TRY', 'Turkish Lira', '₺', 2),
  ('RUB', 'Russian Ruble', '₽', 2),
  ('AED', 'UAE Dirham', 'د.إ', 2),
  ('SAR', 'Saudi Riyal', '﷼', 2),
  ('ILS', 'Israeli Shekel', '₪', 2),
  ('CZK', 'Czech Koruna', 'Kč', 2)
ON CONFLICT(code) DO NOTHING;
