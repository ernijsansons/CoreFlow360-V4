-- Migration: Plaid Bank Integration
-- Description: Tables for managing Plaid bank connections and transaction sync
-- Created: 2025-10-12

-- =======================
-- Plaid Bank Connections
-- =======================

-- Main bank connection record
CREATE TABLE IF NOT EXISTS plaid_connections (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  business_id TEXT NOT NULL,
  institution_id TEXT NOT NULL,
  institution_name TEXT NOT NULL,
  access_token TEXT NOT NULL,  -- Encrypted Plaid access token
  item_id TEXT NOT NULL,       -- Plaid item ID
  status TEXT NOT NULL DEFAULT 'active', -- active, error, disconnected
  error_code TEXT,
  error_message TEXT,
  consent_expiration_time TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  last_sync_at TEXT,
  metadata TEXT,  -- JSON: {logo, primary_color, url}
  FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE
);

-- Bank accounts within a connection
CREATE TABLE IF NOT EXISTS plaid_accounts (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  plaid_connection_id TEXT NOT NULL,
  plaid_account_id TEXT NOT NULL,  -- Plaid's account ID
  account_name TEXT NOT NULL,
  official_name TEXT,
  mask TEXT,  -- Last 4 digits
  type TEXT NOT NULL,  -- depository, credit, loan, investment
  subtype TEXT,  -- checking, savings, credit card, etc.
  balance_current REAL,
  balance_available REAL,
  balance_limit REAL,
  currency_code TEXT NOT NULL DEFAULT 'USD',
  sync_enabled BOOLEAN NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  last_synced_at TEXT,
  FOREIGN KEY (plaid_connection_id) REFERENCES plaid_connections(id) ON DELETE CASCADE,
  UNIQUE(plaid_connection_id, plaid_account_id)
);

-- Plaid transactions (before matching to ledger)
CREATE TABLE IF NOT EXISTS plaid_transactions (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  plaid_account_id TEXT NOT NULL,
  plaid_transaction_id TEXT NOT NULL,  -- Plaid's transaction ID
  transaction_date TEXT NOT NULL,
  authorized_date TEXT,
  amount REAL NOT NULL,  -- Positive for money out, negative for money in
  currency_code TEXT NOT NULL DEFAULT 'USD',
  name TEXT NOT NULL,  -- Merchant/description
  merchant_name TEXT,
  category TEXT,  -- JSON array: ["Food and Drink", "Restaurants"]
  category_id TEXT,
  pending BOOLEAN NOT NULL DEFAULT 0,
  payment_channel TEXT,  -- online, in store, other
  payment_meta TEXT,  -- JSON: {reference_number, ppd_id, payee, etc}
  location TEXT,  -- JSON: {address, city, region, postal_code, country, lat, lon}
  matched_ledger_entry_id TEXT,  -- Link to ledger_entries table
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (plaid_account_id) REFERENCES plaid_accounts(id) ON DELETE CASCADE,
  UNIQUE(plaid_account_id, plaid_transaction_id)
);

-- Sync history and cursor tracking
CREATE TABLE IF NOT EXISTS plaid_sync_log (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  plaid_connection_id TEXT NOT NULL,
  sync_started_at TEXT NOT NULL DEFAULT (datetime('now')),
  sync_completed_at TEXT,
  sync_status TEXT NOT NULL DEFAULT 'in_progress',  -- in_progress, success, error
  transactions_added INTEGER DEFAULT 0,
  transactions_modified INTEGER DEFAULT 0,
  transactions_removed INTEGER DEFAULT 0,
  cursor TEXT,  -- Plaid cursor for incremental sync
  error_code TEXT,
  error_message TEXT,
  FOREIGN KEY (plaid_connection_id) REFERENCES plaid_connections(id) ON DELETE CASCADE
);

-- Plaid webhooks for real-time updates
CREATE TABLE IF NOT EXISTS plaid_webhooks (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  webhook_type TEXT NOT NULL,  -- TRANSACTIONS, ITEM, etc.
  webhook_code TEXT NOT NULL,  -- SYNC_UPDATES_AVAILABLE, ERROR, etc.
  item_id TEXT NOT NULL,
  error_code TEXT,
  error_message TEXT,
  payload TEXT NOT NULL,  -- Full JSON payload
  processed BOOLEAN NOT NULL DEFAULT 0,
  received_at TEXT NOT NULL DEFAULT (datetime('now')),
  processed_at TEXT
);

-- =======================
-- Indexes for Performance
-- =======================

-- Plaid connections
CREATE INDEX idx_plaid_connections_business ON plaid_connections(business_id);
CREATE INDEX idx_plaid_connections_item ON plaid_connections(item_id);
CREATE INDEX idx_plaid_connections_status ON plaid_connections(status);

-- Plaid accounts
CREATE INDEX idx_plaid_accounts_connection ON plaid_accounts(plaid_connection_id);
CREATE INDEX idx_plaid_accounts_plaid_id ON plaid_accounts(plaid_account_id);
CREATE INDEX idx_plaid_accounts_sync_enabled ON plaid_accounts(sync_enabled);

-- Plaid transactions
CREATE INDEX idx_plaid_transactions_account ON plaid_transactions(plaid_account_id);
CREATE INDEX idx_plaid_transactions_plaid_id ON plaid_transactions(plaid_transaction_id);
CREATE INDEX idx_plaid_transactions_date ON plaid_transactions(transaction_date);
CREATE INDEX idx_plaid_transactions_pending ON plaid_transactions(pending);
CREATE INDEX idx_plaid_transactions_matched ON plaid_transactions(matched_ledger_entry_id);
CREATE INDEX idx_plaid_transactions_unmatched ON plaid_transactions(plaid_account_id, matched_ledger_entry_id)
  WHERE matched_ledger_entry_id IS NULL;

-- Sync log
CREATE INDEX idx_plaid_sync_log_connection ON plaid_sync_log(plaid_connection_id);
CREATE INDEX idx_plaid_sync_log_status ON plaid_sync_log(sync_status);
CREATE INDEX idx_plaid_sync_log_time ON plaid_sync_log(sync_started_at);

-- Webhooks
CREATE INDEX idx_plaid_webhooks_item ON plaid_webhooks(item_id);
CREATE INDEX idx_plaid_webhooks_processed ON plaid_webhooks(processed);
CREATE INDEX idx_plaid_webhooks_type_code ON plaid_webhooks(webhook_type, webhook_code);
