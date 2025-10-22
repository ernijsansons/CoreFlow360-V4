-- ================================================
-- Document Processing & OCR System
-- Migration 030 - OCR document processing
-- ================================================

-- Processed documents table (OCR results)
CREATE TABLE IF NOT EXISTS processed_documents (
  id TEXT PRIMARY KEY,
  business_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  document_type TEXT NOT NULL CHECK (document_type IN ('invoice', 'receipt', 'bill', 'unknown')),
  original_filename TEXT NOT NULL,
  confidence_score INTEGER NOT NULL DEFAULT 0,
  extracted_data TEXT NOT NULL, -- JSON
  raw_text TEXT NOT NULL,
  file_url TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),

  FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_processed_documents_business ON processed_documents(business_id);
CREATE INDEX IF NOT EXISTS idx_processed_documents_type ON processed_documents(document_type);
CREATE INDEX IF NOT EXISTS idx_processed_documents_created ON processed_documents(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_processed_documents_confidence ON processed_documents(confidence_score);

-- Bank connections table
CREATE TABLE IF NOT EXISTS bank_connections (
  id TEXT PRIMARY KEY,
  business_id TEXT NOT NULL,
  plaid_item_id TEXT NOT NULL UNIQUE,
  plaid_access_token TEXT NOT NULL,
  institution_id TEXT NOT NULL,
  institution_name TEXT NOT NULL,
  accounts TEXT NOT NULL, -- JSON array of connected accounts
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'error')),
  last_synced_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),

  FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_bank_connections_business ON bank_connections(business_id);
CREATE INDEX IF NOT EXISTS idx_bank_connections_plaid_item ON bank_connections(plaid_item_id);

-- Bank transactions table (imported from bank)
CREATE TABLE IF NOT EXISTS bank_transactions (
  id TEXT PRIMARY KEY,
  business_id TEXT NOT NULL,
  connection_id TEXT NOT NULL,
  plaid_transaction_id TEXT NOT NULL UNIQUE,
  account_id TEXT NOT NULL,
  amount REAL NOT NULL,
  currency TEXT NOT NULL DEFAULT 'USD',
  transaction_date TEXT NOT NULL,
  description TEXT NOT NULL,
  merchant_name TEXT,
  category TEXT,
  pending INTEGER NOT NULL DEFAULT 0,
  matched_invoice_id TEXT,
  matched_expense_id TEXT,
  matched_at TEXT,
  status TEXT NOT NULL DEFAULT 'unmatched' CHECK (status IN ('unmatched', 'matched', 'ignored', 'review')),
  confidence_score INTEGER DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),

  FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
  FOREIGN KEY (connection_id) REFERENCES bank_connections(id) ON DELETE CASCADE,
  FOREIGN KEY (matched_invoice_id) REFERENCES invoices(id) ON DELETE SET NULL,
  FOREIGN KEY (matched_expense_id) REFERENCES expenses(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_bank_transactions_business ON bank_transactions(business_id);
CREATE INDEX IF NOT EXISTS idx_bank_transactions_connection ON bank_transactions(connection_id);
CREATE INDEX IF NOT EXISTS idx_bank_transactions_date ON bank_transactions(transaction_date DESC);
CREATE INDEX IF NOT EXISTS idx_bank_transactions_status ON bank_transactions(status);
CREATE INDEX IF NOT EXISTS idx_bank_transactions_plaid ON bank_transactions(plaid_transaction_id);

-- Transaction matching rules (AI-learned patterns)
CREATE TABLE IF NOT EXISTS transaction_matching_rules (
  id TEXT PRIMARY KEY,
  business_id TEXT NOT NULL,
  rule_type TEXT NOT NULL CHECK (rule_type IN ('pattern', 'amount', 'date', 'merchant', 'category')),
  pattern TEXT NOT NULL,
  target_type TEXT NOT NULL CHECK (target_type IN ('invoice', 'expense', 'customer', 'vendor')),
  target_id TEXT,
  confidence_threshold INTEGER NOT NULL DEFAULT 80,
  auto_match INTEGER NOT NULL DEFAULT 0,
  match_count INTEGER NOT NULL DEFAULT 0,
  last_matched_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),

  FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_matching_rules_business ON transaction_matching_rules(business_id);
CREATE INDEX IF NOT EXISTS idx_matching_rules_type ON transaction_matching_rules(rule_type);

-- Anomaly detection log
CREATE TABLE IF NOT EXISTS transaction_anomalies (
  id TEXT PRIMARY KEY,
  business_id TEXT NOT NULL,
  transaction_type TEXT NOT NULL CHECK (transaction_type IN ('bank', 'invoice', 'expense', 'payment')),
  transaction_id TEXT NOT NULL,
  anomaly_type TEXT NOT NULL CHECK (anomaly_type IN ('duplicate', 'outlier', 'unusual_amount', 'suspicious_vendor', 'timing_anomaly')),
  severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
  description TEXT NOT NULL,
  details TEXT, -- JSON
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'reviewing', 'resolved', 'false_positive')),
  resolved_by TEXT,
  resolved_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),

  FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
  FOREIGN KEY (resolved_by) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_anomalies_business ON transaction_anomalies(business_id);
CREATE INDEX IF NOT EXISTS idx_anomalies_type ON transaction_anomalies(anomaly_type);
CREATE INDEX IF NOT EXISTS idx_anomalies_severity ON transaction_anomalies(severity);
CREATE INDEX IF NOT EXISTS idx_anomalies_status ON transaction_anomalies(status);

-- Purchase orders table
CREATE TABLE IF NOT EXISTS purchase_orders (
  id TEXT PRIMARY KEY,
  business_id TEXT NOT NULL,
  po_number TEXT NOT NULL,
  vendor_id TEXT,
  vendor_name TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'pending_approval', 'approved', 'sent', 'partially_received', 'received', 'cancelled')),
  order_date TEXT NOT NULL,
  expected_delivery_date TEXT,
  subtotal REAL NOT NULL DEFAULT 0,
  tax_amount REAL NOT NULL DEFAULT 0,
  shipping_amount REAL NOT NULL DEFAULT 0,
  total REAL NOT NULL DEFAULT 0,
  currency TEXT NOT NULL DEFAULT 'USD',
  shipping_address TEXT,
  notes TEXT,
  approved_by TEXT,
  approved_at TEXT,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),

  FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
  FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (approved_by) REFERENCES users(id) ON DELETE SET NULL,
  UNIQUE(business_id, po_number)
);

CREATE INDEX IF NOT EXISTS idx_purchase_orders_business ON purchase_orders(business_id);
CREATE INDEX IF NOT EXISTS idx_purchase_orders_status ON purchase_orders(status);
CREATE INDEX IF NOT EXISTS idx_purchase_orders_date ON purchase_orders(order_date DESC);

-- Purchase order line items
CREATE TABLE IF NOT EXISTS purchase_order_items (
  id TEXT PRIMARY KEY,
  po_id TEXT NOT NULL,
  item_number INTEGER NOT NULL,
  description TEXT NOT NULL,
  quantity REAL NOT NULL,
  unit_price REAL NOT NULL,
  amount REAL NOT NULL,
  received_quantity REAL NOT NULL DEFAULT 0,
  notes TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),

  FOREIGN KEY (po_id) REFERENCES purchase_orders(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_po_items_po ON purchase_order_items(po_id);

-- Add source_document_id to existing tables
ALTER TABLE invoices ADD COLUMN source_document_id TEXT REFERENCES processed_documents(id);
ALTER TABLE expenses ADD COLUMN source_document_id TEXT REFERENCES processed_documents(id);

-- Create indexes for new foreign keys
CREATE INDEX IF NOT EXISTS idx_invoices_source_doc ON invoices(source_document_id);
CREATE INDEX IF NOT EXISTS idx_expenses_source_doc ON expenses(source_document_id);
