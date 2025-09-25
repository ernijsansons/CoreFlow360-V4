-- Optimized schema with proper indexes
CREATE TABLE IF NOT EXISTS businesses (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  settings JSON,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_businesses_created ON businesses(created_at);

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  business_id TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  role TEXT NOT NULL,
  settings JSON,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (business_id) REFERENCES businesses(id)
);

CREATE INDEX idx_users_business ON users(business_id);
CREATE INDEX idx_users_email ON users(email);

-- Optimized ledger table
CREATE TABLE IF NOT EXISTS ledger_entries (
  id TEXT PRIMARY KEY,
  business_id TEXT NOT NULL,
  account_id TEXT NOT NULL,
  amount REAL NOT NULL,
  type TEXT CHECK(type IN ('debit', 'credit')),
  description TEXT,
  metadata JSON,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (business_id) REFERENCES businesses(id)
);

CREATE INDEX idx_ledger_business_date ON ledger_entries(business_id, created_at);
CREATE INDEX idx_ledger_account ON ledger_entries(account_id);

-- Audit table (write-only, optimized for inserts)
CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  business_id TEXT NOT NULL,
  user_id TEXT,
  action TEXT NOT NULL,
  resource TEXT,
  metadata JSON,
  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
) WITHOUT ROWID;

CREATE INDEX idx_audit_business_time ON audit_log(business_id, timestamp);