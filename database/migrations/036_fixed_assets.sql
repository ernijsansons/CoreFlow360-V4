-- Migration: Fixed Assets Management
-- Description: Asset tracking, depreciation, and disposal
-- Created: 2025-10-12

-- =======================
-- Asset Categories
-- =======================

CREATE TABLE IF NOT EXISTS asset_categories (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  business_id TEXT NOT NULL,
  name TEXT NOT NULL,
  description TEXT,
  default_useful_life_years INTEGER,
  default_depreciation_method TEXT DEFAULT 'straight_line',
  default_salvage_value_percent REAL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
  UNIQUE(business_id, name)
);

-- =======================
-- Fixed Assets
-- =======================

CREATE TABLE IF NOT EXISTS fixed_assets (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  business_id TEXT NOT NULL,
  category_id TEXT NOT NULL,
  asset_number TEXT NOT NULL,
  name TEXT NOT NULL,
  description TEXT,
  purchase_date TEXT NOT NULL,
  purchase_cost REAL NOT NULL,
  currency TEXT NOT NULL DEFAULT 'USD',
  salvage_value REAL NOT NULL DEFAULT 0,
  useful_life_years INTEGER NOT NULL,
  depreciation_method TEXT NOT NULL DEFAULT 'straight_line',
  status TEXT NOT NULL DEFAULT 'active',
  location TEXT,
  serial_number TEXT,
  vendor_id TEXT,
  warranty_expiry_date TEXT,
  maintenance_schedule TEXT,
  disposal_date TEXT,
  disposal_amount REAL,
  disposal_method TEXT,
  accumulated_depreciation REAL NOT NULL DEFAULT 0,
  book_value REAL NOT NULL,
  metadata TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
  FOREIGN KEY (category_id) REFERENCES asset_categories(id),
  FOREIGN KEY (currency) REFERENCES currencies(code),
  UNIQUE(business_id, asset_number)
);

-- =======================
-- Depreciation Schedule
-- =======================

CREATE TABLE IF NOT EXISTS depreciation_schedule (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  asset_id TEXT NOT NULL,
  period_date TEXT NOT NULL,
  depreciation_amount REAL NOT NULL,
  accumulated_depreciation REAL NOT NULL,
  book_value REAL NOT NULL,
  is_recorded BOOLEAN NOT NULL DEFAULT 0,
  ledger_entry_id TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (asset_id) REFERENCES fixed_assets(id) ON DELETE CASCADE,
  FOREIGN KEY (ledger_entry_id) REFERENCES ledger_entries(id),
  UNIQUE(asset_id, period_date)
);

-- =======================
-- Asset Maintenance
-- =======================

CREATE TABLE IF NOT EXISTS asset_maintenance (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  asset_id TEXT NOT NULL,
  maintenance_type TEXT NOT NULL,
  maintenance_date TEXT NOT NULL,
  cost REAL NOT NULL DEFAULT 0,
  description TEXT NOT NULL,
  performed_by TEXT,
  next_maintenance_date TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (asset_id) REFERENCES fixed_assets(id) ON DELETE CASCADE
);

-- =======================
-- Asset Transfers
-- =======================

CREATE TABLE IF NOT EXISTS asset_transfers (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  asset_id TEXT NOT NULL,
  from_location TEXT NOT NULL,
  to_location TEXT NOT NULL,
  transfer_date TEXT NOT NULL,
  transferred_by TEXT,
  reason TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (asset_id) REFERENCES fixed_assets(id) ON DELETE CASCADE
);

-- =======================
-- Indexes
-- =======================

CREATE INDEX idx_asset_categories_business ON asset_categories(business_id);
CREATE INDEX idx_fixed_assets_business ON fixed_assets(business_id);
CREATE INDEX idx_fixed_assets_category ON fixed_assets(category_id);
CREATE INDEX idx_fixed_assets_status ON fixed_assets(status);
CREATE INDEX idx_fixed_assets_purchase_date ON fixed_assets(purchase_date);
CREATE INDEX idx_depreciation_schedule_asset ON depreciation_schedule(asset_id);
CREATE INDEX idx_depreciation_schedule_date ON depreciation_schedule(period_date);
CREATE INDEX idx_depreciation_schedule_pending ON depreciation_schedule(period_date, is_recorded) WHERE is_recorded = 0;
CREATE INDEX idx_asset_maintenance_asset ON asset_maintenance(asset_id);
CREATE INDEX idx_asset_transfers_asset ON asset_transfers(asset_id);

-- =======================
-- Seed Data: Common Categories
-- =======================

INSERT INTO asset_categories (business_id, name, default_useful_life_years, default_depreciation_method) VALUES
  ('default-business-id', 'Computer Equipment', 3, 'straight_line'),
  ('default-business-id', 'Office Furniture', 7, 'straight_line'),
  ('default-business-id', 'Vehicles', 5, 'declining_balance'),
  ('default-business-id', 'Buildings', 39, 'straight_line'),
  ('default-business-id', 'Machinery', 10, 'units_of_production'),
  ('default-business-id', 'Software', 3, 'straight_line')
ON CONFLICT DO NOTHING;
