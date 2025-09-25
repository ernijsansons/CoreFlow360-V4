-- ============================================================================
-- PRODUCT TAX CONFIGURATION SCHEMA
-- Tables to support product-specific tax filtering and configuration
-- ============================================================================

-- Products table
CREATE TABLE IF NOT EXISTS products (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT,
  sku TEXT,
  category_id TEXT,
  tax_category TEXT, -- e.g., 'taxable', 'exempt', 'reduced_rate'
  is_active INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  business_id TEXT NOT NULL,
  metadata TEXT DEFAULT '{}',

  INDEX idx_products_business (business_id),
  INDEX idx_products_business_active (business_id, is_active) WHERE is_active = 1,
  INDEX idx_products_sku (business_id, sku) WHERE sku IS NOT NULL,
  INDEX idx_products_category (business_id, category_id) WHERE category_id IS NOT NULL,
  INDEX idx_products_tax_category (business_id, tax_category)
);

-- Product Categories table
CREATE TABLE IF NOT EXISTS product_categories (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT,
  parent_id TEXT,
  tax_category TEXT, -- Default tax category for products in this category
  is_active INTEGER NOT NULL DEFAULT 1,
  business_id TEXT NOT NULL,

  FOREIGN KEY (parent_id) REFERENCES product_categories(id),
  INDEX idx_product_categories_business (business_id),
  INDEX idx_product_categories_business_active (business_id, is_active) WHERE is_active = 1,
  INDEX idx_product_categories_parent (parent_id)
);

-- Product Tax Rate Mapping (many-to-many relationship)
CREATE TABLE IF NOT EXISTS product_tax_rates (
  id TEXT PRIMARY KEY,
  product_id TEXT,
  product_category_id TEXT,
  tax_rate_id TEXT NOT NULL,
  jurisdiction TEXT, -- Optional: specific jurisdiction for this mapping
  is_exempt INTEGER NOT NULL DEFAULT 0, -- If 1, this product is exempt from this tax
  effective_date INTEGER NOT NULL,
  expiry_date INTEGER,
  created_at INTEGER NOT NULL,
  business_id TEXT NOT NULL,

  FOREIGN KEY (product_id) REFERENCES products(id),
  FOREIGN KEY (product_category_id) REFERENCES product_categories(id),
  FOREIGN KEY (tax_rate_id) REFERENCES tax_rates(id),
  INDEX idx_product_tax_rates_product (product_id),
  INDEX idx_product_tax_rates_category (product_category_id),
  INDEX idx_product_tax_rates_tax_rate (tax_rate_id),
  INDEX idx_product_tax_rates_business (business_id),
  INDEX idx_product_tax_rates_jurisdiction (business_id, jurisdiction) WHERE jurisdiction IS NOT NULL,
  INDEX idx_product_tax_rates_effective (effective_date, expiry_date),

  -- Ensure only one of product_id or product_category_id is set
  CHECK ((product_id IS NOT NULL AND product_category_id IS NULL) OR
         (product_id IS NULL AND product_category_id IS NOT NULL))
);

-- Tax Exemptions table
CREATE TABLE IF NOT EXISTS tax_exemptions (
  id TEXT PRIMARY KEY,
  product_id TEXT,
  product_category_id TEXT,
  tax_rate_id TEXT,
  tax_type TEXT, -- 'SALES_TAX', 'VAT', 'GST', etc.
  exemption_reason TEXT NOT NULL, -- 'medical', 'food', 'education', etc.
  certificate_number TEXT, -- Exemption certificate reference
  effective_date INTEGER NOT NULL,
  expiry_date INTEGER,
  is_active INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL,
  business_id TEXT NOT NULL,

  FOREIGN KEY (product_id) REFERENCES products(id),
  FOREIGN KEY (product_category_id) REFERENCES product_categories(id),
  FOREIGN KEY (tax_rate_id) REFERENCES tax_rates(id),
  INDEX idx_tax_exemptions_product (product_id),
  INDEX idx_tax_exemptions_category (product_category_id),
  INDEX idx_tax_exemptions_tax_rate (tax_rate_id),
  INDEX idx_tax_exemptions_business (business_id),
  INDEX idx_tax_exemptions_type (business_id, tax_type),
  INDEX idx_tax_exemptions_reason (business_id, exemption_reason),
  INDEX idx_tax_exemptions_effective (effective_date, expiry_date),
  INDEX idx_tax_exemptions_active (business_id, is_active) WHERE is_active = 1,

  -- Ensure only one of product_id or product_category_id is set
  CHECK ((product_id IS NOT NULL AND product_category_id IS NULL) OR
         (product_id IS NULL AND product_category_id IS NOT NULL))
);

-- Product Tax Rules (for complex tax logic)
CREATE TABLE IF NOT EXISTS product_tax_rules (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT,
  rule_type TEXT NOT NULL, -- 'inclusion', 'exclusion', 'rate_override', 'exemption'
  conditions TEXT NOT NULL, -- JSON with conditions (product attributes, amounts, etc.)
  tax_rate_id TEXT,
  override_rate REAL, -- Optional override rate
  priority INTEGER NOT NULL DEFAULT 0, -- Higher priority rules are evaluated first
  is_active INTEGER NOT NULL DEFAULT 1,
  effective_date INTEGER NOT NULL,
  expiry_date INTEGER,
  created_at INTEGER NOT NULL,
  business_id TEXT NOT NULL,

  FOREIGN KEY (tax_rate_id) REFERENCES tax_rates(id),
  INDEX idx_product_tax_rules_business (business_id),
  INDEX idx_product_tax_rules_type (business_id, rule_type),
  INDEX idx_product_tax_rules_priority (business_id, priority),
  INDEX idx_product_tax_rules_active (business_id, is_active) WHERE is_active = 1,
  INDEX idx_product_tax_rules_effective (effective_date, expiry_date)
);

-- ============================================================================
-- SAMPLE DATA FOR COMMON TAX CATEGORIES
-- ============================================================================

-- Insert common product categories with tax implications
INSERT OR IGNORE INTO product_categories (
  id, name, description, tax_category, is_active, business_id
) VALUES
  ('cat_food', 'Food & Beverages', 'Food and beverage products', 'exempt_or_reduced', 1, 'system'),
  ('cat_medical', 'Medical & Healthcare', 'Medical supplies and healthcare products', 'exempt', 1, 'system'),
  ('cat_education', 'Educational Materials', 'Books, educational supplies', 'exempt_or_reduced', 1, 'system'),
  ('cat_digital', 'Digital Products', 'Software, digital downloads', 'special', 1, 'system'),
  ('cat_services', 'Services', 'Professional and personal services', 'standard', 1, 'system'),
  ('cat_luxury', 'Luxury Goods', 'Luxury items and high-value goods', 'standard_or_higher', 1, 'system'),
  ('cat_general', 'General Merchandise', 'General retail products', 'standard', 1, 'system');

-- ============================================================================
-- TRIGGERS FOR DATA INTEGRITY
-- ============================================================================

-- Update product timestamp when tax rates change
CREATE TRIGGER IF NOT EXISTS update_product_on_tax_change
AFTER INSERT ON product_tax_rates
FOR EACH ROW
BEGIN
  UPDATE products
  SET updated_at = strftime('%s', 'now') * 1000
  WHERE id = NEW.product_id;
END;

-- Validate tax rule conditions JSON
CREATE TRIGGER IF NOT EXISTS validate_tax_rule_conditions
BEFORE INSERT ON product_tax_rules
FOR EACH ROW
BEGIN
  -- Basic JSON validation (SQLite has limited JSON validation)
  SELECT CASE
    WHEN json_valid(NEW.conditions) = 0 THEN
      RAISE(FAIL, 'Tax rule conditions must be valid JSON')
  END;
END;

-- ============================================================================
-- SCHEMA VERSION TRACKING
-- ============================================================================

INSERT OR REPLACE INTO schema_versions (module, version, applied_at)
VALUES ('finance_product_tax', '1.0.0', strftime('%s', 'now') * 1000);