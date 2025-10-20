-- Migration: 040_invoices_table
-- Description: Create invoices table for dashboard and finance modules
-- Created: 2025-10-18

CREATE TABLE IF NOT EXISTS invoices (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    business_id TEXT NOT NULL,

    -- Invoice Information
    invoice_number TEXT NOT NULL,
    invoice_date TEXT NOT NULL,
    due_date TEXT NOT NULL,

    -- Customer
    customer_id TEXT,
    customer_name TEXT NOT NULL,
    customer_email TEXT,

    -- Amounts
    subtotal REAL NOT NULL DEFAULT 0,
    tax_amount REAL DEFAULT 0,
    total_amount REAL NOT NULL DEFAULT 0,
    amount_paid REAL DEFAULT 0,

    -- Status
    status TEXT DEFAULT 'draft' CHECK (status IN ('draft', 'sent', 'viewed', 'partial', 'paid', 'overdue', 'cancelled', 'voided')),

    -- Payment
    paid_at TEXT,
    payment_method TEXT,
    payment_reference TEXT,

    -- Terms
    payment_terms TEXT,
    notes TEXT,

    -- Timestamps
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now')),
    sent_at TEXT,
    voided_at TEXT,

    -- Foreign Keys
    FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,

    -- Constraints
    UNIQUE(business_id, invoice_number),
    CHECK (total_amount >= 0),
    CHECK (amount_paid >= 0),
    CHECK (amount_paid <= total_amount)
);

-- Invoice Line Items
CREATE TABLE IF NOT EXISTS invoice_items (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    invoice_id TEXT NOT NULL,
    business_id TEXT NOT NULL,

    -- Item Information
    description TEXT NOT NULL,
    quantity REAL NOT NULL DEFAULT 1,
    unit_price REAL NOT NULL DEFAULT 0,

    -- Amounts
    line_total REAL NOT NULL DEFAULT 0,
    tax_rate REAL DEFAULT 0,
    tax_amount REAL DEFAULT 0,

    -- Product Reference
    product_id TEXT,
    product_name TEXT,

    -- Timestamps
    created_at TEXT DEFAULT (datetime('now')),

    -- Foreign Keys
    FOREIGN KEY (invoice_id) REFERENCES invoices(id) ON DELETE CASCADE,
    FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,

    -- Constraints
    CHECK (quantity > 0),
    CHECK (unit_price >= 0),
    CHECK (line_total >= 0)
);

-- Create indexes
CREATE INDEX idx_invoices_business ON invoices(business_id, status);
CREATE INDEX idx_invoices_number ON invoices(business_id, invoice_number);
CREATE INDEX idx_invoices_customer ON invoices(customer_id) WHERE customer_id IS NOT NULL;
CREATE INDEX idx_invoices_dates ON invoices(invoice_date, due_date);
CREATE INDEX idx_invoices_status_date ON invoices(status, due_date);

CREATE INDEX idx_invoice_items_invoice ON invoice_items(invoice_id);
CREATE INDEX idx_invoice_items_product ON invoice_items(product_id) WHERE product_id IS NOT NULL;
