-- Comprehensive Sample Data for CoreFlow360 V4
-- Provides realistic demo data for new users to explore the platform
-- Includes: CRM data, Finance/Accounting data, Analytics data

-- ==============================================================================
-- SAMPLE CRM DATA
-- ==============================================================================

-- Sample Companies (if not already seeded)
INSERT OR IGNORE INTO crm_companies (id, business_id, name, website, domain, industry, company_size, annual_revenue, lead_score, lifecycle_stage, status, owner_id)
VALUES
('demo-company-001', 'business-founder-001', 'Tech Innovators Inc', 'https://techinnovators.io', 'techinnovators.io', 'SaaS', '101-500', 25000000, 88, 'customer', 'active', '550e8400-e29b-41d4-a716-446655440000'),
('demo-company-002', 'business-founder-001', 'Digital Solutions LLC', 'https://digitalsolutions.com', 'digitalsolutions.com', 'Consulting', '11-50', 3500000, 76, 'opportunity', 'active', '550e8400-e29b-41d4-a716-446655440000'),
('demo-company-003', 'business-founder-001', 'CloudFirst Partners', 'https://cloudfirst.io', 'cloudfirst.io', 'Cloud Services', '51-200', 12000000, 82, 'sql', 'active', '550e8400-e29b-41d4-a716-446655440000'),
('demo-company-004', 'business-founder-001', 'AI Ventures Corp', 'https://aiventures.ai', 'aiventures.ai', 'AI/ML', '201-500', 45000000, 94, 'customer', 'active', '550e8400-e29b-41d4-a716-446655440000'),
('demo-company-005', 'business-founder-001', 'StartupBoost Inc', 'https://startupboost.com', 'startupboost.com', 'Accelerator', '1-10', 850000, 68, 'mql', 'active', '550e8400-e29b-41d4-a716-446655440000');

-- Sample Contacts
INSERT OR IGNORE INTO crm_contacts (id, business_id, company_id, first_name, last_name, email, job_title, seniority_level, lead_score, lifecycle_stage, status, owner_id)
VALUES
('demo-contact-001', 'business-founder-001', 'demo-company-001', 'Alex', 'Martinez', 'alex.martinez@techinnovators.io', 'CEO & Founder', 'c-level', 92, 'customer', 'active', '550e8400-e29b-41d4-a716-446655440000'),
('demo-contact-002', 'business-founder-001', 'demo-company-001', 'Jordan', 'Lee', 'jordan.lee@techinnovators.io', 'VP of Engineering', 'vp', 87, 'customer', 'active', '550e8400-e29b-41d4-a716-446655440000'),
('demo-contact-003', 'business-founder-001', 'demo-company-002', 'Taylor', 'Johnson', 'taylor.j@digitalsolutions.com', 'Managing Director', 'c-level', 78, 'opportunity', 'active', '550e8400-e29b-41d4-a716-446655440000'),
('demo-contact-004', 'business-founder-001', 'demo-company-003', 'Sam', 'Patel', 'sam.patel@cloudfirst.io', 'Head of Sales', 'director', 80, 'sql', 'active', '550e8400-e29b-41d4-a716-446655440000'),
('demo-contact-005', 'business-founder-001', 'demo-company-004', 'Morgan', 'Chen', 'morgan.chen@aiventures.ai', 'Chief Technology Officer', 'c-level', 96, 'customer', 'active', '550e8400-e29b-41d4-a716-446655440000'),
('demo-contact-006', 'business-founder-001', 'demo-company-005', 'Casey', 'Brown', 'casey.brown@startupboost.com', 'Founder & CEO', 'c-level', 70, 'mql', 'active', '550e8400-e29b-41d4-a716-446655440000');

-- Sample Deals with realistic amounts and stages
INSERT OR IGNORE INTO crm_deals (id, business_id, company_id, primary_contact_id, name, deal_type, amount, stage, probability, expected_close_date, status, owner_id)
VALUES
('demo-deal-001', 'business-founder-001', 'demo-company-001', 'demo-contact-001', 'Enterprise Platform Expansion', 'upsell', 185000, 'negotiation', 85, DATE('now', '+25 days'), 'open', '550e8400-e29b-41d4-a716-446655440000'),
('demo-deal-002', 'business-founder-001', 'demo-company-002', 'demo-contact-003', 'Digital Transformation Package', 'new_business', 95000, 'proposal', 60, DATE('now', '+40 days'), 'open', '550e8400-e29b-41d4-a716-446655440000'),
('demo-deal-003', 'business-founder-001', 'demo-company-003', 'demo-contact-004', 'Cloud Migration Services', 'new_business', 320000, 'discovery', 35, DATE('now', '+75 days'), 'open', '550e8400-e29b-41d4-a716-446655440000'),
('demo-deal-004', 'business-founder-001', 'demo-company-004', 'demo-contact-005', 'AI Integration Suite', 'renewal', 425000, 'closed_won', 100, DATE('now', '-10 days'), 'won', '550e8400-e29b-41d4-a716-446655440000'),
('demo-deal-005', 'business-founder-001', 'demo-company-005', 'demo-contact-006', 'Accelerator Program Platform', 'new_business', 65000, 'qualification', 45, DATE('now', '+55 days'), 'open', '550e8400-e29b-41d4-a716-446655440000');

-- Sample Activities (calls, meetings, emails)
INSERT OR IGNORE INTO crm_activities (id, business_id, type, subject, company_id, contact_id, deal_id, scheduled_at, status, owner_id, outcome)
VALUES
('demo-activity-001', 'business-founder-001', 'meeting', 'Executive Briefing - Platform Expansion', 'demo-company-001', 'demo-contact-001', 'demo-deal-001', DATETIME('now', '+3 days', '15:00'), 'pending', '550e8400-e29b-41d4-a716-446655440000', NULL),
('demo-activity-002', 'business-founder-001', 'call', 'Technical Discovery Call', 'demo-company-002', 'demo-contact-003', 'demo-deal-002', DATETIME('now', '+7 days', '11:00'), 'pending', '550e8400-e29b-41d4-a716-446655440000', NULL),
('demo-activity-003', 'business-founder-001', 'email', 'Proposal Follow-up', 'demo-company-002', 'demo-contact-003', 'demo-deal-002', DATETIME('now', '-2 days'), 'completed', '550e8400-e29b-41d4-a716-446655440000', 'positive'),
('demo-activity-004', 'business-founder-001', 'meeting', 'Cloud Strategy Workshop', 'demo-company-003', 'demo-contact-004', 'demo-deal-003', DATETIME('now', '-5 days'), 'completed', '550e8400-e29b-41d4-a716-446655440000', 'neutral'),
('demo-activity-005', 'business-founder-001', 'call', 'Contract Renewal Discussion', 'demo-company-004', 'demo-contact-005', 'demo-deal-004', DATETIME('now', '-15 days'), 'completed', '550e8400-e29b-41d4-a716-446655440000', 'positive');

-- Sample Leads
INSERT OR IGNORE INTO crm_leads (id, business_id, company_id, contact_id, title, source, lead_score, qualification_status, estimated_budget, owner_id)
VALUES
('demo-lead-001', 'business-founder-001', 'demo-company-005', 'demo-contact-006', 'Platform Demo Request - Accelerator Tools', 'website', 70, 'working', 75000, '550e8400-e29b-41d4-a716-446655440000'),
('demo-lead-002', 'business-founder-001', NULL, NULL, 'Enterprise Trial Signup - Fortune 500', 'paid_ad', 82, 'qualified', 500000, '550e8400-e29b-41d4-a716-446655440000'),
('demo-lead-003', 'business-founder-001', NULL, NULL, 'Conference Lead - Tech Summit 2025', 'event', 58, 'new', 125000, '550e8400-e29b-41d4-a716-446655440000'),
('demo-lead-004', 'business-founder-001', NULL, NULL, 'Referral - Partner Network', 'referral', 74, 'working', 95000, '550e8400-e29b-41d4-a716-446655440000');

-- Sample Notes
INSERT OR IGNORE INTO crm_notes (id, business_id, title, content, company_id, deal_id, created_by)
VALUES
('demo-note-001', 'business-founder-001', 'Platform Expansion Strategy', 'Alex is excited about expanding to 5 new departments. Timeline is Q2 2025. Budget approved by board.', 'demo-company-001', 'demo-deal-001', '550e8400-e29b-41d4-a716-446655440000'),
('demo-note-002', 'business-founder-001', 'Integration Requirements', 'Need Salesforce, HubSpot, and Slack integrations. Security review required. GDPR compliance critical.', 'demo-company-002', 'demo-deal-002', '550e8400-e29b-41d4-a716-446655440000'),
('demo-note-003', 'business-founder-001', 'Competitive Situation', 'Also evaluating 2 competitors. Our AI features are differentiator. Price sensitive - need flexible terms.', 'demo-company-003', 'demo-deal-003', '550e8400-e29b-41d4-a716-446655440000'),
('demo-note-004', 'business-founder-001', 'Success Story', 'Exceeded ROI targets by 340%. Want to become case study. Planning to expand to international markets.', 'demo-company-004', 'demo-deal-004', '550e8400-e29b-41d4-a716-446655440000');

-- ==============================================================================
-- SAMPLE FINANCE DATA
-- ==============================================================================

-- Sample Chart of Accounts (Basic Structure)
INSERT OR IGNORE INTO chart_of_accounts (id, business_id, account_code, account_name, account_type, account_category, parent_account_id, is_active)
VALUES
-- Assets
('demo-coa-1000', 'business-founder-001', '1000', 'Cash - Operating Account', 'asset', 'current_assets', NULL, 1),
('demo-coa-1100', 'business-founder-001', '1100', 'Accounts Receivable', 'asset', 'current_assets', NULL, 1),
('demo-coa-1500', 'business-founder-001', '1500', 'Equipment', 'asset', 'fixed_assets', NULL, 1),
-- Liabilities
('demo-coa-2000', 'business-founder-001', '2000', 'Accounts Payable', 'liability', 'current_liabilities', NULL, 1),
('demo-coa-2100', 'business-founder-001', '2100', 'Credit Card Payable', 'liability', 'current_liabilities', NULL, 1),
-- Revenue
('demo-coa-4000', 'business-founder-001', '4000', 'Software License Revenue', 'revenue', 'operating_revenue', NULL, 1),
('demo-coa-4100', 'business-founder-001', '4100', 'Consulting Revenue', 'revenue', 'operating_revenue', NULL, 1),
-- Expenses
('demo-coa-5000', 'business-founder-001', '5000', 'Salary Expense', 'expense', 'operating_expenses', NULL, 1),
('demo-coa-5100', 'business-founder-001', '5100', 'Marketing Expense', 'expense', 'operating_expenses', NULL, 1),
('demo-coa-5200', 'business-founder-001', '5200', 'Office Rent Expense', 'expense', 'operating_expenses', NULL, 1);

-- Sample Invoices (matching the deals)
INSERT OR IGNORE INTO invoices (id, business_id, invoice_number, customer_id, customer_name, issue_date, due_date, subtotal, tax_amount, total_amount, status, currency)
VALUES
('demo-inv-001', 'business-founder-001', 'INV-2025-001', 'demo-company-004', 'AI Ventures Corp', DATE('now', '-25 days'), DATE('now', '-10 days'), 425000.00, 38250.00, 463250.00, 'paid', 'USD'),
('demo-inv-002', 'business-founder-001', 'INV-2025-002', 'demo-company-001', 'Tech Innovators Inc', DATE('now', '-15 days'), DATE('now', '+15 days'), 185000.00, 16650.00, 201650.00, 'sent', 'USD'),
('demo-inv-003', 'business-founder-001', 'INV-2025-003', 'demo-company-002', 'Digital Solutions LLC', DATE('now', '-8 days'), DATE('now', '+22 days'), 95000.00, 8550.00, 103550.00, 'draft', 'USD'),
('demo-inv-004', 'business-founder-001', 'INV-2024-087', 'demo-company-001', 'Tech Innovators Inc', DATE('now', '-45 days'), DATE('now', '-30 days'), 125000.00, 11250.00, 136250.00, 'paid', 'USD'),
('demo-inv-005', 'business-founder-001', 'INV-2024-092', 'demo-company-003', 'CloudFirst Partners', DATE('now', '-30 days'), DATE('now', '-15 days'), 75000.00, 6750.00, 81750.00, 'paid', 'USD');

-- Sample Invoice Line Items
INSERT OR IGNORE INTO invoice_line_items (id, invoice_id, description, quantity, unit_price, tax_rate, amount)
VALUES
-- INV-2025-001 (AI Ventures)
('demo-invline-001', 'demo-inv-001', 'Enterprise AI Platform - Annual License', 1, 425000.00, 9.0, 425000.00),
-- INV-2025-002 (Tech Innovators)
('demo-invline-002', 'demo-inv-002', 'Platform Expansion - 5 Departments', 5, 37000.00, 9.0, 185000.00),
-- INV-2025-003 (Digital Solutions)
('demo-invline-003', 'demo-inv-003', 'Digital Transformation Consulting', 1, 95000.00, 9.0, 95000.00),
-- INV-2024-087 (Previous invoice)
('demo-invline-004', 'demo-inv-004', 'Q4 2024 Professional Services', 1, 125000.00, 9.0, 125000.00),
-- INV-2024-092 (CloudFirst)
('demo-invline-005', 'demo-inv-005', 'Cloud Migration Initial Phase', 1, 75000.00, 9.0, 75000.00);

-- Sample Payments
INSERT OR IGNORE INTO payments (id, business_id, invoice_id, payment_date, amount, payment_method, reference_number, status)
VALUES
('demo-pay-001', 'business-founder-001', 'demo-inv-001', DATE('now', '-12 days'), 463250.00, 'bank_transfer', 'ACH-20250100234', 'completed'),
('demo-pay-002', 'business-founder-001', 'demo-inv-004', DATE('now', '-32 days'), 136250.00, 'credit_card', 'CC-VISA-8234', 'completed'),
('demo-pay-003', 'business-founder-001', 'demo-inv-005', DATE('now', '-18 days'), 81750.00, 'bank_transfer', 'WIRE-20241287', 'completed');

-- Sample General Ledger Entries (Double-Entry Bookkeeping)
-- Entry 1: Record revenue from AI Ventures payment
INSERT OR IGNORE INTO general_ledger (id, business_id, transaction_date, account_id, debit_amount, credit_amount, description, reference_type, reference_id)
VALUES
('demo-gl-001', 'business-founder-001', DATE('now', '-12 days'), 'demo-coa-1000', 463250.00, 0, 'Payment received - AI Ventures Corp', 'payment', 'demo-pay-001'),
('demo-gl-002', 'business-founder-001', DATE('now', '-12 days'), 'demo-coa-4000', 0, 425000.00, 'Revenue - AI Platform License', 'invoice', 'demo-inv-001'),
('demo-gl-003', 'business-founder-001', DATE('now', '-12 days'), 'demo-coa-2000', 0, 38250.00, 'Sales Tax Liability', 'invoice', 'demo-inv-001');

-- Entry 2: Record revenue from Tech Innovators (previous quarter)
INSERT OR IGNORE INTO general_ledger (id, business_id, transaction_date, account_id, debit_amount, credit_amount, description, reference_type, reference_id)
VALUES
('demo-gl-004', 'business-founder-001', DATE('now', '-32 days'), 'demo-coa-1000', 136250.00, 0, 'Payment received - Tech Innovators', 'payment', 'demo-pay-002'),
('demo-gl-005', 'business-founder-001', DATE('now', '-32 days'), 'demo-coa-4100', 0, 125000.00, 'Revenue - Professional Services', 'invoice', 'demo-inv-004'),
('demo-gl-006', 'business-founder-001', DATE('now', '-32 days'), 'demo-coa-2000', 0, 11250.00, 'Sales Tax Liability', 'invoice', 'demo-inv-004');

-- Entry 3: Marketing expense
INSERT OR IGNORE INTO general_ledger (id, business_id, transaction_date, account_id, debit_amount, credit_amount, description, reference_type, reference_id)
VALUES
('demo-gl-007', 'business-founder-001', DATE('now', '-20 days'), 'demo-coa-5100', 15000.00, 0, 'Digital Marketing Campaign - Q1', 'expense', 'EXP-2025-001'),
('demo-gl-008', 'business-founder-001', DATE('now', '-20 days'), 'demo-coa-1000', 0, 15000.00, 'Payment - Marketing Agency', 'expense', 'EXP-2025-001');

-- Entry 4: Office rent
INSERT OR IGNORE INTO general_ledger (id, business_id, transaction_date, account_id, debit_amount, credit_amount, description, reference_type, reference_id)
VALUES
('demo-gl-009', 'business-founder-001', DATE('now', '-5 days'), 'demo-coa-5200', 8500.00, 0, 'Office Rent - January 2025', 'expense', 'EXP-2025-002'),
('demo-gl-010', 'business-founder-001', DATE('now', '-5 days'), 'demo-coa-1000', 0, 8500.00, 'Payment - Property Management', 'expense', 'EXP-2025-002');

-- ==============================================================================
-- SAMPLE ANALYTICS DATA
-- ==============================================================================

-- Sample Request Logs (for analytics dashboard)
INSERT OR IGNORE INTO request_logs (id, endpoint, method, status_code, response_time, user_id, business_id, ip_address, created_at)
VALUES
('demo-log-001', '/api/crm/deals', 'GET', 200, 45, '550e8400-e29b-41d4-a716-446655440000', 'business-founder-001', '203.0.113.42', DATETIME('now', '-1 hours')),
('demo-log-002', '/api/finance/invoices', 'GET', 200, 38, '550e8400-e29b-41d4-a716-446655440000', 'business-founder-001', '203.0.113.42', DATETIME('now', '-2 hours')),
('demo-log-003', '/api/dashboard/metrics', 'GET', 200, 125, '550e8400-e29b-41d4-a716-446655440000', 'business-founder-001', '203.0.113.42', DATETIME('now', '-3 hours')),
('demo-log-004', '/api/crm/companies', 'POST', 201, 89, '550e8400-e29b-41d4-a716-446655440000', 'business-founder-001', '203.0.113.42', DATETIME('now', '-4 hours')),
('demo-log-005', '/api/auth/login', 'POST', 200, 156, '550e8400-e29b-41d4-a716-446655440000', 'business-founder-001', '203.0.113.42', DATETIME('now', '-5 hours'));

-- ==============================================================================
-- SUMMARY
-- ==============================================================================
-- This seed file creates:
-- - 5 CRM companies with contacts, deals, activities, leads, and notes
-- - Complete Chart of Accounts structure
-- - 5 invoices with line items and 3 completed payments
-- - Double-entry general ledger entries showing revenue and expenses
-- - Sample analytics/request logs
--
-- Total revenue in sample data: $720,000
-- Total paid: $681,250
-- Outstanding AR: $305,200
-- This provides a realistic demo environment for new users
