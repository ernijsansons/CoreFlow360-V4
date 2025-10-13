-- Seed: 003_comprehensive_demo_data
-- Description: Comprehensive demo data ecosystem for CoreFlow360 V4
-- Created: 2025-10-12
-- Includes: Companies, Contacts, Deals, Activities, Accounts, Transactions

-- ============================================================
-- STEP 1: Foundation User (Founder Account)
-- ============================================================
-- User already exists: founder@coreflow360.com

-- ============================================================
-- STEP 2: Demo Business
-- ============================================================
INSERT OR IGNORE INTO businesses (id, name, email, subscription_tier, status)
VALUES ('business-demo-001', 'CoreFlow360 Demo Business', 'demo@coreflow360.com', 'professional', 'active');

-- ============================================================
-- STEP 3: Chart of Accounts (Standard GL Accounts)
-- ============================================================

-- ASSETS
INSERT OR IGNORE INTO accounts (id, business_id, account_number, account_name, account_type, category, normal_balance, opening_balance, status) VALUES
('acc-1000', 'business-demo-001', '1000', 'Cash - Operating Account', 'asset', 'cash', 'debit', 50000.00, 'active'),
('acc-1010', 'business-demo-001', '1010', 'Cash - Savings Account', 'asset', 'bank', 'debit', 100000.00, 'active'),
('acc-1100', 'business-demo-001', '1100', 'Accounts Receivable', 'asset', 'accounts_receivable', 'debit', 45000.00, 'active'),
('acc-1200', 'business-demo-001', '1200', 'Inventory', 'asset', 'inventory', 'debit', 25000.00, 'active'),
('acc-1300', 'business-demo-001', '1300', 'Prepaid Expenses', 'asset', 'prepaid_expenses', 'debit', 5000.00, 'active'),
('acc-1500', 'business-demo-001', '1500', 'Equipment', 'asset', 'fixed_assets', 'debit', 80000.00, 'active'),
('acc-1510', 'business-demo-001', '1510', 'Accumulated Depreciation - Equipment', 'contra_asset', 'accumulated_depreciation', 'credit', -15000.00, 'active'),
('acc-1600', 'business-demo-001', '1600', 'Software & Licenses', 'asset', 'intangible_assets', 'debit', 20000.00, 'active');

-- LIABILITIES
INSERT OR IGNORE INTO accounts (id, business_id, account_number, account_name, account_type, category, normal_balance, opening_balance, status) VALUES
('acc-2000', 'business-demo-001', '2000', 'Accounts Payable', 'liability', 'accounts_payable', 'credit', -22000.00, 'active'),
('acc-2100', 'business-demo-001', '2100', 'Accrued Expenses', 'liability', 'accrued_expenses', 'credit', -8000.00, 'active'),
('acc-2200', 'business-demo-001', '2200', 'Unearned Revenue', 'liability', 'unearned_revenue', 'credit', -15000.00, 'active'),
('acc-2300', 'business-demo-001', '2300', 'Notes Payable', 'liability', 'notes_payable', 'credit', -50000.00, 'active'),
('acc-2400', 'business-demo-001', '2400', 'Taxes Payable', 'liability', 'taxes_payable', 'credit', -12000.00, 'active');

-- EQUITY
INSERT OR IGNORE INTO accounts (id, business_id, account_number, account_name, account_type, category, normal_balance, opening_balance, status) VALUES
('acc-3000', 'business-demo-001', '3000', 'Owners Equity', 'equity', 'owners_equity', 'credit', -150000.00, 'active'),
('acc-3100', 'business-demo-001', '3100', 'Retained Earnings', 'equity', 'retained_earnings', 'credit', -48000.00, 'active'),
('acc-3200', 'business-demo-001', '3200', 'Dividends', 'equity', 'dividends', 'debit', 0.00, 'active');

-- REVENUE
INSERT OR IGNORE INTO accounts (id, business_id, account_number, account_name, account_type, category, normal_balance, opening_balance, status) VALUES
('acc-4000', 'business-demo-001', '4000', 'Software License Revenue', 'revenue', 'sales_revenue', 'credit', 0.00, 'active'),
('acc-4100', 'business-demo-001', '4100', 'Consulting Revenue', 'revenue', 'service_revenue', 'credit', 0.00, 'active'),
('acc-4200', 'business-demo-001', '4200', 'Implementation Services', 'revenue', 'service_revenue', 'credit', 0.00, 'active'),
('acc-4300', 'business-demo-001', '4300', 'Support & Maintenance', 'revenue', 'service_revenue', 'credit', 0.00, 'active'),
('acc-4900', 'business-demo-001', '4900', 'Other Income', 'revenue', 'other_income', 'credit', 0.00, 'active');

-- EXPENSES
INSERT OR IGNORE INTO accounts (id, business_id, account_number, account_name, account_type, category, normal_balance, opening_balance, status) VALUES
('acc-5000', 'business-demo-001', '5000', 'Cost of Goods Sold', 'expense', 'cost_of_goods_sold', 'debit', 0.00, 'active'),
('acc-6000', 'business-demo-001', '6000', 'Salaries & Wages', 'expense', 'salaries_expense', 'debit', 0.00, 'active'),
('acc-6100', 'business-demo-001', '6100', 'Payroll Taxes', 'expense', 'tax_expense', 'debit', 0.00, 'active'),
('acc-6200', 'business-demo-001', '6200', 'Employee Benefits', 'expense', 'salaries_expense', 'debit', 0.00, 'active'),
('acc-6300', 'business-demo-001', '6300', 'Rent Expense', 'expense', 'rent_expense', 'debit', 0.00, 'active'),
('acc-6400', 'business-demo-001', '6400', 'Utilities', 'expense', 'utilities_expense', 'debit', 0.00, 'active'),
('acc-6500', 'business-demo-001', '6500', 'Office Supplies', 'expense', 'other_expense', 'debit', 0.00, 'active'),
('acc-6600', 'business-demo-001', '6600', 'Software & Subscriptions', 'expense', 'other_expense', 'debit', 0.00, 'active'),
('acc-6700', 'business-demo-001', '6700', 'Marketing & Advertising', 'expense', 'other_expense', 'debit', 0.00, 'active'),
('acc-6800', 'business-demo-001', '6800', 'Professional Services', 'expense', 'other_expense', 'debit', 0.00, 'active'),
('acc-6900', 'business-demo-001', '6900', 'Travel & Entertainment', 'expense', 'other_expense', 'debit', 0.00, 'active'),
('acc-7000', 'business-demo-001', '7000', 'Depreciation Expense', 'expense', 'depreciation_expense', 'debit', 0.00, 'active'),
('acc-7100', 'business-demo-001', '7100', 'Interest Expense', 'expense', 'interest_expense', 'debit', 0.00, 'active'),
('acc-7200', 'business-demo-001', '7200', 'Bad Debt Expense', 'expense', 'other_expense', 'debit', 0.00, 'active'),
('acc-7300', 'business-demo-001', '7300', 'Insurance Expense', 'expense', 'other_expense', 'debit', 0.00, 'active'),
('acc-7400', 'business-demo-001', '7400', 'Miscellaneous Expense', 'expense', 'other_expense', 'debit', 0.00, 'active');

-- ============================================================
-- STEP 4: CRM Companies (10 Diverse Companies)
-- ============================================================
INSERT OR IGNORE INTO crm_companies (id, business_id, name, website, domain, industry, company_size, annual_revenue, lead_score, lifecycle_stage, status, owner_id, email, phone, city, state, country) VALUES
('comp-001', 'business-demo-001', 'TechFlow Solutions Inc', 'https://techflow.io', 'techflow.io', 'Software Development', '51-200', 5000000, 92, 'customer', 'active', '550e8400-e29b-41d4-a716-446655440000', 'contact@techflow.io', '(555) 123-4567', 'San Francisco', 'CA', 'US'),
('comp-002', 'business-demo-001', 'CloudFirst Enterprises', 'https://cloudfirst.com', 'cloudfirst.com', 'Cloud Infrastructure', '201-500', 15000000, 88, 'opportunity', 'active', '550e8400-e29b-41d4-a716-446655440000', 'sales@cloudfirst.com', '(555) 234-5678', 'Seattle', 'WA', 'US'),
('comp-003', 'business-demo-001', 'DataViz Analytics Corp', 'https://dataviz.ai', 'dataviz.ai', 'Data Analytics', '11-50', 2000000, 85, 'sql', 'active', '550e8400-e29b-41d4-a716-446655440000', 'info@dataviz.ai', '(555) 345-6789', 'Austin', 'TX', 'US'),
('comp-004', 'business-demo-001', 'SecureNet Systems', 'https://securenet.tech', 'securenet.tech', 'Cybersecurity', '501-1000', 25000000, 78, 'mql', 'active', '550e8400-e29b-41d4-a716-446655440000', 'contact@securenet.tech', '(555) 456-7890', 'Boston', 'MA', 'US'),
('comp-005', 'business-demo-001', 'FinTech Innovations LLC', 'https://fintechinnov.com', 'fintechinnov.com', 'Financial Technology', '1-10', 800000, 95, 'customer', 'active', '550e8400-e29b-41d4-a716-446655440000', 'hello@fintechinnov.com', '(555) 567-8901', 'New York', 'NY', 'US'),
('comp-006', 'business-demo-001', 'HealthTech Partners', 'https://healthtech.partners', 'healthtech.partners', 'Healthcare IT', '101-500', 8000000, 72, 'lead', 'prospect', '550e8400-e29b-41d4-a716-446655440000', 'partnerships@healthtech.partners', '(555) 678-9012', 'Denver', 'CO', 'US'),
('comp-007', 'business-demo-001', 'EduSmart Platform', 'https://edusmart.edu', 'edusmart.edu', 'Education Technology', '51-200', 3500000, 68, 'lead', 'prospect', '550e8400-e29b-41d4-a716-446655440000', 'contact@edusmart.edu', '(555) 789-0123', 'Chicago', 'IL', 'US'),
('comp-008', 'business-demo-001', 'RetailPro Solutions', 'https://retailpro.com', 'retailpro.com', 'Retail Technology', '201-500', 12000000, 81, 'opportunity', 'active', '550e8400-e29b-41d4-a716-446655440000', 'sales@retailpro.com', '(555) 890-1234', 'Los Angeles', 'CA', 'US'),
('comp-009', 'business-demo-001', 'GreenEnergy Tech', 'https://greenenergy.io', 'greenenergy.io', 'Clean Energy', '11-50', 4000000, 75, 'sql', 'active', '550e8400-e29b-41d4-a716-446655440000', 'info@greenenergy.io', '(555) 901-2345', 'Portland', 'OR', 'US'),
('comp-010', 'business-demo-001', 'AutoDrive Systems Inc', 'https://autodrive.ai', 'autodrive.ai', 'Autonomous Vehicles', '501-1000', 35000000, 90, 'customer', 'active', '550e8400-e29b-41d4-a716-446655440000', 'contact@autodrive.ai', '(555) 012-3456', 'Detroit', 'MI', 'US');

-- ============================================================
-- STEP 5: CRM Contacts (3 per company = 30 contacts)
-- ============================================================

-- TechFlow Solutions contacts
INSERT OR IGNORE INTO crm_contacts (id, business_id, company_id, first_name, last_name, email, job_title, phone, seniority_level, lead_score, lifecycle_stage, status, owner_id) VALUES
('cont-001', 'business-demo-001', 'comp-001', 'Sarah', 'Johnson', 'sarah.johnson@techflow.io', 'CEO & Founder', '(555) 123-4501', 'c-level', 95, 'customer', 'active', '550e8400-e29b-41d4-a716-446655440000'),
('cont-002', 'business-demo-001', 'comp-001', 'Michael', 'Chen', 'michael.chen@techflow.io', 'VP of Engineering', '(555) 123-4502', 'vp', 88, 'customer', 'active', '550e8400-e29b-41d4-a716-446655440000'),
('cont-003', 'business-demo-001', 'comp-001', 'Emily', 'Rodriguez', 'emily.r@techflow.io', 'Product Manager', '(555) 123-4503', 'manager', 82, 'customer', 'active', '550e8400-e29b-41d4-a716-446655440000');

-- CloudFirst Enterprises contacts
INSERT OR IGNORE INTO crm_contacts (id, business_id, company_id, first_name, last_name, email, job_title, phone, seniority_level, lead_score, lifecycle_stage, status, owner_id) VALUES
('cont-004', 'business-demo-001', 'comp-002', 'David', 'Thompson', 'david.t@cloudfirst.com', 'CTO', '(555) 234-5601', 'c-level', 92, 'opportunity', 'active', '550e8400-e29b-41d4-a716-446655440000'),
('cont-005', 'business-demo-001', 'comp-002', 'Lisa', 'Wang', 'lisa.wang@cloudfirst.com', 'Director of Cloud Operations', '(555) 234-5602', 'director', 85, 'opportunity', 'active', '550e8400-e29b-41d4-a716-446655440000'),
('cont-006', 'business-demo-001', 'comp-002', 'James', 'Martinez', 'j.martinez@cloudfirst.com', 'Senior DevOps Engineer', '(555) 234-5603', 'individual', 78, 'sql', 'active', '550e8400-e29b-41d4-a716-446655440000');

-- DataViz Analytics contacts
INSERT OR IGNORE INTO crm_contacts (id, business_id, company_id, first_name, last_name, email, job_title, phone, seniority_level, lead_score, lifecycle_stage, status, owner_id) VALUES
('cont-007', 'business-demo-001', 'comp-003', 'Amanda', 'Foster', 'amanda@dataviz.ai', 'Chief Data Officer', '(555) 345-6701', 'c-level', 90, 'sql', 'active', '550e8400-e29b-41d4-a716-446655440000'),
('cont-008', 'business-demo-001', 'comp-003', 'Robert', 'Kim', 'robert.kim@dataviz.ai', 'Analytics Team Lead', '(555) 345-6702', 'manager', 83, 'sql', 'active', '550e8400-e29b-41d4-a716-446655440000'),
('cont-009', 'business-demo-001', 'comp-003', 'Nicole', 'Patel', 'nicole.p@dataviz.ai', 'Data Scientist', '(555) 345-6703', 'individual', 75, 'mql', 'active', '550e8400-e29b-41d4-a716-446655440000');

-- SecureNet Systems contacts
INSERT OR IGNORE INTO crm_contacts (id, business_id, company_id, first_name, last_name, email, job_title, phone, seniority_level, lead_score, lifecycle_stage, status, owner_id) VALUES
('cont-010', 'business-demo-001', 'comp-004', 'Kevin', 'O''Brien', 'kevin@securenet.tech', 'VP of Security', '(555) 456-7801', 'vp', 85, 'mql', 'active', '550e8400-e29b-41d4-a716-446655440000'),
('cont-011', 'business-demo-001', 'comp-004', 'Rachel', 'Singh', 'rachel.singh@securenet.tech', 'Security Architect', '(555) 456-7802', 'individual', 78, 'mql', 'active', '550e8400-e29b-41d4-a716-446655440000'),
('cont-012', 'business-demo-001', 'comp-004', 'Thomas', 'Lee', 'thomas.lee@securenet.tech', 'Compliance Manager', '(555) 456-7803', 'manager', 72, 'lead', 'active', '550e8400-e29b-41d4-a716-446655440000');

-- FinTech Innovations contacts
INSERT OR IGNORE INTO crm_contacts (id, business_id, company_id, first_name, last_name, email, job_title, phone, seniority_level, lead_score, lifecycle_stage, status, owner_id) VALUES
('cont-013', 'business-demo-001', 'comp-005', 'Jennifer', 'Adams', 'jennifer@fintechinnov.com', 'Founder & CEO', '(555) 567-8801', 'owner', 98, 'customer', 'active', '550e8400-e29b-41d4-a716-446655440000'),
('cont-014', 'business-demo-001', 'comp-005', 'Daniel', 'Brown', 'daniel.b@fintechinnov.com', 'Head of Product', '(555) 567-8802', 'director', 92, 'customer', 'active', '550e8400-e29b-41d4-a716-446655440000'),
('cont-015', 'business-demo-001', 'comp-005', 'Sophia', 'Taylor', 'sophia.t@fintechinnov.com', 'Engineering Lead', '(555) 567-8803', 'manager', 88, 'customer', 'active', '550e8400-e29b-41d4-a716-446655440000');

-- HealthTech Partners contacts
INSERT OR IGNORE INTO crm_contacts (id, business_id, company_id, first_name, last_name, email, job_title, phone, seniority_level, lead_score, lifecycle_stage, status, owner_id) VALUES
('cont-016', 'business-demo-001', 'comp-006', 'Christopher', 'Wilson', 'c.wilson@healthtech.partners', 'Chief Medical Officer', '(555) 678-9001', 'c-level', 80, 'lead', 'active', '550e8400-e29b-41d4-a716-446655440000'),
('cont-017', 'business-demo-001', 'comp-006', 'Michelle', 'Garcia', 'michelle.g@healthtech.partners', 'Director of IT', '(555) 678-9002', 'director', 75, 'lead', 'active', '550e8400-e29b-41d4-a716-446655440000'),
('cont-018', 'business-demo-001', 'comp-006', 'Andrew', 'White', 'andrew.white@healthtech.partners', 'Project Manager', '(555) 678-9003', 'manager', 68, 'lead', 'active', '550e8400-e29b-41d4-a716-446655440000');

-- EduSmart Platform contacts
INSERT OR IGNORE INTO crm_contacts (id, business_id, company_id, first_name, last_name, email, job_title, phone, seniority_level, lead_score, lifecycle_stage, status, owner_id) VALUES
('cont-019', 'business-demo-001', 'comp-007', 'Jessica', 'Miller', 'jessica@edusmart.edu', 'Dean of Technology', '(555) 789-0101', 'director', 72, 'lead', 'active', '550e8400-e29b-41d4-a716-446655440000'),
('cont-020', 'business-demo-001', 'comp-007', 'Brian', 'Anderson', 'brian.a@edusmart.edu', 'IT Coordinator', '(555) 789-0102', 'manager', 65, 'lead', 'active', '550e8400-e29b-41d4-a716-446655440000'),
('cont-021', 'business-demo-001', 'comp-007', 'Lauren', 'Thomas', 'lauren.t@edusmart.edu', 'Curriculum Developer', '(555) 789-0103', 'individual', 60, 'subscriber', 'active', '550e8400-e29b-41d4-a716-446655440000');

-- RetailPro Solutions contacts
INSERT OR IGNORE INTO crm_contacts (id, business_id, company_id, first_name, last_name, email, job_title, phone, seniority_level, lead_score, lifecycle_stage, status, owner_id) VALUES
('cont-022', 'business-demo-001', 'comp-008', 'Matthew', 'Jackson', 'matthew.j@retailpro.com', 'VP of Operations', '(555) 890-1201', 'vp', 88, 'opportunity', 'active', '550e8400-e29b-41d4-a716-446655440000'),
('cont-023', 'business-demo-001', 'comp-008', 'Ashley', 'Moore', 'ashley.m@retailpro.com', 'Retail Technology Manager', '(555) 890-1202', 'manager', 82, 'opportunity', 'active', '550e8400-e29b-41d4-a716-446655440000'),
('cont-024', 'business-demo-001', 'comp-008', 'Joshua', 'Davis', 'joshua.d@retailpro.com', 'Systems Analyst', '(555) 890-1203', 'individual', 75, 'sql', 'active', '550e8400-e29b-41d4-a716-446655440000');

-- GreenEnergy Tech contacts
INSERT OR IGNORE INTO crm_contacts (id, business_id, company_id, first_name, last_name, email, job_title, phone, seniority_level, lead_score, lifecycle_stage, status, owner_id) VALUES
('cont-025', 'business-demo-001', 'comp-009', 'Elizabeth', 'Martinez', 'elizabeth@greenenergy.io', 'Chief Sustainability Officer', '(555) 901-2301', 'c-level', 82, 'sql', 'active', '550e8400-e29b-41d4-a716-446655440000'),
('cont-026', 'business-demo-001', 'comp-009', 'Ryan', 'Lopez', 'ryan.lopez@greenenergy.io', 'Energy Systems Engineer', '(555) 901-2302', 'individual', 76, 'sql', 'active', '550e8400-e29b-41d4-a716-446655440000'),
('cont-027', 'business-demo-001', 'comp-009', 'Hannah', 'Clark', 'hannah.c@greenenergy.io', 'Operations Manager', '(555) 901-2303', 'manager', 70, 'mql', 'active', '550e8400-e29b-41d4-a716-446655440000');

-- AutoDrive Systems contacts
INSERT OR IGNORE INTO crm_contacts (id, business_id, company_id, first_name, last_name, email, job_title, phone, seniority_level, lead_score, lifecycle_stage, status, owner_id) VALUES
('cont-028', 'business-demo-001', 'comp-010', 'William', 'Rodriguez', 'william.r@autodrive.ai', 'Chief Technology Officer', '(555) 012-3401', 'c-level', 96, 'customer', 'active', '550e8400-e29b-41d4-a716-446655440000'),
('cont-029', 'business-demo-001', 'comp-010', 'Samantha', 'Lewis', 'samantha.l@autodrive.ai', 'VP of Engineering', '(555) 012-3402', 'vp', 91, 'customer', 'active', '550e8400-e29b-41d4-a716-446655440000'),
('cont-030', 'business-demo-001', 'comp-010', 'Nathan', 'Walker', 'nathan.w@autodrive.ai', 'Senior AI Researcher', '(555) 012-3403', 'individual', 87, 'customer', 'active', '550e8400-e29b-41d4-a716-446655440000');

-- ============================================================
-- STEP 6: CRM Deals (20 deals across pipeline)
-- ============================================================
INSERT OR IGNORE INTO crm_deals (id, business_id, company_id, contact_id, title, amount, currency, stage, pipeline, probability, expected_close_date, status, owner_id) VALUES
-- Won deals (customers)
('deal-001', 'business-demo-001', 'comp-001', 'cont-001', 'Enterprise License - Year 1', 250000, 'USD', 'closed_won', 'sales', 100, '2025-03-15', 'won', '550e8400-e29b-41d4-a716-446655440000'),
('deal-002', 'business-demo-001', 'comp-005', 'cont-013', 'Implementation Services', 85000, 'USD', 'closed_won', 'sales', 100, '2025-04-20', 'won', '550e8400-e29b-41d4-a716-446655440000'),
('deal-003', 'business-demo-001', 'comp-010', 'cont-028', 'Custom AI Integration', 450000, 'USD', 'closed_won', 'sales', 100, '2025-05-10', 'won', '550e8400-e29b-41d4-a716-446655440000'),

-- Negotiation/contract stage
('deal-004', 'business-demo-001', 'comp-002', 'cont-004', 'Cloud Infrastructure Package', 320000, 'USD', 'negotiation', 'sales', 75, '2025-11-15', 'open', '550e8400-e29b-41d4-a716-446655440000'),
('deal-005', 'business-demo-001', 'comp-008', 'cont-022', 'Retail Management Suite', 180000, 'USD', 'contract', 'sales', 80, '2025-11-30', 'open', '550e8400-e29b-41d4-a716-446655440000'),

-- Proposal stage
('deal-006', 'business-demo-001', 'comp-003', 'cont-007', 'Analytics Platform License', 95000, 'USD', 'proposal', 'sales', 60, '2025-12-01', 'open', '550e8400-e29b-41d4-a716-446655440000'),
('deal-007', 'business-demo-001', 'comp-009', 'cont-025', 'Energy Monitoring System', 125000, 'USD', 'proposal', 'sales', 55, '2025-12-10', 'open', '550e8400-e29b-41d4-a716-446655440000'),

-- Demo/trial stage
('deal-008', 'business-demo-001', 'comp-004', 'cont-010', 'Security Compliance Tool', 220000, 'USD', 'demo', 'sales', 45, '2025-12-20', 'open', '550e8400-e29b-41d4-a716-446655440000'),
('deal-009', 'business-demo-001', 'comp-006', 'cont-016', 'Healthcare Integration Platform', 275000, 'USD', 'trial', 'sales', 40, '2026-01-05', 'open', '550e8400-e29b-41d4-a716-446655440000'),
('deal-010', 'business-demo-001', 'comp-007', 'cont-019', 'Education Management System', 150000, 'USD', 'demo', 'sales', 35, '2026-01-15', 'open', '550e8400-e29b-41d4-a716-446655440000'),

-- Discovery/qualification stage
('deal-011', 'business-demo-001', 'comp-002', 'cont-005', 'DevOps Automation Suite', 95000, 'USD', 'discovery', 'sales', 30, '2026-02-01', 'open', '550e8400-e29b-41d4-a716-446655440000'),
('deal-012', 'business-demo-001', 'comp-003', 'cont-008', 'Data Warehouse Solution', 185000, 'USD', 'qualification', 'sales', 25, '2026-02-15', 'open', '550e8400-e29b-41d4-a716-446655440000'),
('deal-013', 'business-demo-001', 'comp-006', 'cont-017', 'Patient Data Platform', 310000, 'USD', 'discovery', 'sales', 20, '2026-03-01', 'open', '550e8400-e29b-41d4-a716-446655440000'),

-- Prospecting stage
('deal-014', 'business-demo-001', 'comp-007', 'cont-020', 'Learning Analytics Tool', 75000, 'USD', 'prospecting', 'sales', 15, '2026-03-15', 'open', '550e8400-e29b-41d4-a716-446655440000'),
('deal-015', 'business-demo-001', 'comp-008', 'cont-023', 'Inventory Optimization AI', 140000, 'USD', 'prospecting', 'sales', 15, '2026-04-01', 'open', '550e8400-e29b-41d4-a716-446655440000'),
('deal-016', 'business-demo-001', 'comp-009', 'cont-026', 'Smart Grid Integration', 195000, 'USD', 'prospecting', 'sales', 10, '2026-04-20', 'open', '550e8400-e29b-41d4-a716-446655440000'),

-- Additional opportunities
('deal-017', 'business-demo-001', 'comp-001', 'cont-002', 'Year 2 Renewal + Expansion', 320000, 'USD', 'negotiation', 'sales', 85, '2026-03-01', 'open', '550e8400-e29b-41d4-a716-446655440000'),
('deal-018', 'business-demo-001', 'comp-005', 'cont-014', 'Advanced Features Package', 120000, 'USD', 'proposal', 'sales', 70, '2025-12-15', 'open', '550e8400-e29b-41d4-a716-446655440000'),
('deal-019', 'business-demo-001', 'comp-010', 'cont-029', 'ML Training Services', 200000, 'USD', 'contract', 'sales', 75, '2025-11-25', 'open', '550e8400-e29b-41d4-a716-446655440000'),

-- Lost deal (for realistic data)
('deal-020', 'business-demo-001', 'comp-004', 'cont-011', 'Basic Security Package', 65000, 'USD', 'closed_lost', 'sales', 0, '2025-09-30', 'lost', '550e8400-e29b-41d4-a716-446655440000');

-- Demo data seed complete
