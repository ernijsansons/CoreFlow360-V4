#!/bin/bash
# Simple Demo Data Seeding Script
# Description: Seeds companies, contacts, and accounts to production
# Date: 2025-10-12

echo "========================================"
echo "CoreFlow360 V4 - Demo Data Seeding"
echo "========================================"
echo ""

DATABASE="coreflow360-agents"
ENV="production"

# Demo Business
echo "[1/8] Creating Demo Business..."
wrangler d1 execute $DATABASE --env $ENV --remote --command \
"INSERT OR IGNORE INTO businesses (id, name, email, subscription_tier, status) VALUES ('business-demo-001', 'CoreFlow360 Demo Business', 'demo@coreflow360.com', 'professional', 'active');"

# Chart of Accounts - Assets
echo "[2/8] Creating Asset Accounts..."
wrangler d1 execute $DATABASE --env $ENV --remote --command \
"INSERT OR IGNORE INTO accounts (id, business_id, account_number, account_name, account_type, category, normal_balance, opening_balance, status) VALUES
('acc-1000', 'business-demo-001', '1000', 'Cash - Operating', 'asset', 'cash', 'debit', 50000, 'active'),
('acc-1100', 'business-demo-001', '1100', 'Accounts Receivable', 'asset', 'accounts_receivable', 'debit', 45000, 'active'),
('acc-1500', 'business-demo-001', '1500', 'Equipment', 'asset', 'fixed_assets', 'debit', 80000, 'active');"

# Chart of Accounts - Liabilities & Equity
echo "[3/8] Creating Liability and Equity Accounts..."
wrangler d1 execute $DATABASE --env $ENV --remote --command \
"INSERT OR IGNORE INTO accounts (id, business_id, account_number, account_name, account_type, category, normal_balance, opening_balance, status) VALUES
('acc-2000', 'business-demo-001', '2000', 'Accounts Payable', 'liability', 'accounts_payable', 'credit', -22000, 'active'),
('acc-3000', 'business-demo-001', '3000', 'Owners Equity', 'equity', 'owners_equity', 'credit', -150000, 'active');"

# Revenue Accounts
echo "[4/8] Creating Revenue Accounts..."
wrangler d1 execute $DATABASE --env $ENV --remote --command \
"INSERT OR IGNORE INTO accounts (id, business_id, account_number, account_name, account_type, category, normal_balance, status) VALUES
('acc-4000', 'business-demo-001', '4000', 'Software Revenue', 'revenue', 'sales_revenue', 'credit', 'active'),
('acc-4100', 'business-demo-001', '4100', 'Consulting Revenue', 'revenue', 'service_revenue', 'credit', 'active');"

# Expense Accounts
echo "[5/8] Creating Expense Accounts..."
wrangler d1 execute $DATABASE --env $ENV --remote --command \
"INSERT OR IGNORE INTO accounts (id, business_id, account_number, account_name, account_type, category, normal_balance, status) VALUES
('acc-6000', 'business-demo-001', '6000', 'Salaries', 'expense', 'salaries_expense', 'debit', 'active'),
('acc-6300', 'business-demo-001', '6300', 'Rent', 'expense', 'rent_expense', 'debit', 'active'),
('acc-6700', 'business-demo-001', '6700', 'Marketing', 'expense', 'other_expense', 'debit', 'active');"

# Companies - Batch 1
echo "[6/8] Creating Companies (Batch 1/2)..."
wrangler d1 execute $DATABASE --env $ENV --remote --command \
"INSERT OR IGNORE INTO crm_companies (id, business_id, name, website, industry, company_size, annual_revenue, lead_score, lifecycle_stage, status, owner_id, email) VALUES
('comp-001', 'business-demo-001', 'TechFlow Solutions', 'https://techflow.io', 'Software', '51-200', 5000000, 92, 'customer', 'active', '550e8400-e29b-41d4-a716-446655440000', 'contact@techflow.io'),
('comp-002', 'business-demo-001', 'CloudFirst Corp', 'https://cloudfirst.com', 'Cloud', '201-500', 15000000, 88, 'opportunity', 'active', '550e8400-e29b-41d4-a716-446655440000', 'sales@cloudfirst.com'),
('comp-003', 'business-demo-001', 'DataViz Analytics', 'https://dataviz.ai', 'Analytics', '11-50', 2000000, 85, 'sql', 'active', '550e8400-e29b-41d4-a716-446655440000', 'info@dataviz.ai'),
('comp-004', 'business-demo-001', 'SecureNet Systems', 'https://securenet.tech', 'Security', '501-1000', 25000000, 78, 'mql', 'active', '550e8400-e29b-41d4-a716-446655440000', 'contact@securenet.tech'),
('comp-005', 'business-demo-001', 'FinTech Innovations', 'https://fintechinnov.com', 'FinTech', '1-10', 800000, 95, 'customer', 'active', '550e8400-e29b-41d4-a716-446655440000', 'hello@fintechinnov.com');"

# Companies - Batch 2
echo "[7/8] Creating Companies (Batch 2/2)..."
wrangler d1 execute $DATABASE --env $ENV --remote --command \
"INSERT OR IGNORE INTO crm_companies (id, business_id, name, website, industry, company_size, annual_revenue, lead_score, lifecycle_stage, status, owner_id, email) VALUES
('comp-006', 'business-demo-001', 'HealthTech Partners', 'https://healthtech.io', 'Healthcare', '101-500', 8000000, 72, 'lead', 'prospect', '550e8400-e29b-41d4-a716-446655440000', 'hi@healthtech.io'),
('comp-007', 'business-demo-001', 'EduSmart Platform', 'https://edusmart.edu', 'Education', '51-200', 3500000, 68, 'lead', 'prospect', '550e8400-e29b-41d4-a716-446655440000', 'contact@edusmart.edu'),
('comp-008', 'business-demo-001', 'RetailPro Solutions', 'https://retailpro.com', 'Retail', '201-500', 12000000, 81, 'opportunity', 'active', '550e8400-e29b-41d4-a716-446655440000', 'sales@retailpro.com'),
('comp-009', 'business-demo-001', 'GreenEnergy Tech', 'https://greenenergy.io', 'Clean Energy', '11-50', 4000000, 75, 'sql', 'active', '550e8400-e29b-41d4-a716-446655440000', 'info@greenenergy.io'),
('comp-010', 'business-demo-001', 'AutoDrive Systems', 'https://autodrive.ai', 'Automotive', '501-1000', 35000000, 90, 'customer', 'active', '550e8400-e29b-41d4-a716-446655440000', 'contact@autodrive.ai');"

# Contacts - Sample batch (10 key contacts)
echo "[8/8] Creating Key Contacts..."
wrangler d1 execute $DATABASE --env $ENV --remote --command \
"INSERT OR IGNORE INTO crm_contacts (id, business_id, company_id, first_name, last_name, email, job_title, seniority_level, lead_score, lifecycle_stage, status, owner_id) VALUES
('cont-001', 'business-demo-001', 'comp-001', 'Sarah', 'Johnson', 'sarah@techflow.io', 'CEO', 'c-level', 95, 'customer', 'active', '550e8400-e29b-41d4-a716-446655440000'),
('cont-002', 'business-demo-001', 'comp-002', 'David', 'Thompson', 'david@cloudfirst.com', 'CTO', 'c-level', 92, 'opportunity', 'active', '550e8400-e29b-41d4-a716-446655440000'),
('cont-003', 'business-demo-001', 'comp-003', 'Amanda', 'Foster', 'amanda@dataviz.ai', 'CDO', 'c-level', 90, 'sql', 'active', '550e8400-e29b-41d4-a716-446655440000'),
('cont-004', 'business-demo-001', 'comp-004', 'Kevin', 'OBrien', 'kevin@securenet.tech', 'VP Security', 'vp', 85, 'mql', 'active', '550e8400-e29b-41d4-a716-446655440000'),
('cont-005', 'business-demo-001', 'comp-005', 'Jennifer', 'Adams', 'jen@fintechinnov.com', 'Founder', 'owner', 98, 'customer', 'active', '550e8400-e29b-41d4-a716-446655440000'),
('cont-006', 'business-demo-001', 'comp-006', 'Christopher', 'Wilson', 'chris@healthtech.io', 'CMO', 'c-level', 80, 'lead', 'active', '550e8400-e29b-41d4-a716-446655440000'),
('cont-007', 'business-demo-001', 'comp-007', 'Jessica', 'Miller', 'jess@edusmart.edu', 'Dean', 'director', 72, 'lead', 'active', '550e8400-e29b-41d4-a716-446655440000'),
('cont-008', 'business-demo-001', 'comp-008', 'Matthew', 'Jackson', 'matt@retailpro.com', 'VP Ops', 'vp', 88, 'opportunity', 'active', '550e8400-e29b-41d4-a716-446655440000'),
('cont-009', 'business-demo-001', 'comp-009', 'Elizabeth', 'Martinez', 'liz@greenenergy.io', 'CSO', 'c-level', 82, 'sql', 'active', '550e8400-e29b-41d4-a716-446655440000'),
('cont-010', 'business-demo-001', 'comp-010', 'William', 'Rodriguez', 'will@autodrive.ai', 'CTO', 'c-level', 96, 'customer', 'active', '550e8400-e29b-41d4-a716-446655440000');"

echo ""
echo "========================================"
echo "✓ Demo Data Seeding Complete!"
echo "========================================"
echo ""
echo "Summary:"
echo "  ✓ 1 Demo Business"
echo "  ✓ 10 Chart of Accounts"
echo "  ✓ 10 CRM Companies"
echo "  ✓ 10 Key Contacts"
echo ""
echo "Next: Run seed-deals-simple.sh to add CRM deals"
