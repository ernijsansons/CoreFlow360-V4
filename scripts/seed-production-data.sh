#!/bin/bash
# Production Demo Data Seeding (Works with existing schema)
# Date: 2025-10-12

echo "========================================"
echo "CoreFlow360 V4 - Production Data Seeding"
echo "========================================"
echo ""

DATABASE="coreflow360-agents"
ENV="production"

# Get founder user ID
echo "[1/3] Getting founder user ID..."
FOUNDER_ID=$(wrangler d1 execute $DATABASE --env $ENV --remote --json --command \
"SELECT id FROM users WHERE email='founder@coreflow360.com' LIMIT 1;" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)

if [ -z "$FOUNDER_ID" ]; then
    echo "  ✗ Founder user not found!"
    exit 1
fi

echo "  ✓ Founder ID: $FOUNDER_ID"

# Get business ID
echo "[2/3] Getting business ID..."
BUSINESS_ID=$(wrangler d1 execute $DATABASE --env $ENV --remote --json --command \
"SELECT id FROM businesses LIMIT 1;" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)

if [ -z "$BUSINESS_ID" ]; then
    echo "  ✗ No business found! Creating one..."
    wrangler d1 execute $DATABASE --env $ENV --remote --command \
    "INSERT INTO businesses (id, name, slug, email, plan, status) VALUES ('bus-demo-001', 'Demo Business', 'demo-business', 'demo@coreflow360.com', 'business', 'active');"
    BUSINESS_ID="bus-demo-001"
fi

echo "  ✓ Business ID: $BUSINESS_ID"

# Seed CRM Companies
echo "[3/3] Seeding CRM Data..."
echo "  Creating companies..."
wrangler d1 execute $DATABASE --env $ENV --remote --command \
"INSERT OR IGNORE INTO crm_companies (id, business_id, name, website, industry, company_size, annual_revenue, lead_score, lifecycle_stage, status, owner_id, email) VALUES
('comp-001', '$BUSINESS_ID', 'TechFlow Solutions Inc', 'https://techflow.io', 'Software Development', '51-200', 5000000, 92, 'customer', 'active', '$FOUNDER_ID', 'contact@techflow.io'),
('comp-002', '$BUSINESS_ID', 'CloudFirst Enterprises', 'https://cloudfirst.com', 'Cloud Infrastructure', '201-500', 15000000, 88, 'opportunity', 'active', '$FOUNDER_ID', 'sales@cloudfirst.com'),
('comp-003', '$BUSINESS_ID', 'DataViz Analytics Corp', 'https://dataviz.ai', 'Data Analytics', '11-50', 2000000, 85, 'sql', 'active', '$FOUNDER_ID', 'info@dataviz.ai'),
('comp-004', '$BUSINESS_ID', 'SecureNet Systems', 'https://securenet.tech', 'Cybersecurity', '501-1000', 25000000, 78, 'mql', 'active', '$FOUNDER_ID', 'contact@securenet.tech'),
('comp-005', '$BUSINESS_ID', 'FinTech Innovations LLC', 'https://fintechinnov.com', 'Financial Technology', '1-10', 800000, 95, 'customer', 'active', '$FOUNDER_ID', 'hello@fintechinnov.com');"

wrangler d1 execute $DATABASE --env $ENV --remote --command \
"INSERT OR IGNORE INTO crm_companies (id, business_id, name, website, industry, company_size, annual_revenue, lead_score, lifecycle_stage, status, owner_id, email) VALUES
('comp-006', '$BUSINESS_ID', 'HealthTech Partners', 'https://healthtech.partners', 'Healthcare IT', '101-500', 8000000, 72, 'lead', 'prospect', '$FOUNDER_ID', 'partnerships@healthtech.partners'),
('comp-007', '$BUSINESS_ID', 'EduSmart Platform', 'https://edusmart.edu', 'Education Technology', '51-200', 3500000, 68, 'lead', 'prospect', '$FOUNDER_ID', 'contact@edusmart.edu'),
('comp-008', '$BUSINESS_ID', 'RetailPro Solutions', 'https://retailpro.com', 'Retail Technology', '201-500', 12000000, 81, 'opportunity', 'active', '$FOUNDER_ID', 'sales@retailpro.com'),
('comp-009', '$BUSINESS_ID', 'GreenEnergy Tech', 'https://greenenergy.io', 'Clean Energy', '11-50', 4000000, 75, 'sql', 'active', '$FOUNDER_ID', 'info@greenenergy.io'),
('comp-010', '$BUSINESS_ID', 'AutoDrive Systems Inc', 'https://autodrive.ai', 'Autonomous Vehicles', '501-1000', 35000000, 90, 'customer', 'active', '$FOUNDER_ID', 'contact@autodrive.ai');"

echo "  Creating contacts..."
wrangler d1 execute $DATABASE --env $ENV --remote --command \
"INSERT OR IGNORE INTO crm_contacts (id, business_id, company_id, first_name, last_name, email, job_title, seniority_level, lead_score, lifecycle_stage, status, owner_id) VALUES
('cont-001', '$BUSINESS_ID', 'comp-001', 'Sarah', 'Johnson', 'sarah.johnson@techflow.io', 'CEO & Founder', 'c-level', 95, 'customer', 'active', '$FOUNDER_ID'),
('cont-002', '$BUSINESS_ID', 'comp-001', 'Michael', 'Chen', 'michael.chen@techflow.io', 'VP of Engineering', 'vp', 88, 'customer', 'active', '$FOUNDER_ID'),
('cont-003', '$BUSINESS_ID', 'comp-002', 'David', 'Thompson', 'david.t@cloudfirst.com', 'CTO', 'c-level', 92, 'opportunity', 'active', '$FOUNDER_ID'),
('cont-004', '$BUSINESS_ID', 'comp-002', 'Lisa', 'Wang', 'lisa.wang@cloudfirst.com', 'Director', 'director', 85, 'opportunity', 'active', '$FOUNDER_ID'),
('cont-005', '$BUSINESS_ID', 'comp-003', 'Amanda', 'Foster', 'amanda@dataviz.ai', 'CDO', 'c-level', 90, 'sql', 'active', '$FOUNDER_ID');"

wrangler d1 execute $DATABASE --env $ENV --remote --command \
"INSERT OR IGNORE INTO crm_contacts (id, business_id, company_id, first_name, last_name, email, job_title, seniority_level, lead_score, lifecycle_stage, status, owner_id) VALUES
('cont-006', '$BUSINESS_ID', 'comp-004', 'Kevin', 'OBrien', 'kevin@securenet.tech', 'VP Security', 'vp', 85, 'mql', 'active', '$FOUNDER_ID'),
('cont-007', '$BUSINESS_ID', 'comp-005', 'Jennifer', 'Adams', 'jennifer@fintechinnov.com', 'Founder', 'owner', 98, 'customer', 'active', '$FOUNDER_ID'),
('cont-008', '$BUSINESS_ID', 'comp-006', 'Christopher', 'Wilson', 'c.wilson@healthtech.partners', 'CMO', 'c-level', 80, 'lead', 'active', '$FOUNDER_ID'),
('cont-009', '$BUSINESS_ID', 'comp-008', 'Matthew', 'Jackson', 'matthew.j@retailpro.com', 'VP Ops', 'vp', 88, 'opportunity', 'active', '$FOUNDER_ID'),
('cont-010', '$BUSINESS_ID', 'comp-010', 'William', 'Rodriguez', 'william.r@autodrive.ai', 'CTO', 'c-level', 96, 'customer', 'active', '$FOUNDER_ID');"

echo "  Creating deals..."
wrangler d1 execute $DATABASE --env $ENV --remote --command \
"INSERT OR IGNORE INTO crm_deals (id, business_id, company_id, contact_id, title, amount, currency, stage, pipeline, probability, expected_close_date, status, owner_id) VALUES
('deal-001', '$BUSINESS_ID', 'comp-001', 'cont-001', 'Enterprise License - Year 1', 250000, 'USD', 'closed_won', 'sales', 100, '2025-03-15', 'won', '$FOUNDER_ID'),
('deal-002', '$BUSINESS_ID', 'comp-005', 'cont-007', 'Implementation Services', 85000, 'USD', 'closed_won', 'sales', 100, '2025-04-20', 'won', '$FOUNDER_ID'),
('deal-003', '$BUSINESS_ID', 'comp-010', 'cont-010', 'Custom AI Integration', 450000, 'USD', 'closed_won', 'sales', 100, '2025-05-10', 'won', '$FOUNDER_ID'),
('deal-004', '$BUSINESS_ID', 'comp-002', 'cont-003', 'Cloud Infrastructure Package', 320000, 'USD', 'negotiation', 'sales', 75, '2025-11-15', 'open', '$FOUNDER_ID'),
('deal-005', '$BUSINESS_ID', 'comp-008', 'cont-009', 'Retail Management Suite', 180000, 'USD', 'contract', 'sales', 80, '2025-11-30', 'open', '$FOUNDER_ID');"

wrangler d1 execute $DATABASE --env $ENV --remote --command \
"INSERT OR IGNORE INTO crm_deals (id, business_id, company_id, contact_id, title, amount, currency, stage, pipeline, probability, expected_close_date, status, owner_id) VALUES
('deal-006', '$BUSINESS_ID', 'comp-003', 'cont-005', 'Analytics Platform License', 95000, 'USD', 'proposal', 'sales', 60, '2025-12-01', 'open', '$FOUNDER_ID'),
('deal-007', '$BUSINESS_ID', 'comp-004', 'cont-006', 'Security Compliance Tool', 220000, 'USD', 'demo', 'sales', 45, '2025-12-20', 'open', '$FOUNDER_ID'),
('deal-008', '$BUSINESS_ID', 'comp-006', 'cont-008', 'Healthcare Integration', 275000, 'USD', 'trial', 'sales', 40, '2026-01-05', 'open', '$FOUNDER_ID'),
('deal-009', '$BUSINESS_ID', 'comp-001', 'cont-002', 'Year 2 Renewal + Expansion', 320000, 'USD', 'negotiation', 'sales', 85, '2026-03-01', 'open', '$FOUNDER_ID'),
('deal-010', '$BUSINESS_ID', 'comp-002', 'cont-004', 'DevOps Automation Suite', 95000, 'USD', 'discovery', 'sales', 30, '2026-02-01', 'open', '$FOUNDER_ID');"

echo ""
echo "========================================"
echo "✓ Production Data Seeding Complete!"
echo "========================================"
echo ""
echo "Summary:"
echo "  ✓ 10 CRM Companies"
echo "  ✓ 10 Key Contacts"
echo "  ✓ 10 CRM Deals"
echo ""
echo "Total Pipeline Value: $2,290,000"
echo "Won Deals: $785,000"
echo ""
