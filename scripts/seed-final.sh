#!/bin/bash
# Final Production Data Seeding
# Date: 2025-10-12

echo "========================================"
echo "CoreFlow360 V4 - Final Data Seeding"
echo "========================================"
echo ""

DATABASE="coreflow360-agents"
ENV="production"

# Use known IDs
FOUNDER_ID="550e8400-e29b-41d4-a716-446655440000"
BUSINESS_ID="business-founder-001"

echo "Using:"
echo "  Founder ID: $FOUNDER_ID"
echo "  Business ID: $BUSINESS_ID"
echo ""

# Seed CRM Companies
echo "[1/3] Seeding 10 CRM Companies..."
wrangler d1 execute $DATABASE --env $ENV --remote --command \
"INSERT OR IGNORE INTO crm_companies (id, business_id, name, website, industry, company_size, annual_revenue, lead_score, lifecycle_stage, status, owner_id, email) VALUES
('comp-demo-001', '$BUSINESS_ID', 'TechFlow Solutions Inc', 'https://techflow.io', 'Software Development', '51-200', 5000000, 92, 'customer', 'active', '$FOUNDER_ID', 'contact@techflow.io'),
('comp-demo-002', '$BUSINESS_ID', 'CloudFirst Enterprises', 'https://cloudfirst.com', 'Cloud Infrastructure', '201-500', 15000000, 88, 'opportunity', 'active', '$FOUNDER_ID', 'sales@cloudfirst.com'),
('comp-demo-003', '$BUSINESS_ID', 'DataViz Analytics Corp', 'https://dataviz.ai', 'Data Analytics', '11-50', 2000000, 85, 'sql', 'active', '$FOUNDER_ID', 'info@dataviz.ai'),
('comp-demo-004', '$BUSINESS_ID', 'SecureNet Systems', 'https://securenet.tech', 'Cybersecurity', '501-1000', 25000000, 78, 'mql', 'active', '$FOUNDER_ID', 'contact@securenet.tech'),
('comp-demo-005', '$BUSINESS_ID', 'FinTech Innovations LLC', 'https://fintechinnov.com', 'Financial Technology', '1-10', 800000, 95, 'customer', 'active', '$FOUNDER_ID', 'hello@fintechinnov.com'),
('comp-demo-006', '$BUSINESS_ID', 'HealthTech Partners', 'https://healthtech.partners', 'Healthcare IT', '101-500', 8000000, 72, 'lead', 'prospect', '$FOUNDER_ID', 'partnerships@healthtech.partners'),
('comp-demo-007', '$BUSINESS_ID', 'EduSmart Platform', 'https://edusmart.edu', 'Education Technology', '51-200', 3500000, 68, 'lead', 'prospect', '$FOUNDER_ID', 'contact@edusmart.edu'),
('comp-demo-008', '$BUSINESS_ID', 'RetailPro Solutions', 'https://retailpro.com', 'Retail Technology', '201-500', 12000000, 81, 'opportunity', 'active', '$FOUNDER_ID', 'sales@retailpro.com'),
('comp-demo-009', '$BUSINESS_ID', 'GreenEnergy Tech', 'https://greenenergy.io', 'Clean Energy', '11-50', 4000000, 75, 'sql', 'active', '$FOUNDER_ID', 'info@greenenergy.io'),
('comp-demo-010', '$BUSINESS_ID', 'AutoDrive Systems Inc', 'https://autodrive.ai', 'Autonomous Vehicles', '501-1000', 35000000, 90, 'customer', 'active', '$FOUNDER_ID', 'contact@autodrive.ai');"

echo "  ✓ Companies created"

# Seed CRM Contacts
echo "[2/3] Seeding 10 Key Contacts..."
wrangler d1 execute $DATABASE --env $ENV --remote --command \
"INSERT OR IGNORE INTO crm_contacts (id, business_id, company_id, first_name, last_name, email, job_title, seniority_level, lead_score, lifecycle_stage, status, owner_id) VALUES
('cont-demo-001', '$BUSINESS_ID', 'comp-demo-001', 'Sarah', 'Johnson', 'sarah.johnson@techflow.io', 'CEO & Founder', 'c-level', 95, 'customer', 'active', '$FOUNDER_ID'),
('cont-demo-002', '$BUSINESS_ID', 'comp-demo-001', 'Michael', 'Chen', 'michael.chen@techflow.io', 'VP of Engineering', 'vp', 88, 'customer', 'active', '$FOUNDER_ID'),
('cont-demo-003', '$BUSINESS_ID', 'comp-demo-002', 'David', 'Thompson', 'david.t@cloudfirst.com', 'CTO', 'c-level', 92, 'opportunity', 'active', '$FOUNDER_ID'),
('cont-demo-004', '$BUSINESS_ID', 'comp-demo-002', 'Lisa', 'Wang', 'lisa.wang@cloudfirst.com', 'Director of Ops', 'director', 85, 'opportunity', 'active', '$FOUNDER_ID'),
('cont-demo-005', '$BUSINESS_ID', 'comp-demo-003', 'Amanda', 'Foster', 'amanda@dataviz.ai', 'Chief Data Officer', 'c-level', 90, 'sql', 'active', '$FOUNDER_ID'),
('cont-demo-006', '$BUSINESS_ID', 'comp-demo-004', 'Kevin', 'OBrien', 'kevin@securenet.tech', 'VP of Security', 'vp', 85, 'mql', 'active', '$FOUNDER_ID'),
('cont-demo-007', '$BUSINESS_ID', 'comp-demo-005', 'Jennifer', 'Adams', 'jennifer@fintechinnov.com', 'Founder & CEO', 'owner', 98, 'customer', 'active', '$FOUNDER_ID'),
('cont-demo-008', '$BUSINESS_ID', 'comp-demo-006', 'Christopher', 'Wilson', 'c.wilson@healthtech.partners', 'Chief Medical Officer', 'c-level', 80, 'lead', 'active', '$FOUNDER_ID'),
('cont-demo-009', '$BUSINESS_ID', 'comp-demo-008', 'Matthew', 'Jackson', 'matthew.j@retailpro.com', 'VP of Operations', 'vp', 88, 'opportunity', 'active', '$FOUNDER_ID'),
('cont-demo-010', '$BUSINESS_ID', 'comp-demo-010', 'William', 'Rodriguez', 'william.r@autodrive.ai', 'Chief Technology Officer', 'c-level', 96, 'customer', 'active', '$FOUNDER_ID');"

echo "  ✓ Contacts created"

# Seed CRM Deals
echo "[3/3] Seeding 10 CRM Deals..."
wrangler d1 execute $DATABASE --env $ENV --remote --command \
"INSERT OR IGNORE INTO crm_deals (id, business_id, company_id, contact_id, title, amount, currency, stage, pipeline, probability, expected_close_date, status, owner_id) VALUES
('deal-demo-001', '$BUSINESS_ID', 'comp-demo-001', 'cont-demo-001', 'Enterprise License - Year 1', 250000, 'USD', 'closed_won', 'sales', 100, '2025-03-15', 'won', '$FOUNDER_ID'),
('deal-demo-002', '$BUSINESS_ID', 'comp-demo-005', 'cont-demo-007', 'Implementation Services', 85000, 'USD', 'closed_won', 'sales', 100, '2025-04-20', 'won', '$FOUNDER_ID'),
('deal-demo-003', '$BUSINESS_ID', 'comp-demo-010', 'cont-demo-010', 'Custom AI Integration', 450000, 'USD', 'closed_won', 'sales', 100, '2025-05-10', 'won', '$FOUNDER_ID'),
('deal-demo-004', '$BUSINESS_ID', 'comp-demo-002', 'cont-demo-003', 'Cloud Infrastructure Package', 320000, 'USD', 'negotiation', 'sales', 75, '2025-11-15', 'open', '$FOUNDER_ID'),
('deal-demo-005', '$BUSINESS_ID', 'comp-demo-008', 'cont-demo-009', 'Retail Management Suite', 180000, 'USD', 'contract', 'sales', 80, '2025-11-30', 'open', '$FOUNDER_ID'),
('deal-demo-006', '$BUSINESS_ID', 'comp-demo-003', 'cont-demo-005', 'Analytics Platform License', 95000, 'USD', 'proposal', 'sales', 60, '2025-12-01', 'open', '$FOUNDER_ID'),
('deal-demo-007', '$BUSINESS_ID', 'comp-demo-004', 'cont-demo-006', 'Security Compliance Tool', 220000, 'USD', 'demo', 'sales', 45, '2025-12-20', 'open', '$FOUNDER_ID'),
('deal-demo-008', '$BUSINESS_ID', 'comp-demo-006', 'cont-demo-008', 'Healthcare Integration Platform', 275000, 'USD', 'trial', 'sales', 40, '2026-01-05', 'open', '$FOUNDER_ID'),
('deal-demo-009', '$BUSINESS_ID', 'comp-demo-001', 'cont-demo-002', 'Year 2 Renewal + Expansion', 320000, 'USD', 'negotiation', 'sales', 85, '2026-03-01', 'open', '$FOUNDER_ID'),
('deal-demo-010', '$BUSINESS_ID', 'comp-demo-002', 'cont-demo-004', 'DevOps Automation Suite', 95000, 'USD', 'discovery', 'sales', 30, '2026-02-01', 'open', '$FOUNDER_ID');"

echo "  ✓ Deals created"

echo ""
echo "========================================"
echo "✓ Production Data Seeding Complete!"
echo "========================================"
echo ""
echo "Summary:"
echo "  ✓ 10 CRM Companies (diverse industries)"
echo "  ✓ 10 Key Contacts (C-level & VPs)"
echo "  ✓ 10 CRM Deals across pipeline"
echo ""
echo "Pipeline Breakdown:"
echo "  - Won Deals: 3 (\$785,000)"
echo "  - Negotiation: 2 (\$640,000)"
echo "  - Proposal: 1 (\$95,000)"
echo "  - Demo/Trial: 2 (\$495,000)"
echo "  - Discovery: 1 (\$95,000)"
echo "  - Contract: 1 (\$180,000)"
echo ""
echo "Total Pipeline Value: \$2,290,000"
echo ""
