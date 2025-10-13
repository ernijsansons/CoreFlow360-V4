#!/bin/bash
# Quick Demo Data Seeding - Inserts 5 companies with contacts and deals
# Usage: bash scripts/quick-seed-demo-data.sh

echo "🌱 Seeding demo data to production database..."

# Insert 5 Demo Companies
echo "📊 Inserting companies..."
wrangler d1 execute coreflow360-agents --env production --remote --command "
INSERT OR IGNORE INTO crm_companies (id, business_id, name, website, domain, industry, company_size, annual_revenue, lead_score, lifecycle_stage, status, owner_id)
VALUES
('demo-001', 'business-founder-001', 'Tech Innovators Inc', 'https://techinnovators.io', 'techinnovators.io', 'SaaS', '101-500', 25000000, 88, 'customer', 'active', '550e8400-e29b-41d4-a716-446655440000'),
('demo-002', 'business-founder-001', 'Digital Solutions LLC', 'https://digitalsolutions.com', 'digitalsolutions.com', 'Consulting', '11-50', 3500000, 76, 'opportunity', 'active', '550e8400-e29b-41d4-a716-446655440000'),
('demo-003', 'business-founder-001', 'CloudFirst Partners', 'https://cloudfirst.io', 'cloudfirst.io', 'Cloud Services', '51-200', 12000000, 82, 'sql', 'active', '550e8400-e29b-41d4-a716-446655440000'),
('demo-004', 'business-founder-001', 'AI Ventures Corp', 'https://aiventures.ai', 'aiventures.ai', 'AI/ML', '201-500', 45000000, 94, 'customer', 'active', '550e8400-e29b-41d4-a716-446655440000'),
('demo-005', 'business-founder-001', 'StartupBoost Inc', 'https://startupboost.com', 'startupboost.com', 'Accelerator', '1-10', 850000, 68, 'mql', 'active', '550e8400-e29b-41d4-a716-446655440000')
"

# Insert Demo Contacts
echo "👥 Inserting contacts..."
wrangler d1 execute coreflow360-agents --env production --remote --command "
INSERT OR IGNORE INTO crm_contacts (id, business_id, company_id, first_name, last_name, email, job_title, seniority_level, lead_score, lifecycle_stage, status, owner_id)
VALUES
('demo-contact-001', 'business-founder-001', 'demo-001', 'Alex', 'Martinez', 'alex.martinez@techinnovators.io', 'CEO & Founder', 'c-level', 92, 'customer', 'active', '550e8400-e29b-41d4-a716-446655440000'),
('demo-contact-002', 'business-founder-001', 'demo-001', 'Jordan', 'Lee', 'jordan.lee@techinnovators.io', 'VP of Engineering', 'vp', 87, 'customer', 'active', '550e8400-e29b-41d4-a716-446655440000'),
('demo-contact-003', 'business-founder-001', 'demo-002', 'Taylor', 'Johnson', 'taylor.j@digitalsolutions.com', 'Managing Director', 'c-level', 78, 'opportunity', 'active', '550e8400-e29b-41d4-a716-446655440000'),
('demo-contact-004', 'business-founder-001', 'demo-003', 'Sam', 'Patel', 'sam.patel@cloudfirst.io', 'Head of Sales', 'director', 80, 'sql', 'active', '550e8400-e29b-41d4-a716-446655440000'),
('demo-contact-005', 'business-founder-001', 'demo-004', 'Morgan', 'Chen', 'morgan.chen@aiventures.ai', 'Chief Technology Officer', 'c-level', 96, 'customer', 'active', '550e8400-e29b-41d4-a716-446655440000')
"

# Insert Demo Deals
echo "💰 Inserting deals..."
wrangler d1 execute coreflow360-agents --env production --remote --command "
INSERT OR IGNORE INTO crm_deals (id, business_id, company_id, primary_contact_id, name, deal_type, amount, stage, probability, expected_close_date, status, owner_id)
VALUES
('demo-deal-001', 'business-founder-001', 'demo-001', 'demo-contact-001', 'Enterprise Platform Expansion', 'upsell', 185000, 'negotiation', 85, DATE('now', '+25 days'), 'open', '550e8400-e29b-41d4-a716-446655440000'),
('demo-deal-002', 'business-founder-001', 'demo-002', 'demo-contact-003', 'Digital Transformation Package', 'new_business', 95000, 'proposal', 60, DATE('now', '+40 days'), 'open', '550e8400-e29b-41d4-a716-446655440000'),
('demo-deal-003', 'business-founder-001', 'demo-003', 'demo-contact-004', 'Cloud Migration Services', 'new_business', 320000, 'discovery', 35, DATE('now', '+75 days'), 'open', '550e8400-e29b-41d4-a716-446655440000'),
('demo-deal-004', 'business-founder-001', 'demo-004', 'demo-contact-005', 'AI Integration Suite', 'renewal', 425000, 'closed_won', 100, DATE('now', '-10 days'), 'won', '550e8400-e29b-41d4-a716-446655440000')
"

echo "✅ Demo data seeded successfully!"
echo ""
echo "📊 Created:"
echo "  - 5 Companies"
echo "  - 5 Contacts"
echo "  - 4 Deals"
echo ""
echo "🌐 View at: https://production.coreflow360-frontend.pages.dev/crm/companies"
echo "🔑 Login: founder@coreflow360.com / Founder2025!"
