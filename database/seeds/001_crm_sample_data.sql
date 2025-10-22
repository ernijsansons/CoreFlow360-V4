-- CRM Sample Data Seed
-- Creates realistic Fortune 50-level CRM data for testing

-- Insert Sample Companies
INSERT INTO crm_companies (id, business_id, name, website, domain, industry, company_size, annual_revenue, lead_score, lifecycle_stage, status, owner_id)
VALUES
('company-001', 'business-founder-001', 'Acme Corporation', 'https://acme.com', 'acme.com', 'Technology', '501-1000', 50000000, 85, 'customer', 'active', '550e8400-e29b-41d4-a716-446655440000'),
('company-002', 'business-founder-001', 'TechStart Inc', 'https://techstart.io', 'techstart.io', 'Software', '51-200', 5000000, 72, 'opportunity', 'active', '550e8400-e29b-41d4-a716-446655440000'),
('company-003', 'business-founder-001', 'Global Enterprises', 'https://globalent.com', 'globalent.com', 'Manufacturing', '5001-10000', 250000000, 65, 'sql', 'active', '550e8400-e29b-41d4-a716-446655440000'),
('company-004', 'business-founder-001', 'InnovateLabs', 'https://innovatelabs.com', 'innovatelabs.com', 'Research', '11-50', 2000000, 90, 'mql', 'active', '550e8400-e29b-41d4-a716-446655440000'),
('company-005', 'business-founder-001', 'DataDriven Solutions', 'https://datadriven.io', 'datadriven.io', 'Analytics', '201-500', 15000000, 78, 'lead', 'active', '550e8400-e29b-41d4-a716-446655440000');

-- Insert Sample Contacts
INSERT INTO crm_contacts (id, business_id, company_id, first_name, last_name, email, job_title, seniority_level, lead_score, lifecycle_stage, status, owner_id)
VALUES
('contact-001', 'business-founder-001', 'company-001', 'John', 'Smith', 'john.smith@acme.com', 'CEO', 'c-level', 90, 'customer', 'active', '550e8400-e29b-41d4-a716-446655440000'),
('contact-002', 'business-founder-001', 'company-001', 'Sarah', 'Johnson', 'sarah.j@acme.com', 'VP of Sales', 'vp', 85, 'customer', 'active', '550e8400-e29b-41d4-a716-446655440000'),
('contact-003', 'business-founder-001', 'company-002', 'Michael', 'Chen', 'mchen@techstart.io', 'CTO', 'c-level', 75, 'opportunity', 'active', '550e8400-e29b-41d4-a716-446655440000'),
('contact-004', 'business-founder-001', 'company-003', 'Emily', 'Rodriguez', 'emily.r@globalent.com', 'Director of Operations', 'director', 68, 'sql', 'active', '550e8400-e29b-41d4-a716-446655440000'),
('contact-005', 'business-founder-001', 'company-004', 'David', 'Kim', 'dkim@innovatelabs.com', 'Head of Product', 'director', 92, 'mql', 'active', '550e8400-e29b-41d4-a716-446655440000'),
('contact-006', 'business-founder-001', 'company-005', 'Lisa', 'Anderson', 'landerson@datadriven.io', 'VP Engineering', 'vp', 80, 'lead', 'active', '550e8400-e29b-41d4-a716-446655440000');

-- Insert Sample Deals
INSERT INTO crm_deals (id, business_id, company_id, primary_contact_id, name, deal_type, amount, stage, probability, expected_close_date, status, owner_id)
VALUES
('deal-001', 'business-founder-001', 'company-001', 'contact-001', 'Acme Enterprise License Renewal', 'renewal', 150000, 'negotiation', 90, DATE('now', '+30 days'), 'open', '550e8400-e29b-41d4-a716-446655440000'),
('deal-002', 'business-founder-001', 'company-002', 'contact-003', 'TechStart Platform Implementation', 'new_business', 85000, 'proposal', 65, DATE('now', '+45 days'), 'open', '550e8400-e29b-41d4-a716-446655440000'),
('deal-003', 'business-founder-001', 'company-003', 'contact-004', 'Global Enterprises Pilot Program', 'new_business', 250000, 'discovery', 40, DATE('now', '+90 days'), 'open', '550e8400-e29b-41d4-a716-446655440000'),
('deal-004', 'business-founder-001', 'company-004', 'contact-005', 'InnovateLabs Growth Package', 'upsell', 45000, 'closed_won', 100, DATE('now', '-15 days'), 'won', '550e8400-e29b-41d4-a716-446655440000'),
('deal-005', 'business-founder-001', 'company-005', 'contact-006', 'DataDriven Analytics Suite', 'new_business', 120000, 'qualification', 25, DATE('now', '+60 days'), 'open', '550e8400-e29b-41d4-a716-446655440000');

-- Insert Sample Activities
INSERT INTO crm_activities (id, business_id, type, subject, company_id, contact_id, deal_id, scheduled_at, status, owner_id, outcome)
VALUES
('activity-001', 'business-founder-001', 'call', 'Q1 Business Review Call', 'company-001', 'contact-001', 'deal-001', DATETIME('now', '+2 days', '10:00'), 'pending', '550e8400-e29b-41d4-a716-446655440000', NULL),
('activity-002', 'business-founder-001', 'meeting', 'Product Demo Session', 'company-002', 'contact-003', 'deal-002', DATETIME('now', '+5 days', '14:00'), 'pending', '550e8400-e29b-41d4-a716-446655440000', NULL),
('activity-003', 'business-founder-001', 'email', 'Follow-up on Proposal', 'company-002', 'contact-003', 'deal-002', DATETIME('now', '-1 days'), 'completed', '550e8400-e29b-41d4-a716-446655440000', 'positive'),
('activity-004', 'business-founder-001', 'call', 'Discovery Call - Pain Points Discussion', 'company-003', 'contact-004', 'deal-003', DATETIME('now', '-3 days'), 'completed', '550e8400-e29b-41d4-a716-446655440000', 'positive'),
('activity-005', 'business-founder-001', 'meeting', 'Contract Signing Meeting', 'company-004', 'contact-005', 'deal-004', DATETIME('now', '-20 days'), 'completed', '550e8400-e29b-41d4-a716-446655440000', 'positive');

-- Insert Sample Leads
INSERT INTO crm_leads (id, business_id, company_id, contact_id, title, source, lead_score, qualification_status, estimated_budget, owner_id)
VALUES
('lead-001', 'business-founder-001', 'company-005', 'contact-006', 'Interested in Analytics Platform', 'website', 78, 'working', 100000, '550e8400-e29b-41d4-a716-446655440000'),
('lead-002', 'business-founder-001', NULL, NULL, 'Enterprise Demo Request', 'paid_ad', 65, 'new', 150000, '550e8400-e29b-41d4-a716-446655440000'),
('lead-003', 'business-founder-001', NULL, NULL, 'Conference Booth Visitor', 'event', 55, 'qualified', 50000, '550e8400-e29b-41d4-a716-446655440000');

-- Insert Sample Notes
INSERT INTO crm_notes (id, business_id, title, content, company_id, deal_id, created_by)
VALUES
('note-001', 'business-founder-001', 'Q1 Strategy Discussion', 'Discussed renewal terms. Customer very happy with current service. Looking to expand to 3 additional departments.', 'company-001', 'deal-001', '550e8400-e29b-41d4-a716-446655440000'),
('note-002', 'business-founder-001', 'Technical Requirements', 'Need integration with Salesforce and HubSpot. Timeline is aggressive - wants go-live in 6 weeks.', 'company-002', 'deal-002', '550e8400-e29b-41d4-a716-446655440000'),
('note-003', 'business-founder-001', 'Budget Concerns', 'CFO concerned about ROI timeline. Need to prepare detailed cost-benefit analysis.', 'company-003', 'deal-003', '550e8400-e29b-41d4-a716-446655440000');
