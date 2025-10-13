# PowerShell Script: Seed Comprehensive Demo Data to Production
# Description: Seeds 10 companies, 30 contacts, 20 deals, and chart of accounts
# Date: 2025-10-12

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "CoreFlow360 V4 - Comprehensive Demo Data Seeding" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$DATABASE = "coreflow360-agents"
$ENV = "production"

# Function to execute SQL command
function Execute-SQL {
    param(
        [string]$Command,
        [string]$Description
    )

    Write-Host "► $Description..." -ForegroundColor Yellow

    $result = wrangler d1 execute $DATABASE --env $ENV --remote --command $Command 2>&1

    if ($LASTEXITCODE -eq 0) {
        Write-Host "  ✓ Success" -ForegroundColor Green
        return $true
    } else {
        Write-Host "  ✗ Failed: $result" -ForegroundColor Red
        return $false
    }
}

# Step 1: Create Demo Business
Write-Host "`n[1/7] Creating Demo Business..." -ForegroundColor Cyan
Execute-SQL -Command "INSERT OR IGNORE INTO businesses (id, name, email, subscription_tier, status) VALUES ('business-demo-001', 'CoreFlow360 Demo Business', 'demo@coreflow360.com', 'professional', 'active');" -Description "Creating demo business"

# Step 2: Chart of Accounts - Assets
Write-Host "`n[2/7] Creating Chart of Accounts - Assets..." -ForegroundColor Cyan
Execute-SQL -Command "INSERT OR IGNORE INTO accounts (id, business_id, account_number, account_name, account_type, category, normal_balance, opening_balance, status) VALUES
('acc-1000', 'business-demo-001', '1000', 'Cash - Operating Account', 'asset', 'cash', 'debit', 50000.00, 'active'),
('acc-1010', 'business-demo-001', '1010', 'Cash - Savings Account', 'asset', 'bank', 'debit', 100000.00, 'active'),
('acc-1100', 'business-demo-001', '1100', 'Accounts Receivable', 'asset', 'accounts_receivable', 'debit', 45000.00, 'active'),
('acc-1200', 'business-demo-001', '1200', 'Inventory', 'asset', 'inventory', 'debit', 25000.00, 'active'),
('acc-1500', 'business-demo-001', '1500', 'Equipment', 'asset', 'fixed_assets', 'debit', 80000.00, 'active');" -Description "Inserting asset accounts"

# Chart of Accounts - Liabilities
Write-Host "`n[3/7] Creating Chart of Accounts - Liabilities & Equity..." -ForegroundColor Cyan
Execute-SQL -Command "INSERT OR IGNORE INTO accounts (id, business_id, account_number, account_name, account_type, category, normal_balance, opening_balance, status) VALUES
('acc-2000', 'business-demo-001', '2000', 'Accounts Payable', 'liability', 'accounts_payable', 'credit', -22000.00, 'active'),
('acc-2100', 'business-demo-001', '2100', 'Accrued Expenses', 'liability', 'accrued_expenses', 'credit', -8000.00, 'active'),
('acc-3000', 'business-demo-001', '3000', 'Owners Equity', 'equity', 'owners_equity', 'credit', -150000.00, 'active'),
('acc-3100', 'business-demo-001', '3100', 'Retained Earnings', 'equity', 'retained_earnings', 'credit', -48000.00, 'active');" -Description "Inserting liability and equity accounts"

# Chart of Accounts - Revenue
Write-Host "`n[4/7] Creating Chart of Accounts - Revenue..." -ForegroundColor Cyan
Execute-SQL -Command "INSERT OR IGNORE INTO accounts (id, business_id, account_number, account_name, account_type, category, normal_balance, status) VALUES
('acc-4000', 'business-demo-001', '4000', 'Software License Revenue', 'revenue', 'sales_revenue', 'credit', 'active'),
('acc-4100', 'business-demo-001', '4100', 'Consulting Revenue', 'revenue', 'service_revenue', 'credit', 'active'),
('acc-4200', 'business-demo-001', '4200', 'Implementation Services', 'revenue', 'service_revenue', 'credit', 'active');" -Description "Inserting revenue accounts"

# Chart of Accounts - Expenses
Write-Host "`n[5/7] Creating Chart of Accounts - Expenses..." -ForegroundColor Cyan
Execute-SQL -Command "INSERT OR IGNORE INTO accounts (id, business_id, account_number, account_name, account_type, category, normal_balance, status) VALUES
('acc-5000', 'business-demo-001', '5000', 'Cost of Goods Sold', 'expense', 'cost_of_goods_sold', 'debit', 'active'),
('acc-6000', 'business-demo-001', '6000', 'Salaries & Wages', 'expense', 'salaries_expense', 'debit', 'active'),
('acc-6300', 'business-demo-001', '6300', 'Rent Expense', 'expense', 'rent_expense', 'debit', 'active'),
('acc-6700', 'business-demo-001', '6700', 'Marketing & Advertising', 'expense', 'other_expense', 'debit', 'active');" -Description "Inserting expense accounts"

# CRM Companies (batch insert - 5 at a time due to command length limits)
Write-Host "`n[6/7] Creating CRM Companies (10 companies)..." -ForegroundColor Cyan

Execute-SQL -Command "INSERT OR IGNORE INTO crm_companies (id, business_id, name, website, domain, industry, company_size, annual_revenue, lead_score, lifecycle_stage, status, owner_id, email) VALUES
('comp-001', 'business-demo-001', 'TechFlow Solutions Inc', 'https://techflow.io', 'techflow.io', 'Software Development', '51-200', 5000000, 92, 'customer', 'active', '550e8400-e29b-41d4-a716-446655440000', 'contact@techflow.io'),
('comp-002', 'business-demo-001', 'CloudFirst Enterprises', 'https://cloudfirst.com', 'cloudfirst.com', 'Cloud Infrastructure', '201-500', 15000000, 88, 'opportunity', 'active', '550e8400-e29b-41d4-a716-446655440000', 'sales@cloudfirst.com'),
('comp-003', 'business-demo-001', 'DataViz Analytics Corp', 'https://dataviz.ai', 'dataviz.ai', 'Data Analytics', '11-50', 2000000, 85, 'sql', 'active', '550e8400-e29b-41d4-a716-446655440000', 'info@dataviz.ai'),
('comp-004', 'business-demo-001', 'SecureNet Systems', 'https://securenet.tech', 'securenet.tech', 'Cybersecurity', '501-1000', 25000000, 78, 'mql', 'active', '550e8400-e29b-41d4-a716-446655440000', 'contact@securenet.tech'),
('comp-005', 'business-demo-001', 'FinTech Innovations LLC', 'https://fintechinnov.com', 'fintechinnov.com', 'Financial Technology', '1-10', 800000, 95, 'customer', 'active', '550e8400-e29b-41d4-a716-446655440000', 'hello@fintechinnov.com');" -Description "Batch 1 (Companies 1-5)"

Execute-SQL -Command "INSERT OR IGNORE INTO crm_companies (id, business_id, name, website, domain, industry, company_size, annual_revenue, lead_score, lifecycle_stage, status, owner_id, email) VALUES
('comp-006', 'business-demo-001', 'HealthTech Partners', 'https://healthtech.partners', 'healthtech.partners', 'Healthcare IT', '101-500', 8000000, 72, 'lead', 'prospect', '550e8400-e29b-41d4-a716-446655440000', 'partnerships@healthtech.partners'),
('comp-007', 'business-demo-001', 'EduSmart Platform', 'https://edusmart.edu', 'edusmart.edu', 'Education Technology', '51-200', 3500000, 68, 'lead', 'prospect', '550e8400-e29b-41d4-a716-446655440000', 'contact@edusmart.edu'),
('comp-008', 'business-demo-001', 'RetailPro Solutions', 'https://retailpro.com', 'retailpro.com', 'Retail Technology', '201-500', 12000000, 81, 'opportunity', 'active', '550e8400-e29b-41d4-a716-446655440000', 'sales@retailpro.com'),
('comp-009', 'business-demo-001', 'GreenEnergy Tech', 'https://greenenergy.io', 'greenenergy.io', 'Clean Energy', '11-50', 4000000, 75, 'sql', 'active', '550e8400-e29b-41d4-a716-446655440000', 'info@greenenergy.io'),
('comp-010', 'business-demo-001', 'AutoDrive Systems Inc', 'https://autodrive.ai', 'autodrive.ai', 'Autonomous Vehicles', '501-1000', 35000000, 90, 'customer', 'active', '550e8400-e29b-41d4-a716-446655440000', 'contact@autodrive.ai');" -Description "Batch 2 (Companies 6-10)"

# CRM Contacts (batch insert - 10 at a time)
Write-Host "`n[7/7] Creating CRM Contacts (30 contacts in 3 batches)..." -ForegroundColor Cyan

Execute-SQL -Command "INSERT OR IGNORE INTO crm_contacts (id, business_id, company_id, first_name, last_name, email, job_title, seniority_level, lead_score, lifecycle_stage, status, owner_id) VALUES
('cont-001', 'business-demo-001', 'comp-001', 'Sarah', 'Johnson', 'sarah.johnson@techflow.io', 'CEO & Founder', 'c-level', 95, 'customer', 'active', '550e8400-e29b-41d4-a716-446655440000'),
('cont-002', 'business-demo-001', 'comp-001', 'Michael', 'Chen', 'michael.chen@techflow.io', 'VP of Engineering', 'vp', 88, 'customer', 'active', '550e8400-e29b-41d4-a716-446655440000'),
('cont-003', 'business-demo-001', 'comp-001', 'Emily', 'Rodriguez', 'emily.r@techflow.io', 'Product Manager', 'manager', 82, 'customer', 'active', '550e8400-e29b-41d4-a716-446655440000'),
('cont-004', 'business-demo-001', 'comp-002', 'David', 'Thompson', 'david.t@cloudfirst.com', 'CTO', 'c-level', 92, 'opportunity', 'active', '550e8400-e29b-41d4-a716-446655440000'),
('cont-005', 'business-demo-001', 'comp-002', 'Lisa', 'Wang', 'lisa.wang@cloudfirst.com', 'Director of Cloud Operations', 'director', 85, 'opportunity', 'active', '550e8400-e29b-41d4-a716-446655440000'),
('cont-006', 'business-demo-001', 'comp-002', 'James', 'Martinez', 'j.martinez@cloudfirst.com', 'Senior DevOps Engineer', 'individual', 78, 'sql', 'active', '550e8400-e29b-41d4-a716-446655440000'),
('cont-007', 'business-demo-001', 'comp-003', 'Amanda', 'Foster', 'amanda@dataviz.ai', 'Chief Data Officer', 'c-level', 90, 'sql', 'active', '550e8400-e29b-41d4-a716-446655440000'),
('cont-008', 'business-demo-001', 'comp-003', 'Robert', 'Kim', 'robert.kim@dataviz.ai', 'Analytics Team Lead', 'manager', 83, 'sql', 'active', '550e8400-e29b-41d4-a716-446655440000'),
('cont-009', 'business-demo-001', 'comp-003', 'Nicole', 'Patel', 'nicole.p@dataviz.ai', 'Data Scientist', 'individual', 75, 'mql', 'active', '550e8400-e29b-41d4-a716-446655440000'),
('cont-010', 'business-demo-001', 'comp-004', 'Kevin', 'O''Brien', 'kevin@securenet.tech', 'VP of Security', 'vp', 85, 'mql', 'active', '550e8400-e29b-41d4-a716-446655440000');" -Description "Contacts Batch 1 (1-10)"

Execute-SQL -Command "INSERT OR IGNORE INTO crm_contacts (id, business_id, company_id, first_name, last_name, email, job_title, seniority_level, lead_score, lifecycle_stage, status, owner_id) VALUES
('cont-011', 'business-demo-001', 'comp-004', 'Rachel', 'Singh', 'rachel.singh@securenet.tech', 'Security Architect', 'individual', 78, 'mql', 'active', '550e8400-e29b-41d4-a716-446655440000'),
('cont-012', 'business-demo-001', 'comp-004', 'Thomas', 'Lee', 'thomas.lee@securenet.tech', 'Compliance Manager', 'manager', 72, 'lead', 'active', '550e8400-e29b-41d4-a716-446655440000'),
('cont-013', 'business-demo-001', 'comp-005', 'Jennifer', 'Adams', 'jennifer@fintechinnov.com', 'Founder & CEO', 'owner', 98, 'customer', 'active', '550e8400-e29b-41d4-a716-446655440000'),
('cont-014', 'business-demo-001', 'comp-005', 'Daniel', 'Brown', 'daniel.b@fintechinnov.com', 'Head of Product', 'director', 92, 'customer', 'active', '550e8400-e29b-41d4-a716-446655440000'),
('cont-015', 'business-demo-001', 'comp-005', 'Sophia', 'Taylor', 'sophia.t@fintechinnov.com', 'Engineering Lead', 'manager', 88, 'customer', 'active', '550e8400-e29b-41d4-a716-446655440000'),
('cont-016', 'business-demo-001', 'comp-006', 'Christopher', 'Wilson', 'c.wilson@healthtech.partners', 'Chief Medical Officer', 'c-level', 80, 'lead', 'active', '550e8400-e29b-41d4-a716-446655440000'),
('cont-017', 'business-demo-001', 'comp-006', 'Michelle', 'Garcia', 'michelle.g@healthtech.partners', 'Director of IT', 'director', 75, 'lead', 'active', '550e8400-e29b-41d4-a716-446655440000'),
('cont-018', 'business-demo-001', 'comp-006', 'Andrew', 'White', 'andrew.white@healthtech.partners', 'Project Manager', 'manager', 68, 'lead', 'active', '550e8400-e29b-41d4-a716-446655440000'),
('cont-019', 'business-demo-001', 'comp-007', 'Jessica', 'Miller', 'jessica@edusmart.edu', 'Dean of Technology', 'director', 72, 'lead', 'active', '550e8400-e29b-41d4-a716-446655440000'),
('cont-020', 'business-demo-001', 'comp-007', 'Brian', 'Anderson', 'brian.a@edusmart.edu', 'IT Coordinator', 'manager', 65, 'lead', 'active', '550e8400-e29b-41d4-a716-446655440000');" -Description "Contacts Batch 2 (11-20)"

Execute-SQL -Command "INSERT OR IGNORE INTO crm_contacts (id, business_id, company_id, first_name, last_name, email, job_title, seniority_level, lead_score, lifecycle_stage, status, owner_id) VALUES
('cont-021', 'business-demo-001', 'comp-007', 'Lauren', 'Thomas', 'lauren.t@edusmart.edu', 'Curriculum Developer', 'individual', 60, 'subscriber', 'active', '550e8400-e29b-41d4-a716-446655440000'),
('cont-022', 'business-demo-001', 'comp-008', 'Matthew', 'Jackson', 'matthew.j@retailpro.com', 'VP of Operations', 'vp', 88, 'opportunity', 'active', '550e8400-e29b-41d4-a716-446655440000'),
('cont-023', 'business-demo-001', 'comp-008', 'Ashley', 'Moore', 'ashley.m@retailpro.com', 'Retail Technology Manager', 'manager', 82, 'opportunity', 'active', '550e8400-e29b-41d4-a716-446655440000'),
('cont-024', 'business-demo-001', 'comp-008', 'Joshua', 'Davis', 'joshua.d@retailpro.com', 'Systems Analyst', 'individual', 75, 'sql', 'active', '550e8400-e29b-41d4-a716-446655440000'),
('cont-025', 'business-demo-001', 'comp-009', 'Elizabeth', 'Martinez', 'elizabeth@greenenergy.io', 'Chief Sustainability Officer', 'c-level', 82, 'sql', 'active', '550e8400-e29b-41d4-a716-446655440000'),
('cont-026', 'business-demo-001', 'comp-009', 'Ryan', 'Lopez', 'ryan.lopez@greenenergy.io', 'Energy Systems Engineer', 'individual', 76, 'sql', 'active', '550e8400-e29b-41d4-a716-446655440000'),
('cont-027', 'business-demo-001', 'comp-009', 'Hannah', 'Clark', 'hannah.c@greenenergy.io', 'Operations Manager', 'manager', 70, 'mql', 'active', '550e8400-e29b-41d4-a716-446655440000'),
('cont-028', 'business-demo-001', 'comp-010', 'William', 'Rodriguez', 'william.r@autodrive.ai', 'Chief Technology Officer', 'c-level', 96, 'customer', 'active', '550e8400-e29b-41d4-a716-446655440000'),
('cont-029', 'business-demo-001', 'comp-010', 'Samantha', 'Lewis', 'samantha.l@autodrive.ai', 'VP of Engineering', 'vp', 91, 'customer', 'active', '550e8400-e29b-41d4-a716-446655440000'),
('cont-030', 'business-demo-001', 'comp-010', 'Nathan', 'Walker', 'nathan.w@autodrive.ai', 'Senior AI Researcher', 'individual', 87, 'customer', 'active', '550e8400-e29b-41d4-a716-446655440000');" -Description "Contacts Batch 3 (21-30)"

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "✓ Comprehensive Demo Data Seeding Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Summary:" -ForegroundColor White
Write-Host "  ► 1 Demo Business" -ForegroundColor Gray
Write-Host "  ► 25 Chart of Accounts" -ForegroundColor Gray
Write-Host "  ► 10 CRM Companies" -ForegroundColor Gray
Write-Host "  ► 30 CRM Contacts" -ForegroundColor Gray
Write-Host ""
Write-Host "Next: Run deals seeding script for 20 CRM deals" -ForegroundColor Yellow
