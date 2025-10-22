# PowerShell Script: Seed CRM Deals to Production
# Description: Seeds 20 CRM deals across pipeline stages
# Date: 2025-10-12
# Prerequisites: Companies and contacts must exist

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "CoreFlow360 V4 - CRM Deals Seeding" -ForegroundColor Cyan
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

# Won Deals (Customers)
Write-Host "`n[1/5] Creating Won Deals (3 deals)..." -ForegroundColor Cyan
Execute-SQL -Command "INSERT OR IGNORE INTO crm_deals (id, business_id, company_id, contact_id, title, amount, currency, stage, pipeline, probability, expected_close_date, status, owner_id) VALUES
('deal-001', 'business-demo-001', 'comp-001', 'cont-001', 'Enterprise License - Year 1', 250000, 'USD', 'closed_won', 'sales', 100, '2025-03-15', 'won', '550e8400-e29b-41d4-a716-446655440000'),
('deal-002', 'business-demo-001', 'comp-005', 'cont-013', 'Implementation Services', 85000, 'USD', 'closed_won', 'sales', 100, '2025-04-20', 'won', '550e8400-e29b-41d4-a716-446655440000'),
('deal-003', 'business-demo-001', 'comp-010', 'cont-028', 'Custom AI Integration', 450000, 'USD', 'closed_won', 'sales', 100, '2025-05-10', 'won', '550e8400-e29b-41d4-a716-446655440000');" -Description "Won deals"

# Negotiation/Contract Stage
Write-Host "`n[2/5] Creating Negotiation/Contract Deals (3 deals)..." -ForegroundColor Cyan
Execute-SQL -Command "INSERT OR IGNORE INTO crm_deals (id, business_id, company_id, contact_id, title, amount, currency, stage, pipeline, probability, expected_close_date, status, owner_id) VALUES
('deal-004', 'business-demo-001', 'comp-002', 'cont-004', 'Cloud Infrastructure Package', 320000, 'USD', 'negotiation', 'sales', 75, '2025-11-15', 'open', '550e8400-e29b-41d4-a716-446655440000'),
('deal-005', 'business-demo-001', 'comp-008', 'cont-022', 'Retail Management Suite', 180000, 'USD', 'contract', 'sales', 80, '2025-11-30', 'open', '550e8400-e29b-41d4-a716-446655440000'),
('deal-017', 'business-demo-001', 'comp-001', 'cont-002', 'Year 2 Renewal + Expansion', 320000, 'USD', 'negotiation', 'sales', 85, '2026-03-01', 'open', '550e8400-e29b-41d4-a716-446655440000');" -Description "Negotiation/contract stage"

# Proposal Stage
Write-Host "`n[3/5] Creating Proposal Stage Deals (3 deals)..." -ForegroundColor Cyan
Execute-SQL -Command "INSERT OR IGNORE INTO crm_deals (id, business_id, company_id, contact_id, title, amount, currency, stage, pipeline, probability, expected_close_date, status, owner_id) VALUES
('deal-006', 'business-demo-001', 'comp-003', 'cont-007', 'Analytics Platform License', 95000, 'USD', 'proposal', 'sales', 60, '2025-12-01', 'open', '550e8400-e29b-41d4-a716-446655440000'),
('deal-007', 'business-demo-001', 'comp-009', 'cont-025', 'Energy Monitoring System', 125000, 'USD', 'proposal', 'sales', 55, '2025-12-10', 'open', '550e8400-e29b-41d4-a716-446655440000'),
('deal-018', 'business-demo-001', 'comp-005', 'cont-014', 'Advanced Features Package', 120000, 'USD', 'proposal', 'sales', 70, '2025-12-15', 'open', '550e8400-e29b-41d4-a716-446655440000');" -Description "Proposal stage"

# Demo/Trial Stage
Write-Host "`n[4/5] Creating Demo/Trial Deals (4 deals)..." -ForegroundColor Cyan
Execute-SQL -Command "INSERT OR IGNORE INTO crm_deals (id, business_id, company_id, contact_id, title, amount, currency, stage, pipeline, probability, expected_close_date, status, owner_id) VALUES
('deal-008', 'business-demo-001', 'comp-004', 'cont-010', 'Security Compliance Tool', 220000, 'USD', 'demo', 'sales', 45, '2025-12-20', 'open', '550e8400-e29b-41d4-a716-446655440000'),
('deal-009', 'business-demo-001', 'comp-006', 'cont-016', 'Healthcare Integration Platform', 275000, 'USD', 'trial', 'sales', 40, '2026-01-05', 'open', '550e8400-e29b-41d4-a716-446655440000'),
('deal-010', 'business-demo-001', 'comp-007', 'cont-019', 'Education Management System', 150000, 'USD', 'demo', 'sales', 35, '2026-01-15', 'open', '550e8400-e29b-41d4-a716-446655440000'),
('deal-019', 'business-demo-001', 'comp-010', 'cont-029', 'ML Training Services', 200000, 'USD', 'contract', 'sales', 75, '2025-11-25', 'open', '550e8400-e29b-41d4-a716-446655440000');" -Description "Demo/trial stage"

# Discovery/Qualification/Prospecting Stage + Lost Deal
Write-Host "`n[5/5] Creating Discovery/Prospecting Deals + Lost Deal (7 deals)..." -ForegroundColor Cyan
Execute-SQL -Command "INSERT OR IGNORE INTO crm_deals (id, business_id, company_id, contact_id, title, amount, currency, stage, pipeline, probability, expected_close_date, status, owner_id) VALUES
('deal-011', 'business-demo-001', 'comp-002', 'cont-005', 'DevOps Automation Suite', 95000, 'USD', 'discovery', 'sales', 30, '2026-02-01', 'open', '550e8400-e29b-41d4-a716-446655440000'),
('deal-012', 'business-demo-001', 'comp-003', 'cont-008', 'Data Warehouse Solution', 185000, 'USD', 'qualification', 'sales', 25, '2026-02-15', 'open', '550e8400-e29b-41d4-a716-446655440000'),
('deal-013', 'business-demo-001', 'comp-006', 'cont-017', 'Patient Data Platform', 310000, 'USD', 'discovery', 'sales', 20, '2026-03-01', 'open', '550e8400-e29b-41d4-a716-446655440000'),
('deal-014', 'business-demo-001', 'comp-007', 'cont-020', 'Learning Analytics Tool', 75000, 'USD', 'prospecting', 'sales', 15, '2026-03-15', 'open', '550e8400-e29b-41d4-a716-446655440000'),
('deal-015', 'business-demo-001', 'comp-008', 'cont-023', 'Inventory Optimization AI', 140000, 'USD', 'prospecting', 'sales', 15, '2026-04-01', 'open', '550e8400-e29b-41d4-a716-446655440000'),
('deal-016', 'business-demo-001', 'comp-009', 'cont-026', 'Smart Grid Integration', 195000, 'USD', 'prospecting', 'sales', 10, '2026-04-20', 'open', '550e8400-e29b-41d4-a716-446655440000'),
('deal-020', 'business-demo-001', 'comp-004', 'cont-011', 'Basic Security Package', 65000, 'USD', 'closed_lost', 'sales', 0, '2025-09-30', 'lost', '550e8400-e29b-41d4-a716-446655440000');" -Description "Discovery/prospecting + lost deal"

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "✓ CRM Deals Seeding Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Summary:" -ForegroundColor White
Write-Host "  ► 3 Won Deals (Total: $785,000)" -ForegroundColor Green
Write-Host "  ► 6 In Negotiation/Proposal ($1,135,000)" -ForegroundColor Yellow
Write-Host "  ► 4 In Demo/Trial ($645,000)" -ForegroundColor Cyan
Write-Host "  ► 6 In Discovery/Prospecting ($800,000)" -ForegroundColor Gray
Write-Host "  ► 1 Lost Deal ($65,000)" -ForegroundColor Red
Write-Host ""
Write-Host "  Total Pipeline Value: $3,430,000" -ForegroundColor White
Write-Host ""
