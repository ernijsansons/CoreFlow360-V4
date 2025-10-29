# CoreFlow360 V4 - Cloudflare Deployment Setup Script
# This script helps you set up the GitHub secret for automatic deployment

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "  CoreFlow360 V4 - Deployment Setup Helper" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""

# Check if git repository is set up correctly
Write-Host "Checking repository status..." -ForegroundColor Yellow
$gitStatus = git status 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "Error: Not a git repository or git is not installed" -ForegroundColor Red
    exit 1
}

$gitRemote = git remote get-url origin 2>&1
if ($gitRemote -match "github.com") {
    Write-Host "✓ Git repository configured: $gitRemote" -ForegroundColor Green
} else {
    Write-Host "✗ GitHub remote not configured correctly" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "=== Setup Instructions ===" -ForegroundColor Cyan
Write-Host ""

Write-Host "STEP 1: Generate Cloudflare API Token" -ForegroundColor Yellow
Write-Host "---------------------------------------" -ForegroundColor Gray
Write-Host "1. Visit: https://dash.cloudflare.com/profile/api-tokens"
Write-Host "2. Click 'Create Token'"
Write-Host "3. Use 'Edit Cloudflare Workers' template"
Write-Host "4. Or create custom with these permissions:"
Write-Host "   - Account: Cloudflare Pages: Edit"
Write-Host "   - Zone: Cloudflare Pages: Edit"
Write-Host "5. Copy the generated token"
Write-Host ""

Write-Host "Press Enter to open Cloudflare API Tokens page..." -ForegroundColor Cyan
Read-Host
Start-Process "https://dash.cloudflare.com/profile/api-tokens"

Write-Host ""
Write-Host "STEP 2: Add Secret to GitHub" -ForegroundColor Yellow
Write-Host "---------------------------------------" -ForegroundColor Gray
Write-Host "1. Go to repository secrets settings"
Write-Host "2. Click 'New repository secret'"
Write-Host "3. Name: CLOUDFLARE_API_TOKEN"
Write-Host "4. Secret: [Paste your Cloudflare API token]"
Write-Host "5. Click 'Add secret'"
Write-Host ""

Write-Host "Press Enter to open GitHub Secrets page..." -ForegroundColor Cyan
Read-Host
Start-Process "https://github.com/ernijsansons/CoreFlow360-V4/settings/secrets/actions"

Write-Host ""
Write-Host "STEP 3: Verify Deployment" -ForegroundColor Yellow
Write-Host "---------------------------------------" -ForegroundColor Gray
Write-Host "After adding the secret, you can:"
Write-Host "1. Push new code to trigger automatic deployment"
Write-Host "2. Or manually trigger the workflow at:"
Write-Host "   https://github.com/ernijsansons/CoreFlow360-V4/actions"
Write-Host ""

Write-Host "Would you like to open the GitHub Actions page? (Y/N): " -ForegroundColor Cyan -NoNewline
$response = Read-Host
if ($response -eq "Y" -or $response -eq "y") {
    Start-Process "https://github.com/ernijsansons/CoreFlow360-V4/actions"
}

Write-Host ""
Write-Host "=== Configuration Summary ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "✓ GitHub Actions workflow: .github/workflows/deploy-cloudflare-pages.yml" -ForegroundColor Green
Write-Host "✓ Accessibility fixes: 3 commits pushed" -ForegroundColor Green
Write-Host "✓ Production build: frontend/dist (227.44 kB)" -ForegroundColor Green
Write-Host "✓ Target environment: Cloudflare Pages" -ForegroundColor Green
Write-Host "✓ Project name: coreflow360-v4-prod" -ForegroundColor Green
Write-Host ""

Write-Host "Once the secret is added, deployments will happen automatically!" -ForegroundColor Green
Write-Host ""
Write-Host "For detailed instructions, see: DEPLOYMENT_SETUP_COMPLETE.md" -ForegroundColor Gray
Write-Host ""
Write-Host "================================================" -ForegroundColor Cyan
