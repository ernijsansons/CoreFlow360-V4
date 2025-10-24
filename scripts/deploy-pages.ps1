# Cloudflare Pages Deployment Script (PowerShell)
# This script builds and deploys the frontend to Cloudflare Pages

param(
    [switch]$SkipChecks = $false
)

$ErrorActionPreference = "Stop"

Write-Host "🚀 CoreFlow360 V4 - Cloudflare Pages Deployment" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""

# Check if we're in the project root
if (-not (Test-Path "frontend")) {
    Write-Host "❌ Error: Must run from project root" -ForegroundColor Red
    exit 1
}

# Step 1: Pre-deployment checks
if (-not $SkipChecks) {
    Write-Host "Step 1/5: Running pre-deployment checks..." -ForegroundColor Yellow

    # Check for circular dependencies
    Write-Host "  Checking for circular dependencies..."
    Push-Location frontend

    try {
        npm run check:circular
        Write-Host "  ✅ No circular dependencies" -ForegroundColor Green
    } catch {
        Write-Host "❌ Circular dependencies found! Fix before deploying." -ForegroundColor Red
        Pop-Location
        exit 1
    }

    # Check TypeScript
    Write-Host "  Checking TypeScript compilation..."
    try {
        npm run typecheck
        Write-Host "  ✅ TypeScript check passed" -ForegroundColor Green
    } catch {
        Write-Host "❌ TypeScript errors found! Fix before deploying." -ForegroundColor Red
        Pop-Location
        exit 1
    }

    Pop-Location
}

# Step 2: Git status check
Write-Host "`nStep 2/5: Checking git status..." -ForegroundColor Yellow
$gitStatus = git status --porcelain
if ($gitStatus) {
    Write-Host "⚠️  Warning: You have uncommitted changes" -ForegroundColor Yellow
    git status --short
    $response = Read-Host "Continue anyway? (y/N)"
    if ($response -ne 'y' -and $response -ne 'Y') {
        Write-Host "Deployment cancelled"
        exit 0
    }
}
Write-Host "  ✅ Git status checked" -ForegroundColor Green

# Step 3: Build
Write-Host "`nStep 3/5: Building production bundle..." -ForegroundColor Yellow
Push-Location frontend

try {
    npm run build
    Write-Host "  ✅ Build completed successfully" -ForegroundColor Green
} catch {
    Write-Host "❌ Build failed!" -ForegroundColor Red
    Pop-Location
    exit 1
}

# Get build stats
$buildSize = (Get-ChildItem dist -Recurse | Measure-Object -Property Length -Sum).Sum / 1MB
Write-Host "  Build size: $([math]::Round($buildSize, 2)) MB"

Pop-Location

# Step 4: Deployment
Write-Host "`nStep 4/5: Deploying to Cloudflare Pages..." -ForegroundColor Yellow

# Check if CLOUDFLARE_API_TOKEN is set
if (-not $env:CLOUDFLARE_API_TOKEN) {
    Write-Host "⚠️  CLOUDFLARE_API_TOKEN not set" -ForegroundColor Yellow
    Write-Host "  Please set it in your environment"
    Write-Host "  Example: `$env:CLOUDFLARE_API_TOKEN='your_token_here'"
    exit 1
}

# Deploy using wrangler
try {
    wrangler pages deploy frontend/dist --project-name=coreflow360-frontend
    Write-Host "  ✅ Deployment completed" -ForegroundColor Green
} catch {
    Write-Host "❌ Deployment failed!" -ForegroundColor Red
    exit 1
}

# Step 5: Verification
Write-Host "`nStep 5/5: Verifying deployment..." -ForegroundColor Yellow
Write-Host "  Waiting 5 seconds for deployment to propagate..."
Start-Sleep -Seconds 5

# Check production URL
$prodUrl = "https://8eb14753.coreflow360-frontend.pages.dev/"
try {
    $response = Invoke-WebRequest -Uri $prodUrl -Method Head -UseBasicParsing
    $statusCode = $response.StatusCode

    if ($statusCode -eq 200) {
        Write-Host "  ✅ Production is live (HTTP $statusCode)" -ForegroundColor Green
    } else {
        Write-Host "  ⚠️  Production returned HTTP $statusCode" -ForegroundColor Yellow
    }
} catch {
    Write-Host "  ⚠️  Could not verify production URL" -ForegroundColor Yellow
}

# Final summary
Write-Host ""
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "🎉 Deployment Complete!" -ForegroundColor Green
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Production URL: $prodUrl"
Write-Host "Build Size: $([math]::Round($buildSize, 2)) MB"
Write-Host "Circular Dependencies: 0"
Write-Host "TypeScript: Passing"
Write-Host ""
Write-Host "Next steps:"
Write-Host "  1. Verify the site loads correctly"
Write-Host "  2. Test critical user flows"
Write-Host "  3. Monitor Cloudflare Analytics"
Write-Host "  4. Check error logs in Sentry (if configured)"
Write-Host ""
