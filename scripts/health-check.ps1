# CoreFlow360 V4 - System Health Check Script (PowerShell)
# Runs all critical checks to verify system health

$ErrorActionPreference = "Continue"

Write-Host "🏥 CoreFlow360 V4 - System Health Check" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$passed = 0
$failed = 0
$warnings = 0

# Function to run a check
function Run-Check {
    param(
        [string]$Name,
        [scriptblock]$Command,
        [string]$Critical = "critical"  # "critical" or "warning"
    )

    Write-Host -NoNewline "Checking $Name... "

    try {
        $null = & $Command 2>&1
        if ($LASTEXITCODE -eq 0 -or $null -eq $LASTEXITCODE) {
            Write-Host "✅ PASS" -ForegroundColor Green
            $script:passed++
            return $true
        } else {
            throw "Command failed"
        }
    } catch {
        if ($Critical -eq "critical") {
            Write-Host "❌ FAIL" -ForegroundColor Red
            $script:failed++
        } else {
            Write-Host "⚠️  WARNING" -ForegroundColor Yellow
            $script:warnings++
        }
        return $false
    }
}

# Production Health
Write-Host "=== Production Health ===" -ForegroundColor Cyan
Run-Check "Production URL" {
    $response = Invoke-WebRequest -Uri "https://8eb14753.coreflow360-frontend.pages.dev/" -Method Head -UseBasicParsing -TimeoutSec 10
    if ($response.StatusCode -ne 200) { throw "Status code: $($response.StatusCode)" }
} "critical"
Write-Host ""

# Code Quality
Write-Host "=== Code Quality ===" -ForegroundColor Cyan
Run-Check "Circular Dependencies" {
    Push-Location frontend
    npm run check:circular
    Pop-Location
} "critical"
Run-Check "TypeScript Compilation" {
    Push-Location frontend
    npm run typecheck
    Pop-Location
} "critical"
Run-Check "Production Build" {
    Push-Location frontend
    npm run build
    Pop-Location
} "critical"
Write-Host ""

# Security
Write-Host "=== Security ===" -ForegroundColor Cyan
Run-Check "NPM Audit (Root)" {
    npm audit --audit-level=critical
} "warning"
Run-Check "NPM Audit (Frontend)" {
    Push-Location frontend
    npm audit --audit-level=critical
    Pop-Location
} "warning"
Write-Host ""

# Git Health
Write-Host "=== Git Health ===" -ForegroundColor Cyan
Run-Check "Clean Working Tree" {
    $status = git status --porcelain
    if ($status) { throw "Uncommitted changes" }
} "warning"
Run-Check "Remote Sync" {
    $local = git rev-parse HEAD
    $remote = git rev-parse "@{u}" 2>$null
    if ($local -ne $remote) { throw "Out of sync" }
} "warning"
Write-Host ""

# Summary
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Health Check Summary:"
Write-Host "  Passed: $passed" -ForegroundColor Green
if ($warnings -gt 0) {
    Write-Host "  Warnings: $warnings" -ForegroundColor Yellow
}
if ($failed -gt 0) {
    Write-Host "  Failed: $failed" -ForegroundColor Red
}
Write-Host "========================================" -ForegroundColor Cyan

# Exit code
if ($failed -gt 0) {
    Write-Host "❌ Health check FAILED" -ForegroundColor Red
    exit 1
} elseif ($warnings -gt 0) {
    Write-Host "⚠️  Health check passed with warnings" -ForegroundColor Yellow
    exit 0
} else {
    Write-Host "✅ All health checks PASSED" -ForegroundColor Green
    exit 0
}
