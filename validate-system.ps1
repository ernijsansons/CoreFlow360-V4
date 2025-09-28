# CoreFlow360 V4 - Comprehensive Validation Script
Write-Host "🔍 Running comprehensive validation..." -ForegroundColor Cyan

Write-Host "1. Testing TypeScript compilation..." -ForegroundColor Yellow
try {
    $tscResult = npx tsc --noEmit 2>&1
    $errorCount = ($tscResult | Where-Object { $_ -match "error TS" } | Measure-Object).Count
    Write-Host "   TypeScript errors: $errorCount" -ForegroundColor 
} catch {
    Write-Host "   TypeScript check failed" -ForegroundColor Red
}

Write-Host "2. Testing ESLint..." -ForegroundColor Yellow
try {
    $eslintResult = npm run lint 2>&1
    $eslintErrors = ($eslintResult | Where-Object { $_ -match "error" } | Measure-Object).Count
    Write-Host "   ESLint errors: $eslintErrors" -ForegroundColor 
} catch {
    Write-Host "   ESLint check failed" -ForegroundColor Red
}

Write-Host "3. Testing build..." -ForegroundColor Yellow
try {
    $buildResult = npm run build 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "   Build: SUCCESS" -ForegroundColor Green
    } else {
        Write-Host "   Build: FAILED" -ForegroundColor Red
    }
} catch {
    Write-Host "   Build check failed" -ForegroundColor Red
}

Write-Host "
🎯 Next steps based on results:" -ForegroundColor Cyan
Write-Host "   - If TypeScript errors > 0: Run additional syntax fixes" -ForegroundColor Yellow
Write-Host "   - If ESLint errors > 0: Check parser configuration" -ForegroundColor Yellow  
Write-Host "   - If build fails: Review compilation errors" -ForegroundColor Yellow
Write-Host "   - If all pass: Ready for testing phase" -ForegroundColor Green
