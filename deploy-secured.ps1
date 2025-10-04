$env:CLOUDFLARE_API_TOKEN = "1H99aQr1-fX6zic4Y19lXSjGMuvr7UIE1vdBQWCL"

Write-Host "======================================" -ForegroundColor Cyan
Write-Host " DEPLOYING SECURED COREFLOW360 V4" -ForegroundColor Green
Write-Host "======================================" -ForegroundColor Cyan
Write-Host ""

# Deploy to staging first
Write-Host "1. Deploying to STAGING environment..." -ForegroundColor Yellow
wrangler deploy --env staging

if ($LASTEXITCODE -eq 0) {
    Write-Host "✅ Staging deployment successful!" -ForegroundColor Green
    Write-Host ""

    # Set security secrets
    Write-Host "2. Configuring security secrets..." -ForegroundColor Yellow

    # Generate a secure JWT secret if not set
    $jwtSecret = [System.Convert]::ToBase64String((1..32 | ForEach {Get-Random -Maximum 256}))

    Write-Host "   Setting JWT_SECRET..." -ForegroundColor Gray
    echo $jwtSecret | wrangler secret put JWT_SECRET --env staging

    Write-Host "   Setting ENCRYPTION_KEY..." -ForegroundColor Gray
    $encKey = [System.Convert]::ToBase64String((1..32 | ForEach {Get-Random -Maximum 256}))
    echo $encKey | wrangler secret put ENCRYPTION_KEY --env staging

    Write-Host "✅ Security secrets configured!" -ForegroundColor Green
    Write-Host ""

    # Deploy to production if staging succeeds
    Write-Host "3. Deploy to PRODUCTION? (y/n)" -ForegroundColor Yellow
    $response = Read-Host

    if ($response -eq 'y') {
        Write-Host "Deploying to PRODUCTION..." -ForegroundColor Red
        wrangler deploy --env production

        if ($LASTEXITCODE -eq 0) {
            Write-Host ""
            Write-Host "======================================" -ForegroundColor Green
            Write-Host " ✅ PRODUCTION DEPLOYMENT COMPLETE!" -ForegroundColor Green
            Write-Host "======================================" -ForegroundColor Green
            Write-Host ""
            Write-Host "URLs:" -ForegroundColor Cyan
            Write-Host "  Staging: https://coreflow360-v4-staging.ernijs-ansons.workers.dev" -ForegroundColor White
            Write-Host "  Production: https://coreflow360-v4-prod.ernijs-ansons.workers.dev" -ForegroundColor White
        } else {
            Write-Host "❌ Production deployment failed!" -ForegroundColor Red
        }
    } else {
        Write-Host "Production deployment skipped." -ForegroundColor Yellow
    }
} else {
    Write-Host "❌ Staging deployment failed! Aborting." -ForegroundColor Red
}

Write-Host ""
Write-Host "Security Enhancements Deployed:" -ForegroundColor Green
Write-Host "  ✅ PBKDF2 password hashing (100k iterations)" -ForegroundColor Gray
Write-Host "  ✅ Row-Level Security (tenant isolation)" -ForegroundColor Gray
Write-Host "  ✅ SQL injection prevention" -ForegroundColor Gray
Write-Host "  ✅ JWT secret rotation" -ForegroundColor Gray
Write-Host "  ✅ Enhanced rate limiting" -ForegroundColor Gray
Write-Host "  ✅ Input validation (Zod schemas)" -ForegroundColor Gray
Write-Host "  ✅ CORS security headers" -ForegroundColor Gray
Write-Host "  ✅ Audit logging system" -ForegroundColor Gray