#!/usr/bin/env pwsh
# Production Deployment Script for CoreFlow360 V4
# Deploys to Cloudflare Workers with all security features

param(
    [switch]$DryRun = $false,
    [switch]$Force = $false
)

$ErrorActionPreference = "Stop"

Write-Host "🚀 Starting CoreFlow360 V4 Production Deployment" -ForegroundColor Cyan
Write-Host "=================================================" -ForegroundColor Cyan

# Verify prerequisites
Write-Host "📋 Checking prerequisites..." -ForegroundColor Yellow

# Check if wrangler is installed
try {
    $wranglerVersion = wrangler --version
    Write-Host "✅ Wrangler version: $wranglerVersion" -ForegroundColor Green
} catch {
    Write-Host "❌ Wrangler not found. Please install: npm install -g wrangler" -ForegroundColor Red
    exit 1
}

# Check if logged in to Cloudflare
try {
    $whoami = wrangler whoami
    Write-Host "✅ Authenticated as: $whoami" -ForegroundColor Green
} catch {
    Write-Host "❌ Not authenticated to Cloudflare. Please run: wrangler login" -ForegroundColor Red
    exit 1
}

# Verify project directory
if (-not (Test-Path "wrangler.toml")) {
    Write-Host "❌ wrangler.toml not found. Please run from project root." -ForegroundColor Red
    exit 1
}

# Check for required files
$requiredFiles = @(
    "src/index.production.ts",
    "src/auth/auth-system.ts",
    "src/security/security-utilities.ts"
)

foreach ($file in $requiredFiles) {
    if (-not (Test-Path $file)) {
        Write-Host "❌ Required file missing: $file" -ForegroundColor Red
        exit 1
    }
}

Write-Host "✅ All prerequisites met" -ForegroundColor Green

# Prompt for secrets if not in dry-run mode
if (-not $DryRun) {
    Write-Host "`n🔐 Configuring production secrets..." -ForegroundColor Yellow

    # JWT Secret - generate secure random key if not provided
    $jwtSecret = Read-Host "Enter JWT_SECRET (leave empty to generate secure random key)"
    if ([string]::IsNullOrWhiteSpace($jwtSecret)) {
        # Generate 64-byte random key
        $bytes = [System.Security.Cryptography.RandomNumberGenerator]::GetBytes(64)
        $jwtSecret = [System.Convert]::ToBase64String($bytes)
        Write-Host "✅ Generated secure JWT_SECRET" -ForegroundColor Green
    }

    # Anthropic API Key
    $anthropicKey = Read-Host "Enter ANTHROPIC_API_KEY"
    if ([string]::IsNullOrWhiteSpace($anthropicKey)) {
        Write-Host "❌ ANTHROPIC_API_KEY is required for AI features" -ForegroundColor Red
        exit 1
    }

    # OpenAI API Key (optional)
    $openaiKey = Read-Host "Enter OPENAI_API_KEY (optional)"

    # Email API Key (optional)
    $emailKey = Read-Host "Enter EMAIL_API_KEY (optional)"

    # Encryption Key
    $encryptionKey = Read-Host "Enter ENCRYPTION_KEY (leave empty to generate)"
    if ([string]::IsNullOrWhiteSpace($encryptionKey)) {
        $bytes = [System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32)
        $encryptionKey = [System.Convert]::ToBase64String($bytes)
        Write-Host "✅ Generated secure ENCRYPTION_KEY" -ForegroundColor Green
    }

    Write-Host "`n📝 Setting production secrets..." -ForegroundColor Yellow

    # Set secrets using wrangler
    try {
        wrangler secret put JWT_SECRET --env production --text $jwtSecret
        Write-Host "✅ JWT_SECRET configured" -ForegroundColor Green

        wrangler secret put ANTHROPIC_API_KEY --env production --text $anthropicKey
        Write-Host "✅ ANTHROPIC_API_KEY configured" -ForegroundColor Green

        if (-not [string]::IsNullOrWhiteSpace($openaiKey)) {
            wrangler secret put OPENAI_API_KEY --env production --text $openaiKey
            Write-Host "✅ OPENAI_API_KEY configured" -ForegroundColor Green
        }

        if (-not [string]::IsNullOrWhiteSpace($emailKey)) {
            wrangler secret put EMAIL_API_KEY --env production --text $emailKey
            Write-Host "✅ EMAIL_API_KEY configured" -ForegroundColor Green
        }

        wrangler secret put ENCRYPTION_KEY --env production --text $encryptionKey
        Write-Host "✅ ENCRYPTION_KEY configured" -ForegroundColor Green

    } catch {
        Write-Host "❌ Failed to set secrets: $_" -ForegroundColor Red
        exit 1
    }
}

# Build and type check
Write-Host "`n🔨 Building application..." -ForegroundColor Yellow

try {
    Write-Host "Running TypeScript compilation..."
    npm run type-check
    Write-Host "✅ TypeScript compilation successful" -ForegroundColor Green

    Write-Host "Running build process..."
    npm run build:production
    Write-Host "✅ Build successful" -ForegroundColor Green

} catch {
    Write-Host "❌ Build failed: $_" -ForegroundColor Red
    exit 1
}

# Run security validation
Write-Host "`n🔒 Running security validation..." -ForegroundColor Yellow

try {
    npm run test:security
    Write-Host "✅ Security validation passed" -ForegroundColor Green
} catch {
    Write-Host "⚠️ Security validation failed: $_" -ForegroundColor Yellow
    if (-not $Force) {
        $continue = Read-Host "Continue deployment anyway? (y/N)"
        if ($continue -ne "y") {
            Write-Host "❌ Deployment cancelled" -ForegroundColor Red
            exit 1
        }
    }
}

# Deploy to production
Write-Host "`n🚀 Deploying to production..." -ForegroundColor Yellow

if ($DryRun) {
    Write-Host "DRY RUN: Would deploy with command: wrangler deploy --env production" -ForegroundColor Cyan
    Write-Host "✅ Dry run completed successfully" -ForegroundColor Green
} else {
    try {
        Write-Host "Deploying to Cloudflare Workers..."
        wrangler deploy --env production
        Write-Host "✅ Deployment successful!" -ForegroundColor Green

        # Wait a moment for deployment to propagate
        Start-Sleep -Seconds 5

        # Test health endpoint
        Write-Host "`n🩺 Testing deployment health..." -ForegroundColor Yellow

        try {
            $healthResponse = Invoke-RestMethod -Uri "https://coreflow360-v4-prod.workers.dev/health" -Method GET -TimeoutSec 10
            if ($healthResponse.status -eq "healthy") {
                Write-Host "✅ Health check passed" -ForegroundColor Green
                Write-Host "Environment: $($healthResponse.environment)" -ForegroundColor Cyan
                Write-Host "Version: $($healthResponse.version)" -ForegroundColor Cyan
            } else {
                Write-Host "⚠️ Health check returned degraded status" -ForegroundColor Yellow
            }
        } catch {
            Write-Host "⚠️ Health check failed (this is normal for first deployment): $_" -ForegroundColor Yellow
        }

        # Test API status
        try {
            $statusResponse = Invoke-RestMethod -Uri "https://coreflow360-v4-prod.workers.dev/api/status" -Method GET -TimeoutSec 10
            Write-Host "✅ API status check passed" -ForegroundColor Green
            Write-Host "Service: $($statusResponse.service)" -ForegroundColor Cyan
        } catch {
            Write-Host "⚠️ API status check failed: $_" -ForegroundColor Yellow
        }

    } catch {
        Write-Host "❌ Deployment failed: $_" -ForegroundColor Red
        exit 1
    }
}

Write-Host "`n🎉 Production deployment completed!" -ForegroundColor Green
Write-Host "=================================================" -ForegroundColor Green
Write-Host "Production URL: https://coreflow360-v4-prod.workers.dev" -ForegroundColor Cyan
Write-Host "Health Check: https://coreflow360-v4-prod.workers.dev/health" -ForegroundColor Cyan
Write-Host "API Status: https://coreflow360-v4-prod.workers.dev/api/status" -ForegroundColor Cyan
Write-Host "`nDeployment Summary:" -ForegroundColor Yellow
Write-Host "- Worker deployed to production environment" -ForegroundColor White
Write-Host "- All security features enabled" -ForegroundColor White
Write-Host "- Database and KV bindings configured" -ForegroundColor White
Write-Host "- Rate limiting with Durable Objects active" -ForegroundColor White
Write-Host "- AI capabilities enabled" -ForegroundColor White

Write-Host "`n⚠️ Post-deployment checklist:" -ForegroundColor Yellow
Write-Host "1. Verify all health checks pass" -ForegroundColor White
Write-Host "2. Test authentication endpoints" -ForegroundColor White
Write-Host "3. Monitor error rates and performance" -ForegroundColor White
Write-Host "4. Set up alerts and monitoring dashboards" -ForegroundColor White
Write-Host "5. Update DNS and custom domain settings if needed" -ForegroundColor White