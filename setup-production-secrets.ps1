# PowerShell Script to Setup Production Secrets for CoreFlow360 V4
# Run this script to configure all required secrets for production deployment

Write-Host "🚀 CoreFlow360 V4 - Production Secrets Setup" -ForegroundColor Cyan
Write-Host "=" * 50 -ForegroundColor DarkGray

# Check if running in correct directory
if (-not (Test-Path "wrangler.toml")) {
    Write-Host "❌ Error: wrangler.toml not found. Please run this script from the project root." -ForegroundColor Red
    exit 1
}

Write-Host "`n📝 This script will set up the following production secrets:" -ForegroundColor Yellow
Write-Host "  - AUTH_SECRET (JWT signing secret)"
Write-Host "  - ENCRYPTION_KEY (Data encryption key)"
Write-Host "  - JWT_SECRET (JWT token secret)"
Write-Host "  - STRIPE_SECRET_KEY (Payment processing)"
Write-Host "  - STRIPE_PUBLISHABLE_KEY (Frontend payment)"
Write-Host "  - STRIPE_WEBHOOK_SECRET (Webhook validation)"
Write-Host "  - PAYPAL_CLIENT_ID (PayPal integration)"
Write-Host "  - PAYPAL_CLIENT_SECRET (PayPal auth)"
Write-Host "  - OPENAI_API_KEY (AI capabilities)"
Write-Host "  - ANTHROPIC_API_KEY (Claude AI)"
Write-Host "  - EMAIL_API_KEY (Email service)"
Write-Host "  - SENTRY_DSN (Error tracking)"
Write-Host "  - API_BASE_URL (API endpoint)"
Write-Host "  - ALLOWED_ORIGINS (CORS configuration)"

Write-Host "`n⚠️  You'll need to have these values ready." -ForegroundColor Yellow
$continue = Read-Host "Continue? (y/n)"
if ($continue -ne "y") {
    Write-Host "Setup cancelled." -ForegroundColor Yellow
    exit 0
}

# Function to generate secure random string
function Generate-SecureString {
    param([int]$length = 32)
    $bytes = New-Object byte[] $length
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    return [System.Convert]::ToBase64String($bytes)
}

# Function to set secret with wrangler
function Set-Secret {
    param(
        [string]$name,
        [string]$value,
        [string]$environment = "production"
    )

    Write-Host "Setting $name..." -ForegroundColor Cyan -NoNewline

    # Echo the value to wrangler secret put
    $value | wrangler secret put $name --env $environment 2>&1 | Out-Null

    if ($LASTEXITCODE -eq 0) {
        Write-Host " ✓" -ForegroundColor Green
        return $true
    } else {
        Write-Host " ✗" -ForegroundColor Red
        return $false
    }
}

Write-Host "`n🔐 Generating secure secrets..." -ForegroundColor Cyan

# Generate secure secrets
$authSecret = Generate-SecureString 64
$encryptionKey = Generate-SecureString 32
$jwtSecret = Generate-SecureString 48

Write-Host "Generated AUTH_SECRET (64 bytes)" -ForegroundColor Green
Write-Host "Generated ENCRYPTION_KEY (32 bytes)" -ForegroundColor Green
Write-Host "Generated JWT_SECRET (48 bytes)" -ForegroundColor Green

Write-Host "`n📋 Enter your API keys and configuration:" -ForegroundColor Yellow

# Collect required values
$stripeSecretKey = Read-Host "STRIPE_SECRET_KEY (sk_live_...)"
$stripePublishableKey = Read-Host "STRIPE_PUBLISHABLE_KEY (pk_live_...)"
$stripeWebhookSecret = Read-Host "STRIPE_WEBHOOK_SECRET (whsec_...)"
$paypalClientId = Read-Host "PAYPAL_CLIENT_ID"
$paypalClientSecret = Read-Host "PAYPAL_CLIENT_SECRET" -AsSecureString
$openaiApiKey = Read-Host "OPENAI_API_KEY (sk-...)" -AsSecureString
$anthropicApiKey = Read-Host "ANTHROPIC_API_KEY (sk-ant-...)" -AsSecureString
$emailApiKey = Read-Host "EMAIL_API_KEY (SendGrid/Resend key)" -AsSecureString
$sentryDsn = Read-Host "SENTRY_DSN (https://...@sentry.io/...)"
$apiBaseUrl = Read-Host "API_BASE_URL (e.g., https://api.coreflow360.com)"
$allowedOrigins = Read-Host "ALLOWED_ORIGINS (comma-separated, e.g., https://app.coreflow360.com,https://coreflow360.com)"

# Convert SecureString to plain text for setting secrets
$paypalClientSecretPlain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($paypalClientSecret))
$openaiApiKeyPlain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($openaiApiKey))
$anthropicApiKeyPlain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($anthropicApiKey))
$emailApiKeyPlain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($emailApiKey))

Write-Host "`n🚀 Setting production secrets..." -ForegroundColor Cyan

$success = $true

# Set all secrets
$success = $success -and (Set-Secret "AUTH_SECRET" $authSecret)
$success = $success -and (Set-Secret "ENCRYPTION_KEY" $encryptionKey)
$success = $success -and (Set-Secret "JWT_SECRET" $jwtSecret)

if ($stripeSecretKey) {
    $success = $success -and (Set-Secret "STRIPE_SECRET_KEY" $stripeSecretKey)
}
if ($stripePublishableKey) {
    $success = $success -and (Set-Secret "STRIPE_PUBLISHABLE_KEY" $stripePublishableKey)
}
if ($stripeWebhookSecret) {
    $success = $success -and (Set-Secret "STRIPE_WEBHOOK_SECRET" $stripeWebhookSecret)
}
if ($paypalClientId) {
    $success = $success -and (Set-Secret "PAYPAL_CLIENT_ID" $paypalClientId)
}
if ($paypalClientSecretPlain) {
    $success = $success -and (Set-Secret "PAYPAL_CLIENT_SECRET" $paypalClientSecretPlain)
}
if ($openaiApiKeyPlain) {
    $success = $success -and (Set-Secret "OPENAI_API_KEY" $openaiApiKeyPlain)
}
if ($anthropicApiKeyPlain) {
    $success = $success -and (Set-Secret "ANTHROPIC_API_KEY" $anthropicApiKeyPlain)
}
if ($emailApiKeyPlain) {
    $success = $success -and (Set-Secret "EMAIL_API_KEY" $emailApiKeyPlain)
}
if ($sentryDsn) {
    $success = $success -and (Set-Secret "SENTRY_DSN" $sentryDsn)
}
if ($apiBaseUrl) {
    $success = $success -and (Set-Secret "API_BASE_URL" $apiBaseUrl)
}
if ($allowedOrigins) {
    $success = $success -and (Set-Secret "ALLOWED_ORIGINS" $allowedOrigins)
}

# Clear sensitive variables from memory
$paypalClientSecretPlain = $null
$openaiApiKeyPlain = $null
$anthropicApiKeyPlain = $null
$emailApiKeyPlain = $null
[System.GC]::Collect()

Write-Host "`n" + ("=" * 50) -ForegroundColor DarkGray

if ($success) {
    Write-Host "✅ Production secrets configured successfully!" -ForegroundColor Green
    Write-Host "`n📝 Next steps:" -ForegroundColor Yellow
    Write-Host "  1. Run: wrangler deploy --env production"
    Write-Host "  2. Test health endpoint: https://your-worker.workers.dev/health"
    Write-Host "  3. Monitor deployment: wrangler tail --env production"

    Write-Host "`n💡 Save these generated secrets securely:" -ForegroundColor Cyan
    Write-Host "  AUTH_SECRET: $($authSecret.Substring(0, 10))..." -ForegroundColor DarkGray
    Write-Host "  ENCRYPTION_KEY: $($encryptionKey.Substring(0, 10))..." -ForegroundColor DarkGray
    Write-Host "  JWT_SECRET: $($jwtSecret.Substring(0, 10))..." -ForegroundColor DarkGray
} else {
    Write-Host "⚠️  Some secrets failed to set. Please check the errors above." -ForegroundColor Yellow
    Write-Host "You can manually set secrets using:" -ForegroundColor Yellow
    Write-Host "  echo 'value' | wrangler secret put SECRET_NAME --env production" -ForegroundColor DarkGray
}

Write-Host "`n🔒 Security reminder: Never commit secrets to version control!" -ForegroundColor Red