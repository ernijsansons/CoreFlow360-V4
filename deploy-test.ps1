$env:CLOUDFLARE_API_TOKEN = "1H99aQr1-fX6zic4Y19lXSjGMuvr7UIE1vdBQWCL"
Write-Host "Testing Cloudflare connection..."
wrangler whoami
Write-Host "`nTesting deployment (dry run)..."
wrangler deploy --dry-run