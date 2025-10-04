$env:CLOUDFLARE_API_TOKEN = "1H99aQr1-fX6zic4Y19lXSjGMuvr7UIE1vdBQWCL"
Write-Host "Deploying CoreFlow360 V4 to Cloudflare Workers (Development)..." -ForegroundColor Green
wrangler deploy --env development
Write-Host "`nDeployment complete!" -ForegroundColor Green
Write-Host "Your worker will be available at: https://coreflow360-v4-dev.<your-subdomain>.workers.dev" -ForegroundColor Cyan