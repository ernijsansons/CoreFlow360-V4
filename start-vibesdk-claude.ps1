# PowerShell script to start VibeSDK with Claude Local Bridge
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  VibeSDK with Claude Local Bridge" -ForegroundColor Yellow
Write-Host "  Zero API Costs - Claude Max Only" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Start Claude Local Bridge in a new PowerShell window
Write-Host "Starting Claude Local Bridge..." -ForegroundColor Yellow
$bridgeProcess = Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd src\vibesdk-claude-bridge; npm start" -PassThru

# Wait for bridge to start
Write-Host "Waiting for bridge to initialize..." -ForegroundColor Yellow
Start-Sleep -Seconds 3

# Test bridge connection
Write-Host "Testing bridge connection..." -ForegroundColor Yellow
try {
    $response = Invoke-WebRequest -Uri "http://localhost:8787/health" -UseBasicParsing -TimeoutSec 2
    if ($response.StatusCode -eq 200) {
        Write-Host "✅ Bridge is running successfully!" -ForegroundColor Green
        $bridgeStatus = $response.Content | ConvertFrom-Json
        Write-Host "   Mode: $($bridgeStatus.mode)" -ForegroundColor Gray
        Write-Host "   Provider: $($bridgeStatus.provider)" -ForegroundColor Gray
    }
} catch {
    Write-Host "⚠️  Bridge may not be ready yet. Starting VibeSDK anyway..." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Starting VibeSDK in a new window..." -ForegroundColor Yellow

# Start VibeSDK in a new PowerShell window
$vibeProcess = Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd vibesdk-local; bun run dev" -PassThru

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Both services are starting up:" -ForegroundColor Green
Write-Host "  • Claude Bridge: http://localhost:8787" -ForegroundColor White
Write-Host "  • VibeSDK: http://localhost:5173" -ForegroundColor White
Write-Host ""
Write-Host "Tip: Both services are running in separate windows." -ForegroundColor Gray
Write-Host "     Close this window to keep them running." -ForegroundColor Gray
Write-Host "========================================" -ForegroundColor Cyan

# Keep this window open for monitoring
Write-Host ""
Write-Host "Press any key to close this monitoring window..." -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")