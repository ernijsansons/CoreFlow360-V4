# CoreFlow360 V4 - Development Startup Script
# This script starts both the backend and frontend servers for development

Write-Host "🚀 Starting CoreFlow360 V4 Development Environment..." -ForegroundColor Green

# Set environment variables for development
$env:NODE_ENV = "development"
$env:JWT_SECRET = "development-jwt-secret-key-minimum-32-characters-long"
$env:ENCRYPTION_KEY = "development-encryption-key-32-chars"
$env:AUTH_SECRET = "development-auth-secret-key"
$env:PORT = "3001"

Write-Host "📦 Starting Backend Server on port 3001..." -ForegroundColor Yellow
$backendCommand = "cd '$PWD'; `$env:NODE_ENV='development'; `$env:JWT_SECRET='development-jwt-secret-key-minimum-32-characters-long'; `$env:ENCRYPTION_KEY='development-encryption-key-32-chars'; `$env:AUTH_SECRET='development-auth-secret-key'; `$env:PORT='3001'; node server-simple.js"
Start-Process powershell -ArgumentList "-NoExit", "-Command", $backendCommand

Start-Sleep -Seconds 3

Write-Host "🎨 Starting Frontend Development Server on port 5173..." -ForegroundColor Yellow
$frontendCommand = "cd '$PWD\frontend'; npm run dev -- --port 5173"
Start-Process powershell -ArgumentList "-NoExit", "-Command", $frontendCommand

Start-Sleep -Seconds 5

Write-Host "✅ Development servers started!" -ForegroundColor Green
Write-Host "🌐 Frontend: http://localhost:5173" -ForegroundColor Cyan
Write-Host "🔧 Backend API: http://localhost:3001" -ForegroundColor Cyan
Write-Host "💚 Health Check: http://localhost:3001/health" -ForegroundColor Cyan
Write-Host ""
Write-Host "Press any key to open the application in your browser..." -ForegroundColor White
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

Start-Process "http://localhost:5173"
