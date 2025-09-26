@echo off
echo ========================================
echo   VibeSDK with Claude Local Bridge
echo   Zero API Costs - Claude Max Only
echo ========================================
echo.

echo Checking if bridge is already running...
powershell -Command "try { Invoke-WebRequest -Uri 'http://localhost:8787/health' -UseBasicParsing -TimeoutSec 2 | Out-Null; Write-Host 'Bridge is already running!' -ForegroundColor Green } catch { Write-Host 'Starting Claude Local Bridge...' -ForegroundColor Yellow; Start-Process cmd -ArgumentList '/c', 'cd src\vibesdk-claude-bridge && npm start' }"

echo.
echo Waiting for bridge to be ready...
timeout /t 5 /nobreak > nul

echo.
echo Testing bridge connection...
powershell -Command "try { $response = Invoke-WebRequest -Uri 'http://localhost:8787/health' -UseBasicParsing -TimeoutSec 3; $data = $response.Content | ConvertFrom-Json; Write-Host 'Bridge Status:' $data.status '(' $data.mode ')' -ForegroundColor Green } catch { Write-Host 'WARNING: Bridge may not be ready. Check manually at http://localhost:8787/health' -ForegroundColor Red }"

echo.
echo ========================================
echo Bridge should be running at: http://localhost:8787
echo Now you can start VibeSDK manually with:
echo   cd vibesdk-local
echo   bun run dev
echo ========================================
echo.
echo Press any key to open bridge in browser...
pause > nul
start http://localhost:8787/health