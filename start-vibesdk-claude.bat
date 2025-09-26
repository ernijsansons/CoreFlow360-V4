@echo off
echo ========================================
echo   VibeSDK with Claude Local Bridge
echo   Zero API Costs - Claude Max Only
echo ========================================
echo.

echo Step 1: Starting Claude Local Bridge...
start /B cmd /c "cd src\vibesdk-claude-bridge && npm start"

echo Step 2: Waiting for bridge to start...
timeout /t 3 /nobreak > nul

echo Step 3: Testing bridge connection...
curl -s http://localhost:8787/health > nul 2>&1
if %errorlevel% neq 0 (
    echo WARNING: Bridge may not be ready yet. Starting VibeSDK anyway...
) else (
    echo Bridge is running successfully!
)

echo.
echo Step 4: Starting VibeSDK...
cd vibesdk-local
bun run dev

echo.
echo ========================================
echo Both services should now be running:
echo - Claude Bridge: http://localhost:8787
echo - VibeSDK: http://localhost:5173
echo ========================================
pause