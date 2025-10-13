@echo off
echo 🚀 Starting CoreFlow360 V4 Development Environment...

REM Set environment variables
set NODE_ENV=development
set JWT_SECRET=development-jwt-secret-key-minimum-32-characters-long
set ENCRYPTION_KEY=development-encryption-key-32-chars
set AUTH_SECRET=development-auth-secret-key
set PORT=3001

echo 📦 Starting Backend Server on port 3001...
start "Backend Server" cmd /k "set NODE_ENV=development && set JWT_SECRET=development-jwt-secret-key-minimum-32-characters-long && set ENCRYPTION_KEY=development-encryption-key-32-chars && set AUTH_SECRET=development-auth-secret-key && set PORT=3001 && node server-simple.js"

timeout /t 3 /nobreak >nul

echo 🎨 Starting Frontend Development Server on port 5173...
start "Frontend Server" cmd /k "cd frontend && npm run dev -- --port 5173"

timeout /t 5 /nobreak >nul

echo ✅ Development servers started!
echo 🌐 Frontend: http://localhost:5173
echo 🔧 Backend API: http://localhost:3001
echo 💚 Health Check: http://localhost:3001/health
echo.
echo Opening application in browser...
start http://localhost:5173

pause
