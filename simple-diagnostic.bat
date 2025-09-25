@echo off
echo OpCode Diagnostic - Simple Version
echo =================================
echo.

echo 1. Checking if OpCode is installed...
if exist "%PROGRAMFILES%\OpCode" (
    echo    OpCode found in Program Files
) else (
    echo    OpCode NOT found in Program Files
)
echo.

echo 2. Checking OpCode data folder...
if exist "%APPDATA%\OpCode" (
    echo    OpCode data folder exists
) else (
    echo    OpCode data folder NOT found
)
echo.

echo 3. Checking if OpCode is running...
tasklist | findstr "OpCode"
echo.

echo 4. Checking Node.js...
node --version
echo.

echo 5. Checking Python...
python --version
echo.

echo 6. Checking network...
ping -n 1 8.8.8.8
echo.

echo Diagnostic complete. Press any key to close.
pause >nul
