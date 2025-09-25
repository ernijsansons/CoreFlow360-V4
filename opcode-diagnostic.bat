@echo off
echo ========================================
echo OpCode Diagnostic Script
echo ========================================
echo.

echo Checking Windows version...
winver
echo.

echo Checking system memory...
systeminfo | findstr "Total Physical Memory"
echo.

echo Checking network connectivity...
ping -n 1 google.com
echo.

echo Checking if OpCode is running...
tasklist | findstr "OpCode"
echo.

echo Checking OpCode installation directory...
if exist "%PROGRAMFILES%\OpCode" (
    echo OpCode found in Program Files
    dir "%PROGRAMFILES%\OpCode"
) else (
    echo OpCode not found in Program Files
)
echo.

echo Checking OpCode data directory...
if exist "%APPDATA%\OpCode" (
    echo OpCode data directory exists
    dir "%APPDATA%\OpCode"
) else (
    echo OpCode data directory not found
)
echo.

echo Checking Node.js installation...
node --version 2>nul
if %errorlevel% equ 0 (
    echo Node.js is installed
) else (
    echo Node.js is NOT installed
)
echo.

echo Checking Python installation...
python --version 2>nul
if %errorlevel% equ 0 (
    echo Python is installed
) else (
    echo Python is NOT installed
)
echo.

echo Checking for MCP packages...
npm list -g | findstr "mcp" 2>nul
if %errorlevel% equ 0 (
    echo MCP packages found
) else (
    echo No MCP packages found
)
echo.

echo Checking Windows Event Logs for OpCode errors...
wevtutil qe Application /c:5 /rd:true /f:text | findstr "OpCode"
echo.

echo ========================================
echo Diagnostic complete
echo ========================================
pause
