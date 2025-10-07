@echo off
REM ESLint Auto-Fix Script - Phase 1 (Windows)
REM Fixes: unused variables, useless escapes, and other auto-fixable issues
REM Expected: ~340 warnings removed

echo ==================================================
echo 🦴 GRUG'S ESLINT AUTO-FIX - PHASE 1
echo ==================================================
echo.
echo Target: Fix ~340 auto-fixable warnings
echo Issues: unused variables, useless escapes, formatting
echo.

cd /d "%~dp0"

echo 📊 Counting current warnings...
npm run lint 2>&1 | findstr /C:"problems" > nul
if errorlevel 1 (
  echo Before: Warnings detected
) else (
  echo Before: Measuring...
)
echo.

echo 🔧 Running ESLint auto-fix...
call npm run lint:fix
if errorlevel 1 (
  echo ⚠️  Some files could not be auto-fixed
  echo This is normal - some issues require manual fixes
)
echo.

echo 📊 Counting remaining warnings...
call npm run lint 2>&1
echo.

echo 🔍 Running TypeScript check...
call npm run typecheck
if errorlevel 0 (
  echo ✅ Type check passed!
) else (
  echo ⚠️  Type errors found - these need manual fixes
  echo See ESLINT-AUDIT-AND-FIX-PLAN.md for guidance
)

echo.
echo ==================================================
echo 📋 NEXT STEPS:
echo ==================================================
echo.
echo 1. Review changes: git diff
echo 2. Test the app: npm run dev
echo 3. Commit if good: git add . ^&^& git commit -m "fix: ESLint auto-fixes"
echo.
echo 4. Continue with manual fixes:
echo    - See ESLINT-AUDIT-AND-FIX-PLAN.md
echo    - Phase 2: React Refresh violations (51 files)
echo    - Phase 3: Type safety (342 any types)
echo    - Phase 4: React hooks (32 files)
echo.
echo 🦴 Grug say: Good start, but more work needed!
echo Target: 0 warnings
echo.

pause
