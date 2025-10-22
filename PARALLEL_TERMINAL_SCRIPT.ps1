# Parallel ESLint Fixing Script - PowerShell Version
# Run this in a SEPARATE PowerShell terminal

Write-Host "=== CoreFlow360 V4 - ESLint Auto-Fix (Windows) ===" -ForegroundColor Cyan
Write-Host "Focus: Unused variables, imports, and parameters" -ForegroundColor Yellow
Write-Host ""

# Navigate to project
Set-Location "c:\Users\ernij\OneDrive\Documents\CoreFlow360 V4"

# Function to fix unused parameters in files
function Fix-UnusedParams {
    param(
        [string]$Directory,
        [string]$Pattern = "*.ts"
    )

    Write-Host "Processing: $Directory" -ForegroundColor Green
    $fileCount = 0

    Get-ChildItem -Path $Directory -Filter $Pattern -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
        $content = Get-Content $_.FullName -Raw
        $modified = $false

        # Fix catch blocks: catch (error) => catch (_error)
        if ($content -match '\) catch \(error\) \{') {
            $content = $content -replace '\) catch \(error\) \{', ') catch (_error) {'
            $modified = $true
        }

        # Fix promise catch: .catch((error) => .catch((_error)
        if ($content -match '\.catch\(\(error\) ') {
            $content = $content -replace '\.catch\(\(error\) ', '.catch((_error) '
            $modified = $true
        }

        # Fix arrow function params: (error) => (_error)
        if ($content -match '\(error\) =>') {
            $content = $content -replace '\(error\) =>', '(_error) =>'
            $modified = $true
        }

        # Fix function params: (error: => (_error:
        if ($content -match '\(error: ') {
            $content = $content -replace '\(error: ', '(_error: '
            $modified = $true
        }

        if ($modified) {
            Set-Content $_.FullName -Value $content -NoNewline
            $fileCount++
            Write-Host "  ✓ Fixed: $($_.Name)" -ForegroundColor DarkGray
        }
    }

    Write-Host "  Modified $fileCount files in $Directory" -ForegroundColor Cyan
    Write-Host ""
}

# Phase 1: Fix src/services
Write-Host "`n=== Phase 1: src/services ===" -ForegroundColor Magenta
Fix-UnusedParams -Directory "src\services" -Pattern "*.ts"

# Check progress
Write-Host "Running ESLint check..." -ForegroundColor Yellow
npm run lint 2>&1 | Select-String -Pattern "✖ \d+ problems" | Write-Host

# Phase 2: Fix src/workers
Write-Host "`n=== Phase 2: src/workers ===" -ForegroundColor Magenta
Fix-UnusedParams -Directory "src\workers" -Pattern "*.ts"

# Check progress
Write-Host "Running ESLint check..." -ForegroundColor Yellow
npm run lint 2>&1 | Select-String -Pattern "✖ \d+ problems" | Write-Host

# Phase 3: Fix src/shared
Write-Host "`n=== Phase 3: src/shared ===" -ForegroundColor Magenta
Fix-UnusedParams -Directory "src\shared" -Pattern "*.ts"

# Check progress
Write-Host "Running ESLint check..." -ForegroundColor Yellow
npm run lint 2>&1 | Select-String -Pattern "✖ \d+ problems" | Write-Host

# Phase 4: Fix src/utils
Write-Host "`n=== Phase 4: src/utils ===" -ForegroundColor Magenta
Fix-UnusedParams -Directory "src\utils" -Pattern "*.ts"

# Phase 5: Fix src/middleware
Write-Host "`n=== Phase 5: src/middleware ===" -ForegroundColor Magenta
Fix-UnusedParams -Directory "src\middleware" -Pattern "*.ts"

# Phase 6: Fix src/modules
Write-Host "`n=== Phase 6: src/modules ===" -ForegroundColor Magenta
Fix-UnusedParams -Directory "src\modules" -Pattern "*.ts"

# Final check
Write-Host "`n=== Final ESLint Check ===" -ForegroundColor Magenta
npm run lint 2>&1 | Select-String -Pattern "✖ \d+ problems|✔" | Write-Host

Write-Host "`n✅ Terminal 2 completed! Check warnings count above." -ForegroundColor Green
Write-Host "Press any key to exit..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
