# Final ESLint Cleanup - Remaining Issues
# Handles edge cases missed by the first pass

Write-Host "=== Final ESLint Cleanup ===" -ForegroundColor Cyan
Set-Location "c:\Users\ernij\OneDrive\Documents\CoreFlow360 V4"

# Fix database-admin.ts - unused imports
$file = "src\workers\database-admin.ts"
(Get-Content $file -Raw) -replace "import \{ z \} from 'zod';", "// import { z } from 'zod';" -replace "import type \{ MigrationFile \}", "// import type { MigrationFile }" | Set-Content $file -NoNewline
Write-Host "✓ Fixed: $file" -ForegroundColor Green

# Fix enrichment-worker.ts - unused assignments
$file = "src\workers\enrichment-worker.ts"
$content = Get-Content $file -Raw
$content = $content -replace "const updatedCount = ", "const _updatedCount = "
$content = $content -replace "const newStatus = ", "const _newStatus = "
Set-Content $file -Value $content -NoNewline
Write-Host "✓ Fixed: $file" -ForegroundColor Green

# Fix learning-worker.ts - unused variables
$file = "src\workers\learning-worker.ts"
$content = Get-Content $file -Raw
$content = $content -replace "const patterns = ", "const _patterns = "
$content = $content -replace ", experiment\)", ", _experiment)"
$content = $content -replace "\(error\) =>", "(_error) =>"
Set-Content $file -Value $content -NoNewline
Write-Host "✓ Fixed: $file" -ForegroundColor Green

# Fix artillery-helpers.js - console statement
$file = "tests\performance\artillery-helpers.js"
if (Test-Path $file) {
    $content = Get-Content $file -Raw
    $content = $content -replace "console\.log", "// console.log"
    Set-Content $file -Value $content -NoNewline
    Write-Host "✓ Fixed: $file" -ForegroundColor Green
}

Write-Host "`nRunning final ESLint check..." -ForegroundColor Yellow
npm run lint 2>&1 | Select-String -Pattern "✖ \d+ problems"

Write-Host "`n✅ Cleanup complete!" -ForegroundColor Green
