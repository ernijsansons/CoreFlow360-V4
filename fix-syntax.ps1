# Fix syntax errors introduced by the comprehensive script
Write-Host "Fixing syntax errors..."

# Get files with TS1003 errors
$errorFiles = @("src/database/crm-database.ts", "src/durable-objects/dashboard-stream.ts")

foreach ($filePath in $errorFiles) {
    if (Test-Path $filePath) {
        $content = Get-Content $filePath -Raw
        
        # Fix common pattern: entry.(error as Error) -> (entry.error as Error)
        $content = $content -replace "(\w+)\.\((.*? as Error)\)", "(`$1.error as Error)"
        
        # Fix error property access patterns that got mangled
        $content = $content -replace "error\.(error as Error)", "error"
        $content = $content -replace "(\w+)\.\((error as Error)\)\.(\w+)", "(`$1.error as Error).`$3"
        
        # Fix .message, .stack, .name that got mangled
        $content = $content -replace "\.((error as Error)\.message)", ".message"
        $content = $content -replace "\.((error as Error)\.stack)", ".stack"
        $content = $content -replace "\.((error as Error)\.name)", ".name"
        
        # Fix double semicolons
        $content = $content -replace ";;", ";"
        
        Set-Content $filePath $content -NoNewline
        Write-Host "Fixed syntax errors in: $filePath"
    }
}

Write-Host "Syntax error fixes completed!"