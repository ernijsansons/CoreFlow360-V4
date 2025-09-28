# Fix result.meta.success to result.success
$file = "src\database\crm-database.ts"
$content = Get-Content $file -Raw

# Replace all instances
$content = $content -replace "result\.meta\.success", "result.success"
$content = $content -replace "Boolean\(result\.success\)", "result.success"

Set-Content $file $content -NoNewline

Write-Host "Fixed result.meta.success patterns in $file"