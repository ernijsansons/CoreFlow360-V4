# Repository Size Audit Script for Windows
# Phase 1 Discovery - CoreFlow360 V4

param(
    [string]$Path = (Get-Location).Path,
    [int]$TopCount = 50,
    [switch]$IncludeGit = $false,
    [switch]$IncludeNodeModules = $false
)

Write-Host "Starting Repository Size Audit..." -ForegroundColor Cyan
Write-Host "Path: $Path" -ForegroundColor Gray
Write-Host ""

# Function to format bytes to human readable
function Format-FileSize {
    param([int64]$Size)

    if ($Size -gt 1GB) {
        return "{0:N2} GB" -f ($Size / 1GB)
    } elseif ($Size -gt 1MB) {
        return "{0:N2} MB" -f ($Size / 1MB)
    } elseif ($Size -gt 1KB) {
        return "{0:N2} KB" -f ($Size / 1KB)
    } else {
        return "$Size B"
    }
}

# Build exclusion filter
$excludePatterns = @()
if (-not $IncludeGit) {
    $excludePatterns += "*\.git\*"
}
if (-not $IncludeNodeModules) {
    $excludePatterns += "*\node_modules\*"
}

# Get all files
Write-Host "Scanning files..." -ForegroundColor Yellow
$allFiles = Get-ChildItem -Path $Path -Recurse -File -ErrorAction SilentlyContinue | Where-Object {
    $file = $_
    $exclude = $false
    foreach ($pattern in $excludePatterns) {
        if ($file.FullName -like $pattern) {
            $exclude = $true
            break
        }
    }
    -not $exclude
}

$totalSize = ($allFiles | Measure-Object -Property Length -Sum).Sum
Write-Host "Total repository size (excluding .git and node_modules): $(Format-FileSize $totalSize)" -ForegroundColor Green
Write-Host "Total file count: $($allFiles.Count)" -ForegroundColor Green
Write-Host ""

# Group by extension
Write-Host "=== File Types by Size ===" -ForegroundColor Cyan
$fileTypes = $allFiles | Group-Object Extension | Select-Object @{
    Name='Extension'; Expression={if ($_.Name) {$_.Name} else {'(no ext)'}}
}, @{
    Name='Count'; Expression={$_.Count}
}, @{
    Name='TotalSize'; Expression={($_.Group | Measure-Object -Property Length -Sum).Sum}
}, @{
    Name='SizeFormatted'; Expression={Format-FileSize ($_.Group | Measure-Object -Property Length -Sum).Sum}
} | Sort-Object TotalSize -Descending | Select-Object -First 20

$fileTypes | Format-Table Extension, Count, SizeFormatted -AutoSize

# Top largest files
Write-Host ""
Write-Host "=== Top $TopCount Largest Files ===" -ForegroundColor Cyan
$largestFiles = $allFiles | Sort-Object Length -Descending | Select-Object -First $TopCount | Select-Object @{
    Name='Size'; Expression={Format-FileSize $_.Length}
}, @{
    Name='Path'; Expression={$_.FullName.Replace($Path + '\', '')}
}

$largestFiles | Format-Table -AutoSize

# Directory sizes
Write-Host ""
Write-Host "=== Directory Sizes ===" -ForegroundColor Cyan
$directories = Get-ChildItem -Path $Path -Directory -ErrorAction SilentlyContinue | Where-Object {
    $_.Name -ne '.git' -and $_.Name -ne 'node_modules'
} | ForEach-Object {
    $dir = $_
    $dirFiles = Get-ChildItem -Path $dir.FullName -Recurse -File -ErrorAction SilentlyContinue | Where-Object {
        $file = $_
        $exclude = $false
        foreach ($pattern in $excludePatterns) {
            if ($file.FullName -like $pattern) {
                $exclude = $true
                break
            }
        }
        -not $exclude
    }

    $dirSize = ($dirFiles | Measure-Object -Property Length -Sum).Sum

    [PSCustomObject]@{
        Directory = $dir.Name
        FileCount = $dirFiles.Count
        Size = $dirSize
        SizeFormatted = Format-FileSize $dirSize
    }
} | Sort-Object Size -Descending

$directories | Format-Table Directory, FileCount, SizeFormatted -AutoSize

# Check for common bloat patterns
Write-Host ""
Write-Host "=== Checking for Common Bloat Patterns ===" -ForegroundColor Cyan

$bloatPatterns = @(
    @{Pattern='*.log'; Description='Log files'},
    @{Pattern='*.tmp'; Description='Temporary files'},
    @{Pattern='*.cache'; Description='Cache files'},
    @{Pattern='*.bak'; Description='Backup files'},
    @{Pattern='*.old'; Description='Old files'},
    @{Pattern='*.zip'; Description='Archive files'},
    @{Pattern='*.tar'; Description='Tar archives'},
    @{Pattern='*.gz'; Description='Gzip files'},
    @{Pattern='*.msi'; Description='MSI installers'},
    @{Pattern='*.exe'; Description='Executable files'},
    @{Pattern='*.dll'; Description='DLL files'},
    @{Pattern='*.pdb'; Description='Debug symbols'},
    @{Pattern='*.map'; Description='Source maps'},
    @{Pattern='coverage\*'; Description='Coverage reports'},
    @{Pattern='dist\*'; Description='Distribution files'},
    @{Pattern='build\*'; Description='Build outputs'},
    @{Pattern='.turbo\*'; Description='Turbo cache'},
    @{Pattern='.next\*'; Description='Next.js cache'},
    @{Pattern='storybook-static\*'; Description='Storybook static'},
    @{Pattern='.venv\*'; Description='Python virtual env'},
    @{Pattern='.wrangler\*'; Description='Wrangler cache'}
)

$bloatResults = @()
foreach ($pattern in $bloatPatterns) {
    $matchedFiles = $allFiles | Where-Object {$_.FullName -like "*$($pattern.Pattern)"}
    if ($matchedFiles) {
        $totalBloatSize = ($matchedFiles | Measure-Object -Property Length -Sum).Sum
        $bloatResults += [PSCustomObject]@{
            Pattern = $pattern.Pattern
            Description = $pattern.Description
            FileCount = $matchedFiles.Count
            TotalSize = Format-FileSize $totalBloatSize
            SizeBytes = $totalBloatSize
        }
    }
}

$bloatResults | Sort-Object SizeBytes -Descending | Format-Table Pattern, Description, FileCount, TotalSize -AutoSize

# Generate summary JSON
$summary = @{
    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    TotalSize = $totalSize
    TotalSizeFormatted = Format-FileSize $totalSize
    FileCount = $allFiles.Count
    TopFileTypes = $fileTypes | Select-Object -First 10
    TopDirectories = $directories | Select-Object -First 10
    TopFiles = $largestFiles | Select-Object -First 20
    BloatPatterns = $bloatResults
}

$summary | ConvertTo-Json -Depth 10 | Out-File "repo_size_audit_results.json"
Write-Host ""
Write-Host "Audit complete. Results saved to repo_size_audit_results.json" -ForegroundColor Green