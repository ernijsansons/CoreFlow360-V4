# Safe Repository Cleanup Script - Phase 2 Execution
# CoreFlow360 V4 - Windows PowerShell Version
#
# SAFETY FEATURES:
# - Moves files to __graveyard__ instead of deleting
# - Validates after each operation
# - Automatic rollback on failure
# - Dry run mode by default

param(
    [Parameter()]
    [switch]$DryRun = $true,
    [switch]$Force = $false,
    [switch]$SkipValidation = $false,
    [string]$ManifestPath = "CLEANUP_MANIFEST.yaml"
)

# Colors for output
$script:colors = @{
    Success = "Green"
    Warning = "Yellow"
    Error = "Red"
    Info = "Cyan"
    DryRun = "Magenta"
}

function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = "White"
    )
    Write-Host $Message -ForegroundColor $Color
}

# Safety check - must be on correct branch
function Test-SafetyBranch {
    $currentBranch = git branch --show-current 2>$null
    if ($currentBranch -ne "repo-slim/PH1-discovery" -and $currentBranch -ne "repo-slim/PH2-execution") {
        Write-ColorOutput "ERROR: Must be on repo-slim branch for safety" $colors.Error
        Write-ColorOutput "Current branch: $currentBranch" $colors.Warning

        if (-not $Force) {
            Write-ColorOutput "Create branch with: git checkout -b repo-slim/PH2-execution" $colors.Info
            exit 1
        }
    }
    return $true
}

# Create graveyard structure
function Initialize-Graveyard {
    $graveyardPath = "__graveyard__"

    if ($DryRun) {
        Write-ColorOutput "[DRY RUN] Would create graveyard at: $graveyardPath" $colors.DryRun
        return $true
    }

    if (-not (Test-Path $graveyardPath)) {
        New-Item -ItemType Directory -Path $graveyardPath -Force | Out-Null
        Write-ColorOutput "Created graveyard directory: $graveyardPath" $colors.Success
    }

    # Create README in graveyard
    $readmeContent = @"
# Graveyard Directory
## Repository Cleanup - $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")

This directory contains files moved during repository cleanup.
Files here are safe to delete after validation.

To restore a file:
``Move-Item "__graveyard__/[path]" "[original-path]"``

To permanently delete after confirmation:
``Remove-Item "__graveyard__" -Recurse -Force``
"@

    $readmeContent | Out-File "$graveyardPath/README.md" -Encoding UTF8
    return $true
}

# Move file or directory to graveyard
function Move-ToGraveyard {
    param(
        [string]$SourcePath,
        [string]$DestinationSubPath
    )

    $graveyardDest = Join-Path "__graveyard__" $DestinationSubPath

    if (-not (Test-Path $SourcePath)) {
        Write-ColorOutput "  Skip: $SourcePath does not exist" $colors.Warning
        return $true
    }

    $item = Get-Item $SourcePath
    $sizeKB = if ($item.PSIsContainer) {
        (Get-ChildItem $SourcePath -Recurse | Measure-Object -Property Length -Sum).Sum / 1KB
    } else {
        $item.Length / 1KB
    }

    if ($DryRun) {
        Write-ColorOutput "  [DRY RUN] Would move: $SourcePath → $graveyardDest ($('{0:N2}' -f $sizeKB) KB)" $colors.DryRun
        return $true
    }

    try {
        # Create destination directory
        $destDir = Split-Path $graveyardDest -Parent
        if ($destDir -and -not (Test-Path $destDir)) {
            New-Item -ItemType Directory -Path $destDir -Force | Out-Null
        }

        # Move the item
        Move-Item -Path $SourcePath -Destination $graveyardDest -Force
        Write-ColorOutput "  Moved: $SourcePath → $graveyardDest ($('{0:N2}' -f $sizeKB) KB)" $colors.Success
        return $true
    }
    catch {
        Write-ColorOutput "  ERROR moving $SourcePath : $_" $colors.Error
        return $false
    }
}

# Run validation command
function Test-Validation {
    param(
        [string]$Command,
        [string]$Description
    )

    if ($SkipValidation) {
        Write-ColorOutput "  [SKIP] $Description" $colors.Warning
        return $true
    }

    if ($DryRun) {
        Write-ColorOutput "  [DRY RUN] Would validate: $Description" $colors.DryRun
        return $true
    }

    Write-ColorOutput "  Validating: $Description" $colors.Info

    try {
        $output = Invoke-Expression $Command 2>&1
        $success = $LASTEXITCODE -eq 0

        if ($success) {
            Write-ColorOutput "  [PASS] $Description passed" $colors.Success
        } else {
            Write-ColorOutput "  [FAIL] $Description failed" $colors.Error
            Write-ColorOutput "    Output: $output" $colors.Error
        }

        return $success
    }
    catch {
        Write-ColorOutput "  ✗ $Description errored: $_" $colors.Error
        return $false
    }
}

# Rollback function
function Invoke-Rollback {
    param(
        [array]$MovedItems
    )

    Write-ColorOutput "`nROLLBACK: Restoring moved items..." $colors.Warning

    foreach ($item in $MovedItems) {
        $graveyardPath = Join-Path "__graveyard__" $item.DestinationSubPath

        if (Test-Path $graveyardPath) {
            try {
                Move-Item -Path $graveyardPath -Destination $item.OriginalPath -Force
                Write-ColorOutput "  Restored: $($item.OriginalPath)" $colors.Success
            }
            catch {
                Write-ColorOutput "  ERROR restoring $($item.OriginalPath): $_" $colors.Error
            }
        }
    }
}

# Main cleanup execution
function Start-Cleanup {
    Write-ColorOutput "`n=== REPOSITORY CLEANUP SCRIPT ===" $colors.Info
    Write-ColorOutput "Mode: $(if ($DryRun) {'DRY RUN'} else {'EXECUTE'})" $colors.Info
    Write-ColorOutput "Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" $colors.Info
    Write-ColorOutput "" $colors.Info

    # Safety checks
    if (-not (Test-SafetyBranch)) {
        return $false
    }

    # Initialize graveyard
    Initialize-Graveyard

    # Track moved items for rollback
    $movedItems = @()
    $totalSizeKB = 0

    # Define cleanup targets
    $targets = @(
        @{Path="PowerShell-7.4.6-win-x64.msi"; Dest="installers/"; Desc="PowerShell installer"},
        @{Path=".venv"; Dest="python_venv/"; Desc="Python virtual environment"},
        @{Path="audit-reports/quantum-audit-2025-09-21T23-12-16-166Z.json"; Dest="large_reports/"; Desc="Large audit JSON"},
        @{Path="design-system/dist"; Dest="build_artifacts/design-system/"; Desc="Design system build"},
        @{Path="frontend/dist"; Dest="build_artifacts/frontend/"; Desc="Frontend build"},
        @{Path=".wrangler"; Dest="caches/wrangler/"; Desc="Wrangler cache"},
        @{Path="coverage"; Dest="generated_reports/coverage/"; Desc="Coverage reports"},
        @{Path="compilation_check.log"; Dest="temp_files/"; Desc="Compilation log"},
        @{Path="tsc_errors.txt"; Dest="temp_files/"; Desc="TypeScript errors"},
        @{Path="test-output.txt"; Dest="temp_files/"; Desc="Test output"},
        @{Path="file_list.txt"; Dest="temp_files/"; Desc="File list"}
    )

    # Add backup files
    Get-ChildItem "design-system/design-tokens.backup-*.json" -ErrorAction SilentlyContinue | ForEach-Object {
        $targets += @{Path=$_.FullName; Dest="redundant_backups/token_backups/"; Desc="Token backup"}
    }

    Get-ChildItem "design-system/design-tokens.sync-backup-*.json" -ErrorAction SilentlyContinue | ForEach-Object {
        $targets += @{Path=$_.FullName; Dest="redundant_backups/token_sync_backups/"; Desc="Token sync backup"}
    }

    # Add test files in root
    Get-ChildItem "test-*.js" -ErrorAction SilentlyContinue | ForEach-Object {
        $targets += @{Path=$_.Name; Dest="misplaced_tests/"; Desc="Test file in root"}
    }

    # Add server files in root
    Get-ChildItem "server-*.js" -ErrorAction SilentlyContinue | ForEach-Object {
        $targets += @{Path=$_.Name; Dest="dev_helpers/"; Desc="Server script in root"}
    }

    Write-ColorOutput "Processing $(($targets).Count) cleanup targets..." $colors.Info
    Write-ColorOutput "" $colors.Info

    # Process each target
    $successCount = 0
    $failCount = 0

    foreach ($target in $targets) {
        Write-ColorOutput "Processing: $($target.Desc)" $colors.Info

        if (Move-ToGraveyard -SourcePath $target.Path -DestinationSubPath $target.Dest) {
            $successCount++
            $movedItems += @{
                OriginalPath = $target.Path
                DestinationSubPath = $target.Dest
            }

            # Calculate size if exists
            if (Test-Path (Join-Path "__graveyard__" $target.Dest)) {
                $item = Get-Item (Join-Path "__graveyard__" $target.Dest)
                if ($item.PSIsContainer) {
                    $totalSizeKB += (Get-ChildItem $item.FullName -Recurse | Measure-Object -Property Length -Sum).Sum / 1KB
                } else {
                    $totalSizeKB += $item.Length / 1KB
                }
            }
        } else {
            $failCount++

            if (-not $DryRun -and -not $Force) {
                Write-ColorOutput "`nERROR: Failed to move file. Starting rollback..." $colors.Error
                Invoke-Rollback -MovedItems $movedItems
                return $false
            }
        }
    }

    Write-ColorOutput "`n=== VALIDATION ===" $colors.Info

    # Run validation tests
    $validationPassed = $true

    if (-not $SkipValidation -and -not $DryRun) {
        $validationPassed = $validationPassed -and (Test-Validation "npm run type-check" "TypeScript compilation")
        $validationPassed = $validationPassed -and (Test-Validation "npm test" "Test suite")

        if (-not $validationPassed -and -not $Force) {
            Write-ColorOutput "`nVALIDATION FAILED: Starting rollback..." $colors.Error
            Invoke-Rollback -MovedItems $movedItems
            return $false
        }
    }

    # Summary
    Write-ColorOutput "`n=== CLEANUP SUMMARY ===" $colors.Info
    Write-ColorOutput "Successful moves: $successCount" $colors.Success
    Write-ColorOutput "Failed moves: $failCount" $(if ($failCount -eq 0) {$colors.Success} else {$colors.Warning})
    Write-ColorOutput "Total size moved: $('{0:N2}' -f ($totalSizeKB / 1024)) MB" $colors.Info
    Write-ColorOutput "Validation: $(if ($validationPassed) {'PASSED'} else {'FAILED'})" $(if ($validationPassed) {$colors.Success} else {$colors.Error})

    if ($DryRun) {
        Write-ColorOutput "`n[DRY RUN COMPLETE]" $colors.DryRun
        Write-ColorOutput "To execute cleanup, run:" $colors.Info
        Write-ColorOutput "  .\scripts\safe_cleanup.ps1 -DryRun:`$false" $colors.Info
    } else {
        Write-ColorOutput "`nCLEANUP COMPLETE" $colors.Success
        Write-ColorOutput "Files moved to __graveyard__/" $colors.Info
        Write-ColorOutput 'To permanently delete: Remove-Item __graveyard__ -Recurse -Force' $colors.Info
    }

    return $true
}

# Execute cleanup
Start-Cleanup