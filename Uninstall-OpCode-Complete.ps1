# OpCode Complete Uninstall Script
# This script will remove OpCode and all associated files

Write-Host "========================================" -ForegroundColor Red
Write-Host "OpCode Complete Uninstall Script" -ForegroundColor Red
Write-Host "========================================" -ForegroundColor Red
Write-Host ""

# Check if running as administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "This script requires Administrator privileges. Please run as Administrator." -ForegroundColor Red
    Write-Host "Right-click PowerShell and select 'Run as Administrator'" -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host "Running as Administrator - Good!" -ForegroundColor Green
Write-Host ""

# Function to safely remove folder
function Remove-FolderSafely {
    param($Path)
    if (Test-Path $Path) {
        try {
            Write-Host "Removing: $Path" -ForegroundColor Yellow
            Remove-Item -Path $Path -Recurse -Force -ErrorAction Stop
            Write-Host "Successfully removed: $Path" -ForegroundColor Green
        }
        catch {
            Write-Host "Failed to remove: $Path - $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    else {
        Write-Host "Not found: $Path" -ForegroundColor Gray
    }
}

# Function to safely remove registry key
function Remove-RegistryKeySafely {
    param($Path)
    try {
        if (Test-Path $Path) {
            Write-Host "Removing registry key: $Path" -ForegroundColor Yellow
            Remove-Item -Path $Path -Recurse -Force -ErrorAction Stop
            Write-Host "Successfully removed registry key: $Path" -ForegroundColor Green
        }
        else {
            Write-Host "Registry key not found: $Path" -ForegroundColor Gray
        }
    }
    catch {
        Write-Host "Failed to remove registry key: $Path - $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host "Step 1: Stopping OpCode processes..." -ForegroundColor Cyan
Get-Process | Where-Object {$_.ProcessName -like "*OpCode*"} | ForEach-Object {
    Write-Host "Stopping process: $($_.ProcessName)" -ForegroundColor Yellow
    try {
        Stop-Process -Id $_.Id -Force -ErrorAction Stop
        Write-Host "Successfully stopped: $($_.ProcessName)" -ForegroundColor Green
    }
    catch {
        Write-Host "Failed to stop: $($_.ProcessName)" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "Step 2: Uninstalling OpCode from Programs and Features..." -ForegroundColor Cyan
$uninstallKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
)

foreach ($key in $uninstallKeys) {
    Get-ItemProperty $key | Where-Object {$_.DisplayName -like "*OpCode*"} | ForEach-Object {
        Write-Host "Found OpCode installation: $($_.DisplayName)" -ForegroundColor Yellow
        if ($_.UninstallString) {
            $uninstallString = $_.UninstallString -replace '"', ''
            Write-Host "Running uninstaller: $uninstallString" -ForegroundColor Yellow
            try {
                Start-Process -FilePath $uninstallString -ArgumentList "/S" -Wait -ErrorAction Stop
                Write-Host "Uninstaller completed successfully" -ForegroundColor Green
            }
            catch {
                Write-Host "Uninstaller failed: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    }
}

Write-Host ""
Write-Host "Step 3: Removing OpCode folders..." -ForegroundColor Cyan

# Common OpCode folder locations
$opcodeFolders = @(
    "$env:PROGRAMFILES\OpCode",
    "${env:PROGRAMFILES(X86)}\OpCode",
    "$env:APPDATA\OpCode",
    "$env:LOCALAPPDATA\OpCode",
    "$env:PROGRAMDATA\OpCode",
    "$env:USERPROFILE\AppData\Local\OpCode",
    "$env:USERPROFILE\AppData\Roaming\OpCode",
    "$env:USERPROFILE\Documents\OpCode",
    "$env:USERPROFILE\Desktop\OpCode",
    "$env:USERPROFILE\Downloads\OpCode"
)

foreach ($folder in $opcodeFolders) {
    Remove-FolderSafely -Path $folder
}

Write-Host ""
Write-Host "Step 4: Removing OpCode registry keys..." -ForegroundColor Cyan

# Registry keys to remove
$registryKeys = @(
    "HKCU:\Software\OpCode",
    "HKLM:\SOFTWARE\OpCode",
    "HKLM:\SOFTWARE\WOW6432Node\OpCode",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\OpCode",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\OpCode"
)

foreach ($key in $registryKeys) {
    Remove-RegistryKeySafely -Path $key
}

Write-Host ""
Write-Host "Step 5: Removing OpCode shortcuts..." -ForegroundColor Cyan

# Shortcut locations
$shortcutLocations = @(
    "$env:USERPROFILE\Desktop\OpCode*",
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\OpCode*",
    "$env:ALLUSERSPROFILE\Microsoft\Windows\Start Menu\Programs\OpCode*"
)

foreach ($location in $shortcutLocations) {
    Get-ChildItem -Path $location -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Host "Removing shortcut: $($_.FullName)" -ForegroundColor Yellow
        try {
            Remove-Item -Path $_.FullName -Force -ErrorAction Stop
            Write-Host "Successfully removed shortcut: $($_.FullName)" -ForegroundColor Green
        }
        catch {
            Write-Host "Failed to remove shortcut: $($_.FullName)" -ForegroundColor Red
        }
    }
}

Write-Host ""
Write-Host "Step 6: Cleaning temporary files..." -ForegroundColor Cyan

# Temporary file locations
$tempLocations = @(
    "$env:TEMP\OpCode*",
    "$env:TMP\OpCode*",
    "$env:LOCALAPPDATA\Temp\OpCode*"
)

foreach ($location in $tempLocations) {
    Get-ChildItem -Path $location -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Host "Removing temp file: $($_.FullName)" -ForegroundColor Yellow
        try {
            Remove-Item -Path $_.FullName -Recurse -Force -ErrorAction Stop
            Write-Host "Successfully removed temp file: $($_.FullName)" -ForegroundColor Green
        }
        catch {
            Write-Host "Failed to remove temp file: $($_.FullName)" -ForegroundColor Red
        }
    }
}

Write-Host ""
Write-Host "Step 7: Final verification..." -ForegroundColor Cyan

# Check if any OpCode processes are still running
$remainingProcesses = Get-Process | Where-Object {$_.ProcessName -like "*OpCode*"}
if ($remainingProcesses) {
    Write-Host "Warning: OpCode processes still running:" -ForegroundColor Yellow
    $remainingProcesses | ForEach-Object { Write-Host "  - $($_.ProcessName)" -ForegroundColor Yellow }
}
else {
    Write-Host "No OpCode processes found running" -ForegroundColor Green
}

# Check if any OpCode folders still exist
$remainingFolders = $opcodeFolders | Where-Object {Test-Path $_}
if ($remainingFolders) {
    Write-Host "Warning: OpCode folders still exist:" -ForegroundColor Yellow
    $remainingFolders | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
}
else {
    Write-Host "No OpCode folders found" -ForegroundColor Green
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Red
Write-Host "OpCode Uninstall Complete!" -ForegroundColor Red
Write-Host "========================================" -ForegroundColor Red
Write-Host ""
Write-Host "Recommendations:" -ForegroundColor Cyan
Write-Host "1. Restart your computer to complete the cleanup" -ForegroundColor White
Write-Host "2. Download fresh OpCode installer from opcode.com" -ForegroundColor White
Write-Host "3. Install as Administrator" -ForegroundColor White
Write-Host "4. Don't configure MCP servers initially" -ForegroundColor White
Write-Host ""
Write-Host "Press any key to exit..." -ForegroundColor Yellow
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
