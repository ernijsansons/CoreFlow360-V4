# Create Desktop Shortcut for VibeSDK Claude Local Bridge
Write-Host "Creating desktop shortcut..." -ForegroundColor Yellow

$WshShell = New-Object -comObject WScript.Shell
$DesktopPath = [Environment]::GetFolderPath("Desktop")
$ShortcutPath = Join-Path $DesktopPath "VibeSDK Claude Local.lnk"
$Shortcut = $WshShell.CreateShortcut($ShortcutPath)

# Set shortcut properties
$CurrentDir = Get-Location
$Shortcut.TargetPath = Join-Path $CurrentDir "start-vibesdk-claude.bat"
$Shortcut.WorkingDirectory = $CurrentDir
$Shortcut.Description = "Launch VibeSDK with Claude Local Bridge - Zero API Costs!"
$Shortcut.IconLocation = "shell32.dll,70"  # Use a nice computer icon

# Save the shortcut
$Shortcut.Save()

Write-Host "✅ Desktop shortcut created successfully!" -ForegroundColor Green
Write-Host "📍 Location: $ShortcutPath" -ForegroundColor Gray
Write-Host "🚀 Double-click to launch VibeSDK with Claude Local Bridge" -ForegroundColor Cyan