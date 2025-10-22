#!/usr/bin/env pwsh

<#
.SYNOPSIS
    CoreFlow360 V4 - Parallel Agent Test Execution Script

.DESCRIPTION
    Launches 8 PowerShell terminals running agent tests in parallel.
    Reduces test execution time from ~32 seconds to ~7 seconds.

.EXAMPLE
    .\run-parallel-tests.ps1

.NOTES
    File Name      : run-parallel-tests.ps1
    Author         : CoreFlow360 Engineering Team
    Prerequisite   : PowerShell 7+, Node.js 20+
    Copyright 2025 : CoreFlow360
#>

# Display banner
Write-Host ""
Write-Host "╔═══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║                                                           ║" -ForegroundColor Cyan
Write-Host "║   CoreFlow360 V4 - Parallel Agent Test Execution         ║" -ForegroundColor Cyan
Write-Host "║                                                           ║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""
Write-Host "🚀 Starting Parallel Test Execution..." -ForegroundColor Green
Write-Host "Opening 8 terminals for agent test suites...`n" -ForegroundColor Yellow

# Define test suites with metadata
$tests = @(
    @{
        Name = "Claude Agent"
        Command = "npm test -- --run src/modules/agents/__tests__/claude-agent.test.ts"
        Tests = "38"
        Priority = "P0"
        Color = "Blue"
    },
    @{
        Name = "Finance Agent"
        Command = "npm test -- --run src/modules/agents/__tests__/finance-agent.test.ts"
        Tests = "90"
        Priority = "P0"
        Color = "Green"
    },
    @{
        Name = "Support Ticket"
        Command = "npm test -- --run src/modules/agents/__tests__/support-ticket-agent.test.ts"
        Tests = "43"
        Priority = "P0"
        Color = "Yellow"
    },
    @{
        Name = "Chat Support"
        Command = "npm test -- --run src/modules/agents/__tests__/chat-support-agent.test.ts"
        Tests = "39"
        Priority = "P1"
        Color = "Cyan"
    },
    @{
        Name = "Qualification"
        Command = "npm test -- --run src/modules/agents/__tests__/qualification-agent.test.ts"
        Tests = "37"
        Priority = "P1"
        Color = "Magenta"
    },
    @{
        Name = "Knowledge Base"
        Command = "npm test -- --run src/modules/agents/__tests__/knowledge-base-agent.test.ts"
        Tests = "34"
        Priority = "P2"
        Color = "DarkGreen"
    },
    @{
        Name = "Onboarding"
        Command = "npm test -- --run src/modules/agents/__tests__/onboarding-agent.test.ts"
        Tests = "18"
        Priority = "P2"
        Color = "DarkYellow"
    },
    @{
        Name = "Company Knowledge"
        Command = "npm test -- --run src/modules/agents/__tests__/company-knowledge-agent.test.ts"
        Tests = "19"
        Priority = "P2"
        Color = "DarkCyan"
    }
)

# Launch each test suite in a new terminal
$launchedCount = 0
foreach ($test in $tests) {
    Write-Host "📋 Launching: " -NoNewline -ForegroundColor Gray
    Write-Host "$($test.Name)" -NoNewline -ForegroundColor $test.Color
    Write-Host " [$($test.Priority)] " -NoNewline -ForegroundColor DarkGray
    Write-Host "($($test.Tests) tests)" -ForegroundColor DarkGray

    try {
        # Create a startup command that shows info and runs tests
        $startupCommand = @"
Write-Host '═══════════════════════════════════════════════════' -ForegroundColor Cyan
Write-Host ' $($test.Name) Test Suite' -ForegroundColor White
Write-Host ' Tests: $($test.Tests) | Priority: $($test.Priority)' -ForegroundColor Gray
Write-Host '═══════════════════════════════════════════════════' -ForegroundColor Cyan
Write-Host ''
$($test.Command)
Write-Host ''
Write-Host 'Press any key to close this window...' -ForegroundColor Yellow
`$null = `$Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
"@

        Start-Process pwsh -ArgumentList "-NoExit", "-Command", $startupCommand
        $launchedCount++
        Start-Sleep -Milliseconds 500  # Stagger launches to avoid resource contention
    }
    catch {
        Write-Host "   ⚠️  Failed to launch: $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "✅ Successfully launched $launchedCount/$($tests.Count) test terminals!" -ForegroundColor Green
Write-Host ""
Write-Host "╔═══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║  Expected Results:                                        ║" -ForegroundColor Cyan
Write-Host "║    • Total Tests: 317 (318 with 1 skipped)               ║" -ForegroundColor White
Write-Host "║    • Completion Time: ~7-10 seconds                       ║" -ForegroundColor White
Write-Host "║    • Sequential Time: ~32 seconds                         ║" -ForegroundColor White
Write-Host "║    • Speed Improvement: 78% faster                        ║" -ForegroundColor Green
Write-Host "╚═══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""
Write-Host "💡 Tips:" -ForegroundColor Yellow
Write-Host "   • Watch each terminal for real-time progress" -ForegroundColor Gray
Write-Host "   • All tests should show ✓ (passing) status" -ForegroundColor Gray
Write-Host "   • Slowest suite (Claude Agent) determines total time" -ForegroundColor Gray
Write-Host ""
Write-Host "📊 Monitor terminals for results..." -ForegroundColor Cyan
Write-Host ""

# Optional: Wait for user input before closing
Write-Host "Press Enter to exit this launcher..." -ForegroundColor DarkGray
Read-Host
