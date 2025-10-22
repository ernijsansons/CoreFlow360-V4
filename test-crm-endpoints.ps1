# CoreFlow360 V4 - CRM Integration Endpoints Testing Script
# Tests all newly added backend endpoints

$baseUrl = "http://127.0.0.1:8790"
$testResults = @()

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "CoreFlow360 V4 - CRM Endpoints Testing" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Test 1: Health Check
Write-Host "[1/8] Testing Health Endpoint..." -ForegroundColor Yellow
try {
    $health = Invoke-RestMethod -Uri "$baseUrl/health" -Method GET
    Write-Host "  ✓ Health: $($health.status)" -ForegroundColor Green
    $testResults += @{Test="Health Check"; Status="PASS"; Response=$health.status}
} catch {
    Write-Host "  ✗ Health check failed: $_" -ForegroundColor Red
    $testResults += @{Test="Health Check"; Status="FAIL"; Error=$_.Exception.Message}
}

# Test 2: Conversation Logs List (without auth - should fail or return empty)
Write-Host "`n[2/8] Testing Conversation Logs List..." -ForegroundColor Yellow
try {
    $logs = Invoke-RestMethod -Uri "$baseUrl/api/v1/crm/conversation-logs?limit=10" -Method GET
    Write-Host "  ✓ Conversation logs response received" -ForegroundColor Green
    $testResults += @{Test="Conversation Logs List"; Status="PASS"; Response="Success"}
} catch {
    if ($_.Exception.Response.StatusCode -eq 401) {
        Write-Host "  ✓ Auth required (as expected)" -ForegroundColor Green
        $testResults += @{Test="Conversation Logs List"; Status="PASS"; Response="Auth Required"}
    } else {
        Write-Host "  ✗ Failed: $_" -ForegroundColor Red
        $testResults += @{Test="Conversation Logs List"; Status="FAIL"; Error=$_.Exception.Message}
    }
}

# Test 3: Conversation Logs Stats
Write-Host "`n[3/8] Testing Conversation Logs Stats..." -ForegroundColor Yellow
try {
    $stats = Invoke-RestMethod -Uri "$baseUrl/api/v1/crm/conversation-logs/stats/summary" -Method GET
    Write-Host "  ✓ Stats response received" -ForegroundColor Green
    $testResults += @{Test="Conversation Logs Stats"; Status="PASS"}
} catch {
    if ($_.Exception.Response.StatusCode -eq 401) {
        Write-Host "  ✓ Auth required (as expected)" -ForegroundColor Green
        $testResults += @{Test="Conversation Logs Stats"; Status="PASS"; Response="Auth Required"}
    } else {
        Write-Host "  ✗ Failed: $_" -ForegroundColor Red
        $testResults += @{Test="Conversation Logs Stats"; Status="FAIL"}
    }
}

# Test 4: CRM Integrations Sync Status
Write-Host "`n[4/8] Testing CRM Integrations Sync Status..." -ForegroundColor Yellow
try {
    $sync = Invoke-RestMethod -Uri "$baseUrl/api/v1/crm/integrations/sync-status" -Method GET
    Write-Host "  ✓ Sync status response received" -ForegroundColor Green
    $testResults += @{Test="Sync Status"; Status="PASS"}
} catch {
    if ($_.Exception.Response.StatusCode -eq 401) {
        Write-Host "  ✓ Auth required (as expected)" -ForegroundColor Green
        $testResults += @{Test="Sync Status"; Status="PASS"; Response="Auth Required"}
    } else {
        Write-Host "  ✗ Failed: $_" -ForegroundColor Red
        $testResults += @{Test="Sync Status"; Status="FAIL"}
    }
}

# Test 5: Gmail Integration Test
Write-Host "`n[5/8] Testing Gmail Integration Test Endpoint..." -ForegroundColor Yellow
try {
    $gmailTest = Invoke-RestMethod -Uri "$baseUrl/api/v1/crm/integrations/gmail/test" -Method POST
    Write-Host "  ✓ Gmail test endpoint responded" -ForegroundColor Green
    $testResults += @{Test="Gmail Test"; Status="PASS"}
} catch {
    if ($_.Exception.Response.StatusCode -eq 401) {
        Write-Host "  ✓ Auth required (as expected)" -ForegroundColor Green
        $testResults += @{Test="Gmail Test"; Status="PASS"; Response="Auth Required"}
    } else {
        Write-Host "  ✗ Failed: $_" -ForegroundColor Red
        $testResults += @{Test="Gmail Test"; Status="FAIL"}
    }
}

# Test 6: Outlook Integration Test
Write-Host "`n[6/8] Testing Outlook Integration Test Endpoint..." -ForegroundColor Yellow
try {
    $outlookTest = Invoke-RestMethod -Uri "$baseUrl/api/v1/crm/integrations/outlook/test" -Method POST
    Write-Host "  ✓ Outlook test endpoint responded" -ForegroundColor Green
    $testResults += @{Test="Outlook Test"; Status="PASS"}
} catch {
    if ($_.Exception.Response.StatusCode -eq 401) {
        Write-Host "  ✓ Auth required (as expected)" -ForegroundColor Green
        $testResults += @{Test="Outlook Test"; Status="PASS"; Response="Auth Required"}
    } else {
        Write-Host "  ✗ Failed: $_" -ForegroundColor Red
        $testResults += @{Test="Outlook Test"; Status="FAIL"}
    }
}

# Test 7: Twilio Integration Test
Write-Host "`n[7/8] Testing Twilio Integration Test Endpoint..." -ForegroundColor Yellow
try {
    $twilioTest = Invoke-RestMethod -Uri "$baseUrl/api/v1/crm/integrations/twilio/test" -Method POST
    Write-Host "  ✓ Twilio test endpoint responded" -ForegroundColor Green
    $testResults += @{Test="Twilio Test"; Status="PASS"}
} catch {
    if ($_.Exception.Response.StatusCode -eq 401) {
        Write-Host "  ✓ Auth required (as expected)" -ForegroundColor Green
        $testResults += @{Test="Twilio Test"; Status="PASS"; Response="Auth Required"}
    } else {
        Write-Host "  ✗ Failed: $_" -ForegroundColor Red
        $testResults += @{Test="Twilio Test"; Status="FAIL"}
    }
}

# Test 8: Gmail Config Update
Write-Host "`n[8/8] Testing Gmail Config Update Endpoint..." -ForegroundColor Yellow
try {
    $body = @{sync_enabled=$true; sync_frequency=15} | ConvertTo-Json
    $configUpdate = Invoke-RestMethod -Uri "$baseUrl/api/v1/crm/integrations/gmail/config" -Method PUT -Body $body -ContentType "application/json"
    Write-Host "  ✓ Config update endpoint responded" -ForegroundColor Green
    $testResults += @{Test="Gmail Config"; Status="PASS"}
} catch {
    if ($_.Exception.Response.StatusCode -eq 401) {
        Write-Host "  ✓ Auth required (as expected)" -ForegroundColor Green
        $testResults += @{Test="Gmail Config"; Status="PASS"; Response="Auth Required"}
    } else {
        Write-Host "  ✗ Failed: $_" -ForegroundColor Red
        $testResults += @{Test="Gmail Config"; Status="FAIL"}
    }
}

# Summary
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "TEST SUMMARY" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$passCount = ($testResults | Where-Object {$_.Status -eq "PASS"}).Count
$failCount = ($testResults | Where-Object {$_.Status -eq "FAIL"}).Count

Write-Host "`nTotal Tests: $($testResults.Count)" -ForegroundColor White
Write-Host "Passed: $passCount" -ForegroundColor Green
Write-Host "Failed: $failCount" -ForegroundColor $(if($failCount -eq 0){"Green"}else{"Red"})

Write-Host "`nDetailed Results:" -ForegroundColor White
$testResults | ForEach-Object {
    $color = if($_.Status -eq "PASS"){"Green"}else{"Red"}
    Write-Host "  $($_.Test): $($_.Status)" -ForegroundColor $color
}

Write-Host "`n========================================`n" -ForegroundColor Cyan
