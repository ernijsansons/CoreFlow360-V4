#!/bin/bash

################################################################################
# CoreFlow360 V4 - Production Health Check Script
#
# Performs comprehensive health checks on production and staging environments
# - API endpoint availability
# - Response time validation
# - Database connectivity
# - Cache status
# - Authentication system
# - Critical user flows
#
# Usage:
#   ./scripts/health-check.sh [environment]
#
# Examples:
#   ./scripts/health-check.sh production
#   ./scripts/health-check.sh staging
################################################################################

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
ENVIRONMENT="${1:-staging}"
TIMEOUT=10
MAX_RESPONSE_TIME=2000  # 2 seconds in milliseconds

# Environment URLs
if [ "$ENVIRONMENT" = "production" ]; then
    BASE_URL="https://api.coreflow360.com"
    FRONTEND_URL="https://coreflow360.com"
elif [ "$ENVIRONMENT" = "staging" ]; then
    BASE_URL="https://staging-api.coreflow360.com"
    FRONTEND_URL="https://staging.coreflow360.com"
else
    echo -e "${RED}❌ Invalid environment: $ENVIRONMENT${NC}"
    echo "Usage: $0 [production|staging]"
    exit 1
fi

# Counters
PASSED=0
FAILED=0
WARNINGS=0

################################################################################
# Helper Functions
################################################################################

print_header() {
    echo ""
    echo -e "${BLUE}================================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}================================================${NC}"
    echo ""
}

print_check() {
    echo -e "${YELLOW}⏳ Checking: $1${NC}"
}

print_pass() {
    echo -e "${GREEN}✅ PASS: $1${NC}"
    PASSED=$((PASSED + 1))
}

print_fail() {
    echo -e "${RED}❌ FAIL: $1${NC}"
    FAILED=$((FAILED + 1))
}

print_warn() {
    echo -e "${YELLOW}⚠️  WARN: $1${NC}"
    WARNINGS=$((WARNINGS + 1))
}

check_endpoint() {
    local endpoint=$1
    local expected_status=${2:-200}
    local description=$3

    print_check "$description"

    local response=$(curl -s -w "\n%{http_code}\n%{time_total}" -o /dev/null "$BASE_URL$endpoint" --max-time $TIMEOUT 2>&1)
    local status_code=$(echo "$response" | sed -n '1p')
    local response_time=$(echo "$response" | sed -n '2p')

    # Convert response time to milliseconds
    local response_time_ms=$(echo "$response_time * 1000" | bc | cut -d'.' -f1)

    if [ "$status_code" = "$expected_status" ]; then
        if [ "$response_time_ms" -lt "$MAX_RESPONSE_TIME" ]; then
            print_pass "$description (${response_time_ms}ms)"
        else
            print_warn "$description returned $status_code but slow response (${response_time_ms}ms > ${MAX_RESPONSE_TIME}ms)"
        fi
    else
        print_fail "$description (Expected $expected_status, got $status_code)"
    fi
}

check_json_endpoint() {
    local endpoint=$1
    local description=$2
    local required_field=$3

    print_check "$description"

    local response=$(curl -s "$BASE_URL$endpoint" --max-time $TIMEOUT 2>&1)
    local status=$?

    if [ $status -ne 0 ]; then
        print_fail "$description (Connection failed)"
        return
    fi

    # Check if response is valid JSON
    if echo "$response" | jq . >/dev/null 2>&1; then
        if [ -n "$required_field" ]; then
            # Check if required field exists
            local field_value=$(echo "$response" | jq -r ".$required_field" 2>/dev/null)
            if [ "$field_value" != "null" ] && [ -n "$field_value" ]; then
                print_pass "$description (JSON valid, $required_field present)"
            else
                print_warn "$description (JSON valid but $required_field missing)"
            fi
        else
            print_pass "$description (JSON valid)"
        fi
    else
        print_fail "$description (Invalid JSON response)"
    fi
}

################################################################################
# Health Checks
################################################################################

print_header "CoreFlow360 V4 Health Check - $ENVIRONMENT"
echo "Target API: $BASE_URL"
echo "Frontend: $FRONTEND_URL"
echo "Timeout: ${TIMEOUT}s"
echo "Max Response Time: ${MAX_RESPONSE_TIME}ms"

# 1. Basic Connectivity
print_header "1. Basic Connectivity"

check_endpoint "/health" 200 "Health endpoint"
check_endpoint "/api/status" 200 "API status endpoint"

# 2. Authentication System
print_header "2. Authentication System"

# Test rate limiting (should return 429 after threshold)
print_check "Rate limiting functionality"
for i in {1..6}; do
    status=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/api/auth/test-rate-limit" --max-time $TIMEOUT 2>&1)
    if [ $i -eq 6 ] && [ "$status" = "429" ]; then
        print_pass "Rate limiting working (got 429 on 6th request)"
        break
    elif [ $i -eq 6 ]; then
        print_warn "Rate limiting may not be working (expected 429, got $status)"
    fi
done

# Test authentication (should return 401 without token)
check_endpoint "/api/users/me" 401 "Authentication enforcement"

# 3. API Endpoints
print_header "3. API Endpoints"

check_json_endpoint "/api/status" "API status with version" "version"
check_json_endpoint "/api/agents/status" "AI agents status" "agents"

# 4. Database Connectivity
print_header "4. Database Connectivity"

check_json_endpoint "/api/health/db" "Database health check" "status"

# 5. Cache System
print_header "5. Cache System"

print_check "Cache system status"
cache_response=$(curl -s "$BASE_URL/api/health/cache" --max-time $TIMEOUT 2>&1)
if echo "$cache_response" | jq -e '.kv == "healthy"' >/dev/null 2>&1; then
    print_pass "Cache system healthy"
else
    print_warn "Cache system may have issues"
fi

# 6. Response Time Analysis
print_header "6. Response Time Analysis"

endpoints=(
    "/health"
    "/api/status"
    "/api/agents/status"
)

total_time=0
count=0

for endpoint in "${endpoints[@]}"; do
    response_time=$(curl -s -w "%{time_total}" -o /dev/null "$BASE_URL$endpoint" --max-time $TIMEOUT 2>&1)
    response_time_ms=$(echo "$response_time * 1000" | bc | cut -d'.' -f1)
    total_time=$((total_time + response_time_ms))
    count=$((count + 1))

    echo "  $endpoint: ${response_time_ms}ms"
done

avg_time=$((total_time / count))
echo ""
echo "  Average response time: ${avg_time}ms"

if [ $avg_time -lt 100 ]; then
    print_pass "Excellent average response time (<100ms)"
elif [ $avg_time -lt 200 ]; then
    print_pass "Good average response time (<200ms)"
elif [ $avg_time -lt 500 ]; then
    print_warn "Acceptable average response time (${avg_time}ms)"
else
    print_fail "Slow average response time (${avg_time}ms)"
fi

# 7. Frontend Availability
print_header "7. Frontend Availability"

check_endpoint "" 200 "Frontend landing page"

# Check if frontend loads key resources
print_check "Frontend resources"
frontend_response=$(curl -s "$FRONTEND_URL" --max-time $TIMEOUT 2>&1)
if echo "$frontend_response" | grep -q "vite"; then
    print_pass "Frontend built with Vite (modern build system)"
else
    print_warn "Frontend may not be using expected build system"
fi

# 8. Security Headers
print_header "8. Security Headers"

print_check "Security headers"
headers=$(curl -sI "$BASE_URL/health" --max-time $TIMEOUT 2>&1)

# Check for important security headers
if echo "$headers" | grep -qi "X-Content-Type-Options"; then
    print_pass "X-Content-Type-Options header present"
else
    print_warn "X-Content-Type-Options header missing"
fi

if echo "$headers" | grep -qi "X-Frame-Options"; then
    print_pass "X-Frame-Options header present"
else
    print_warn "X-Frame-Options header missing"
fi

if echo "$headers" | grep -qi "Strict-Transport-Security"; then
    print_pass "HSTS header present"
else
    print_warn "HSTS header missing (HTTPS security)"
fi

# 9. CORS Configuration
print_header "9. CORS Configuration"

print_check "CORS headers"
cors_response=$(curl -sI -X OPTIONS "$BASE_URL/api/status" \
    -H "Origin: https://coreflow360.com" \
    -H "Access-Control-Request-Method: GET" \
    --max-time $TIMEOUT 2>&1)

if echo "$cors_response" | grep -qi "Access-Control-Allow-Origin"; then
    print_pass "CORS configured correctly"
else
    print_warn "CORS headers may not be configured"
fi

# 10. AI Agent System
print_header "10. AI Agent System"

check_json_endpoint "/api/agents/status" "AI agent orchestrator" "orchestrator"
check_json_endpoint "/api/agents/capabilities" "AI agent capabilities" "capabilities"

################################################################################
# Summary Report
################################################################################

print_header "Health Check Summary"

echo ""
echo "Environment: $ENVIRONMENT"
echo "Target: $BASE_URL"
echo ""
echo -e "${GREEN}Passed: $PASSED${NC}"
echo -e "${YELLOW}Warnings: $WARNINGS${NC}"
echo -e "${RED}Failed: $FAILED${NC}"
echo ""

# Generate report file
REPORT_FILE="health-check-${ENVIRONMENT}-$(date +%Y%m%d-%H%M%S).txt"
cat > "$REPORT_FILE" <<EOF
CoreFlow360 V4 Health Check Report
===================================

Environment: $ENVIRONMENT
Target: $BASE_URL
Date: $(date)

Results:
--------
Passed: $PASSED
Warnings: $WARNINGS
Failed: $FAILED

Status: $([ $FAILED -eq 0 ] && echo "HEALTHY" || echo "UNHEALTHY")

Average Response Time: ${avg_time}ms
Max Response Time Threshold: ${MAX_RESPONSE_TIME}ms

Next Check: Schedule in 4 hours
EOF

echo "Report saved to: $REPORT_FILE"
echo ""

# Send to monitoring (if Slack webhook configured)
if [ -n "$SLACK_WEBHOOK_URL" ]; then
    print_check "Sending notification to Slack"

    status_emoji=$([ $FAILED -eq 0 ] && echo "✅" || echo "❌")
    status_text=$([ $FAILED -eq 0 ] && echo "HEALTHY" || echo "UNHEALTHY")

    curl -X POST "$SLACK_WEBHOOK_URL" \
        -H 'Content-Type: application/json' \
        -d "{
            \"text\": \"${status_emoji} Health Check: $ENVIRONMENT - $status_text\",
            \"attachments\": [{
                \"color\": \"$([ $FAILED -eq 0 ] && echo 'good' || echo 'danger')\",
                \"fields\": [
                    {\"title\": \"Environment\", \"value\": \"$ENVIRONMENT\", \"short\": true},
                    {\"title\": \"Passed\", \"value\": \"$PASSED\", \"short\": true},
                    {\"title\": \"Warnings\", \"value\": \"$WARNINGS\", \"short\": true},
                    {\"title\": \"Failed\", \"value\": \"$FAILED\", \"short\": true},
                    {\"title\": \"Avg Response Time\", \"value\": \"${avg_time}ms\", \"short\": true}
                ]
            }]
        }" \
        --silent > /dev/null

    print_pass "Notification sent to Slack"
fi

# Exit with appropriate code
if [ $FAILED -gt 0 ]; then
    echo -e "${RED}❌ Health check FAILED${NC}"
    exit 1
else
    echo -e "${GREEN}✅ Health check PASSED${NC}"
    exit 0
fi
