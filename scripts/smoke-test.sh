#!/bin/bash

################################################################################
# CoreFlow360 V4 - Smoke Test Script
#
# Quick smoke tests for critical user flows after deployment
# - User registration
# - User login
# - Dashboard access
# - API functionality
# - AI agent interactions
#
# Usage:
#   ./scripts/smoke-test.sh [environment]
#
# Examples:
#   ./scripts/smoke-test.sh production
#   ./scripts/smoke-test.sh staging
################################################################################

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
ENVIRONMENT="${1:-staging}"
TEST_EMAIL="smoke-test-$(date +%s)@coreflow360.com"
TEST_PASSWORD="SecureTestPassword123!@#"

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

# Test results
PASSED=0
FAILED=0

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

print_test() {
    echo -e "${YELLOW}▶ Testing: $1${NC}"
}

print_pass() {
    echo -e "${GREEN}✅ PASS: $1${NC}"
    PASSED=$((PASSED + 1))
}

print_fail() {
    echo -e "${RED}❌ FAIL: $1${NC}"
    FAILED=$((FAILED + 1))
}

################################################################################
# Smoke Tests
################################################################################

print_header "CoreFlow360 V4 Smoke Tests - $ENVIRONMENT"
echo "API: $BASE_URL"
echo "Frontend: $FRONTEND_URL"
echo "Test User: $TEST_EMAIL"
echo ""

# 1. Test User Registration
print_header "1. User Registration Flow"
print_test "Registering new user"

REGISTER_RESPONSE=$(curl -s -X POST "$BASE_URL/api/auth/register" \
    -H "Content-Type: application/json" \
    -d "{
        \"email\": \"$TEST_EMAIL\",
        \"password\": \"$TEST_PASSWORD\",
        \"fullName\": \"Smoke Test User\"
    }" 2>&1)

REGISTER_STATUS=$(echo "$REGISTER_RESPONSE" | jq -r '.success // "false"')

if [ "$REGISTER_STATUS" = "true" ]; then
    USER_ID=$(echo "$REGISTER_RESPONSE" | jq -r '.userId')
    print_pass "User registered successfully (ID: $USER_ID)"
else
    print_fail "User registration failed"
    echo "Response: $REGISTER_RESPONSE"
fi

# 2. Test User Login
print_header "2. User Login Flow"
print_test "Logging in user"

LOGIN_RESPONSE=$(curl -s -X POST "$BASE_URL/api/auth/login" \
    -H "Content-Type: application/json" \
    -d "{
        \"email\": \"$TEST_EMAIL\",
        \"password\": \"$TEST_PASSWORD\"
    }" 2>&1)

LOGIN_SUCCESS=$(echo "$LOGIN_RESPONSE" | jq -r '.success // "false"')

if [ "$LOGIN_SUCCESS" = "true" ]; then
    ACCESS_TOKEN=$(echo "$LOGIN_RESPONSE" | jq -r '.accessToken')
    REFRESH_TOKEN=$(echo "$LOGIN_RESPONSE" | jq -r '.refreshToken')
    print_pass "User logged in successfully"
    echo "  Access Token: ${ACCESS_TOKEN:0:20}..."
else
    print_fail "User login failed"
    echo "Response: $LOGIN_RESPONSE"
    exit 1
fi

# 3. Test Authenticated Endpoint
print_header "3. Authenticated API Access"
print_test "Accessing /api/users/me"

ME_RESPONSE=$(curl -s "$BASE_URL/api/users/me" \
    -H "Authorization: Bearer $ACCESS_TOKEN" 2>&1)

ME_EMAIL=$(echo "$ME_RESPONSE" | jq -r '.email // "null"')

if [ "$ME_EMAIL" = "$TEST_EMAIL" ]; then
    print_pass "Authenticated endpoint access successful"
else
    print_fail "Authenticated endpoint access failed"
    echo "Response: $ME_RESPONSE"
fi

# 4. Test Dashboard Data
print_header "4. Dashboard Data Retrieval"
print_test "Fetching dashboard data"

DASHBOARD_RESPONSE=$(curl -s "$BASE_URL/api/dashboard" \
    -H "Authorization: Bearer $ACCESS_TOKEN" 2>&1)

DASHBOARD_SUCCESS=$(echo "$DASHBOARD_RESPONSE" | jq -r '.success // "false"')

if [ "$DASHBOARD_SUCCESS" = "true" ]; then
    print_pass "Dashboard data retrieved successfully"
else
    print_fail "Dashboard data retrieval failed"
    echo "Response: $DASHBOARD_RESPONSE"
fi

# 5. Test AI Agent Status
print_header "5. AI Agent System"
print_test "Checking AI agent status"

AGENT_RESPONSE=$(curl -s "$BASE_URL/api/agents/status" \
    -H "Authorization: Bearer $ACCESS_TOKEN" 2>&1)

AGENT_STATUS=$(echo "$AGENT_RESPONSE" | jq -r '.orchestrator.status // "null"')

if [ "$AGENT_STATUS" = "operational" ]; then
    print_pass "AI agent system operational"
else
    print_fail "AI agent system not operational"
    echo "Response: $AGENT_RESPONSE"
fi

# 6. Test Token Refresh
print_header "6. Token Refresh Flow"
print_test "Refreshing access token"

REFRESH_RESPONSE=$(curl -s -X POST "$BASE_URL/api/auth/refresh" \
    -H "Content-Type: application/json" \
    -d "{
        \"refreshToken\": \"$REFRESH_TOKEN\"
    }" 2>&1)

NEW_ACCESS_TOKEN=$(echo "$REFRESH_RESPONSE" | jq -r '.accessToken // "null"')

if [ "$NEW_ACCESS_TOKEN" != "null" ] && [ "$NEW_ACCESS_TOKEN" != "$ACCESS_TOKEN" ]; then
    print_pass "Token refresh successful"
    ACCESS_TOKEN="$NEW_ACCESS_TOKEN"
else
    print_fail "Token refresh failed"
    echo "Response: $REFRESH_RESPONSE"
fi

# 7. Test Business Creation
print_header "7. Business Management"
print_test "Creating a test business"

BUSINESS_RESPONSE=$(curl -s -X POST "$BASE_URL/api/businesses" \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{
        \"name\": \"Smoke Test Business\",
        \"industry\": \"Technology\",
        \"description\": \"Test business for smoke testing\"
    }" 2>&1)

BUSINESS_ID=$(echo "$BUSINESS_RESPONSE" | jq -r '.businessId // "null"')

if [ "$BUSINESS_ID" != "null" ]; then
    print_pass "Business created successfully (ID: $BUSINESS_ID)"
else
    print_fail "Business creation failed"
    echo "Response: $BUSINESS_RESPONSE"
fi

# 8. Test CRM Functionality
print_header "8. CRM System"
print_test "Creating a test lead"

LEAD_RESPONSE=$(curl -s -X POST "$BASE_URL/api/crm/leads" \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{
        \"name\": \"Test Lead\",
        \"email\": \"lead@example.com\",
        \"source\": \"Smoke Test\",
        \"businessId\": \"$BUSINESS_ID\"
    }" 2>&1)

LEAD_ID=$(echo "$LEAD_RESPONSE" | jq -r '.leadId // "null"')

if [ "$LEAD_ID" != "null" ]; then
    print_pass "Lead created successfully (ID: $LEAD_ID)"
else
    print_fail "Lead creation failed"
    echo "Response: $LEAD_RESPONSE"
fi

# 9. Test Finance Module
print_header "9. Finance System"
print_test "Creating a test invoice"

INVOICE_RESPONSE=$(curl -s -X POST "$BASE_URL/api/finance/invoices" \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{
        \"businessId\": \"$BUSINESS_ID\",
        \"customerId\": \"$LEAD_ID\",
        \"items\": [{
            \"description\": \"Test Service\",
            \"quantity\": 1,
            \"unitPrice\": 100
        }]
    }" 2>&1)

INVOICE_ID=$(echo "$INVOICE_RESPONSE" | jq -r '.invoiceId // "null"')

if [ "$INVOICE_ID" != "null" ]; then
    print_pass "Invoice created successfully (ID: $INVOICE_ID)"
else
    print_fail "Invoice creation failed"
    echo "Response: $INVOICE_RESPONSE"
fi

# 10. Test User Logout
print_header "10. User Logout Flow"
print_test "Logging out user"

LOGOUT_RESPONSE=$(curl -s -X POST "$BASE_URL/api/auth/logout" \
    -H "Authorization: Bearer $ACCESS_TOKEN" 2>&1)

LOGOUT_SUCCESS=$(echo "$LOGOUT_RESPONSE" | jq -r '.success // "false"')

if [ "$LOGOUT_SUCCESS" = "true" ]; then
    print_pass "User logged out successfully"
else
    print_fail "User logout failed"
    echo "Response: $LOGOUT_RESPONSE"
fi

# 11. Verify Token Invalidation
print_header "11. Token Invalidation"
print_test "Verifying token is invalidated"

INVALID_RESPONSE=$(curl -s "$BASE_URL/api/users/me" \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -w "\n%{http_code}" 2>&1)

HTTP_STATUS=$(echo "$INVALID_RESPONSE" | tail -n 1)

if [ "$HTTP_STATUS" = "401" ]; then
    print_pass "Token correctly invalidated after logout"
else
    print_fail "Token still valid after logout (security issue)"
fi

# 12. Test Frontend
print_header "12. Frontend Availability"
print_test "Checking frontend landing page"

FRONTEND_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$FRONTEND_URL" 2>&1)

if [ "$FRONTEND_STATUS" = "200" ]; then
    print_pass "Frontend landing page accessible"
else
    print_fail "Frontend landing page not accessible (status: $FRONTEND_STATUS)"
fi

################################################################################
# Cleanup
################################################################################

print_header "Cleanup"
print_test "Cleaning up test data"

# Note: In production, you might want to keep test users for monitoring
# or implement a cleanup API endpoint

echo "  Test user: $TEST_EMAIL (manual cleanup required)"
echo "  Business ID: $BUSINESS_ID"
echo "  Lead ID: $LEAD_ID"
echo "  Invoice ID: $INVOICE_ID"

################################################################################
# Summary
################################################################################

print_header "Smoke Test Summary"

echo ""
echo "Environment: $ENVIRONMENT"
echo "Target: $BASE_URL"
echo ""
echo -e "${GREEN}Passed: $PASSED${NC}"
echo -e "${RED}Failed: $FAILED${NC}"
echo ""

# Generate report
REPORT_FILE="smoke-test-${ENVIRONMENT}-$(date +%Y%m%d-%H%M%S).txt"
cat > "$REPORT_FILE" <<EOF
CoreFlow360 V4 Smoke Test Report
=================================

Environment: $ENVIRONMENT
Target: $BASE_URL
Date: $(date)

Test Results:
-------------
Passed: $PASSED
Failed: $FAILED

Status: $([ $FAILED -eq 0 ] && echo "ALL TESTS PASSED ✅" || echo "SOME TESTS FAILED ❌")

Test User: $TEST_EMAIL
Business ID: $BUSINESS_ID
Lead ID: $LEAD_ID
Invoice ID: $INVOICE_ID

Critical Flows Tested:
- User Registration ✓
- User Login ✓
- Authentication ✓
- Dashboard Access ✓
- AI Agents ✓
- Token Refresh ✓
- Business Creation ✓
- CRM Functionality ✓
- Finance Module ✓
- User Logout ✓
- Token Invalidation ✓
- Frontend Access ✓
EOF

echo "Report saved to: $REPORT_FILE"
echo ""

# Send notification
if [ -n "$SLACK_WEBHOOK_URL" ]; then
    print_test "Sending notification to Slack"

    status_emoji=$([ $FAILED -eq 0 ] && echo "✅" || echo "❌")
    status_text=$([ $FAILED -eq 0 ] && echo "ALL PASSED" || echo "SOME FAILED")

    curl -X POST "$SLACK_WEBHOOK_URL" \
        -H 'Content-Type: application/json' \
        -d "{
            \"text\": \"${status_emoji} Smoke Tests: $ENVIRONMENT - $status_text\",
            \"attachments\": [{
                \"color\": \"$([ $FAILED -eq 0 ] && echo 'good' || echo 'danger')\",
                \"fields\": [
                    {\"title\": \"Environment\", \"value\": \"$ENVIRONMENT\", \"short\": true},
                    {\"title\": \"Passed\", \"value\": \"$PASSED\", \"short\": true},
                    {\"title\": \"Failed\", \"value\": \"$FAILED\", \"short\": true},
                    {\"title\": \"Report\", \"value\": \"$REPORT_FILE\", \"short\": false}
                ]
            }]
        }" \
        --silent > /dev/null

    print_pass "Notification sent to Slack"
fi

# Exit
if [ $FAILED -gt 0 ]; then
    echo -e "${RED}❌ Smoke tests FAILED${NC}"
    echo "Review the failures above and investigate"
    exit 1
else
    echo -e "${GREEN}✅ All smoke tests PASSED${NC}"
    echo "Deployment verified successfully"
    exit 0
fi
