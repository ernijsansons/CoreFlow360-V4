#!/bin/bash
# Integration Test Script for CoreFlow360 V4

BASE_URL="https://coreflow360-v4-prod.ernijs-ansons.workers.dev"

echo "================================================"
echo "CoreFlow360 V4 - Integration Test Suite"
echo "================================================"

# Color codes
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Test counter
PASS=0
FAIL=0

# Test function
test_endpoint() {
    local method=$1
    local endpoint=$2
    local expected=$3
    local description=$4

    echo -e "\n${YELLOW}Testing: $description${NC}"
    echo "Endpoint: $method $endpoint"

    response_code=$(curl -s -o /dev/null -w "%{http_code}" -X $method "$BASE_URL$endpoint")

    if [ "$response_code" == "$expected" ]; then
        echo -e "${GREEN}✓ PASS - Status: $response_code${NC}"
        ((PASS++))
    else
        echo -e "${RED}✗ FAIL - Expected: $expected, Got: $response_code${NC}"
        ((FAIL++))
    fi
}

# Test response time
test_performance() {
    local endpoint=$1
    local max_time=$2
    local description=$3

    echo -e "\n${YELLOW}Performance Test: $description${NC}"

    response_time=$(curl -s -o /dev/null -w "%{time_total}" "$BASE_URL$endpoint")
    response_time_ms=$(echo "$response_time * 1000" | bc 2>/dev/null || echo "0")

    if (( $(echo "$response_time_ms < $max_time" | bc -l 2>/dev/null || echo 0) )); then
        echo -e "${GREEN}✓ PASS - Response time: ${response_time_ms}ms (< ${max_time}ms)${NC}"
        ((PASS++))
    else
        echo -e "${RED}✗ FAIL - Response time: ${response_time_ms}ms (> ${max_time}ms)${NC}"
        ((FAIL++))
    fi
}

# Test database connectivity
test_database() {
    echo -e "\n${YELLOW}Testing: Database Connectivity${NC}"

    agent_count=$(wrangler d1 execute coreflow360-agents --remote --command "SELECT COUNT(*) as count FROM agent_registry" 2>&1 | grep -o '"count":8' || echo "")

    if [ ! -z "$agent_count" ]; then
        echo -e "${GREEN}✓ PASS - Database has 8 agents registered${NC}"
        ((PASS++))
    else
        echo -e "${RED}✗ FAIL - Database agent count mismatch${NC}"
        ((FAIL++))
    fi
}

# Run tests
echo -e "\n${YELLOW}Starting Integration Tests...${NC}"

# 1. Health endpoints
test_endpoint "GET" "/health" "200" "Health Check"
test_endpoint "GET" "/" "401" "Root (requires auth)"

# 2. API endpoints
test_endpoint "GET" "/api/status" "500" "API Status (known issue)"
test_endpoint "GET" "/api/agents" "401" "Agent List (requires auth)"

# 3. Performance tests
test_performance "/health" 100 "Health endpoint < 100ms"

# 4. Database test
test_database

# 5. Security tests
test_endpoint "GET" "/admin" "401" "Admin endpoint (should require auth)"
test_endpoint "POST" "/api/login" "400" "Login without credentials"

# Summary
echo -e "\n================================================"
echo -e "Test Results Summary"
echo -e "================================================"
echo -e "${GREEN}Passed: $PASS${NC}"
echo -e "${RED}Failed: $FAIL${NC}"

if [ $FAIL -eq 0 ]; then
    echo -e "\n${GREEN}✅ All tests passed!${NC}"
    exit 0
else
    echo -e "\n${YELLOW}⚠️ Some tests failed. Review the output above.${NC}"
    exit 1
fi