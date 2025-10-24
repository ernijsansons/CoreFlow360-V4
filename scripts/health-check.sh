#!/bin/bash

# CoreFlow360 V4 - System Health Check Script
# Runs all critical checks to verify system health

set -e

echo "🏥 CoreFlow360 V4 - System Health Check"
echo "========================================"
echo ""

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

PASSED=0
FAILED=0
WARNINGS=0

# Function to run a check
run_check() {
    local name="$1"
    local command="$2"
    local critical="$3"  # "critical" or "warning"

    echo -n "Checking $name... "

    if eval "$command" > /dev/null 2>&1; then
        echo -e "${GREEN}✅ PASS${NC}"
        ((PASSED++))
        return 0
    else
        if [ "$critical" = "critical" ]; then
            echo -e "${RED}❌ FAIL${NC}"
            ((FAILED++))
        else
            echo -e "${YELLOW}⚠️  WARNING${NC}"
            ((WARNINGS++))
        fi
        return 1
    fi
}

# Production Health
echo "=== Production Health ==="
run_check "Production URL" "curl -f -s -o /dev/null https://8eb14753.coreflow360-frontend.pages.dev/" "critical"
echo ""

# Code Quality
echo "=== Code Quality ==="
run_check "Circular Dependencies" "cd frontend && npm run check:circular" "critical"
run_check "TypeScript Compilation" "cd frontend && npm run typecheck" "critical"
run_check "Production Build" "cd frontend && npm run build" "critical"
echo ""

# Security
echo "=== Security ==="
run_check "NPM Audit (Root)" "npm audit --audit-level=critical" "warning"
run_check "NPM Audit (Frontend)" "cd frontend && npm audit --audit-level=critical" "warning"
echo ""

# Git Health
echo "=== Git Health ==="
run_check "Clean Working Tree" "test -z \"\$(git status --porcelain)\"" "warning"
run_check "Remote Sync" "test \"\$(git rev-parse HEAD)\" = \"\$(git rev-parse @{u})\" 2>/dev/null" "warning"
echo ""

# Summary
echo "========================================"
echo "Health Check Summary:"
echo -e "  ${GREEN}Passed: $PASSED${NC}"
if [ $WARNINGS -gt 0 ]; then
    echo -e "  ${YELLOW}Warnings: $WARNINGS${NC}"
fi
if [ $FAILED -gt 0 ]; then
    echo -e "  ${RED}Failed: $FAILED${NC}"
fi
echo "========================================"

# Exit code
if [ $FAILED -gt 0 ]; then
    echo -e "${RED}❌ Health check FAILED${NC}"
    exit 1
elif [ $WARNINGS -gt 0 ]; then
    echo -e "${YELLOW}⚠️  Health check passed with warnings${NC}"
    exit 0
else
    echo -e "${GREEN}✅ All health checks PASSED${NC}"
    exit 0
fi
