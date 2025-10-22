#!/bin/bash

################################################################################
# CoreFlow360 V4 - Deployment Success Validation Script
#
# Validates that all production-ready AI agents are deployed successfully
# and meeting performance targets
#
# Usage: bash scripts/validate-deployment-success.sh [--env production]
################################################################################

set -e

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
ENVIRONMENT="${1:-production}"
API_BASE="https://api.coreflow360.com"

if [ "$ENVIRONMENT" != "production" ]; then
  API_BASE="https://api-${ENVIRONMENT}.coreflow360.com"
fi

# Performance Targets
declare -A LATENCY_TARGETS=(
  ["qualification-agent"]=500
  ["chat-support-agent"]=800
  ["finance-agent"]=1000
  ["onboarding-agent"]=1500
  ["knowledge-base-agent"]=600
)

declare -A ERROR_RATE_TARGETS=(
  ["qualification-agent"]=0.01
  ["chat-support-agent"]=0.02
  ["finance-agent"]=0.005
  ["onboarding-agent"]=0.03
  ["knowledge-base-agent"]=0.01
)

# Results tracking
TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0
declare -a FAILURES=()

################################################################################
# Helper Functions
################################################################################

print_header() {
  echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo -e "${BLUE}  $1${NC}"
  echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

print_success() {
  echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
  echo -e "${RED}✗ $1${NC}"
}

print_warning() {
  echo -e "${YELLOW}⚠ $1${NC}"
}

print_info() {
  echo -e "${BLUE}ℹ $1${NC}"
}

record_check() {
  local passed=$1
  local message=$2

  TOTAL_CHECKS=$((TOTAL_CHECKS + 1))

  if [ "$passed" = true ]; then
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
    print_success "$message"
  else
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
    FAILURES+=("$message")
    print_error "$message"
  fi
}

################################################################################
# Validation Functions
################################################################################

validate_agent_health() {
  local agent=$1
  local agent_name=$2

  print_info "Validating $agent_name..."

  # Health check endpoint
  local health_url="${API_BASE}/agents/${agent}/health"

  # Make request and capture response
  local response=$(curl -s -w "\n%{http_code}" "$health_url" 2>/dev/null)
  local http_code=$(echo "$response" | tail -n 1)
  local body=$(echo "$response" | sed '$d')

  # Check HTTP status
  if [ "$http_code" != "200" ]; then
    record_check false "$agent_name: Health endpoint returned HTTP $http_code"
    return 1
  fi

  record_check true "$agent_name: Health endpoint accessible (HTTP 200)"

  # Parse JSON response (basic validation)
  local status=$(echo "$body" | grep -o '"status":"[^"]*"' | cut -d':' -f2 | tr -d '"')

  if [ "$status" = "healthy" ]; then
    record_check true "$agent_name: Status is healthy"
  else
    record_check false "$agent_name: Status is '$status' (expected 'healthy')"
    return 1
  fi

  # Extract latency
  local latency=$(echo "$body" | grep -o '"latency":[0-9]*' | cut -d':' -f2)
  local target=${LATENCY_TARGETS[$agent]}

  if [ -n "$latency" ] && [ "$latency" -lt "$target" ]; then
    record_check true "$agent_name: Latency ${latency}ms < ${target}ms target"
  elif [ -n "$latency" ]; then
    record_check false "$agent_name: Latency ${latency}ms exceeds ${target}ms target"
  else
    print_warning "$agent_name: Could not extract latency from response"
  fi

  # Extract error rate
  local error_rate=$(echo "$body" | grep -o '"errorRate":[0-9.]*' | cut -d':' -f2)
  local error_target=${ERROR_RATE_TARGETS[$agent]}

  if [ -n "$error_rate" ]; then
    local error_pct=$(echo "$error_rate * 100" | bc)
    local target_pct=$(echo "$error_target * 100" | bc)

    if (( $(echo "$error_rate < $error_target" | bc -l) )); then
      record_check true "$agent_name: Error rate ${error_pct}% < ${target_pct}% target"
    else
      record_check false "$agent_name: Error rate ${error_pct}% exceeds ${target_pct}% target"
    fi
  else
    print_warning "$agent_name: Could not extract error rate from response"
  fi

  # Check capabilities
  local capabilities=$(echo "$body" | grep -o '"capabilities":\[[^]]*\]')
  if [ -n "$capabilities" ]; then
    record_check true "$agent_name: Capabilities reported"
  else
    record_check false "$agent_name: No capabilities in health response"
  fi

  echo ""
}

validate_agent_api() {
  local agent=$1
  local agent_name=$2

  print_info "Testing $agent_name API endpoint..."

  # Test task execution endpoint
  local task_url="${API_BASE}/api/v1/agents/${agent}/execute"

  # Simple test task payload
  local payload='{
    "task": {
      "id": "validation-test",
      "capability": "analysis",
      "input": {"data": {"query": "test"}},
      "priority": "normal"
    },
    "context": {
      "userId": "validation-user",
      "businessId": "validation-business",
      "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'",
      "requestId": "validation-request"
    }
  }'

  # Make request
  local response=$(curl -s -w "\n%{http_code}" -X POST \
    -H "Content-Type: application/json" \
    -d "$payload" \
    "$task_url" 2>/dev/null)

  local http_code=$(echo "$response" | tail -n 1)

  # Note: We expect this might fail in some cases (auth, etc)
  # Just checking that endpoint responds
  if [ "$http_code" = "200" ] || [ "$http_code" = "201" ]; then
    record_check true "$agent_name: API endpoint responds successfully"
  elif [ "$http_code" = "401" ] || [ "$http_code" = "403" ]; then
    record_check true "$agent_name: API endpoint accessible (auth required as expected)"
  else
    print_warning "$agent_name: API endpoint returned HTTP $http_code (may need auth)"
  fi

  echo ""
}

validate_monitoring_endpoints() {
  print_header "Validating Monitoring Infrastructure"

  # Check global status endpoint
  print_info "Checking global agent status..."
  local status_url="${API_BASE}/api/v1/agents/status"
  local response=$(curl -s -w "\n%{http_code}" "$status_url" 2>/dev/null)
  local http_code=$(echo "$response" | tail -n 1)

  if [ "$http_code" = "200" ]; then
    record_check true "Global agent status endpoint accessible"
  else
    record_check false "Global agent status endpoint returned HTTP $http_code"
  fi

  echo ""
}

validate_database_connectivity() {
  print_header "Validating Database Connectivity"

  print_info "Checking database health..."
  local db_health_url="${API_BASE}/health/database"
  local response=$(curl -s -w "\n%{http_code}" "$db_health_url" 2>/dev/null)
  local http_code=$(echo "$response" | tail -n 1)

  if [ "$http_code" = "200" ]; then
    record_check true "Database connectivity healthy"
  else
    record_check false "Database health check failed (HTTP $http_code)"
  fi

  echo ""
}

generate_report() {
  print_header "Deployment Validation Report"

  echo ""
  echo "Environment: $ENVIRONMENT"
  echo "Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo ""

  # Overall status
  local pass_rate=$(echo "scale=1; $PASSED_CHECKS * 100 / $TOTAL_CHECKS" | bc)

  echo "Total Checks: $TOTAL_CHECKS"
  echo -e "Passed: ${GREEN}$PASSED_CHECKS${NC}"
  echo -e "Failed: ${RED}$FAILED_CHECKS${NC}"
  echo "Pass Rate: ${pass_rate}%"
  echo ""

  # Deployment status
  if [ "$FAILED_CHECKS" -eq 0 ]; then
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}  ✅ DEPLOYMENT SUCCESSFUL${NC}"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo "All agents deployed successfully and meeting performance targets."
    echo ""
    echo "Next Steps:"
    echo "  • Monitor dashboards: https://dash.coreflow360.com/agents"
    echo "  • View logs: wrangler tail <agent-name> --env $ENVIRONMENT"
    echo "  • Configure alerts: npm run alerts:configure"
    echo ""
    return 0
  elif (( $(echo "$pass_rate >= 80" | bc -l) )); then
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${YELLOW}  ⚠️  DEPLOYMENT PARTIALLY SUCCESSFUL${NC}"
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo "Most checks passed but some issues detected:"
    echo ""
    for failure in "${FAILURES[@]}"; do
      echo "  • $failure"
    done
    echo ""
    echo "Recommended Actions:"
    echo "  • Review agent logs for errors"
    echo "  • Check environment variables"
    echo "  • Verify API keys and secrets"
    echo ""
    return 1
  else
    echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${RED}  ❌ DEPLOYMENT FAILED${NC}"
    echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo "Critical failures detected:"
    echo ""
    for failure in "${FAILURES[@]}"; do
      echo "  • $failure"
    done
    echo ""
    echo "Required Actions:"
    echo "  • Review deployment logs"
    echo "  • Verify Cloudflare Workers deployment"
    echo "  • Check wrangler.toml configuration"
    echo "  • Validate environment variables"
    echo "  • Re-run deployment: bash scripts/deploy-production-agents.sh"
    echo ""
    return 2
  fi
}

################################################################################
# Main Execution
################################################################################

main() {
  echo ""
  print_header "CoreFlow360 V4 - Deployment Validation"
  echo ""
  echo "Environment: $ENVIRONMENT"
  echo "API Base: $API_BASE"
  echo ""

  # Validate each production-ready agent
  print_header "Agent Health Validation"
  echo ""

  validate_agent_health "qualification-agent" "QualificationAgent"
  validate_agent_health "chat-support-agent" "ChatSupportAgent"
  validate_agent_health "finance-agent" "FinanceAgent"
  validate_agent_health "onboarding-agent" "OnboardingAgent"
  validate_agent_health "knowledge-base-agent" "KnowledgeBaseAgent"

  # Validate monitoring infrastructure
  validate_monitoring_endpoints

  # Validate database connectivity
  validate_database_connectivity

  # Generate final report
  generate_report

  local exit_code=$?

  # Save report to file
  local report_file="deployment-validation-$(date +%Y%m%d-%H%M%S).txt"
  {
    echo "CoreFlow360 V4 - Deployment Validation Report"
    echo "Environment: $ENVIRONMENT"
    echo "Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo ""
    echo "Total Checks: $TOTAL_CHECKS"
    echo "Passed: $PASSED_CHECKS"
    echo "Failed: $FAILED_CHECKS"
    echo "Pass Rate: $(echo "scale=1; $PASSED_CHECKS * 100 / $TOTAL_CHECKS" | bc)%"
    echo ""
    if [ ${#FAILURES[@]} -gt 0 ]; then
      echo "Failures:"
      for failure in "${FAILURES[@]}"; do
        echo "  • $failure"
      done
    fi
  } > "$report_file"

  print_info "Report saved to: $report_file"
  echo ""

  exit $exit_code
}

# Run main function
main "$@"
