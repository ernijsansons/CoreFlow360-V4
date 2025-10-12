#!/bin/bash

###############################################################################
# Production Environment Validation Script
#
# Validates all required environment variables and secrets before deployment
###############################################################################

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Counters
ERRORS=0
WARNINGS=0
CHECKS=0

# Helper functions
error() {
  echo -e "${RED}❌ ERROR: $1${NC}"
  ((ERRORS++))
}

warning() {
  echo -e "${YELLOW}⚠️  WARNING: $1${NC}"
  ((WARNINGS++))
}

success() {
  echo -e "${GREEN}✓ $1${NC}"
}

info() {
  echo -e "${BLUE}ℹ️  $1${NC}"
}

check_var() {
  local var_name=$1
  local required=$2
  local min_length=${3:-0}

  ((CHECKS++))

  if [ -z "${!var_name}" ]; then
    if [ "$required" = "true" ]; then
      error "Missing required environment variable: $var_name"
    else
      warning "Optional environment variable not set: $var_name"
    fi
    return 1
  fi

  local value="${!var_name}"
  local length=${#value}

  if [ $min_length -gt 0 ] && [ $length -lt $min_length ]; then
    error "$var_name is too short (min: $min_length, actual: $length)"
    return 1
  fi

  success "$var_name is set (length: $length)"
  return 0
}

echo "🔍 Production Environment Validation"
echo "====================================="
echo ""

# Critical Security Variables
echo "🔐 Security Variables:"
check_var "JWT_SECRET" true 64
check_var "ENCRYPTION_KEY" true 32
check_var "AUTH_SECRET" true 32
echo ""

# AI API Keys
echo "🤖 AI Service Keys:"
check_var "ANTHROPIC_API_KEY" true 20
check_var "OPENAI_API_KEY" true 20
echo ""

# Database & Storage
echo "💾 Database & Storage:"
check_var "DB_MAIN" true
check_var "KV_CACHE" true
check_var "KV_SESSION" true
check_var "KV_RATE_LIMIT_METRICS" false
check_var "R2_DOCUMENTS" false
echo ""

# Payment Processing
echo "💳 Payment Processing:"
check_var "STRIPE_SECRET_KEY" false
check_var "STRIPE_PUBLISHABLE_KEY" false
check_var "PAYPAL_CLIENT_ID" false
check_var "PAYPAL_CLIENT_SECRET" false
echo ""

# Monitoring & Analytics
echo "📊 Monitoring & Analytics:"
check_var "SENTRY_DSN" false
check_var "CLOUDFLARE_ANALYTICS_TOKEN" false
echo ""

# Validate JWT_SECRET strength
echo "🔒 JWT Secret Security Check:"
if [ ! -z "$JWT_SECRET" ]; then
  # Check for weak patterns
  if echo "$JWT_SECRET" | grep -qiE "(test|dev|demo|debug|changeme|secret|password)"; then
    error "JWT_SECRET contains weak patterns (test/dev/demo/etc)"
  else
    success "JWT_SECRET does not contain weak patterns"
  fi

  # Check character diversity
  if echo "$JWT_SECRET" | grep -q '[A-Z]' && \
     echo "$JWT_SECRET" | grep -q '[a-z]' && \
     echo "$JWT_SECRET" | grep -q '[0-9]' && \
     echo "$JWT_SECRET" | grep -qE '[^A-Za-z0-9]'; then
    success "JWT_SECRET has good character diversity"
  else
    warning "JWT_SECRET should contain uppercase, lowercase, numbers, and special characters"
  fi
else
  error "Cannot validate JWT_SECRET - not set"
fi
echo ""

# Print Summary
echo "====================================="
echo "📊 Validation Summary:"
echo "  Total Checks: $CHECKS"
echo "  Errors: $ERRORS"
echo "  Warnings: $WARNINGS"
echo "====================================="
echo ""

if [ $ERRORS -eq 0 ]; then
  echo -e "${GREEN}✅ ✅ ✅  ENVIRONMENT VALIDATED  ✅ ✅ ✅${NC}"
  echo ""
  echo "🚀 Ready for production deployment!"
  echo ""
  echo "Next steps:"
  echo "  1. npm run build"
  echo "  2. cd frontend && npm run build"
  echo "  3. npm run verify:production"
  echo "  4. wrangler deploy --env production"
  echo ""
  exit 0
else
  echo -e "${RED}❌ ❌ ❌  ENVIRONMENT VALIDATION FAILED  ❌ ❌ ❌${NC}"
  echo ""
  echo "🛑 Fix the errors above before deploying to production"
  echo ""
  echo "To fix:"
  echo "  1. Set missing environment variables in .env"
  echo "  2. Update wrangler.toml with Cloudflare bindings"
  echo "  3. Run: wrangler secret put JWT_SECRET"
  echo "  4. Run this script again"
  echo ""
  exit 1
fi
