#!/bin/bash

# CoreFlow360 V4 - Configuration Verification Script
# Phase 4: Verify Domain Configuration and Pre-Deployment Checks
#
# This script validates all configuration before deployment

set -e

echo "=================================================="
echo "CoreFlow360 V4 - Configuration Verification"
echo "=================================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

ERRORS=0
WARNINGS=0

# Function to log error
log_error() {
  echo -e "${RED}❌ $1${NC}"
  ((ERRORS++))
}

# Function to log warning
log_warning() {
  echo -e "${YELLOW}⚠️  $1${NC}"
  ((WARNINGS++))
}

# Function to log success
log_success() {
  echo -e "${GREEN}✅ $1${NC}"
}

# Check 1: API Token
echo "=================================================="
echo "Check 1: Cloudflare API Token"
echo "=================================================="
echo ""

if [ -z "$CLOUDFLARE_API_TOKEN" ]; then
  log_error "CLOUDFLARE_API_TOKEN not set in environment"
else
  if npx wrangler whoami &>/dev/null; then
    log_success "API token is valid"
    npx wrangler whoami | head -n 3
  else
    log_error "API token is invalid"
  fi
fi
echo ""

# Check 2: Build Status
echo "=================================================="
echo "Check 2: Build Status"
echo "=================================================="
echo ""

echo "Running production build..."
if npm run build &>/dev/null; then
  log_success "Build successful"

  # Check for eval() warnings
  if npm run build 2>&1 | grep -q "direct-eval"; then
    log_warning "Build contains eval() warnings"
  else
    log_success "No eval() warnings in build"
  fi
else
  log_error "Build failed"
fi
echo ""

# Check 3: TypeScript Validation
echo "=================================================="
echo "Check 3: TypeScript Validation"
echo "=================================================="
echo ""

if npm run type-check &>/dev/null; then
  log_success "TypeScript validation passed"
else
  log_error "TypeScript validation failed"
fi
echo ""

# Check 4: wrangler.production.toml Validation
echo "=================================================="
echo "Check 4: Production Configuration"
echo "=================================================="
echo ""

if [ ! -f "wrangler.production.toml" ]; then
  log_error "wrangler.production.toml not found"
else
  log_success "wrangler.production.toml exists"

  # Check for PLACEHOLDER markers
  if grep -q "PLACEHOLDER" wrangler.production.toml; then
    log_warning "Configuration contains PLACEHOLDER markers"
    echo "   Run Phase 2 to create production KV namespaces"
  else
    log_success "No PLACEHOLDER markers found"
  fi

  # Check Durable Objects
  if grep -q "SessionManagerDO\|AnalyticsAggregatorDO" wrangler.production.toml; then
    log_error "Configuration contains phantom Durable Objects"
  else
    log_success "No phantom Durable Objects"
  fi

  # Check compatibility_date
  COMPAT_DATE=$(grep "compatibility_date" wrangler.production.toml | head -n 1 | cut -d'"' -f2)
  if [ "$COMPAT_DATE" = "2024-09-01" ]; then
    log_success "Compatibility date is correct: $COMPAT_DATE"
  else
    log_warning "Compatibility date may need update: $COMPAT_DATE"
  fi
fi
echo ""

# Check 5: Secrets Configuration
echo "=================================================="
echo "Check 5: Production Secrets"
echo "=================================================="
echo ""

echo "Checking configured secrets..."
SECRET_LIST=$(npx wrangler secret list --env production 2>&1)

# Required secrets
REQUIRED_SECRETS=("JWT_SECRET" "ENCRYPTION_KEY" "AUTH_SECRET" "ANTHROPIC_API_KEY" "OPENAI_API_KEY")

for SECRET in "${REQUIRED_SECRETS[@]}"; do
  if echo "$SECRET_LIST" | grep -q "$SECRET"; then
    log_success "$SECRET is configured"
  else
    log_error "$SECRET is missing"
  fi
done

# Optional secrets
OPTIONAL_SECRETS=("STRIPE_SECRET_KEY" "STRIPE_WEBHOOK_SECRET" "SENTRY_DSN" "EMAIL_API_KEY")

for SECRET in "${OPTIONAL_SECRETS[@]}"; do
  if echo "$SECRET_LIST" | grep -q "$SECRET"; then
    log_success "$SECRET is configured (optional)"
  else
    log_warning "$SECRET not configured (optional)"
  fi
done
echo ""

# Check 6: KV Namespace Configuration
echo "=================================================="
echo "Check 6: KV Namespaces"
echo "=================================================="
echo ""

# Extract KV namespace IDs from wrangler.production.toml
if [ -f "wrangler.production.toml" ]; then
  echo "Checking KV namespace configuration..."

  REQUIRED_BINDINGS=("KV_CACHE" "KV_SESSION" "KV_RATE_LIMIT_METRICS" "KV_AUTH" "AGENT_CACHE" "AGENT_MEMORY" "PATTERN_CACHE")

  for BINDING in "${REQUIRED_BINDINGS[@]}"; do
    if grep -A 1 "binding = \"$BINDING\"" wrangler.production.toml | grep -q "id = \"[a-f0-9]\{32\}\""; then
      log_success "$BINDING configured"
    else
      log_error "$BINDING missing or invalid"
    fi
  done
fi
echo ""

# Check 7: Custom Domain Configuration
echo "=================================================="
echo "Check 7: Custom Domain"
echo "=================================================="
echo ""

if grep -q "coreflow360.com" wrangler.production.toml; then
  echo "Checking custom domain: coreflow360.com"

  # Try to query Cloudflare API for zone
  ZONE_CHECK=$(npx wrangler pages deployment list --project-name=coreflow360-frontend 2>&1 || echo "not_found")

  if echo "$ZONE_CHECK" | grep -q "not_found\|error\|Error"; then
    log_warning "Custom domain may not be configured in Cloudflare"
    echo "   Options:"
    echo "   1. Configure domain in Cloudflare Dashboard"
    echo "   2. Comment out routes in wrangler.production.toml to use workers.dev"
  else
    log_success "Custom domain appears to be configured"
  fi
else
  log_success "Using workers.dev domain (no custom domain configured)"
fi
echo ""

# Check 8: D1 Database Configuration
echo "=================================================="
echo "Check 8: D1 Database"
echo "=================================================="
echo ""

if grep -q "database_name = \"coreflow360-agents\"" wrangler.production.toml; then
  log_success "D1 database binding configured"

  # Check if database exists
  DB_LIST=$(npx wrangler d1 list 2>&1)
  if echo "$DB_LIST" | grep -q "coreflow360-agents"; then
    log_success "Database 'coreflow360-agents' exists"
  else
    log_warning "Database 'coreflow360-agents' may need to be created"
  fi
else
  log_error "D1 database binding not configured"
fi
echo ""

# Check 9: R2 Bucket Configuration
echo "=================================================="
echo "Check 9: R2 Buckets"
echo "=================================================="
echo ""

REQUIRED_BUCKETS=("coreflow360-documents" "coreflow360-backups")

for BUCKET in "${REQUIRED_BUCKETS[@]}"; do
  if grep -q "bucket_name = \"$BUCKET\"" wrangler.production.toml; then
    log_success "R2 bucket '$BUCKET' configured"
  else
    log_warning "R2 bucket '$BUCKET' not configured"
  fi
done
echo ""

# Check 10: Git Status
echo "=================================================="
echo "Check 10: Git Status"
echo "=================================================="
echo ""

# Check for uncommitted changes
if git diff --quiet && git diff --cached --quiet; then
  log_success "No uncommitted changes"
else
  log_warning "Uncommitted changes detected"
  echo "   Consider committing changes before deployment"
fi

# Check if .env files are gitignored
if git check-ignore .env.local &>/dev/null; then
  log_success ".env.local is gitignored"
else
  log_warning ".env.local may not be in .gitignore"
fi
echo ""

# Check 11: Dry-Run Deployment
echo "=================================================="
echo "Check 11: Dry-Run Deployment Test"
echo "=================================================="
echo ""

echo "Running deployment dry-run..."
DRY_RUN_OUTPUT=$(npx wrangler deploy --dry-run --config wrangler.production.toml 2>&1 || echo "DRY_RUN_FAILED")

if echo "$DRY_RUN_OUTPUT" | grep -q "DRY_RUN_FAILED\|error\|Error"; then
  log_error "Dry-run deployment failed"
  echo "$DRY_RUN_OUTPUT" | head -n 20
else
  log_success "Dry-run deployment successful"
fi
echo ""

# Final Summary
echo "=================================================="
echo "Verification Summary"
echo "=================================================="
echo ""

if [ $ERRORS -eq 0 ] && [ $WARNINGS -eq 0 ]; then
  echo -e "${GREEN}🎉 All checks passed! Ready for deployment.${NC}"
  echo ""
  echo "Next step: Deploy to production"
  echo "  Run: ./scripts/5-deploy-production.sh"
elif [ $ERRORS -eq 0 ]; then
  echo -e "${YELLOW}⚠️  $WARNINGS warnings detected (deployment possible but not optimal)${NC}"
  echo ""
  echo "You can proceed with deployment, but consider addressing warnings first."
  echo "  Run: ./scripts/5-deploy-production.sh"
else
  echo -e "${RED}❌ $ERRORS errors and $WARNINGS warnings detected${NC}"
  echo ""
  echo "Please fix errors before deployment:"
  if echo "$SECRET_LIST" | grep -q "JWT_SECRET.*missing"; then
    echo "  - Run: ./scripts/3-configure-secrets.sh"
  fi
  if grep -q "PLACEHOLDER" wrangler.production.toml 2>/dev/null; then
    echo "  - Run: ./scripts/2-create-production-kv.sh"
  fi
fi

echo ""
echo "Full report:"
echo "  Errors: $ERRORS"
echo "  Warnings: $WARNINGS"
echo ""

# Exit with error code if there are errors
if [ $ERRORS -gt 0 ]; then
  exit 1
fi
