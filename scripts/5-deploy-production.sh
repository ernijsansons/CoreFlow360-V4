#!/bin/bash

# CoreFlow360 V4 - Production Deployment Script
# Phase 5: Deploy to Production with Safety Checks
#
# This script performs a safe production deployment with rollback capability

set -e

echo "=================================================="
echo "CoreFlow360 V4 - Production Deployment"
echo "=================================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check if API token is set
if [ -z "$CLOUDFLARE_API_TOKEN" ]; then
  echo -e "${RED}❌ CLOUDFLARE_API_TOKEN not set${NC}"
  echo "Please set it first:"
  echo "  export CLOUDFLARE_API_TOKEN='your_api_token'"
  exit 1
fi

# Step 1: Pre-Deployment Verification
echo "=================================================="
echo "Step 1: Pre-Deployment Verification"
echo "=================================================="
echo ""

if [ -f "./scripts/4-verify-configuration.sh" ]; then
  echo "Running configuration verification..."
  if bash ./scripts/4-verify-configuration.sh; then
    echo -e "${GREEN}✅ Verification passed${NC}"
  else
    echo -e "${RED}❌ Verification failed${NC}"
    read -p "Continue anyway? (y/n) " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
      exit 1
    fi
  fi
else
  echo -e "${YELLOW}⚠️  Verification script not found, skipping...${NC}"
fi
echo ""

# Step 2: Build Production Bundle
echo "=================================================="
echo "Step 2: Building Production Bundle"
echo "=================================================="
echo ""

echo "Running production build..."
if npm run build; then
  echo -e "${GREEN}✅ Build successful${NC}"

  # Check bundle size
  if [ -f "dist/worker.js" ]; then
    BUNDLE_SIZE=$(du -h dist/worker.js | cut -f1)
    echo "Bundle size: $BUNDLE_SIZE"

    # Warn if bundle is large (>5MB)
    BUNDLE_SIZE_BYTES=$(stat -f%z dist/worker.js 2>/dev/null || stat -c%s dist/worker.js)
    if [ $BUNDLE_SIZE_BYTES -gt 5242880 ]; then
      echo -e "${YELLOW}⚠️  Warning: Bundle size exceeds 5MB${NC}"
    fi
  fi
else
  echo -e "${RED}❌ Build failed${NC}"
  exit 1
fi
echo ""

# Step 3: Git Status Check
echo "=================================================="
echo "Step 3: Git Status"
echo "=================================================="
echo ""

# Get current branch
CURRENT_BRANCH=$(git branch --show-current)
echo "Current branch: $CURRENT_BRANCH"

# Check for uncommitted changes
if git diff --quiet && git diff --cached --quiet; then
  echo -e "${GREEN}✅ No uncommitted changes${NC}"
else
  echo -e "${YELLOW}⚠️  Uncommitted changes detected${NC}"
  git status --short
  echo ""
  read -p "Continue with uncommitted changes? (y/n) " -n 1 -r
  echo ""
  if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    exit 1
  fi
fi

# Get current commit for rollback reference
CURRENT_COMMIT=$(git rev-parse HEAD)
CURRENT_COMMIT_SHORT=$(git rev-parse --short HEAD)
echo "Deploying commit: $CURRENT_COMMIT_SHORT"
echo ""

# Step 4: Deployment Confirmation
echo "=================================================="
echo "Step 4: Deployment Confirmation"
echo "=================================================="
echo ""

echo -e "${YELLOW}⚠️  PRODUCTION DEPLOYMENT WARNING${NC}"
echo ""
echo "You are about to deploy to PRODUCTION environment:"
echo "  Worker: coreflow360-v4-prod"
echo "  Branch: $CURRENT_BRANCH"
echo "  Commit: $CURRENT_COMMIT_SHORT"
echo "  Config: wrangler.production.toml"
echo ""
read -p "Proceed with production deployment? (yes/no) " CONFIRM

if [ "$CONFIRM" != "yes" ]; then
  echo -e "${YELLOW}Deployment cancelled${NC}"
  exit 0
fi
echo ""

# Step 5: Deploy to Production
echo "=================================================="
echo "Step 5: Deploying to Production"
echo "=================================================="
echo ""

echo "Starting deployment..."
DEPLOYMENT_START=$(date +%s)

# Capture deployment output
DEPLOY_OUTPUT=$(npx wrangler deploy --config wrangler.production.toml --env production 2>&1)
DEPLOY_EXIT_CODE=$?

DEPLOYMENT_END=$(date +%s)
DEPLOYMENT_DURATION=$((DEPLOYMENT_END - DEPLOYMENT_START))

echo "$DEPLOY_OUTPUT"
echo ""

if [ $DEPLOY_EXIT_CODE -eq 0 ]; then
  echo -e "${GREEN}✅ Deployment successful (${DEPLOYMENT_DURATION}s)${NC}"

  # Extract worker URL from output
  WORKER_URL=$(echo "$DEPLOY_OUTPUT" | grep -oP 'https://[a-zA-Z0-9\-]+\.workers\.dev' | head -n 1)
  if [ ! -z "$WORKER_URL" ]; then
    echo "Worker URL: $WORKER_URL"
  fi
else
  echo -e "${RED}❌ Deployment failed${NC}"
  exit 1
fi
echo ""

# Step 6: Health Check
echo "=================================================="
echo "Step 6: Post-Deployment Health Check"
echo "=================================================="
echo ""

echo "Waiting 5 seconds for worker to initialize..."
sleep 5

# Determine health check URL
if [ ! -z "$WORKER_URL" ]; then
  HEALTH_URL="$WORKER_URL/health"
else
  # Try custom domain
  if grep -q "api.coreflow360.com" wrangler.production.toml; then
    HEALTH_URL="https://api.coreflow360.com/health"
  else
    echo -e "${YELLOW}⚠️  Could not determine health check URL${NC}"
    HEALTH_URL=""
  fi
fi

if [ ! -z "$HEALTH_URL" ]; then
  echo "Checking health endpoint: $HEALTH_URL"

  if curl -f -s -o /dev/null -w "%{http_code}" "$HEALTH_URL" | grep -q "200\|204"; then
    echo -e "${GREEN}✅ Health check passed${NC}"

    # Get health response
    HEALTH_RESPONSE=$(curl -s "$HEALTH_URL")
    echo "Response: $HEALTH_RESPONSE"
  else
    echo -e "${RED}❌ Health check failed${NC}"
    echo "   This may indicate deployment issues"
  fi
else
  echo -e "${YELLOW}⚠️  Skipping health check (URL not available)${NC}"
fi
echo ""

# Step 7: Monitor Deployment
echo "=================================================="
echo "Step 7: Monitoring"
echo "=================================================="
echo ""

echo "Deployment monitoring commands:"
echo ""
echo "  # Watch live logs:"
echo "  npx wrangler tail coreflow360-v4-prod --env production --format pretty"
echo ""
echo "  # Check worker analytics:"
echo "  https://dash.cloudflare.com/workers"
echo ""
echo "  # View recent deployments:"
echo "  npx wrangler deployments list --name coreflow360-v4-prod"
echo ""

# Step 8: Save Deployment Record
echo "=================================================="
echo "Step 8: Deployment Record"
echo "=================================================="
echo ""

DEPLOYMENT_LOG="deployments/deployment-$(date +%Y%m%d-%H%M%S).log"
mkdir -p deployments

cat > "$DEPLOYMENT_LOG" << EOF
CoreFlow360 V4 - Production Deployment Record
==============================================

Deployment Time: $(date)
Git Branch: $CURRENT_BRANCH
Git Commit: $CURRENT_COMMIT
Commit Message: $(git log -1 --pretty=%B)
Deployed By: $(git config user.name)
Duration: ${DEPLOYMENT_DURATION}s
Worker URL: ${WORKER_URL:-N/A}

Deployment Output:
------------------
$DEPLOY_OUTPUT

Health Check:
-------------
URL: ${HEALTH_URL:-N/A}
Status: ${HEALTH_RESPONSE:-N/A}
EOF

echo -e "${GREEN}✅ Deployment record saved: $DEPLOYMENT_LOG${NC}"
echo ""

# Step 9: Rollback Information
echo "=================================================="
echo "Step 9: Rollback Information"
echo "=================================================="
echo ""

echo "If you need to rollback this deployment:"
echo ""
echo "  # Rollback to previous deployment:"
echo "  npx wrangler rollback --name coreflow360-v4-prod"
echo ""
echo "  # Or deploy previous git commit:"
echo "  git checkout <previous-commit>"
echo "  npx wrangler deploy --config wrangler.production.toml --env production"
echo ""
echo "Current commit for reference: $CURRENT_COMMIT"
echo ""

# Step 10: Next Steps
echo "=================================================="
echo "Step 10: Post-Deployment Actions"
echo "=================================================="
echo ""

echo "Recommended post-deployment actions:"
echo ""
echo "  1. Monitor logs for 5-10 minutes:"
echo "     npx wrangler tail coreflow360-v4-prod --env production"
echo ""
echo "  2. Test critical user flows:"
echo "     - Authentication"
echo "     - AI agent operations"
echo "     - Database queries"
echo ""
echo "  3. Check error rates in Cloudflare Dashboard"
echo ""
echo "  4. Verify Durable Objects are initializing"
echo ""
echo "  5. Test frontend integration"
echo ""

# Final Success Message
echo "=================================================="
echo -e "${GREEN}🚀 Production Deployment Complete!${NC}"
echo "=================================================="
echo ""
echo "Worker: coreflow360-v4-prod"
echo "Commit: $CURRENT_COMMIT_SHORT"
echo "Time: $(date)"
echo ""
echo -e "${GREEN}✅ Deployment successful!${NC}"
echo ""
