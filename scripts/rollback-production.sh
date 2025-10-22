#!/bin/bash

# CoreFlow360 V4 - Production Rollback Script
# Emergency rollback for production deployments
#
# CRITICAL: Use this script to quickly rollback a problematic deployment

set -e

echo "=================================================="
echo "CoreFlow360 V4 - EMERGENCY ROLLBACK"
echo "=================================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if API token is set
if [ -z "$CLOUDFLARE_API_TOKEN" ]; then
  echo -e "${RED}❌ CLOUDFLARE_API_TOKEN not set${NC}"
  echo "Please set it first:"
  echo "  export CLOUDFLARE_API_TOKEN='your_api_token'"
  exit 1
fi

echo -e "${RED}⚠️  WARNING: PRODUCTION ROLLBACK${NC}"
echo ""
echo "This script will rollback the production deployment."
echo ""

# Get deployment history
echo "Fetching deployment history..."
DEPLOYMENT_LIST=$(npx wrangler deployments list --name coreflow360-v4-prod 2>&1)

echo ""
echo "Recent deployments:"
echo "$DEPLOYMENT_LIST" | head -n 10
echo ""

# Rollback options
echo "=================================================="
echo "Rollback Options"
echo "=================================================="
echo ""
echo "1. Automatic rollback (to previous deployment)"
echo "2. Rollback to specific deployment ID"
echo "3. Deploy from specific git commit"
echo "4. Cancel"
echo ""
read -p "Select option (1-4): " ROLLBACK_OPTION

case $ROLLBACK_OPTION in
  1)
    # Automatic rollback
    echo ""
    echo "Performing automatic rollback..."
    echo ""

    read -p "Confirm automatic rollback to previous deployment? (yes/no) " CONFIRM
    if [ "$CONFIRM" != "yes" ]; then
      echo "Rollback cancelled"
      exit 0
    fi

    echo ""
    npx wrangler rollback --name coreflow360-v4-prod

    if [ $? -eq 0 ]; then
      echo ""
      echo -e "${GREEN}✅ Rollback successful${NC}"
    else
      echo ""
      echo -e "${RED}❌ Rollback failed${NC}"
      exit 1
    fi
    ;;

  2)
    # Rollback to specific deployment
    echo ""
    read -p "Enter deployment ID to rollback to: " DEPLOYMENT_ID

    if [ -z "$DEPLOYMENT_ID" ]; then
      echo "No deployment ID provided"
      exit 1
    fi

    echo ""
    read -p "Confirm rollback to deployment $DEPLOYMENT_ID? (yes/no) " CONFIRM
    if [ "$CONFIRM" != "yes" ]; then
      echo "Rollback cancelled"
      exit 0
    fi

    echo ""
    npx wrangler rollback --name coreflow360-v4-prod --deployment-id "$DEPLOYMENT_ID"

    if [ $? -eq 0 ]; then
      echo ""
      echo -e "${GREEN}✅ Rollback successful${NC}"
    else
      echo ""
      echo -e "${RED}❌ Rollback failed${NC}"
      exit 1
    fi
    ;;

  3)
    # Deploy from git commit
    echo ""
    echo "Recent commits:"
    git log --oneline -n 10
    echo ""

    read -p "Enter commit hash to deploy: " COMMIT_HASH

    if [ -z "$COMMIT_HASH" ]; then
      echo "No commit hash provided"
      exit 1
    fi

    # Verify commit exists
    if ! git cat-file -e "$COMMIT_HASH^{commit}" 2>/dev/null; then
      echo -e "${RED}❌ Invalid commit hash${NC}"
      exit 1
    fi

    echo ""
    echo "Commit details:"
    git show --no-patch --format="%h - %s (%an, %ar)" "$COMMIT_HASH"
    echo ""

    read -p "Confirm deployment of commit $COMMIT_HASH? (yes/no) " CONFIRM
    if [ "$CONFIRM" != "yes" ]; then
      echo "Rollback cancelled"
      exit 0
    fi

    # Stash current changes
    echo ""
    echo "Stashing current changes..."
    git stash push -m "Automatic stash before rollback to $COMMIT_HASH"

    # Checkout commit
    echo "Checking out commit $COMMIT_HASH..."
    git checkout "$COMMIT_HASH"

    # Build
    echo "Building..."
    if ! npm run build; then
      echo -e "${RED}❌ Build failed${NC}"
      git checkout -
      exit 1
    fi

    # Deploy
    echo "Deploying..."
    if npx wrangler deploy --config wrangler.production.toml --env production; then
      echo ""
      echo -e "${GREEN}✅ Deployment successful${NC}"

      # Return to previous branch
      git checkout -

      # Optionally restore stashed changes
      read -p "Restore stashed changes? (y/n) " -n 1 -r
      echo ""
      if [[ $REPLY =~ ^[Yy]$ ]]; then
        git stash pop
      fi
    else
      echo ""
      echo -e "${RED}❌ Deployment failed${NC}"
      git checkout -
      exit 1
    fi
    ;;

  4)
    echo "Rollback cancelled"
    exit 0
    ;;

  *)
    echo "Invalid option"
    exit 1
    ;;
esac

# Health check after rollback
echo ""
echo "=================================================="
echo "Post-Rollback Health Check"
echo "=================================================="
echo ""

echo "Waiting 5 seconds for worker to stabilize..."
sleep 5

# Try health endpoint
if grep -q "api.coreflow360.com" wrangler.production.toml 2>/dev/null; then
  HEALTH_URL="https://api.coreflow360.com/health"
elif echo "$DEPLOYMENT_LIST" | grep -q "workers.dev"; then
  WORKER_URL=$(echo "$DEPLOYMENT_LIST" | grep -oP 'https://[a-zA-Z0-9\-]+\.workers\.dev' | head -n 1)
  HEALTH_URL="$WORKER_URL/health"
else
  HEALTH_URL=""
fi

if [ ! -z "$HEALTH_URL" ]; then
  echo "Checking: $HEALTH_URL"

  HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$HEALTH_URL" || echo "000")

  if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "204" ]; then
    echo -e "${GREEN}✅ Health check passed (HTTP $HTTP_CODE)${NC}"
  else
    echo -e "${RED}❌ Health check failed (HTTP $HTTP_CODE)${NC}"
  fi
else
  echo -e "${YELLOW}⚠️  Could not determine health check URL${NC}"
fi

# Monitoring recommendation
echo ""
echo "=================================================="
echo "Post-Rollback Monitoring"
echo "=================================================="
echo ""
echo "Monitor the deployment for the next 5-10 minutes:"
echo ""
echo "  # Watch live logs:"
echo "  npx wrangler tail coreflow360-v4-prod --env production --format pretty"
echo ""
echo "  # Check error rates:"
echo "  https://dash.cloudflare.com/workers"
echo ""

# Log rollback
ROLLBACK_LOG="deployments/rollback-$(date +%Y%m%d-%H%M%S).log"
mkdir -p deployments

cat > "$ROLLBACK_LOG" << EOF
CoreFlow360 V4 - Production Rollback Record
============================================

Rollback Time: $(date)
Rollback Method: Option $ROLLBACK_OPTION
Performed By: $(git config user.name 2>/dev/null || echo "Unknown")
Current Branch: $(git branch --show-current 2>/dev/null || echo "Detached HEAD")
Current Commit: $(git rev-parse HEAD 2>/dev/null || echo "Unknown")

Reason: Emergency rollback via rollback-production.sh

Health Check:
-------------
URL: ${HEALTH_URL:-N/A}
HTTP Code: ${HTTP_CODE:-N/A}

Deployment History:
-------------------
$DEPLOYMENT_LIST
EOF

echo ""
echo -e "${GREEN}✅ Rollback record saved: $ROLLBACK_LOG${NC}"
echo ""
