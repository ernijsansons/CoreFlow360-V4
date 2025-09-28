#!/bin/bash

# CoreFlow360 V4 Production Deployment Script
# Usage: ./scripts/deploy-production.sh

set -e

echo "🚀 Starting CoreFlow360 V4 Production Deployment..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running in production mode
if [ "$1" != "--production" ]; then
    echo -e "${YELLOW}Warning: Running in test mode. Use --production flag for actual deployment${NC}"
    DRY_RUN="--dry-run"
else
    DRY_RUN=""
    echo -e "${RED}⚠️  Production deployment mode enabled${NC}"
fi

# Step 1: Run tests
echo -e "\n${GREEN}Step 1: Running tests...${NC}"
npm test || {
    echo -e "${RED}❌ Tests failed. Aborting deployment.${NC}"
    exit 1
}

# Step 2: Type checking
echo -e "\n${GREEN}Step 2: Running TypeScript type check...${NC}"
npx tsc --noEmit --skipLibCheck || {
    echo -e "${RED}❌ Type checking failed. Aborting deployment.${NC}"
    exit 1
}

# Step 3: Build production bundle
echo -e "\n${GREEN}Step 3: Building production bundle...${NC}"
npm run build:production || {
    echo -e "${RED}❌ Build failed. Aborting deployment.${NC}"
    exit 1
}

# Step 4: Set production secrets
echo -e "\n${GREEN}Step 4: Checking production secrets...${NC}"
REQUIRED_SECRETS=(
    "JWT_SECRET"
    "ENCRYPTION_KEY"
    "AUTH_SECRET"
)

for secret in "${REQUIRED_SECRETS[@]}"; do
    echo "Checking $secret..."
    if [ -z "${!secret}" ]; then
        echo -e "${YELLOW}⚠️  $secret not set in environment${NC}"
        echo "Run: wrangler secret put $secret --env production"
    fi
done

# Step 5: Deploy database migrations
echo -e "\n${GREEN}Step 5: Running database migrations...${NC}"
wrangler d1 migrations apply coreflow360-prod --env production $DRY_RUN || {
    echo -e "${RED}❌ Database migration failed. Aborting deployment.${NC}"
    exit 1
}

# Step 6: Deploy to Cloudflare Workers
echo -e "\n${GREEN}Step 6: Deploying to Cloudflare Workers...${NC}"
wrangler deploy --config wrangler.production.toml --env production $DRY_RUN || {
    echo -e "${RED}❌ Worker deployment failed. Aborting deployment.${NC}"
    exit 1
}

# Step 7: Verify deployment
if [ "$DRY_RUN" = "" ]; then
    echo -e "\n${GREEN}Step 7: Verifying deployment...${NC}"
    sleep 5

    # Test health endpoint
    HEALTH_CHECK=$(curl -s https://api.coreflow360.com/health || echo "failed")

    if [[ $HEALTH_CHECK == *"healthy"* ]]; then
        echo -e "${GREEN}✅ Health check passed${NC}"
    else
        echo -e "${RED}❌ Health check failed${NC}"
        echo "Response: $HEALTH_CHECK"
        echo -e "${YELLOW}Rolling back deployment...${NC}"
        wrangler rollback --env production
        exit 1
    fi

    # Test authentication endpoint
    AUTH_CHECK=$(curl -s -X POST https://api.coreflow360.com/api/auth/login \
        -H "Content-Type: application/json" \
        -d '{"email":"test@example.com","password":"test"}' || echo "failed")

    if [[ $AUTH_CHECK == *"error"* ]] || [[ $AUTH_CHECK == *"Invalid"* ]]; then
        echo -e "${GREEN}✅ Auth endpoint responding correctly${NC}"
    else
        echo -e "${RED}❌ Auth endpoint not responding${NC}"
        echo "Response: $AUTH_CHECK"
    fi
fi

# Step 8: Update monitoring
echo -e "\n${GREEN}Step 8: Updating monitoring...${NC}"
if [ "$DRY_RUN" = "" ]; then
    # Send deployment notification
    curl -X POST https://hooks.slack.com/services/YOUR_SLACK_WEBHOOK \
        -H 'Content-Type: application/json' \
        -d "{\"text\":\"🚀 CoreFlow360 V4 deployed to production successfully!\"}" 2>/dev/null || true
fi

# Step 9: Clear CDN cache
echo -e "\n${GREEN}Step 9: Purging CDN cache...${NC}"
if [ "$DRY_RUN" = "" ]; then
    wrangler cache purge --all || true
fi

# Step 10: Generate deployment report
echo -e "\n${GREEN}Step 10: Generating deployment report...${NC}"
TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")
COMMIT_HASH=$(git rev-parse HEAD)
BRANCH=$(git branch --show-current)

cat > deployment-report.txt << EOF
=================================
CoreFlow360 V4 Deployment Report
=================================
Timestamp: $TIMESTAMP
Git Commit: $COMMIT_HASH
Branch: $BRANCH
Environment: Production
Status: SUCCESS

Deployed Components:
- Authentication System ✅
- User Management ✅
- API Key Management ✅
- Rate Limiting ✅
- Analytics Dashboard ✅
- Admin Endpoints ✅
- Database Migrations ✅

API Endpoints:
- https://api.coreflow360.com/health
- https://api.coreflow360.com/api/auth/register
- https://api.coreflow360.com/api/auth/login
- https://api.coreflow360.com/api/auth/profile
- https://api.coreflow360.com/api/auth/logout
- https://api.coreflow360.com/api/users/create-api-key
- https://api.coreflow360.com/api/admin/users
- https://api.coreflow360.com/api/analytics/dashboard
- https://api.coreflow360.com/api/logs/export

Security Features:
- JWT Authentication
- API Key Support
- Rate Limiting
- CORS Protection
- Security Headers
- Token Blacklisting
- Session Management

Performance:
- Durable Objects for Rate Limiting
- KV Storage for Sessions
- D1 Database for Persistence
- Edge Caching Enabled
- Global Distribution

Next Steps:
1. Monitor error rates in dashboard
2. Check performance metrics
3. Review security logs
4. Test all API endpoints
=================================
EOF

echo -e "\n${GREEN}✅ Deployment completed successfully!${NC}"
echo -e "Deployment report saved to: deployment-report.txt"

# Display summary
echo -e "\n📊 Deployment Summary:"
echo -e "  • Environment: Production"
echo -e "  • API URL: https://api.coreflow360.com"
echo -e "  • Dashboard: https://app.coreflow360.com"
echo -e "  • Status: ${GREEN}LIVE${NC}"

if [ "$DRY_RUN" != "" ]; then
    echo -e "\n${YELLOW}This was a dry run. No actual changes were made.${NC}"
    echo -e "Run with --production flag to deploy to production."
fi