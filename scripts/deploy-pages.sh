#!/bin/bash

# Cloudflare Pages Deployment Script
# This script builds and deploys the frontend to Cloudflare Pages

set -e  # Exit on error

echo "🚀 CoreFlow360 V4 - Cloudflare Pages Deployment"
echo "================================================"
echo ""

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Check if we're in the project root
if [ ! -d "frontend" ]; then
    echo -e "${RED}❌ Error: Must run from project root${NC}"
    exit 1
fi

# Step 1: Pre-deployment checks
echo -e "${YELLOW}Step 1/5: Running pre-deployment checks...${NC}"

# Check for circular dependencies
echo "  Checking for circular dependencies..."
cd frontend
npm run check:circular || {
    echo -e "${RED}❌ Circular dependencies found! Fix before deploying.${NC}"
    exit 1
}
echo -e "${GREEN}  ✅ No circular dependencies${NC}"

# Check TypeScript
echo "  Checking TypeScript compilation..."
npm run typecheck || {
    echo -e "${RED}❌ TypeScript errors found! Fix before deploying.${NC}"
    exit 1
}
echo -e "${GREEN}  ✅ TypeScript check passed${NC}"

cd ..

# Step 2: Git status check
echo -e "\n${YELLOW}Step 2/5: Checking git status...${NC}"
if [ -n "$(git status --porcelain)" ]; then
    echo -e "${YELLOW}⚠️  Warning: You have uncommitted changes${NC}"
    git status --short
    read -p "Continue anyway? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Deployment cancelled"
        exit 1
    fi
fi
echo -e "${GREEN}  ✅ Git status checked${NC}"

# Step 3: Build
echo -e "\n${YELLOW}Step 3/5: Building production bundle...${NC}"
cd frontend
npm run build || {
    echo -e "${RED}❌ Build failed!${NC}"
    exit 1
}
echo -e "${GREEN}  ✅ Build completed successfully${NC}"

# Get build stats
BUILD_SIZE=$(du -sh dist | cut -f1)
echo "  Build size: $BUILD_SIZE"

cd ..

# Step 4: Deployment
echo -e "\n${YELLOW}Step 4/5: Deploying to Cloudflare Pages...${NC}"

# Check if CLOUDFLARE_API_TOKEN is set
if [ -z "$CLOUDFLARE_API_TOKEN" ]; then
    echo -e "${YELLOW}⚠️  CLOUDFLARE_API_TOKEN not set${NC}"
    echo "  Please set it in your environment or .env file"
    echo "  Example: export CLOUDFLARE_API_TOKEN=your_token_here"
    exit 1
fi

# Deploy using wrangler
wrangler pages deploy frontend/dist --project-name=coreflow360-frontend || {
    echo -e "${RED}❌ Deployment failed!${NC}"
    exit 1
}

echo -e "${GREEN}  ✅ Deployment completed${NC}"

# Step 5: Verification
echo -e "\n${YELLOW}Step 5/5: Verifying deployment...${NC}"
echo "  Waiting 5 seconds for deployment to propagate..."
sleep 5

# Check production URL
PROD_URL="https://8eb14753.coreflow360-frontend.pages.dev/"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$PROD_URL")

if [ "$HTTP_CODE" = "200" ]; then
    echo -e "${GREEN}  ✅ Production is live (HTTP $HTTP_CODE)${NC}"
else
    echo -e "${YELLOW}  ⚠️  Production returned HTTP $HTTP_CODE${NC}"
fi

# Final summary
echo ""
echo "================================================"
echo -e "${GREEN}🎉 Deployment Complete!${NC}"
echo "================================================"
echo ""
echo "Production URL: $PROD_URL"
echo "Build Size: $BUILD_SIZE"
echo "Circular Dependencies: 0"
echo "TypeScript: Passing"
echo ""
echo "Next steps:"
echo "  1. Verify the site loads correctly"
echo "  2. Test critical user flows"
echo "  3. Monitor Cloudflare Analytics"
echo "  4. Check error logs in Sentry (if configured)"
echo ""
