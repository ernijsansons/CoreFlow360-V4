#!/bin/bash

# CoreFlow360 V4 - API Token Rotation Script
# Phase 1: Rotate Exposed Cloudflare API Token
#
# SECURITY CRITICAL: This script helps rotate the exposed API token
# Token exposed: Rp3owWaOgVIBOFqv13wVWDzei3YbjfRfO0te5yVH

set -e

echo "=================================================="
echo "CoreFlow360 V4 - API Token Rotation"
echo "=================================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Step 1: Check if current token is set
echo "Step 1: Checking current API token..."
if [ -z "$CLOUDFLARE_API_TOKEN" ]; then
  echo -e "${YELLOW}⚠️  CLOUDFLARE_API_TOKEN not set in environment${NC}"
  echo ""
  echo "Please set it temporarily:"
  echo "  export CLOUDFLARE_API_TOKEN='your_current_token'"
  echo ""
  exit 1
fi

# Step 2: Validate current token
echo "Step 2: Validating current token..."
if npx wrangler whoami &>/dev/null; then
  echo -e "${GREEN}✅ Current token is valid${NC}"
  npx wrangler whoami
else
  echo -e "${RED}❌ Current token is invalid or expired${NC}"
  exit 1
fi

echo ""
echo "=================================================="
echo "🔒 MANUAL ACTION REQUIRED"
echo "=================================================="
echo ""
echo "The following API token needs to be rotated:"
echo -e "${RED}Rp3owWaOgVIBOFqv13wVWDzei3YbjfRfO0te5yVH${NC}"
echo ""
echo "Steps to rotate:"
echo "  1. Go to: https://dash.cloudflare.com/profile/api-tokens"
echo "  2. Find the token ending in '...5yVH'"
echo "  3. Click the three dots (•••) → 'Roll'"
echo "  4. Copy the NEW token that is generated"
echo "  5. Return to this script"
echo ""
read -p "Have you rotated the token? (y/n) " -n 1 -r
echo ""

if [[ ! $REPLY =~ ^[Yy]$ ]]; then
  echo -e "${YELLOW}⚠️  Token rotation cancelled${NC}"
  exit 1
fi

# Step 3: Get new token
echo ""
echo "Step 3: Enter the NEW API token:"
read -s NEW_TOKEN
echo ""

# Step 4: Validate new token
echo "Step 4: Validating new token..."
export CLOUDFLARE_API_TOKEN="$NEW_TOKEN"

if npx wrangler whoami &>/dev/null; then
  echo -e "${GREEN}✅ New token is valid${NC}"
  npx wrangler whoami
else
  echo -e "${RED}❌ New token is invalid${NC}"
  exit 1
fi

# Step 5: Update .env.local
echo ""
echo "Step 5: Updating .env.local..."

if [ -f ".env.local" ]; then
  # Backup existing .env.local
  cp .env.local .env.local.backup.$(date +%Y%m%d_%H%M%S)
  echo -e "${GREEN}✅ Backed up .env.local${NC}"

  # Update token in .env.local
  if grep -q "CLOUDFLARE_API_TOKEN=" .env.local; then
    # Replace existing token
    sed -i "s|CLOUDFLARE_API_TOKEN=.*|CLOUDFLARE_API_TOKEN=$NEW_TOKEN|" .env.local
    echo -e "${GREEN}✅ Updated CLOUDFLARE_API_TOKEN in .env.local${NC}"
  else
    # Add token
    echo "CLOUDFLARE_API_TOKEN=$NEW_TOKEN" >> .env.local
    echo -e "${GREEN}✅ Added CLOUDFLARE_API_TOKEN to .env.local${NC}"
  fi
else
  # Create .env.local
  echo "CLOUDFLARE_API_TOKEN=$NEW_TOKEN" > .env.local
  echo -e "${GREEN}✅ Created .env.local with new token${NC}"
fi

# Step 6: Verify .env.local is in .gitignore
echo ""
echo "Step 6: Verifying .gitignore..."
if grep -q "^\.env\.local$" .gitignore 2>/dev/null; then
  echo -e "${GREEN}✅ .env.local is in .gitignore${NC}"
else
  echo -e "${YELLOW}⚠️  Adding .env.local to .gitignore${NC}"
  echo ".env.local" >> .gitignore
fi

# Step 7: Verify token never committed to git
echo ""
echo "Step 7: Verifying token not in git history..."
if git log --all --source --full-history -- .env.local | grep -q "commit"; then
  echo -e "${RED}⚠️  WARNING: .env.local was committed to git in the past${NC}"
  echo "   Consider checking git history and removing sensitive commits"
else
  echo -e "${GREEN}✅ .env.local never committed to git${NC}"
fi

# Step 8: Final validation
echo ""
echo "Step 8: Final validation..."
export CLOUDFLARE_API_TOKEN="$NEW_TOKEN"
if npx wrangler whoami &>/dev/null; then
  echo -e "${GREEN}✅ Token rotation complete!${NC}"
  echo ""
  echo "Summary:"
  echo "  ✅ New token validated"
  echo "  ✅ .env.local updated"
  echo "  ✅ .env.local in .gitignore"
  echo "  ✅ Old token should now be revoked"
  echo ""
  echo "Next steps:"
  echo "  1. Run: export CLOUDFLARE_API_TOKEN='$NEW_TOKEN'"
  echo "  2. Revoke old token in Cloudflare Dashboard (if not auto-revoked)"
  echo "  3. Proceed to Phase 2: Create Production KV Namespaces"
  echo ""
else
  echo -e "${RED}❌ Final validation failed${NC}"
  exit 1
fi
