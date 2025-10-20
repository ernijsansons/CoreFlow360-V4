#!/bin/bash

# CoreFlow360 V4 - Production Secrets Configuration Script
# Phase 3: Generate and Configure Production Secrets
#
# CRITICAL: Zero secrets currently configured in Cloudflare Workers
# This script generates secure secrets and uploads them to Cloudflare

set -e

echo "=================================================="
echo "CoreFlow360 V4 - Production Secrets Configuration"
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

# Validate token
echo "Validating Cloudflare API token..."
if ! npx wrangler whoami &>/dev/null; then
  echo -e "${RED}❌ Invalid API token${NC}"
  exit 1
fi
echo -e "${GREEN}✅ API token valid${NC}"
echo ""

# Check if openssl is available
if ! command -v openssl &> /dev/null; then
  echo -e "${RED}❌ openssl not found${NC}"
  echo "Please install OpenSSL to generate secure secrets"
  exit 1
fi

echo "=================================================="
echo "Secret Generation Strategy"
echo "=================================================="
echo ""
echo "This script will:"
echo "  1. Generate cryptographically secure secrets (JWT, ENCRYPTION, AUTH)"
echo "  2. Prompt for external service API keys (Anthropic, OpenAI, etc.)"
echo "  3. Upload all secrets to Cloudflare Workers"
echo "  4. Verify all secrets are configured"
echo ""

# Create temporary secrets file (will be deleted)
SECRETS_FILE="./scripts/.secrets.tmp"
touch "$SECRETS_FILE"
chmod 600 "$SECRETS_FILE"

echo "# CoreFlow360 V4 Production Secrets - Generated $(date)" > "$SECRETS_FILE"
echo "# DO NOT COMMIT THIS FILE" >> "$SECRETS_FILE"
echo "" >> "$SECRETS_FILE"

# Step 1: Generate Core Security Secrets
echo "=================================================="
echo "Step 1: Generating Core Security Secrets"
echo "=================================================="
echo ""

# Generate JWT_SECRET (256-bit)
echo -e "${BLUE}Generating JWT_SECRET (256-bit)...${NC}"
JWT_SECRET=$(openssl rand -base64 32)
echo "JWT_SECRET=$JWT_SECRET" >> "$SECRETS_FILE"
echo -e "${GREEN}✅ Generated JWT_SECRET${NC}"

# Generate ENCRYPTION_KEY (256-bit)
echo -e "${BLUE}Generating ENCRYPTION_KEY (256-bit)...${NC}"
ENCRYPTION_KEY=$(openssl rand -base64 32)
echo "ENCRYPTION_KEY=$ENCRYPTION_KEY" >> "$SECRETS_FILE"
echo -e "${GREEN}✅ Generated ENCRYPTION_KEY${NC}"

# Generate AUTH_SECRET (256-bit)
echo -e "${BLUE}Generating AUTH_SECRET (256-bit)...${NC}"
AUTH_SECRET=$(openssl rand -base64 32)
echo "AUTH_SECRET=$AUTH_SECRET" >> "$SECRETS_FILE"
echo -e "${GREEN}✅ Generated AUTH_SECRET${NC}"

echo ""

# Step 2: Prompt for AI Service Keys
echo "=================================================="
echo "Step 2: AI Service API Keys"
echo "=================================================="
echo ""

# Anthropic API Key
echo -e "${YELLOW}Required:${NC} Anthropic API Key"
echo "Get it from: https://console.anthropic.com/account/keys"
read -p "Enter ANTHROPIC_API_KEY: " -s ANTHROPIC_API_KEY
echo ""
if [ -z "$ANTHROPIC_API_KEY" ]; then
  echo -e "${RED}❌ ANTHROPIC_API_KEY is required${NC}"
  exit 1
fi
echo "ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY" >> "$SECRETS_FILE"
echo -e "${GREEN}✅ ANTHROPIC_API_KEY set${NC}"
echo ""

# OpenAI API Key
echo -e "${YELLOW}Required:${NC} OpenAI API Key"
echo "Get it from: https://platform.openai.com/api-keys"
read -p "Enter OPENAI_API_KEY: " -s OPENAI_API_KEY
echo ""
if [ -z "$OPENAI_API_KEY" ]; then
  echo -e "${RED}❌ OPENAI_API_KEY is required${NC}"
  exit 1
fi
echo "OPENAI_API_KEY=$OPENAI_API_KEY" >> "$SECRETS_FILE"
echo -e "${GREEN}✅ OPENAI_API_KEY set${NC}"
echo ""

# Step 3: Optional Payment Processing Keys
echo "=================================================="
echo "Step 3: Payment Processing (Optional)"
echo "=================================================="
echo ""

read -p "Configure Stripe integration? (y/n) " -n 1 -r
echo ""
if [[ $REPLY =~ ^[Yy]$ ]]; then
  echo "Get keys from: https://dashboard.stripe.com/apikeys"

  read -p "Enter STRIPE_SECRET_KEY (sk_...): " -s STRIPE_SECRET_KEY
  echo ""
  if [ ! -z "$STRIPE_SECRET_KEY" ]; then
    echo "STRIPE_SECRET_KEY=$STRIPE_SECRET_KEY" >> "$SECRETS_FILE"
    echo -e "${GREEN}✅ STRIPE_SECRET_KEY set${NC}"
  fi

  read -p "Enter STRIPE_WEBHOOK_SECRET (whsec_...): " -s STRIPE_WEBHOOK_SECRET
  echo ""
  if [ ! -z "$STRIPE_WEBHOOK_SECRET" ]; then
    echo "STRIPE_WEBHOOK_SECRET=$STRIPE_WEBHOOK_SECRET" >> "$SECRETS_FILE"
    echo -e "${GREEN}✅ STRIPE_WEBHOOK_SECRET set${NC}"
  fi
  echo ""
fi

# Step 4: Monitoring (Sentry)
echo "=================================================="
echo "Step 4: Error Monitoring"
echo "=================================================="
echo ""

echo -e "${YELLOW}Required:${NC} Sentry DSN"
echo "Get it from: https://sentry.io/settings/projects/"
read -p "Enter SENTRY_DSN: " -s SENTRY_DSN
echo ""
if [ -z "$SENTRY_DSN" ]; then
  echo -e "${YELLOW}⚠️  Skipping Sentry configuration${NC}"
else
  echo "SENTRY_DSN=$SENTRY_DSN" >> "$SECRETS_FILE"
  echo -e "${GREEN}✅ SENTRY_DSN set${NC}"
fi
echo ""

# Step 5: Optional Email API
echo "=================================================="
echo "Step 5: Email Service (Optional)"
echo "=================================================="
echo ""

read -p "Configure email service (SendGrid/Mailgun)? (y/n) " -n 1 -r
echo ""
if [[ $REPLY =~ ^[Yy]$ ]]; then
  read -p "Enter EMAIL_API_KEY: " -s EMAIL_API_KEY
  echo ""
  if [ ! -z "$EMAIL_API_KEY" ]; then
    echo "EMAIL_API_KEY=$EMAIL_API_KEY" >> "$SECRETS_FILE"
    echo -e "${GREEN}✅ EMAIL_API_KEY set${NC}"
  fi
  echo ""
fi

# Step 6: Display Summary
echo "=================================================="
echo "Summary of Configured Secrets"
echo "=================================================="
echo ""

# Count secrets (excluding comments and empty lines)
SECRET_COUNT=$(grep -v "^#" "$SECRETS_FILE" | grep -v "^$" | wc -l)
echo -e "${GREEN}Total secrets configured: $SECRET_COUNT${NC}"
echo ""
echo "Secrets to be uploaded:"
grep -v "^#" "$SECRETS_FILE" | grep -v "^$" | cut -d'=' -f1 | while read secret; do
  echo "  ✓ $secret"
done
echo ""

# Step 7: Upload to Cloudflare
echo "=================================================="
echo "Step 7: Upload Secrets to Cloudflare Workers"
echo "=================================================="
echo ""

read -p "Upload all secrets to production environment? (y/n) " -n 1 -r
echo ""
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
  echo -e "${YELLOW}⚠️  Secret upload cancelled${NC}"
  echo "Secrets saved to: $SECRETS_FILE"
  echo "You can manually upload them later using:"
  echo "  wrangler secret put SECRET_NAME --env production"
  exit 0
fi

echo ""
echo "Uploading secrets..."
echo ""

# Function to upload secret
upload_secret() {
  local SECRET_NAME=$1
  local SECRET_VALUE=$2

  echo -e "${BLUE}Uploading $SECRET_NAME...${NC}"

  # Create temporary file with secret value
  TEMP_SECRET_FILE=$(mktemp)
  echo -n "$SECRET_VALUE" > "$TEMP_SECRET_FILE"

  # Upload using wrangler
  if echo "$SECRET_VALUE" | npx wrangler secret put "$SECRET_NAME" --env production 2>&1 | grep -q "success\|Success\|created"; then
    echo -e "${GREEN}✅ Uploaded $SECRET_NAME${NC}"
  else
    echo -e "${RED}❌ Failed to upload $SECRET_NAME${NC}"
  fi

  # Clean up temp file
  rm -f "$TEMP_SECRET_FILE"
}

# Upload each secret
while IFS='=' read -r SECRET_NAME SECRET_VALUE; do
  # Skip comments and empty lines
  if [[ $SECRET_NAME =~ ^# ]] || [[ -z $SECRET_NAME ]]; then
    continue
  fi

  upload_secret "$SECRET_NAME" "$SECRET_VALUE"
done < "$SECRETS_FILE"

echo ""

# Step 8: Verify all secrets are set
echo "=================================================="
echo "Step 8: Verification"
echo "=================================================="
echo ""

echo "Listing all configured secrets..."
npx wrangler secret list --env production

echo ""

# Clean up temporary secrets file
echo "=================================================="
echo "Cleanup"
echo "=================================================="
echo ""

read -p "Delete temporary secrets file? (RECOMMENDED) (y/n) " -n 1 -r
echo ""
if [[ $REPLY =~ ^[Yy]$ ]]; then
  shred -u "$SECRETS_FILE" 2>/dev/null || rm -f "$SECRETS_FILE"
  echo -e "${GREEN}✅ Temporary secrets file securely deleted${NC}"
else
  echo -e "${YELLOW}⚠️  Secrets file saved to: $SECRETS_FILE${NC}"
  echo "   Make sure to delete this file manually!"
fi

echo ""
echo -e "${GREEN}✅ Phase 3 Complete!${NC}"
echo ""
echo "Next step: Phase 4 - Verify Configuration"
echo "  Run: ./scripts/4-verify-configuration.sh"
echo ""
