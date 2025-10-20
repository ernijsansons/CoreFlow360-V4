#!/bin/bash

# CoreFlow360 V4 - Production KV Namespace Creation Script
# Phase 2: Create Production KV Namespaces with Unique IDs
#
# CRITICAL: Production and staging currently share KV namespaces
# This script creates separate production namespaces to prevent data leakage

set -e

echo "=================================================="
echo "CoreFlow360 V4 - Production KV Namespace Creation"
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

# Define namespaces to create
declare -A NAMESPACES=(
  ["KV_CACHE"]="KV_CACHE_PROD"
  ["KV_SESSION"]="KV_SESSION_PROD"
  ["KV_RATE_LIMIT_METRICS"]="KV_RATE_LIMIT_METRICS_PROD"
  ["KV_AUTH"]="KV_AUTH_PROD"
  ["AGENT_CACHE"]="AGENT_CACHE_PROD"
  ["AGENT_MEMORY"]="AGENT_MEMORY_PROD"
  ["PATTERN_CACHE"]="PATTERN_CACHE_PROD"
)

# Array to store created namespace IDs
declare -A NAMESPACE_IDS

echo "=================================================="
echo "Creating Production KV Namespaces"
echo "=================================================="
echo ""
echo "This will create 7 new KV namespaces with '-PROD' suffix"
echo ""

# Step 1: Create each namespace
for BINDING in "${!NAMESPACES[@]}"; do
  NAMESPACE_NAME="${NAMESPACES[$BINDING]}"

  echo -e "${BLUE}Creating namespace: $NAMESPACE_NAME${NC}"

  # Create namespace and capture output
  OUTPUT=$(npx wrangler kv:namespace create "$NAMESPACE_NAME" 2>&1)

  # Extract namespace ID from output
  # Expected format: "Created namespace ... with id: abc123..."
  if echo "$OUTPUT" | grep -q "id:"; then
    NAMESPACE_ID=$(echo "$OUTPUT" | grep -oP 'id: \K[a-f0-9]+')
    NAMESPACE_IDS[$BINDING]="$NAMESPACE_ID"
    echo -e "${GREEN}✅ Created $NAMESPACE_NAME: $NAMESPACE_ID${NC}"
  else
    echo -e "${RED}❌ Failed to create $NAMESPACE_NAME${NC}"
    echo "$OUTPUT"
    exit 1
  fi

  echo ""
done

# Step 2: Display summary
echo "=================================================="
echo "Summary of Created Namespaces"
echo "=================================================="
echo ""

for BINDING in "${!NAMESPACE_IDS[@]}"; do
  echo -e "${GREEN}$BINDING${NC} = ${NAMESPACE_IDS[$BINDING]}"
done

echo ""

# Step 3: Generate updated wrangler.production.toml section
echo "=================================================="
echo "Updated wrangler.production.toml Configuration"
echo "=================================================="
echo ""

cat << EOF
# Copy and paste this into wrangler.production.toml:

# KV Namespaces (Production-specific)
[[kv_namespaces]]
binding = "KV_CACHE"
id = "${NAMESPACE_IDS[KV_CACHE]}"

[[kv_namespaces]]
binding = "KV_SESSION"
id = "${NAMESPACE_IDS[KV_SESSION]}"

[[kv_namespaces]]
binding = "KV_RATE_LIMIT_METRICS"
id = "${NAMESPACE_IDS[KV_RATE_LIMIT_METRICS]}"

[[kv_namespaces]]
binding = "KV_AUTH"
id = "${NAMESPACE_IDS[KV_AUTH]}"

[[kv_namespaces]]
binding = "AGENT_CACHE"
id = "${NAMESPACE_IDS[AGENT_CACHE]}"

[[kv_namespaces]]
binding = "AGENT_MEMORY"
id = "${NAMESPACE_IDS[AGENT_MEMORY]}"

[[kv_namespaces]]
binding = "PATTERN_CACHE"
id = "${NAMESPACE_IDS[PATTERN_CACHE]}"
EOF

echo ""
echo "=================================================="

# Step 4: Save IDs to file for automated update
TEMP_FILE="./scripts/.kv-namespace-ids.tmp"
echo "# Generated KV Namespace IDs - $(date)" > "$TEMP_FILE"
for BINDING in "${!NAMESPACE_IDS[@]}"; do
  echo "$BINDING=${NAMESPACE_IDS[$BINDING]}" >> "$TEMP_FILE"
done

echo -e "${GREEN}✅ Namespace IDs saved to: $TEMP_FILE${NC}"
echo ""

# Step 5: Offer to automatically update wrangler.production.toml
echo "=================================================="
echo "Automatic Update Option"
echo "=================================================="
echo ""
read -p "Automatically update wrangler.production.toml? (y/n) " -n 1 -r
echo ""

if [[ $REPLY =~ ^[Yy]$ ]]; then
  echo "Updating wrangler.production.toml..."

  # Backup current file
  cp wrangler.production.toml wrangler.production.toml.backup.$(date +%Y%m%d_%H%M%S)
  echo -e "${GREEN}✅ Backed up wrangler.production.toml${NC}"

  # Replace placeholder IDs with actual IDs
  for BINDING in "${!NAMESPACE_IDS[@]}"; do
    NAMESPACE_ID="${NAMESPACE_IDS[$BINDING]}"

    # Find and replace the ID for this binding
    sed -i "/binding = \"$BINDING\"/,/^id = / s|id = \".*\"|id = \"$NAMESPACE_ID\"|" wrangler.production.toml
  done

  echo -e "${GREEN}✅ Updated wrangler.production.toml with new namespace IDs${NC}"
  echo ""
  echo "Verify the changes:"
  echo "  git diff wrangler.production.toml"
  echo ""
else
  echo -e "${YELLOW}⚠️  Manual update required${NC}"
  echo "Copy the configuration above into wrangler.production.toml"
  echo ""
fi

# Step 6: Validation
echo "=================================================="
echo "Validation"
echo "=================================================="
echo ""
echo "Run this command to validate configuration:"
echo "  npx wrangler deploy --dry-run --config wrangler.production.toml"
echo ""

echo -e "${GREEN}✅ Phase 2 Complete!${NC}"
echo ""
echo "Next step: Phase 3 - Generate and Configure Production Secrets"
echo "  Run: ./scripts/3-configure-secrets.sh"
echo ""
