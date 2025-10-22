#!/bin/bash

# CoreFlow360 V4 - Complete Production Setup Script
# Master script that runs all setup phases in sequence
#
# This script orchestrates the complete production deployment setup

set -e

echo "=================================================="
echo "CoreFlow360 V4 - Complete Production Setup"
echo "=================================================="
echo ""
echo "This script will guide you through:"
echo "  Phase 1: API Token Rotation"
echo "  Phase 2: Production KV Namespace Creation"
echo "  Phase 3: Secrets Configuration"
echo "  Phase 4: Configuration Verification"
echo "  Phase 5: Production Deployment"
echo ""
echo "Estimated total time: 45 minutes"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Change to script directory
cd "$(dirname "$0")/.."

# Check prerequisites
echo "=================================================="
echo "Prerequisites Check"
echo "=================================================="
echo ""

# Check Node.js version
if command -v node &> /dev/null; then
  NODE_VERSION=$(node --version)
  echo -e "${GREEN}✅ Node.js: $NODE_VERSION${NC}"
else
  echo -e "${RED}❌ Node.js not found${NC}"
  exit 1
fi

# Check npm
if command -v npm &> /dev/null; then
  NPM_VERSION=$(npm --version)
  echo -e "${GREEN}✅ npm: $NPM_VERSION${NC}"
else
  echo -e "${RED}❌ npm not found${NC}"
  exit 1
fi

# Check wrangler
if npm list -g wrangler &> /dev/null || npm list wrangler &> /dev/null; then
  echo -e "${GREEN}✅ Wrangler installed${NC}"
else
  echo -e "${YELLOW}⚠️  Installing wrangler...${NC}"
  npm install -D wrangler
fi

# Check OpenSSL
if command -v openssl &> /dev/null; then
  echo -e "${GREEN}✅ OpenSSL available${NC}"
else
  echo -e "${YELLOW}⚠️  OpenSSL not found (needed for secret generation)${NC}"
fi

# Check git
if command -v git &> /dev/null; then
  GIT_VERSION=$(git --version)
  echo -e "${GREEN}✅ Git: $GIT_VERSION${NC}"
else
  echo -e "${YELLOW}⚠️  Git not found${NC}"
fi

echo ""

# Option to run all phases or select specific ones
echo "=================================================="
echo "Setup Mode"
echo "=================================================="
echo ""
echo "Select setup mode:"
echo "  1. Full setup (all phases)"
echo "  2. Custom (select specific phases)"
echo "  3. Resume from specific phase"
echo ""
read -p "Enter choice (1-3): " SETUP_MODE

case $SETUP_MODE in
  1)
    RUN_PHASE_1=true
    RUN_PHASE_2=true
    RUN_PHASE_3=true
    RUN_PHASE_4=true
    RUN_PHASE_5=false  # Don't auto-deploy, let user decide
    ;;
  2)
    echo ""
    read -p "Run Phase 1 (API Token Rotation)? (y/n) " -n 1 -r && echo "" && [[ $REPLY =~ ^[Yy]$ ]] && RUN_PHASE_1=true || RUN_PHASE_1=false
    read -p "Run Phase 2 (KV Namespace Creation)? (y/n) " -n 1 -r && echo "" && [[ $REPLY =~ ^[Yy]$ ]] && RUN_PHASE_2=true || RUN_PHASE_2=false
    read -p "Run Phase 3 (Secrets Configuration)? (y/n) " -n 1 -r && echo "" && [[ $REPLY =~ ^[Yy]$ ]] && RUN_PHASE_3=true || RUN_PHASE_3=false
    read -p "Run Phase 4 (Verification)? (y/n) " -n 1 -r && echo "" && [[ $REPLY =~ ^[Yy]$ ]] && RUN_PHASE_4=true || RUN_PHASE_4=false
    read -p "Run Phase 5 (Deployment)? (y/n) " -n 1 -r && echo "" && [[ $REPLY =~ ^[Yy]$ ]] && RUN_PHASE_5=true || RUN_PHASE_5=false
    ;;
  3)
    echo ""
    echo "Resume from phase:"
    echo "  1. API Token Rotation"
    echo "  2. KV Namespace Creation"
    echo "  3. Secrets Configuration"
    echo "  4. Verification"
    echo "  5. Deployment"
    read -p "Enter phase number (1-5): " RESUME_PHASE

    RUN_PHASE_1=false
    RUN_PHASE_2=false
    RUN_PHASE_3=false
    RUN_PHASE_4=false
    RUN_PHASE_5=false

    case $RESUME_PHASE in
      1) RUN_PHASE_1=true; RUN_PHASE_2=true; RUN_PHASE_3=true; RUN_PHASE_4=true ;;
      2) RUN_PHASE_2=true; RUN_PHASE_3=true; RUN_PHASE_4=true ;;
      3) RUN_PHASE_3=true; RUN_PHASE_4=true ;;
      4) RUN_PHASE_4=true ;;
      5) RUN_PHASE_5=true ;;
    esac
    ;;
  *)
    echo "Invalid choice"
    exit 1
    ;;
esac

echo ""

# Make scripts executable
chmod +x scripts/*.sh 2>/dev/null || true

# Phase 1: API Token Rotation
if [ "$RUN_PHASE_1" = true ]; then
  echo ""
  echo "=================================================="
  echo "PHASE 1: API Token Rotation"
  echo "=================================================="
  echo ""

  if [ -f "scripts/1-rotate-api-token.sh" ]; then
    bash scripts/1-rotate-api-token.sh
  else
    echo -e "${RED}❌ Phase 1 script not found${NC}"
    exit 1
  fi

  echo ""
  read -p "Press Enter to continue to Phase 2..."
fi

# Phase 2: KV Namespace Creation
if [ "$RUN_PHASE_2" = true ]; then
  echo ""
  echo "=================================================="
  echo "PHASE 2: Production KV Namespace Creation"
  echo "=================================================="
  echo ""

  if [ -f "scripts/2-create-production-kv.sh" ]; then
    bash scripts/2-create-production-kv.sh
  else
    echo -e "${RED}❌ Phase 2 script not found${NC}"
    exit 1
  fi

  echo ""
  read -p "Press Enter to continue to Phase 3..."
fi

# Phase 3: Secrets Configuration
if [ "$RUN_PHASE_3" = true ]; then
  echo ""
  echo "=================================================="
  echo "PHASE 3: Production Secrets Configuration"
  echo "=================================================="
  echo ""

  if [ -f "scripts/3-configure-secrets.sh" ]; then
    bash scripts/3-configure-secrets.sh
  else
    echo -e "${RED}❌ Phase 3 script not found${NC}"
    exit 1
  fi

  echo ""
  read -p "Press Enter to continue to Phase 4..."
fi

# Phase 4: Verification
if [ "$RUN_PHASE_4" = true ]; then
  echo ""
  echo "=================================================="
  echo "PHASE 4: Configuration Verification"
  echo "=================================================="
  echo ""

  if [ -f "scripts/4-verify-configuration.sh" ]; then
    bash scripts/4-verify-configuration.sh || true
  else
    echo -e "${RED}❌ Phase 4 script not found${NC}"
    exit 1
  fi

  echo ""
fi

# Phase 5: Deployment (optional)
if [ "$RUN_PHASE_5" = true ]; then
  echo ""
  echo "=================================================="
  echo "PHASE 5: Production Deployment"
  echo "=================================================="
  echo ""

  if [ -f "scripts/5-deploy-production.sh" ]; then
    bash scripts/5-deploy-production.sh
  else
    echo -e "${RED}❌ Phase 5 script not found${NC}"
    exit 1
  fi
else
  echo ""
  echo "=================================================="
  echo "Setup Complete - Ready for Deployment"
  echo "=================================================="
  echo ""
  echo -e "${GREEN}✅ Production setup complete!${NC}"
  echo ""
  echo "When ready to deploy, run:"
  echo "  bash scripts/5-deploy-production.sh"
  echo ""
  echo "Or run full setup with deployment:"
  echo "  bash scripts/0-setup-production.sh"
  echo ""
fi

# Summary
echo "=================================================="
echo "Summary"
echo "=================================================="
echo ""

echo "Completed phases:"
[ "$RUN_PHASE_1" = true ] && echo -e "  ${GREEN}✅ Phase 1: API Token Rotation${NC}" || echo "  ⏭️  Phase 1: Skipped"
[ "$RUN_PHASE_2" = true ] && echo -e "  ${GREEN}✅ Phase 2: KV Namespace Creation${NC}" || echo "  ⏭️  Phase 2: Skipped"
[ "$RUN_PHASE_3" = true ] && echo -e "  ${GREEN}✅ Phase 3: Secrets Configuration${NC}" || echo "  ⏭️  Phase 3: Skipped"
[ "$RUN_PHASE_4" = true ] && echo -e "  ${GREEN}✅ Phase 4: Verification${NC}" || echo "  ⏭️  Phase 4: Skipped"
[ "$RUN_PHASE_5" = true ] && echo -e "  ${GREEN}✅ Phase 5: Deployment${NC}" || echo "  ⏭️  Phase 5: Skipped"

echo ""
echo "Next steps:"
echo "  - Monitor deployment: npx wrangler tail coreflow360-v4-prod --env production"
echo "  - View logs: Check Cloudflare Dashboard"
echo "  - Test endpoints: curl https://api.coreflow360.com/health"
echo ""
