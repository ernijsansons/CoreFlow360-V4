# CoreFlow360 V4 - Production Deployment Scripts

**Complete automation toolkit for production deployment**

## Overview

This directory contains automated scripts to fix all critical manual blockers preventing production deployment. The scripts handle API token rotation, KV namespace creation, secrets configuration, and production deployment with safety checks.

---

## Quick Start

### Option 1: Full Automated Setup (Recommended)

Run all phases in sequence with guided prompts:

```bash
bash scripts/0-setup-production.sh
```

This master script will:
- ✅ Rotate exposed API token
- ✅ Create production KV namespaces
- ✅ Generate and upload secrets
- ✅ Verify configuration
- ✅ Optionally deploy to production

**Estimated time**: 45 minutes

---

### Option 2: Manual Phase-by-Phase Execution

Run individual scripts in order:

```bash
# Phase 1: Rotate API Token (5 min)
bash scripts/1-rotate-api-token.sh

# Phase 2: Create KV Namespaces (10 min)
bash scripts/2-create-production-kv.sh

# Phase 3: Configure Secrets (15 min)
bash scripts/3-configure-secrets.sh

# Phase 4: Verify Configuration (2 min)
bash scripts/4-verify-configuration.sh

# Phase 5: Deploy to Production (5 min)
bash scripts/5-deploy-production.sh
```

---

## Script Reference

### `0-setup-production.sh` - Master Setup Script

**Purpose**: Orchestrates complete production setup

**Features**:
- Checks all prerequisites (Node.js, npm, wrangler, OpenSSL, git)
- Three modes: Full setup, Custom selection, Resume from phase
- Interactive prompts for each phase
- Comprehensive error handling

**Usage**:
```bash
bash scripts/0-setup-production.sh
```

**Options**:
1. **Full setup**: Run all phases sequentially
2. **Custom**: Select specific phases to run
3. **Resume**: Continue from a specific phase

---

### `1-rotate-api-token.sh` - API Token Rotation

**Purpose**: Safely rotate the exposed Cloudflare API token

**What it does**:
- Validates current token
- Guides through Cloudflare Dashboard rotation
- Validates new token
- Updates `.env.local`
- Verifies `.gitignore` configuration
- Checks git history for token exposure

**Prerequisites**:
- `CLOUDFLARE_API_TOKEN` environment variable set

**Security Features**:
- Backs up `.env.local` before modification
- Verifies token never committed to git
- Validates new token before saving

**Usage**:
```bash
export CLOUDFLARE_API_TOKEN="your_current_token"
bash scripts/1-rotate-api-token.sh
```

**Expected Output**:
```
✅ Current token is valid
✅ New token is valid
✅ Backed up .env.local
✅ Updated CLOUDFLARE_API_TOKEN in .env.local
✅ .env.local is in .gitignore
✅ .env.local never committed to git
```

---

### `2-create-production-kv.sh` - KV Namespace Creation

**Purpose**: Create production-specific KV namespaces to prevent data leakage

**Problem Solved**: Production and staging currently share 7 KV namespace IDs, creating serious data leakage risk.

**What it does**:
- Creates 7 production KV namespaces with `-PROD` suffix:
  - `KV_CACHE_PROD`
  - `KV_SESSION_PROD`
  - `KV_RATE_LIMIT_METRICS_PROD`
  - `KV_AUTH_PROD`
  - `AGENT_CACHE_PROD`
  - `AGENT_MEMORY_PROD`
  - `PATTERN_CACHE_PROD`
- Captures new namespace IDs
- Optionally auto-updates `wrangler.production.toml`
- Saves IDs to temporary file for reference

**Prerequisites**:
- Valid `CLOUDFLARE_API_TOKEN`
- Wrangler CLI installed

**Usage**:
```bash
export CLOUDFLARE_API_TOKEN="your_api_token"
bash scripts/2-create-production-kv.sh
```

**Expected Output**:
```
✅ Created KV_CACHE_PROD: abc123...
✅ Created KV_SESSION_PROD: def456...
... (7 total)
✅ Namespace IDs saved to: ./scripts/.kv-namespace-ids.tmp
✅ Updated wrangler.production.toml with new namespace IDs
```

**Manual Alternative**:
If auto-update is declined, the script outputs the exact TOML configuration to copy into `wrangler.production.toml`.

---

### `3-configure-secrets.sh` - Secrets Configuration

**Purpose**: Generate secure secrets and upload to Cloudflare Workers

**What it does**:
- Generates cryptographically secure secrets (JWT, ENCRYPTION, AUTH) using OpenSSL
- Prompts for external service API keys (Anthropic, OpenAI, Stripe, Sentry, etc.)
- Validates secret format
- Uploads all secrets to Cloudflare via `wrangler secret put`
- Verifies all secrets are configured
- Securely deletes temporary secrets file

**Secrets Configured** (9 total):

**Required (Core Security)**:
- `JWT_SECRET` - 256-bit generated
- `ENCRYPTION_KEY` - 256-bit generated
- `AUTH_SECRET` - 256-bit generated
- `ANTHROPIC_API_KEY` - User provided
- `OPENAI_API_KEY` - User provided
- `SENTRY_DSN` - User provided

**Optional (Feature-dependent)**:
- `STRIPE_SECRET_KEY`
- `STRIPE_WEBHOOK_SECRET`
- `EMAIL_API_KEY`

**Prerequisites**:
- Valid `CLOUDFLARE_API_TOKEN`
- OpenSSL installed
- External service API keys ready

**Security Features**:
- Secrets file created with 600 permissions (owner read/write only)
- Uses `shred -u` to securely delete temporary file
- Secrets never echoed to terminal (using `read -s`)

**Usage**:
```bash
export CLOUDFLARE_API_TOKEN="your_api_token"
bash scripts/3-configure-secrets.sh
```

**Expected Output**:
```
✅ Generated JWT_SECRET
✅ Generated ENCRYPTION_KEY
✅ Generated AUTH_SECRET
✅ ANTHROPIC_API_KEY set
✅ OPENAI_API_KEY set
✅ Uploaded JWT_SECRET
... (all secrets)
✅ Temporary secrets file securely deleted
```

---

### `4-verify-configuration.sh` - Configuration Verification

**Purpose**: Comprehensive pre-deployment validation

**What it validates** (11 checks):

1. **Cloudflare API Token**: Valid and authenticated
2. **Build Status**: Production build succeeds without warnings
3. **TypeScript Validation**: Type checking passes
4. **Production Config**: `wrangler.production.toml` exists and valid
5. **Secrets Configuration**: All required secrets present
6. **KV Namespaces**: All 7 namespaces configured
7. **Custom Domain**: Domain configuration (if applicable)
8. **D1 Database**: Database binding configured
9. **R2 Buckets**: Bucket configuration
10. **Git Status**: No uncommitted changes, `.env.local` gitignored
11. **Dry-Run Deployment**: Simulated deployment test

**Exit Codes**:
- `0`: All checks passed (ready for deployment)
- `1`: Errors detected (deployment blocked)

**Usage**:
```bash
export CLOUDFLARE_API_TOKEN="your_api_token"
bash scripts/4-verify-configuration.sh
```

**Expected Output**:
```
✅ API token is valid
✅ Build successful
✅ No eval() warnings in build
✅ TypeScript validation passed
✅ wrangler.production.toml exists
✅ No PLACEHOLDER markers found
✅ No phantom Durable Objects
✅ JWT_SECRET is configured
... (all checks)

🎉 All checks passed! Ready for deployment.
```

**Error Example**:
```
❌ JWT_SECRET is missing
❌ Build failed

❌ 2 errors and 1 warnings detected

Please fix errors before deployment:
  - Run: ./scripts/3-configure-secrets.sh
```

---

### `5-deploy-production.sh` - Production Deployment

**Purpose**: Safe production deployment with health checks and rollback information

**What it does**:
1. Runs pre-deployment verification
2. Builds production bundle
3. Checks git status
4. Requires explicit "yes" confirmation
5. Deploys to Cloudflare Workers
6. Performs health check
7. Saves deployment record
8. Provides rollback commands

**Safety Features**:
- Requires typing "yes" (not just "y") for deployment
- Captures current git commit for rollback reference
- Warns about uncommitted changes
- Health check after deployment
- Deployment log with full details

**Prerequisites**:
- Valid `CLOUDFLARE_API_TOKEN`
- All verification checks passed
- Production build successful

**Usage**:
```bash
export CLOUDFLARE_API_TOKEN="your_api_token"
bash scripts/5-deploy-production.sh
```

**Expected Output**:
```
✅ Verification passed
✅ Build successful
Bundle size: 2.1M
Current branch: main
Deploying commit: a1b2c3d

⚠️  PRODUCTION DEPLOYMENT WARNING

You are about to deploy to PRODUCTION environment:
  Worker: coreflow360-v4-prod
  Branch: main
  Commit: a1b2c3d
  Config: wrangler.production.toml

Proceed with production deployment? (yes/no) yes

✅ Deployment successful (12s)
Worker URL: https://coreflow360-v4-prod.workers.dev
✅ Health check passed

✅ Deployment record saved: deployments/deployment-20250114-153045.log

🚀 Production Deployment Complete!
```

**Deployment Record**: Saves complete deployment details to `deployments/` directory for audit trail.

---

### `rollback-production.sh` - Emergency Rollback

**Purpose**: Quick rollback for problematic deployments

**Rollback Options**:

1. **Automatic rollback**: Reverts to previous deployment
2. **Rollback to specific deployment ID**: Choose from history
3. **Deploy from git commit**: Deploy any historical commit
4. **Cancel**: Abort rollback

**What it does**:
- Lists recent deployment history
- Validates rollback target
- Performs rollback
- Health check after rollback
- Saves rollback record

**Usage**:
```bash
export CLOUDFLARE_API_TOKEN="your_api_token"
bash scripts/rollback-production.sh
```

**Expected Output**:
```
⚠️  WARNING: PRODUCTION ROLLBACK

Recent deployments:
  abc123... - 2025-01-14 15:30:45
  def456... - 2025-01-14 14:20:12

Rollback Options:
1. Automatic rollback (to previous deployment)
2. Rollback to specific deployment ID
3. Deploy from specific git commit
4. Cancel

Select option (1-4): 1

✅ Rollback successful
✅ Health check passed (HTTP 200)
✅ Rollback record saved: deployments/rollback-20250114-160000.log
```

**Emergency Use**:
```bash
# Fastest rollback (one command)
export CLOUDFLARE_API_TOKEN="your_token"
echo "1" | bash scripts/rollback-production.sh
```

---

## Prerequisites

### Required Software

- **Node.js**: v20.0.0 or higher (enforced by package.json)
- **npm**: Latest version
- **Wrangler CLI**: `npm install -D wrangler`
- **OpenSSL**: For secret generation (usually pre-installed on Unix systems)
- **Git**: For version control operations

### Required Accounts & API Keys

- **Cloudflare Account**: With Workers and D1 access
- **Cloudflare API Token**: With Workers edit permissions
- **Anthropic API Key**: From https://console.anthropic.com/account/keys
- **OpenAI API Key**: From https://platform.openai.com/api-keys
- **Sentry DSN** (optional): For error monitoring
- **Stripe Keys** (optional): For payment processing
- **Email API Key** (optional): SendGrid/Mailgun

---

## Environment Setup

### Before Running Scripts

```bash
# Set Cloudflare API token
export CLOUDFLARE_API_TOKEN="your_api_token"

# Verify token
npx wrangler whoami

# Make scripts executable (Unix/macOS)
chmod +x scripts/*.sh
```

### Windows Users

Run scripts using Git Bash or WSL:

```bash
# Git Bash
bash scripts/0-setup-production.sh

# WSL
wsl bash scripts/0-setup-production.sh
```

---

## Troubleshooting

### Common Issues

#### "CLOUDFLARE_API_TOKEN not set"
```bash
export CLOUDFLARE_API_TOKEN="your_token"
```

#### "Invalid API token"
- Check token hasn't expired
- Verify token has Workers edit permissions
- Try creating new token in Cloudflare Dashboard

#### "Build failed"
```bash
npm install
npm run type-check
npm run build
```

#### "wrangler command not found"
```bash
npm install -D wrangler
# or globally
npm install -g wrangler
```

#### "OpenSSL not found"
- **macOS**: Pre-installed
- **Ubuntu/Debian**: `sudo apt-get install openssl`
- **Windows**: Use Git Bash or install via package manager

#### "Dry-run deployment failed"
Run verification script for detailed diagnostics:
```bash
bash scripts/4-verify-configuration.sh
```

---

## File Reference

### Scripts Created

- `0-setup-production.sh` - Master setup orchestrator
- `1-rotate-api-token.sh` - API token rotation
- `2-create-production-kv.sh` - KV namespace creation
- `3-configure-secrets.sh` - Secrets configuration
- `4-verify-configuration.sh` - Pre-deployment validation
- `5-deploy-production.sh` - Production deployment
- `rollback-production.sh` - Emergency rollback

### Temporary Files (Auto-cleaned)

- `.kv-namespace-ids.tmp` - KV namespace IDs (deleted after Phase 2)
- `.secrets.tmp` - Generated secrets (securely deleted after Phase 3)

### Log Files

- `deployments/deployment-YYYYMMDD-HHMMSS.log` - Deployment records
- `deployments/rollback-YYYYMMDD-HHMMSS.log` - Rollback records

---

## Security Best Practices

### Secrets Management

- ✅ Never commit `.env.local` to git
- ✅ Rotate API tokens every 90 days
- ✅ Use separate tokens for production vs staging
- ✅ Delete temporary secrets files after use
- ✅ Review `wrangler secret list` periodically

### Deployment Safety

- ✅ Always run verification before deployment
- ✅ Review git diff before deploying
- ✅ Use dry-run to test configuration
- ✅ Monitor logs after deployment
- ✅ Keep deployment records for audit trail

### Token Rotation Schedule

```bash
# Recommended rotation schedule
# Every 90 days, run:
bash scripts/1-rotate-api-token.sh
```

---

## Monitoring After Deployment

### Live Logs
```bash
npx wrangler tail coreflow360-v4-prod --env production --format pretty
```

### Health Check
```bash
curl https://api.coreflow360.com/health
```

### Cloudflare Dashboard
https://dash.cloudflare.com/workers

### Deployment History
```bash
npx wrangler deployments list --name coreflow360-v4-prod
```

---

## Emergency Procedures

### Critical Production Issue

**Step 1**: Immediate rollback
```bash
export CLOUDFLARE_API_TOKEN="your_token"
bash scripts/rollback-production.sh
# Select option 1 (automatic rollback)
```

**Step 2**: Monitor health
```bash
npx wrangler tail coreflow360-v4-prod --env production
```

**Step 3**: Investigate issue
```bash
# Check deployment logs
cat deployments/deployment-*.log | tail -n 100

# Review git diff
git diff HEAD~1 HEAD
```

**Step 4**: Fix and redeploy
```bash
# Fix issue in code
git add .
git commit -m "fix: Production issue resolved"

# Verify fix
bash scripts/4-verify-configuration.sh

# Redeploy
bash scripts/5-deploy-production.sh
```

---

## Support

### Documentation
- Main README: `../README.md`
- Deployment Checklist: `../DEPLOYMENT_READINESS_CHECKLIST.md`
- Secrets Guide: `../SECRETS.md`
- KV Namespace Issue: `../CRITICAL_KV_NAMESPACE_ISSUE.md`

### Quick Reference
```bash
# Full setup
bash scripts/0-setup-production.sh

# Verify configuration
bash scripts/4-verify-configuration.sh

# Deploy
bash scripts/5-deploy-production.sh

# Rollback
bash scripts/rollback-production.sh

# Monitor
npx wrangler tail coreflow360-v4-prod --env production
```

---

**Created**: 2025-01-14
**Version**: 1.0
**Status**: Production Ready ✅
