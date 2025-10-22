# CoreFlow360 V4 - Production Deployment Quick Start

**🚀 Get to production in 45 minutes**

---

## ⚡ TL;DR - Fastest Path to Production

```bash
# 1. Set API token
export CLOUDFLARE_API_TOKEN="your_cloudflare_api_token"

# 2. Run master setup script
bash scripts/0-setup-production.sh

# 3. Follow prompts (select option 1 for full setup)

# 4. Done! 🎉
```

---

## 📋 Pre-Flight Checklist

Before starting, have these ready:

- [ ] Cloudflare API Token ([Get it here](https://dash.cloudflare.com/profile/api-tokens))
- [ ] Anthropic API Key ([Get it here](https://console.anthropic.com/account/keys))
- [ ] OpenAI API Key ([Get it here](https://platform.openai.com/api-keys))
- [ ] Sentry DSN (optional, [Get it here](https://sentry.io/settings/projects/))
- [ ] Stripe Keys (optional, [Get it here](https://dashboard.stripe.com/apikeys))

---

## 🎯 Step-by-Step Guide

### Step 1: Environment Setup (2 min)

```bash
# Clone repository (if not already done)
git clone https://github.com/your-org/coreflow360-v4.git
cd coreflow360-v4

# Install dependencies
npm ci

# Verify Node.js version (must be 20+)
node --version
```

### Step 2: Set Cloudflare API Token (1 min)

```bash
# Export your Cloudflare API token
export CLOUDFLARE_API_TOKEN="your_token_here"

# Verify it works
npx wrangler whoami
```

**Expected output:**
```
You are logged in with an API Token
```

### Step 3: Run Master Setup Script (40 min)

```bash
# Make script executable (Unix/Mac)
chmod +x scripts/*.sh

# Run setup
bash scripts/0-setup-production.sh
```

**Select option 1** for full automated setup.

### Step 4: Follow Interactive Prompts

The script will guide you through:

#### Phase 1: API Token Rotation (5 min)
- Opens Cloudflare Dashboard instructions
- Validates new token
- Updates `.env.local`

#### Phase 2: KV Namespace Creation (10 min)
- Creates 7 production KV namespaces
- Updates `wrangler.production.toml` automatically
- Prevents data leakage between environments

#### Phase 3: Secrets Configuration (15 min)
- Generates secure JWT, ENCRYPTION, and AUTH secrets
- Prompts for Anthropic API key
- Prompts for OpenAI API key
- Optionally configures Stripe and Sentry
- Uploads all secrets to Cloudflare

#### Phase 4: Verification (2 min)
- Validates configuration
- Runs build test
- Checks dry-run deployment

#### Phase 5: Deployment (Optional, 5 min)
- Deploys to production
- Runs health checks
- Provides monitoring commands

### Step 5: Verify Deployment (3 min)

```bash
# Check health endpoint
curl https://api.coreflow360.com/health

# Monitor live logs
npx wrangler tail coreflow360-v4-prod --env production --format pretty

# View deployment in Cloudflare Dashboard
# https://dash.cloudflare.com/workers
```

---

## 🔧 Manual Setup (Alternative)

If you prefer manual control, run individual scripts:

```bash
# Phase 1: Rotate API token
bash scripts/1-rotate-api-token.sh

# Phase 2: Create KV namespaces
bash scripts/2-create-production-kv.sh

# Phase 3: Configure secrets
bash scripts/3-configure-secrets.sh

# Phase 4: Verify configuration
bash scripts/4-verify-configuration.sh

# Phase 5: Deploy to production
bash scripts/5-deploy-production.sh
```

---

## 🆘 Emergency Rollback

If deployment causes issues:

```bash
# Immediate rollback to previous deployment
export CLOUDFLARE_API_TOKEN="your_token"
bash scripts/rollback-production.sh
# Select option 1
```

---

## 📊 Verification Commands

### Check Configuration Status

```bash
# Verify all secrets are set
npx wrangler secret list --env production

# Expected output (9 secrets):
# JWT_SECRET
# ENCRYPTION_KEY
# AUTH_SECRET
# ANTHROPIC_API_KEY
# OPENAI_API_KEY
# SENTRY_DSN
# (plus optional Stripe/Email keys)
```

### Test Deployment

```bash
# Dry-run deployment (test without deploying)
npx wrangler deploy --dry-run --config wrangler.production.toml --env production

# Expected: "✅ No errors"
```

### Verify Build

```bash
# Build production bundle
npm run build

# Expected output:
# dist\worker.js  2.1mb
# Done in 65ms
# (No eval() warnings)
```

---

## 🎓 Understanding What Gets Fixed

### Critical Issue #1: Exposed API Token
**Problem**: Cloudflare API token `Rp3owWaOgVIBOFqv13wVWDzei3YbjfRfO0te5yVH` found in `.env.local`

**Fix**: Script 1 rotates the token and ensures `.env.local` is gitignored

### Critical Issue #2: Shared KV Namespaces
**Problem**: Production and staging share same KV namespace IDs, causing data leakage

**Fix**: Script 2 creates 7 new production-only namespaces:
- KV_CACHE_PROD
- KV_SESSION_PROD
- KV_RATE_LIMIT_METRICS_PROD
- KV_AUTH_PROD
- AGENT_CACHE_PROD
- AGENT_MEMORY_PROD
- PATTERN_CACHE_PROD

### Critical Issue #3: Missing Secrets
**Problem**: Zero secrets configured in Cloudflare Workers (0/9 required)

**Fix**: Script 3 generates secure secrets and uploads all 9:
- JWT_SECRET (256-bit generated)
- ENCRYPTION_KEY (256-bit generated)
- AUTH_SECRET (256-bit generated)
- ANTHROPIC_API_KEY (user provided)
- OPENAI_API_KEY (user provided)
- SENTRY_DSN (user provided)
- Plus optional Stripe/Email keys

### Code Quality Issues Fixed Previously
✅ Removed phantom Durable Objects (SessionManagerDO, AnalyticsAggregatorDO)
✅ Eliminated eval() usage from codebase
✅ Updated compatibility_date to stable version
✅ Cleaned up unused wrangler configs
✅ Build passes with zero warnings

---

## 📈 Success Criteria

After successful deployment, you should see:

✅ **Secrets**: All 9 secrets configured in Cloudflare
```bash
npx wrangler secret list --env production
# Shows: JWT_SECRET, ENCRYPTION_KEY, AUTH_SECRET, etc.
```

✅ **KV Namespaces**: 7 production namespaces created
```bash
# wrangler.production.toml contains unique IDs (no PLACEHOLDER)
```

✅ **Build**: Clean production build
```bash
npm run build
# Output: dist\worker.js  2.1mb - Done in 65ms
# No warnings
```

✅ **Health Check**: API responds successfully
```bash
curl https://api.coreflow360.com/health
# Returns: 200 OK or {"status":"healthy"}
```

✅ **Deployment**: Worker deployed successfully
```bash
npx wrangler deployments list --name coreflow360-v4-prod
# Shows recent deployment
```

---

## 🔍 Troubleshooting

### "CLOUDFLARE_API_TOKEN not set"
```bash
export CLOUDFLARE_API_TOKEN="your_token"
# Add to ~/.bashrc or ~/.zshrc for persistence
```

### "Invalid API token"
- Get new token from [Cloudflare Dashboard](https://dash.cloudflare.com/profile/api-tokens)
- Ensure token has **Workers:Edit** permission
- Try `npx wrangler whoami` to verify

### "Build failed"
```bash
# Clean install dependencies
rm -rf node_modules package-lock.json
npm install

# Check TypeScript errors
npm run type-check

# Try build again
npm run build
```

### "Secrets upload failed"
```bash
# List current secrets
npx wrangler secret list --env production

# Manually set a secret
npx wrangler secret put JWT_SECRET --env production
# Then paste the value when prompted
```

### "Dry-run failed"
```bash
# Run verification script for detailed diagnostics
bash scripts/4-verify-configuration.sh

# Fix any reported errors, then retry
```

---

## 📞 Getting Help

### Documentation
- [Scripts README](scripts/README.md) - Detailed script documentation
- [Deployment Checklist](DEPLOYMENT_READINESS_CHECKLIST.md) - Full checklist
- [Secrets Guide](SECRETS.md) - Secrets management
- [KV Namespace Issue](CRITICAL_KV_NAMESPACE_ISSUE.md) - Data leakage fix

### Common Commands
```bash
# Check deployment status
npx wrangler deployments list --name coreflow360-v4-prod

# View live logs
npx wrangler tail coreflow360-v4-prod --env production

# List secrets
npx wrangler secret list --env production

# Rollback deployment
bash scripts/rollback-production.sh

# Verify configuration
bash scripts/4-verify-configuration.sh
```

---

## ⏱️ Time Breakdown

| Phase | Duration | Manual Input Required |
|-------|----------|----------------------|
| Setup environment | 2 min | Install dependencies |
| Phase 1: Token rotation | 5 min | Cloudflare Dashboard + paste new token |
| Phase 2: KV namespaces | 10 min | Confirm auto-update |
| Phase 3: Secrets config | 15 min | Provide API keys (Anthropic, OpenAI, etc.) |
| Phase 4: Verification | 2 min | None (automated) |
| Phase 5: Deployment | 5 min | Type "yes" to confirm |
| Verification | 3 min | Test endpoints |
| **TOTAL** | **~45 min** | Mostly automated |

---

## ✅ Post-Deployment Checklist

After deployment completes:

- [ ] Health check passes: `curl https://api.coreflow360.com/health`
- [ ] Monitor logs for 5 minutes: `npx wrangler tail coreflow360-v4-prod --env production`
- [ ] Test authentication flow
- [ ] Verify AI agent initialization
- [ ] Check error rates in Cloudflare Dashboard
- [ ] Test critical user flows (if frontend deployed)
- [ ] Save deployment record for audit trail
- [ ] Update team on successful deployment

---

## 🎯 Next Steps After Production

1. **Configure Frontend**: Deploy frontend to Cloudflare Pages
2. **Setup Monitoring**: Configure Sentry alerts
3. **Custom Domain**: Point DNS to Workers (if not already done)
4. **Database Migrations**: Apply any pending migrations
5. **R2 CORS**: Configure CORS for document upload
6. **Backups**: Setup automated backups
7. **Team Access**: Add team members to Cloudflare account

---

**🚀 Ready to deploy? Run:**
```bash
export CLOUDFLARE_API_TOKEN="your_token"
bash scripts/0-setup-production.sh
```

**Questions?** Check [scripts/README.md](scripts/README.md) for detailed documentation.

---

**Last Updated**: 2025-01-14
**Version**: 1.0
**Status**: Production Ready ✅
