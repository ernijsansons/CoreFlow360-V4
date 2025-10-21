# Deployment Readiness Checklist

## Status: 🔴 NOT READY FOR DEPLOYMENT

**Last Updated**: 2025-10-14
**Current Build Status**: ✅ PASSING (no eval() warnings)
**Configuration Status**: ⚠️ REQUIRES MANUAL INTERVENTION

---

## Critical Blockers (Must Complete Before Deployment)

### 🔒 1. Rotate Exposed API Token
**Status**: ❌ NOT DONE
**Priority**: CRITICAL - SECURITY ISSUE
**Estimated Time**: 5 minutes

**Steps**:
1. Log into Cloudflare Dashboard: https://dash.cloudflare.com
2. Navigate to: My Profile → API Tokens
3. Find token ending in `...5yVH` (full: `Rp3owWaOgVIBOFqv13wVWDzei3YbjfRfO0te5yVH`)
4. Click "Roll" to rotate the token
5. Update `.env.local` with new token
6. **DO NOT commit `.env.local` to git**

**Verification**:
```bash
# Test new token
export CLOUDFLARE_API_TOKEN="your_new_token"
npx wrangler whoami
```

---

### 🗄️ 2. Create Production KV Namespaces
**Status**: ❌ NOT DONE
**Priority**: CRITICAL - DEPLOYMENT BLOCKER
**Estimated Time**: 10 minutes

**Problem**: Production and staging currently share the same KV namespace IDs, causing data leakage.

**Current Shared Namespaces**:
- `KV_CACHE`: `62253644abcf4ce78558fbd764b366fb`
- `KV_SESSION`: `bd87c1fb6fd34a21b47e6cdbdd5a20ae`
- `KV_RATE_LIMIT_METRICS`: `c74011292d2947ac9d980556d62c1b51`
- `KV_AUTH`: `091859c74f514d5eae66f3e2937b345e`
- `AGENT_CACHE`: `0dd3a20b30f54f5787ec9777d8cc208a`
- `AGENT_MEMORY`: `dd1612a1880845a0a916cef8dea95323`
- `PATTERN_CACHE`: `0b48f9a582754f9e97e67e184589fa8a`

**Steps**:
```bash
# Create production-specific KV namespaces
wrangler kv:namespace create "KV_CACHE_PROD"
wrangler kv:namespace create "KV_SESSION_PROD"
wrangler kv:namespace create "KV_RATE_LIMIT_METRICS_PROD"
wrangler kv:namespace create "KV_AUTH_PROD"
wrangler kv:namespace create "AGENT_CACHE_PROD"
wrangler kv:namespace create "AGENT_MEMORY_PROD"
wrangler kv:namespace create "PATTERN_CACHE_PROD"

# Update wrangler.production.toml with the new IDs
# Replace the PLACEHOLDER_CREATE_NEW_NAMESPACE markers
```

**See Also**: `CRITICAL_KV_NAMESPACE_ISSUE.md` for detailed instructions

---

### 🔐 3. Configure Production Secrets
**Status**: ❌ NOT DONE (0/9 secrets set)
**Priority**: CRITICAL - DEPLOYMENT BLOCKER
**Estimated Time**: 15 minutes

**Required Secrets** (from SECRETS.md):

```bash
# Core Security (REQUIRED)
wrangler secret put JWT_SECRET --env production
wrangler secret put ENCRYPTION_KEY --env production
wrangler secret put AUTH_SECRET --env production

# AI Services (REQUIRED)
wrangler secret put ANTHROPIC_API_KEY --env production
wrangler secret put OPENAI_API_KEY --env production

# Payment Processing (if enabled)
wrangler secret put STRIPE_SECRET_KEY --env production
wrangler secret put STRIPE_WEBHOOK_SECRET --env production

# Monitoring (REQUIRED)
wrangler secret put SENTRY_DSN --env production

# Communication (if enabled)
wrangler secret put EMAIL_API_KEY --env production
```

**Generate Secure Secrets**:
```bash
# Generate JWT_SECRET (256-bit)
openssl rand -base64 32

# Generate ENCRYPTION_KEY (256-bit)
openssl rand -base64 32

# Generate AUTH_SECRET (256-bit)
openssl rand -base64 32
```

**Verification**:
```bash
# List all configured secrets
wrangler secret list --env production
```

---

## High Priority (Recommended Before Deployment)

### 🌐 4. Verify Custom Domain Configuration
**Status**: ⚠️ NEEDS VERIFICATION
**Priority**: HIGH
**Estimated Time**: 5 minutes

**Current Route Configuration**:
```toml
routes = [
  { pattern = "api.coreflow360.com/*", zone_name = "coreflow360.com" }
]
```

**Verification Steps**:
1. Log into Cloudflare Dashboard
2. Check if zone `coreflow360.com` exists
3. If not, either:
   - Create the zone and add DNS records
   - OR comment out the routes in `wrangler.production.toml`

**Alternative (if domain not ready)**:
```toml
# Comment out routes to use workers.dev subdomain
# routes = [
#   { pattern = "api.coreflow360.com/*", zone_name = "coreflow360.com" }
# ]
```

---

### 📦 5. Run Dry-Run Deployment
**Status**: ❌ NOT DONE
**Priority**: HIGH
**Estimated Time**: 2 minutes

**Purpose**: Validate configuration without actually deploying

```bash
# Dry-run to check for issues
wrangler deploy --dry-run --config wrangler.production.toml --env production

# Expected output should show:
# ✅ All bindings resolved
# ✅ No missing Durable Objects
# ✅ Compatibility flags valid
```

---

## Medium Priority (Post-Deployment)

### 📊 6. Configure R2 CORS Rules
**Status**: ⚠️ OPTIONAL
**Priority**: MEDIUM
**Estimated Time**: 10 minutes

**Purpose**: Allow frontend to access R2 buckets directly

```bash
# Example CORS configuration
wrangler r2 bucket cors put coreflow360-documents-prod --cors-config cors.json
```

**cors.json**:
```json
[
  {
    "AllowedOrigins": ["https://app.coreflow360.com"],
    "AllowedMethods": ["GET", "PUT", "POST"],
    "AllowedHeaders": ["*"],
    "MaxAgeSeconds": 3600
  }
]
```

---

### 🗃️ 7. Database Migrations
**Status**: ⚠️ NEEDS PLANNING
**Priority**: MEDIUM
**Estimated Time**: 5 minutes

**Check migration status**:
```bash
# List applied migrations
wrangler d1 migrations list coreflow360-agents --env production

# Apply pending migrations (if any)
wrangler d1 migrations apply coreflow360-agents --env production
```

---

## Pre-Deployment Validation

### ✅ Build Verification (COMPLETED)
```bash
npm run build
# ✅ Output: dist\worker.js  2.1mb - Done in 65ms
# ✅ No eval() warnings
```

### ✅ Configuration Cleanup (COMPLETED)
- ✅ Removed phantom Durable Objects (SessionManagerDO, AnalyticsAggregatorDO)
- ✅ Updated compatibility_date to "2024-09-01"
- ✅ Removed eval() from codebase
- ✅ Deleted unused wrangler configs

---

## Deployment Command (DO NOT RUN YET)

**Only run after completing all Critical Blockers above**:

```bash
# Production deployment
wrangler deploy --config wrangler.production.toml --env production

# Monitor deployment
wrangler tail coreflow360-v4-prod --env production
```

---

## Post-Deployment Verification

### Health Checks
```bash
# API health endpoint
curl -f https://api.coreflow360.com/health

# Worker status
curl -f https://coreflow360-v4-prod.workers.dev/health

# Check logs
wrangler tail coreflow360-v4-prod --env production --format pretty
```

### Monitor First 5 Minutes
1. Check error rates in Cloudflare Dashboard
2. Verify Durable Objects are initializing
3. Test authentication flow
4. Verify database connectivity
5. Check AI agent initialization

---

## Emergency Rollback Plan

If deployment fails or causes issues:

```bash
# Immediate rollback (if previous version exists)
wrangler rollback coreflow360-v4-prod --env production

# OR deploy previous git commit
git checkout <previous-commit-hash>
wrangler deploy --config wrangler.production.toml --env production
```

---

## Summary

**Total Estimated Time to Deployment Ready**: ~40 minutes

**Critical Path**:
1. Rotate API token (5 min)
2. Create production KV namespaces (10 min)
3. Set all production secrets (15 min)
4. Verify domain configuration (5 min)
5. Run dry-run deployment (2 min)
6. Deploy to production (3 min)

**Current Blockers**: 3 critical items must be completed manually before deployment

**Next Immediate Action**: Rotate the exposed Cloudflare API token
