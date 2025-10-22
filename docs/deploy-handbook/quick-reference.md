# Quick Reference Guide - Common Commands & Procedures

**Created**: 2025-10-22
**Purpose**: Fast reference for common deployment, monitoring, and troubleshooting tasks
**Audience**: All engineers, DevOps, on-call

---

## 📋 Table of Contents

1. [Deployment Commands](#deployment-commands)
2. [Feature Flag Management](#feature-flag-management)
3. [Monitoring & Health Checks](#monitoring--health-checks)
4. [Rollback Procedures](#rollback-procedures)
5. [Database Operations](#database-operations)
6. [Troubleshooting](#troubleshooting)
7. [Emergency Contacts](#emergency-contacts)

---

## Deployment Commands

### Deploy to Environments

```bash
# Development (auto-deploys from dev branch)
git push origin dev

# Staging (auto-deploys from main branch)
git push origin main

# Production (manual trigger via GitHub Actions)
# GitHub → Actions → Deploy to Production → Run workflow
# Type "deploy-to-production" to confirm

# Or via CLI (if needed)
wrangler deploy --env production
```

### Check Deployment Status

```bash
# List recent deployments
wrangler deployments list

# View specific deployment
wrangler deployments view <DEPLOYMENT_ID>

# Tail logs
wrangler tail

# Tail with filters
wrangler tail --status error
wrangler tail --method POST
```

### Build & Test Locally

```bash
# Install dependencies
npm ci

# Run tests
npm run test                    # Unit tests
npm run test:e2e               # E2E tests (Playwright)
npm run test:accessibility     # Accessibility tests

# Lint & type check
npm run lint
npm run type-check

# Build
npm run build

# Preview production build
npm run preview
```

---

## Feature Flag Management

### Create Feature Flag

```bash
curl -X POST https://api.coreflow360.com/api/feature-flags \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "key": "enableComplianceGuidelines",
    "name": "Compliance Guidelines Management",
    "description": "Enable UI for managing compliance guidelines",
    "enabled": false,
    "rolloutPercentage": 0
  }'
```

### Check Flag Status

```bash
# Get flag status
curl https://api.coreflow360.com/api/feature-flags/enableComplianceGuidelines

# Get all flags
curl https://api.coreflow360.com/api/feature-flags
```

### Update Rollout Percentage

```bash
# Enable for internal users (beta)
curl -X PATCH https://api.coreflow360.com/api/feature-flags/enableComplianceGuidelines \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "enabled": true,
    "rolloutType": "users",
    "allowedUsers": ["user-1", "user-2", "user-3"]
  }'

# 10% rollout
curl -X PATCH https://api.coreflow360.com/api/feature-flags/enableComplianceGuidelines \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "enabled": true,
    "rolloutType": "percentage",
    "rolloutPercentage": 10
  }'

# 50% rollout
curl -X PATCH https://api.coreflow360.com/api/feature-flags/enableComplianceGuidelines \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{"rolloutPercentage": 50}'

# 100% rollout
curl -X PATCH https://api.coreflow360.com/api/feature-flags/enableComplianceGuidelines \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{"rolloutPercentage": 100}'
```

### Emergency Disable

```bash
# Instantly disable feature flag
curl -X PATCH https://api.coreflow360.com/api/feature-flags/enableComplianceGuidelines \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"enabled": false, "rolloutPercentage": 0}'
```

### Delete Flag (after cleanup)

```bash
curl -X DELETE https://api.coreflow360.com/api/feature-flags/enableComplianceGuidelines \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

---

## Monitoring & Health Checks

### Health Check Endpoints

```bash
# Application health
curl -f https://api.coreflow360.com/health
# Expected: {"status":"healthy","timestamp":"2025-10-22T..."}

# API status
curl -f https://api.coreflow360.com/api/status
# Expected: {"status":"ok","version":"v4",...}

# Database health
curl -f https://api.coreflow360.com/api/db/health
# Expected: {"status":"connected","latency_ms":10}

# Cache health
curl -f https://api.coreflow360.com/api/cache/health
# Expected: {"kv_cache":"connected","session_cache":"connected"}
```

### Metrics Endpoints

```bash
# Error rate (last 15 minutes)
curl https://api.coreflow360.com/api/metrics/errors?last=15m
# Returns: {"error_rate":0.0008,"total_errors":2,"total_requests":2500}

# Response times (last 15 minutes)
curl https://api.coreflow360.com/api/metrics/response-times?last=15m
# Returns: {"p50_ms":89,"p95_ms":245,"p99_ms":512}

# Feature usage
curl https://api.coreflow360.com/api/metrics/feature-usage?feature=enableComplianceGuidelines&last=24h
# Returns: {"feature":"enableComplianceGuidelines","total_usage":157}
```

### Sentry Error Check

```bash
# Check Sentry dashboard
open https://sentry.io/organizations/coreflow360/issues/

# Or via CLI (if sentry-cli installed)
sentry-cli issues list --project coreflow360-frontend
sentry-cli issues list --project coreflow360-backend
```

### Cloudflare Analytics

```bash
# Workers analytics via API
curl -X GET "https://api.cloudflare.com/client/v4/accounts/$CLOUDFLARE_ACCOUNT_ID/workers/scripts/coreflow360-production/analytics" \
  -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN"
```

---

## Rollback Procedures

### Type 1: Feature Flag Disable (< 2 min)

```bash
# Fastest rollback - just disable the feature flag
curl -X PATCH https://api.coreflow360.com/api/feature-flags/enableProblematicFeature \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{"enabled": false, "rolloutPercentage": 0}'

# Verify
curl https://api.coreflow360.com/api/feature-flags/enableProblematicFeature
```

### Type 2: Frontend Rollback (< 10 min)

```bash
# List recent deployments
wrangler pages deployments list --project-name=coreflow360-frontend

# Rollback to previous deployment
wrangler pages deployments rollback <PREVIOUS_DEPLOYMENT_ID> \
  --project-name=coreflow360-frontend

# Verify
curl -f https://coreflow360.com
```

### Type 3: Backend Rollback (< 20 min)

```bash
# List recent deployments
wrangler deployments list

# Rollback to previous deployment
wrangler rollback <PREVIOUS_DEPLOYMENT_ID>

# Verify
curl -f https://api.coreflow360.com/health
curl -f https://api.coreflow360.com/api/status

# Check error rates
curl https://api.coreflow360.com/api/metrics/errors?last=5m
```

### Type 4: Database Rollback (< 60 min)

```bash
# ⚠️ DANGEROUS - Use only when absolutely necessary

# 1. Enable maintenance mode
curl -X POST https://api.coreflow360.com/api/admin/maintenance-mode \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{"enabled": true}'

# 2. List backups
wrangler d1 backup list coreflow360-production

# 3. Restore from backup
wrangler d1 restore coreflow360-production <BACKUP_ID>

# 4. Verify restoration
wrangler d1 execute coreflow360-production --command "SELECT COUNT(*) FROM compliance_guidelines"

# 5. Disable maintenance mode
curl -X POST https://api.coreflow360.com/api/admin/maintenance-mode \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{"enabled": false}'
```

---

## Database Operations

### Run Migrations

```bash
# Local/Development
wrangler d1 migrations apply coreflow360-dev --local

# Staging
wrangler d1 migrations apply coreflow360-staging

# Production (after testing on staging)
wrangler d1 migrations apply coreflow360-production
```

### Database Queries

```bash
# Execute query
wrangler d1 execute coreflow360-production \
  --command "SELECT * FROM compliance_guidelines LIMIT 5"

# Interactive SQL shell
wrangler d1 execute coreflow360-production

# Import data
wrangler d1 import coreflow360-production data.sql
```

### Backups

```bash
# Create backup
wrangler d1 backup create coreflow360-production

# List backups
wrangler d1 backup list coreflow360-production

# Restore backup
wrangler d1 restore coreflow360-production <BACKUP_ID>
```

### Database Info

```bash
# List databases
wrangler d1 list

# Get database info
wrangler d1 info coreflow360-production

# List tables
wrangler d1 execute coreflow360-production \
  --command "SELECT name FROM sqlite_master WHERE type='table'"

# Table schema
wrangler d1 execute coreflow360-production \
  --command "PRAGMA table_info(compliance_guidelines)"
```

---

## Troubleshooting

### Application Not Loading

```bash
# 1. Check health endpoints
curl -f https://api.coreflow360.com/health
curl -f https://coreflow360.com

# 2. Check recent deployments
wrangler deployments list

# 3. Check error rates
curl https://api.coreflow360.com/api/metrics/errors?last=15m

# 4. View logs
wrangler tail --status error

# 5. Check Cloudflare status
curl https://www.cloudflarestatus.com/api/v2/status.json
```

### High Error Rate

```bash
# 1. Check error metrics
curl https://api.coreflow360.com/api/metrics/errors?last=15m

# 2. View error logs
wrangler tail --status error

# 3. Check Sentry for patterns
open https://sentry.io/organizations/coreflow360/issues/

# 4. Check recent changes
git log --oneline -10
wrangler deployments list --limit 5

# 5. Rollback if needed (see Rollback Procedures above)
```

### Slow Response Times

```bash
# 1. Check response time metrics
curl https://api.coreflow360.com/api/metrics/response-times?last=15m

# 2. Check database performance
wrangler d1 execute coreflow360-production \
  --command "SELECT * FROM slow_query_log ORDER BY timestamp DESC LIMIT 10"

# 3. Run performance benchmarks
npm run benchmark

# 4. Check Cloudflare Analytics
# Open: https://dash.cloudflare.com/analytics
```

### Database Connection Issues

```bash
# 1. Check database health
curl -f https://api.coreflow360.com/api/db/health

# 2. Test connection
wrangler d1 execute coreflow360-production --command "SELECT 1"

# 3. Check database status
wrangler d1 info coreflow360-production

# 4. Check recent migrations
wrangler d1 migrations list coreflow360-production
```

### Authentication Issues

```bash
# 1. Test authentication endpoint
curl -X POST https://api.coreflow360.com/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","password":"test123"}'

# 2. Check JWT validation
# Review logs for JWT errors
wrangler tail | grep "JWT"

# 3. Verify environment variables
wrangler secret list
```

### Feature Flag Not Working

```bash
# 1. Check flag status
curl https://api.coreflow360.com/api/feature-flags/enableFeatureName

# 2. Check user eligibility
# Verify user ID is in allowedUsers array (if beta testing)

# 3. Clear cache
curl -X POST https://api.coreflow360.com/api/admin/cache/clear \
  -H "Authorization: Bearer $ADMIN_TOKEN"

# 4. Check frontend console for errors
# Open browser DevTools → Console
```

---

## Performance Testing

### Run Lighthouse

```bash
# Install Lighthouse
npm install -g lighthouse

# Run Lighthouse
lighthouse https://coreflow360.com \
  --output html \
  --output-path ./lighthouse-report.html

# Run Lighthouse CI
lhci autorun
```

### Run Load Tests

```bash
# Install k6
brew install k6  # Mac
# OR
sudo apt-get install k6  # Linux

# Run load test
k6 run scripts/load-test.js

# Run with custom parameters
k6 run --vus 100 --duration 5m scripts/load-test.js
```

### API Response Time Test

```bash
# Quick response time test (100 requests)
bash scripts/test-api-response-time.sh

# Apache Bench (1000 requests, 10 concurrent)
ab -n 1000 -c 10 \
  -H "Authorization: Bearer $AUTH_TOKEN" \
  https://api.coreflow360.com/api/compliance/guidelines
```

---

## Common Tasks

### Add New Team Member

```bash
# 1. Grant repository access (GitHub)
# Settings → Manage access → Invite

# 2. Grant Cloudflare access
# Cloudflare Dashboard → Account → Members → Invite

# 3. Grant Sentry access
# Sentry → Settings → Teams → Add member

# 4. Add to communication channels
# Slack: Add to #engineering, #sprint-34, #incidents
```

### Create New Feature

```bash
# 1. Create feature branch
git checkout -b feature/compliance-guidelines

# 2. Implement feature (follow developer-quick-start.md)

# 3. Create feature flag
curl -X POST https://api.coreflow360.com/api/feature-flags \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{"key":"enableFeatureName","enabled":false}'

# 4. Run tests
npm run test
npm run test:e2e

# 5. Create pull request
gh pr create --title "feat: Add compliance guidelines" \
  --body "Implements compliance guidelines management UI"

# 6. After approval, merge
gh pr merge --squash

# 7. Deploy (auto-deploys to staging)
# Then manually deploy to production via GitHub Actions
```

### Update Dependencies

```bash
# Check outdated packages
npm outdated

# Update dependencies (carefully!)
npm update

# Or update specific package
npm install package-name@latest

# Run tests after updating
npm run test
npm run test:e2e

# Commit changes
git add package.json package-lock.json
git commit -m "chore: Update dependencies"
```

---

## Emergency Contacts

### On-Call Engineers

**Current Schedule**: Check PagerDuty
- **Primary**: [Check PagerDuty schedule]
- **Backup**: [Name] - [Phone]

**Page On-Call**:
```bash
# Via PagerDuty app or web
# OR emergency phone: [Emergency Phone]
```

### Escalation Path

1. **Level 1**: On-Call Engineer (15 min response)
2. **Level 2**: Engineering Lead (30 min response)
3. **Level 3**: CTO (1 hour response)

### Key Contacts

**Engineering**:
- Engineering Lead: [Name] - [Email] - [Phone]
- DevOps Lead: [Name] - [Email] - [Phone]

**Product**:
- Product Manager: [Name] - [Email] - [Phone]

**Executive**:
- CTO: [Name] - [Email] - [Phone] (emergencies only)

### External Support

**Cloudflare**:
- Dashboard: https://dash.cloudflare.com
- Support: https://dash.cloudflare.com/support
- Status: https://www.cloudflarestatus.com

**Sentry**:
- Dashboard: https://sentry.io/organizations/coreflow360/
- Support: support@sentry.io

**GitHub**:
- Support: https://support.github.com

---

## Useful Links

### Dashboards

- **Application**: https://coreflow360.com
- **API**: https://api.coreflow360.com
- **Staging**: https://staging.coreflow360.com
- **Cloudflare**: https://dash.cloudflare.com
- **Sentry**: https://sentry.io/organizations/coreflow360/
- **GitHub**: https://github.com/your-org/coreflow360-v4
- **Status Page**: https://status.coreflow360.com

### Documentation

- **Deployment Handbook**: `docs/deploy-handbook/README.md`
- **Audit Documentation**: `audit/README.md`
- **User Stories**: `audit/user-stories.md`
- **API Documentation**: `audit/backend-routes.md`

---

## Keyboard Shortcuts

### Wrangler CLI

```bash
# Tail logs with auto-refresh
wrangler tail --follow

# Cancel with Ctrl+C

# Search logs
wrangler tail | grep "error"
wrangler tail | grep "compliance"
```

### Git Shortcuts

```bash
# Quick status
git status -sb

# Quick log
git log --oneline -10

# Quick diff
git diff --stat
```

---

## Environment Variables

### Required for Local Development

```bash
# .env.local
VITE_API_URL=http://localhost:8787
VITE_ENVIRONMENT=development
VITE_SENTRY_DSN=your_sentry_dsn
```

### Required for Production

```bash
# Set via wrangler secret
wrangler secret put JWT_SECRET
wrangler secret put ANTHROPIC_API_KEY
wrangler secret put OPENAI_API_KEY
wrangler secret put STRIPE_SECRET_KEY
wrangler secret put SENDGRID_API_KEY
```

### List Current Secrets

```bash
wrangler secret list
```

---

## Quick Decision Matrix

| Situation | Action | Tool/Command |
|-----------|--------|--------------|
| Feature not working | Disable feature flag | `curl -X PATCH .../feature-flags/... -d '{"enabled":false}'` |
| High error rate (>1%) | Rollback deployment | `wrangler rollback <ID>` |
| Slow response (P95 >2s) | Check metrics, investigate | `curl .../metrics/response-times` |
| Database issue | Check health, review migrations | `curl .../api/db/health` |
| Authentication broken | Check JWT, review logs | `wrangler tail | grep "JWT"` |
| Complete outage | Page on-call, execute incident response | Check crisis-management-playbook.md |

---

## Common Error Messages

### "Failed to fetch"
- **Cause**: Network issue, CORS, API down
- **Solution**: Check API health, verify CORS config, check network

### "401 Unauthorized"
- **Cause**: Invalid/expired JWT token
- **Solution**: Re-authenticate, check JWT expiry

### "403 Forbidden"
- **Cause**: Insufficient permissions
- **Solution**: Check ABAC policies, verify user role

### "500 Internal Server Error"
- **Cause**: Backend error
- **Solution**: Check Sentry, review logs, rollback if needed

### "Database locked"
- **Cause**: Concurrent write operations
- **Solution**: Retry, check for long-running queries

---

## Best Practices

### Before Deployment

- [ ] All tests passing
- [ ] Code reviewed and approved
- [ ] Feature flag created (OFF by default)
- [ ] Rollback plan documented
- [ ] Team notified

### During Deployment

- [ ] Monitor error rates
- [ ] Monitor response times
- [ ] Watch Sentry for new errors
- [ ] Keep Slack open (#incidents)

### After Deployment

- [ ] Verify health checks pass
- [ ] Monitor for 30 minutes
- [ ] Update status page (if needed)
- [ ] Document any issues encountered

---

**Document Version**: 1.0
**Last Updated**: 2025-10-22
**Print this page**: Use browser print → Save as PDF for offline reference

**Pro tip**: Bookmark this page for quick access during incidents! 🔖
