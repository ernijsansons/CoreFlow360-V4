# Incident Response Playbook

## Overview

This playbook provides step-by-step procedures for responding to production incidents in CoreFlow360 V4. Follow these procedures to minimize downtime, protect data, and restore service quickly.

## Incident Severity Levels

| Level | Description | Response Time | Examples |
|-------|-------------|---------------|----------|
| **P0 Critical** | Complete service outage, data loss, security breach | Immediate (< 5 min) | Total site down, data breach, authentication bypass |
| **P1 High** | Major functionality impaired | < 15 minutes | API errors affecting >50% users, payment processing down |
| **P2 Medium** | Partial functionality degraded | < 1 hour | Slow response times, non-critical feature broken |
| **P3 Low** | Minor issues, cosmetic bugs | < 1 business day | UI glitches, logging issues |

---

## General Incident Response Process

### 1. Detection and Alert

**Monitoring Channels**:
- Cloudflare Analytics alerts
- Sentry error notifications
- Health check failures
- User reports
- Slack #incidents channel

**Immediate Actions**:
1. Acknowledge the incident in Slack #incidents
2. Assess severity level (P0-P3)
3. Page on-call engineer if P0/P1
4. Start incident timeline documentation

### 2. Initial Assessment (5 minutes)

```bash
# Quick health check
./scripts/health-check.sh production

# Check recent deployments
wrangler deployments list --env production

# Check error rates
curl -s https://api.coreflow360.com/api/health | jq .

# Monitor real-time logs
wrangler tail coreflow360-v4-prod --env production --format pretty
```

**Key Questions**:
- What is broken? (specific feature, entire site, API only)
- When did it start? (correlate with deployments)
- How many users are affected? (check analytics)
- Is data at risk? (check database integrity)

### 3. Communication

**Internal Communication**:
```markdown
🚨 INCIDENT ALERT - P[0-3]

**Status**: Investigating
**Started**: [timestamp]
**Impact**: [description]
**Affected Users**: [percentage or count]

**Initial Assessment**:
- [Finding 1]
- [Finding 2]

**Actions Taken**:
1. [Action 1]
2. [Action 2]

**Next Steps**:
- [Step 1]
- [Step 2]

**Incident Commander**: [@engineer]
```

**External Communication** (P0/P1 only):
```markdown
We are currently experiencing [issue description].
Our team is actively working on a resolution.

Affected: [services]
Started: [time]
ETA: [estimate]

Updates: https://status.coreflow360.com
```

### 4. Mitigation

Follow incident-specific playbooks below based on the issue type.

### 5. Resolution

1. Implement fix (code change, config update, or rollback)
2. Deploy fix to staging first
3. Run smoke tests
4. Deploy to production
5. Monitor for 15 minutes
6. Verify resolution with health checks

### 6. Post-Incident

1. Mark incident as resolved
2. Schedule post-mortem meeting (within 48 hours)
3. Document timeline and root cause
4. Create action items to prevent recurrence
5. Update runbooks and monitoring

---

## Incident-Specific Playbooks

### P0-1: Complete Service Outage

**Symptoms**: Site unreachable, 502/503 errors, workers not responding

**Immediate Actions**:
```bash
# 1. Check worker status
wrangler tail coreflow360-v4-prod --env production

# 2. Check recent deployments
wrangler deployments list --env production | head -5

# 3. Check Cloudflare dashboard
# Visit: https://dash.cloudflare.com/

# 4. Test API directly
curl -v https://api.coreflow360.com/health
```

**Resolution Steps**:

#### If caused by recent deployment:
```bash
# Immediate rollback
cd ~/CoreFlow360-V4
git checkout pre-deploy-[DEPLOYMENT_ID]  # Use rollback tag
./scripts/rollback-production.sh
```

#### If caused by Cloudflare issue:
1. Check Cloudflare status page: https://www.cloudflarestatus.com/
2. Check Workers dashboard for rate limiting or quota issues
3. Verify DNS configuration
4. Check domain routing rules

#### If caused by code error:
```bash
# Check error logs
wrangler tail coreflow360-v4-prod --env production | grep ERROR

# Identify error pattern
# Fix critical issue
# Deploy hotfix

npm run build
CLOUDFLARE_API_TOKEN="$CLOUDFLARE_API_TOKEN" wrangler deploy --env production

# Monitor deployment
wrangler tail coreflow360-v4-prod --env production --format pretty
```

---

### P0-1: Authentication System Down

**Symptoms**: Users cannot log in, 401 errors everywhere, JWT validation failures

**Immediate Actions**:
```bash
# 1. Test authentication
curl -X POST https://api.coreflow360.com/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"test"}'

# 2. Check JWT secret configuration
wrangler secret list --env production | grep JWT_SECRET

# 3. Check rate limiting
curl -I https://api.coreflow360.com/api/auth/login
```

**Resolution Steps**:

#### If JWT secret issue:
```bash
# CRITICAL: Never use fallback secrets
# Verify JWT_SECRET is properly set
wrangler secret put JWT_SECRET --env production
# Enter secure secret (64+ characters)

# Restart workers
wrangler deploy --env production
```

#### If rate limiting issue:
```bash
# Check rate limiter DO
wrangler tail coreflow360-v4-prod --env production | grep "rate limit"

# Temporarily increase limits if legitimate traffic spike
# Edit src/middleware/rate-limiting.ts
# Deploy update
```

#### If token blacklist issue:
```bash
# Check KV namespace
wrangler kv:list --namespace-id YOUR_KV_SESSION_ID --env production

# Clear expired tokens if KV is full
wrangler kv:key delete "blacklist:*" --namespace-id YOUR_KV_SESSION_ID --env production
```

---

### P0-1: Database Outage

**Symptoms**: Database errors, timeout errors, D1 connection failures

**Immediate Actions**:
```bash
# 1. Check D1 database status
wrangler d1 execute coreflow360-agents --command "SELECT 1" --env production

# 2. Check database size and limits
wrangler d1 info coreflow360-agents --env production

# 3. Check for long-running queries
# Via Cloudflare dashboard D1 section
```

**Resolution Steps**:

#### If database is down:
1. Check Cloudflare D1 status page
2. Verify database is not deleted
3. Contact Cloudflare support if infrastructure issue

#### If database is full:
```bash
# Check database size
wrangler d1 info coreflow360-agents --env production

# Archive old data
wrangler d1 execute coreflow360-agents --file ./scripts/archive-old-data.sql --env production

# Vacuum database
wrangler d1 execute coreflow360-agents --command "VACUUM" --env production
```

#### If migration failed:
```bash
# Check migration status
wrangler d1 migrations list coreflow360-agents --env production

# Rollback migration if needed
wrangler d1 migrations apply coreflow360-agents --env production --to [previous_version]

# Restore from backup if critical
./scripts/restore-database.sh [backup_date]
```

---

### P1: Payment Processing Failure

**Symptoms**: Stripe webhooks failing, payment errors, invoice creation failures

**Immediate Actions**:
```bash
# 1. Check Stripe dashboard
# Visit: https://dashboard.stripe.com/

# 2. Test payment endpoint
curl -X POST https://api.coreflow360.com/api/payments/test \
  -H "Authorization: Bearer $TEST_TOKEN" \
  -H "Content-Type: application/json"

# 3. Check webhook logs
wrangler tail coreflow360-v4-prod --env production | grep "stripe"
```

**Resolution Steps**:

#### If Stripe API key issue:
```bash
# Verify Stripe secret is correct
wrangler secret list --env production | grep STRIPE

# Update if needed
wrangler secret put STRIPE_SECRET_KEY --env production
```

#### If webhook signature verification failing:
```bash
# Update webhook secret
wrangler secret put STRIPE_WEBHOOK_SECRET --env production

# Verify webhook endpoint in Stripe dashboard
# Should be: https://api.coreflow360.com/api/webhooks/stripe
```

#### If rate limiting:
- Check Stripe API rate limits in dashboard
- Implement exponential backoff in webhook handler
- Use Stripe webhook retry mechanism

---

### P1: High Error Rate (>5%)

**Symptoms**: Error rate spike in monitoring, multiple users reporting issues

**Immediate Actions**:
```bash
# 1. Check error distribution
wrangler tail coreflow360-v4-prod --env production | grep ERROR | head -20

# 2. Check Sentry for error patterns
# Visit: https://sentry.io/organizations/coreflow360/issues/

# 3. Identify most common error
curl -s https://api.coreflow360.com/api/health | jq '.errors'
```

**Resolution Steps**:

#### If specific endpoint failing:
```bash
# Disable problematic endpoint temporarily
# Add feature flag to disable route

# Deploy hotfix
npm run build
wrangler deploy --env production

# Investigate root cause
# Fix issue
# Re-enable endpoint
```

#### If third-party API failure:
```bash
# Check AI API status (Anthropic, OpenAI)
curl -s https://status.anthropic.com/api/v2/status.json | jq .

# Implement fallback logic
# Cache responses temporarily
# Notify users of degraded AI features
```

---

### P1: Performance Degradation

**Symptoms**: Slow response times (>2s), timeouts, users reporting slowness

**Immediate Actions**:
```bash
# 1. Check response times
./scripts/health-check.sh production | grep "response time"

# 2. Check cache hit rate
curl -s https://api.coreflow360.com/api/health | jq '.cache'

# 3. Monitor database query times
wrangler tail coreflow360-v4-prod --env production | grep "query time"
```

**Resolution Steps**:

#### If cache is cold:
```bash
# Warm up cache with common queries
curl -s https://api.coreflow360.com/api/dashboard # Prime cache
curl -s https://api.coreflow360.com/api/users/me # Prime cache

# Increase cache TTL temporarily
# Edit src/middleware/caching.ts
# Increase default TTL from 300s to 600s
```

#### If database queries slow:
```bash
# Identify slow queries
wrangler tail coreflow360-v4-prod --env production | grep "slow query"

# Add missing indexes
wrangler d1 execute coreflow360-agents --command "
  CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
  CREATE INDEX IF NOT EXISTS idx_ledger_business_id ON ledger_entries(business_id);
" --env production

# Vacuum database
wrangler d1 execute coreflow360-agents --command "VACUUM" --env production
```

#### If traffic spike:
```bash
# Check traffic patterns
# Cloudflare Analytics Dashboard

# Enable aggressive caching
# Update cache headers to cache more aggressively

# Consider rate limiting if DDoS
# src/middleware/rate-limiting.ts - reduce limits temporarily
```

---

### P2: Frontend Assets Not Loading

**Symptoms**: Blank pages, 404 for JS/CSS, "Failed to load resource" errors

**Immediate Actions**:
```bash
# 1. Check Cloudflare Pages deployment status
# Visit: https://dash.cloudflare.com/pages

# 2. Test asset loading
curl -I https://coreflow360.com/assets/index.js

# 3. Check for CDN caching issues
curl -I https://coreflow360.com/ | grep "cf-cache-status"
```

**Resolution Steps**:

#### If Pages deployment failed:
```bash
# Redeploy frontend
cd frontend
npm run build
CLOUDFLARE_API_TOKEN="$CLOUDFLARE_API_TOKEN" npx wrangler pages deploy dist \
  --project-name=coreflow360-frontend \
  --branch=production
```

#### If cache serving old assets:
```bash
# Purge Cloudflare cache
curl -X POST "https://api.cloudflare.com/client/v4/zones/{zone_id}/purge_cache" \
  -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"purge_everything":true}'

# Or use dashboard: Caching > Configuration > Purge Everything
```

---

### P2: AI Agents Not Responding

**Symptoms**: Agent tasks timing out, no AI responses, agent status "degraded"

**Immediate Actions**:
```bash
# 1. Check agent status
curl -s https://api.coreflow360.com/api/agents/status | jq .

# 2. Check AI API keys
wrangler secret list --env production | grep API_KEY

# 3. Test AI APIs directly
curl -s https://api.anthropic.com/v1/messages \
  -H "x-api-key: $ANTHROPIC_API_KEY" \
  -H "anthropic-version: 2023-06-01" \
  -H "Content-Type: application/json" \
  -d '{"model":"claude-3-sonnet-20240229","max_tokens":10,"messages":[{"role":"user","content":"test"}]}'
```

**Resolution Steps**:

#### If API keys expired/invalid:
```bash
# Update API keys
wrangler secret put ANTHROPIC_API_KEY --env production
wrangler secret put OPENAI_API_KEY --env production

# Restart workers
wrangler deploy --env production
```

#### If rate limited by AI provider:
```bash
# Check rate limit headers in logs
wrangler tail coreflow360-v4-prod --env production | grep "rate limit"

# Implement exponential backoff
# Reduce concurrent AI requests
# Queue AI tasks instead of processing immediately
```

#### If agent orchestrator hung:
```bash
# Restart Durable Object
# Unfortunately, DO can't be manually restarted
# Deploy a small change to trigger restart

# Add comment to src/durable-objects/workflow-executor.ts
# Deploy
wrangler deploy --env production
```

---

## Emergency Contacts

| Role | Name | Contact | Responsibilities |
|------|------|---------|-----------------|
| **Primary On-Call** | [Name] | [Phone], [Slack] | First responder, incident commander |
| **Secondary On-Call** | [Name] | [Phone], [Slack] | Backup, database expertise |
| **Engineering Lead** | [Name] | [Phone], [Slack] | Escalation point, architecture decisions |
| **DevOps Lead** | [Name] | [Phone], [Slack] | Infrastructure, Cloudflare expertise |

## Escalation Path

1. **P0 Immediate**: Page primary on-call + engineering lead
2. **P1 <15 min**: Alert primary on-call
3. **P2 <1 hour**: Slack #incidents notification
4. **P3 <1 day**: Create ticket, notify in standup

## Tools and Access

### Required Access
- Cloudflare Dashboard (Workers, Pages, D1, KV, Analytics)
- Wrangler CLI with production credentials
- GitHub repository write access
- Sentry error tracking dashboard
- Slack #incidents channel

### Key Commands
```bash
# Health check
./scripts/health-check.sh production

# Smoke tests
./scripts/smoke-test.sh production

# Rollback
./scripts/rollback-production.sh

# Logs
wrangler tail coreflow360-v4-prod --env production --format pretty

# Deploy
wrangler deploy --env production
```

### Monitoring Dashboards
- **Cloudflare Analytics**: https://dash.cloudflare.com/
- **Sentry**: https://sentry.io/organizations/coreflow360/
- **Status Page**: https://status.coreflow360.com

---

## Post-Incident Review Template

```markdown
# Post-Incident Review: [Incident Title]

**Date**: [Date]
**Incident ID**: [ID]
**Severity**: P[0-3]
**Duration**: [Start] to [End] ([X] minutes)
**Incident Commander**: [Name]

## Impact

- **Users Affected**: [number or percentage]
- **Services Affected**: [list]
- **Revenue Impact**: [if applicable]
- **Data Loss**: [Yes/No, details]

## Timeline

- **[HH:MM]** - Incident detected via [alert/report]
- **[HH:MM]** - Investigation started
- **[HH:MM]** - Root cause identified
- **[HH:MM]** - Mitigation deployed
- **[HH:MM]** - Service restored
- **[HH:MM]** - Incident closed

## Root Cause

[Detailed description of what caused the incident]

## Resolution

[What was done to resolve the incident]

## What Went Well

- [Thing 1]
- [Thing 2]

## What Could Be Improved

- [Improvement 1]
- [Improvement 2]

## Action Items

| Action | Owner | Deadline | Priority |
|--------|-------|----------|----------|
| [Action 1] | [@person] | [date] | P[0-3] |
| [Action 2] | [@person] | [date] | P[0-3] |

## Prevention Measures

- [Measure 1]
- [Measure 2]

## Lessons Learned

[Key takeaways from this incident]
```

---

## Testing This Playbook

Schedule quarterly incident response drills:

```bash
# Simulate production outage
./scripts/simulate-outage.sh

# Practice rollback
./scripts/test-rollback.sh

# Test monitoring alerts
./scripts/test-alerts.sh
```

---

**Last Updated**: 2025-10-21
**Next Review**: 2026-01-21
**Owner**: Engineering Team
