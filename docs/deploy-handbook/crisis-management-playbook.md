# Crisis Management Playbook - Production Incidents

**Created**: 2025-10-22
**Purpose**: Detailed procedures for handling major production incidents
**Audience**: On-call engineers, engineering leads, incident commanders

---

## Table of Contents

1. [Incident Severity Classification](#incident-severity-classification)
2. [Incident Response Procedures](#incident-response-procedures)
3. [Communication Protocols](#communication-protocols)
4. [Common Crisis Scenarios](#common-crisis-scenarios)
5. [Recovery Procedures](#recovery-procedures)
6. [Post-Incident Review](#post-incident-review)

---

## Incident Severity Classification

### SEV1 - Critical (P0)

**Definition**: Complete service outage, data loss, or security breach

**Examples**:
- Entire application is down (500 errors)
- Database inaccessible
- Data breach or unauthorized access detected
- Payment processing completely broken
- Authentication system down (all users locked out)

**Response Time**: Immediate (< 5 minutes)

**Escalation**: Page on-call engineer immediately, notify CTO

**Business Impact**:
- All customers affected
- Revenue loss
- Potential legal/compliance issues
- Significant reputational damage

**Resolution Target**: 1-2 hours maximum

---

### SEV2 - High (P1)

**Definition**: Major feature broken, significant user impact

**Examples**:
- Critical feature completely broken (e.g., unable to create invoices)
- High error rate (5-10% of requests failing)
- Severe performance degradation (P95 > 5 seconds)
- Payment processing partially broken
- Major data inconsistency detected

**Response Time**: 15 minutes

**Escalation**: Notify on-call engineer, engineering lead on standby

**Business Impact**:
- Many customers affected (> 25%)
- Revenue impact
- Customer satisfaction impact
- Workaround may be available

**Resolution Target**: 4-6 hours

---

### SEV3 - Medium (P2)

**Definition**: Minor feature broken, some users affected

**Examples**:
- Non-critical feature broken
- Moderate error rate (1-5% of requests)
- Performance degradation (P95 > 2 seconds)
- UI rendering issues
- Email notifications delayed

**Response Time**: 30 minutes

**Escalation**: Notify on-call engineer

**Business Impact**:
- Some customers affected (5-25%)
- Minor revenue impact
- Workaround available
- Can wait for business hours if outside

**Resolution Target**: 1-2 business days

---

### SEV4 - Low (P3)

**Definition**: Small bug, minimal user impact

**Examples**:
- Cosmetic UI issues
- Low error rate (< 1% of requests)
- Minor performance degradation
- Non-urgent feature requests

**Response Time**: Best effort

**Escalation**: Create ticket, prioritize for next sprint

**Business Impact**:
- Few customers affected (< 5%)
- Negligible revenue impact
- Fix forward, no urgency

**Resolution Target**: Next sprint or backlog

---

## Incident Response Procedures

### Phase 1: Detection (0-5 minutes)

#### Automated Detection

**Monitoring Alerts**:
- Sentry error rate spike (> 10 errors/minute)
- Cloudflare response time degradation (P95 > 2s)
- Uptime monitor failure (service unreachable)
- Custom metric threshold breach

**Alert Channels**:
- PagerDuty (SEV1 only)
- Slack #incidents channel (all severities)
- Email (SEV2+)
- SMS (SEV1 only)

**Initial Automated Response**:
```bash
# Automated health check runs
curl -f https://api.coreflow360.com/health

# If failed, automated diagnostic script runs:
- Check recent deployments
- Check database connectivity
- Check error rates by endpoint
- Check CPU/memory usage
```

#### Manual Detection

**Sources**:
- Customer support ticket (high volume, similar issue)
- Customer email (enterprise customer reports issue)
- Internal user report (Slack, email)
- Monitoring dashboard observation

**Initial Manual Triage**:
```bash
# Quick health check
curl -f https://api.coreflow360.com/health
curl -f https://api.coreflow360.com/api/status

# Check error rates (last 15 minutes)
curl https://api.coreflow360.com/api/metrics/errors?last=15m

# Check recent deployments
wrangler deployments list --limit 5

# Check recent feature flag changes
curl https://api.coreflow360.com/api/feature-flags/recent-changes
```

---

### Phase 2: Assessment (5-10 minutes)

#### Incident Commander Designation

**For SEV1**:
- On-call engineer becomes Incident Commander
- Engineering Lead becomes Deputy Commander
- CTO notified immediately

**For SEV2**:
- On-call engineer becomes Incident Commander
- Engineering Lead notified

**For SEV3/SEV4**:
- On-call engineer handles independently
- Optional: notify Engineering Lead

#### Severity Classification

**SEV1 Classification Criteria** (any of):
- [ ] Error rate > 50%
- [ ] Complete service outage
- [ ] Database inaccessible
- [ ] Security breach detected
- [ ] Data loss detected

**SEV2 Classification Criteria** (any of):
- [ ] Error rate 5-50%
- [ ] Critical feature completely broken
- [ ] P95 response time > 5 seconds
- [ ] Payment processing affected

**Quick Assessment Script**:
```bash
#!/bin/bash
# incident-assessment.sh

echo "=== Incident Assessment ==="
echo ""

# 1. Error rate
echo "Error rate (last 15 min):"
curl -s https://api.coreflow360.com/api/metrics/errors?last=15m | jq '.error_rate'

# 2. Response time
echo ""
echo "P95 response time (last 15 min):"
curl -s https://api.coreflow360.com/api/metrics/response-times?last=15m | jq '.p95_ms'

# 3. Recent deployments
echo ""
echo "Recent deployments:"
wrangler deployments list --limit 3

# 4. Database health
echo ""
echo "Database health:"
curl -f https://api.coreflow360.com/api/db/health

# 5. Recent feature flags
echo ""
echo "Recent feature flag changes:"
curl -s https://api.coreflow360.com/api/feature-flags/recent-changes | jq '.'
```

#### Impact Assessment

**Questions to Answer**:
1. How many users are affected? (0%, 1-5%, 5-25%, 25-50%, 50%+, 100%)
2. What functionality is broken? (specific features)
3. Is there a workaround available? (Yes/No)
4. What is the business impact? (Revenue, compliance, reputation)
5. What is the root cause hypothesis? (Deployment, infrastructure, external dependency)

**Impact Assessment Template**:
```markdown
## Incident Impact Assessment

**Incident ID**: INC-2025-11-20-001
**Severity**: SEV1
**Detected**: 2025-11-20 14:30 UTC
**Incident Commander**: [Name]

### Impact
- **Users Affected**: 100% of all users
- **Functionality Broken**: Cannot login (authentication completely down)
- **Workaround Available**: No
- **Business Impact**: All users locked out, revenue loss $X/hour
- **Root Cause Hypothesis**: Recent deployment broke JWT validation

### Immediate Actions Taken
- [ ] Incident channel created (#incident-2025-11-20-001)
- [ ] Status page updated (https://status.coreflow360.com)
- [ ] CTO notified
- [ ] Rollback initiated

### Next Steps
- Rollback deployment (ETA: 5 minutes)
- Verify authentication restored
- Investigate root cause in staging
```

---

### Phase 3: Containment (10-20 minutes)

**Goal**: Stop the bleeding, prevent further damage

#### Immediate Containment Actions

**For SEV1 Incidents**:

**1. Update Status Page** (< 2 minutes):
```bash
# Post to status page
curl -X POST https://api.coreflow360.com/api/status-page/incidents \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Service Disruption - Authentication",
    "status": "investigating",
    "severity": "critical",
    "message": "We are currently experiencing issues with user authentication. Our team is investigating.",
    "affected_components": ["authentication", "api"],
    "updates": []
  }'
```

**2. Create Incident Channel** (< 1 minute):
```bash
# Create Slack channel
# Naming: #incident-YYYY-MM-DD-brief-description
# Example: #incident-2025-11-20-auth-down

# Add key people:
- Incident Commander (on-call engineer)
- Engineering Lead
- Product Manager
- CTO (SEV1 only)
```

**3. Immediate Mitigation** (< 5 minutes):

Choose fastest mitigation option:

**Option A: Feature Flag Disable** (Fastest - < 2 min):
```bash
# If related to a specific feature, disable immediately
curl -X PATCH https://api.coreflow360.com/api/feature-flags/enableProblematicFeature \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"enabled": false, "rolloutPercentage": 0}'
```

**Option B: Rollback Deployment** (Fast - < 10 min):
```bash
# Get previous deployment ID
wrangler deployments list

# Rollback
wrangler rollback <PREVIOUS_DEPLOYMENT_ID>

# Verify
curl -f https://api.coreflow360.com/health
```

**Option C: Circuit Breaker** (Fast - < 5 min):
```bash
# Enable maintenance mode (if complete outage unavoidable)
curl -X POST https://api.coreflow360.com/api/admin/maintenance-mode \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{"enabled": true, "message": "Emergency maintenance, back online shortly"}'
```

**Option D: Infrastructure Scaling** (Medium - < 15 min):
```bash
# If issue is capacity-related, scale up
# Cloudflare Workers auto-scale, but check:
- Database connections
- External API rate limits
- Memory limits
```

**4. Verify Containment** (< 5 minutes):
```bash
# Health check
curl -f https://api.coreflow360.com/health

# Error rate check
curl https://api.coreflow360.com/api/metrics/errors?last=5m

# User impact check
# Check if users can access the application
# Check if critical flows work
```

---

### Phase 4: Investigation (20-60 minutes)

**Goal**: Identify root cause for permanent fix

#### Root Cause Analysis

**Common Root Causes**:

**1. Code Deployment Issues**:
- New bug introduced in recent deployment
- Configuration error
- Dependency version conflict
- Database migration issue

**Investigation**:
```bash
# Check recent deployments
wrangler deployments list --limit 10

# Review recent commits
git log --oneline -20

# Check deployment diff
git diff <PREVIOUS_DEPLOYMENT> <CURRENT_DEPLOYMENT>

# Review CI/CD logs
# Check GitHub Actions, Cloudflare deployment logs
```

**2. Infrastructure Issues**:
- Cloudflare Workers outage
- Database connectivity issues
- Network issues
- Disk space exhausted

**Investigation**:
```bash
# Check Cloudflare status
curl https://www.cloudflarestatus.com/api/v2/status.json

# Check database health
wrangler d1 execute coreflow360-production --command "SELECT 1"

# Check resource usage
# Cloudflare dashboard → Analytics → Resource usage
```

**3. External Dependency Failures**:
- Third-party API down (Stripe, SendGrid, etc.)
- DNS issues
- CDN issues

**Investigation**:
```bash
# Check external service status pages
# Stripe: https://status.stripe.com
# SendGrid: https://status.sendgrid.com
# etc.

# Test external API connectivity
curl -f https://api.stripe.com/v1/health
```

**4. Database Issues**:
- Query performance degradation
- Index missing
- Table lock
- Data corruption

**Investigation**:
```bash
# Check slow queries
wrangler d1 execute coreflow360-production \
  --command "SELECT * FROM slow_query_log ORDER BY timestamp DESC LIMIT 10"

# Check table locks
# Check database size
# Review recent database migrations
```

**5. Feature Flag Issues**:
- Flag configuration error
- Rollout percentage too aggressive
- Feature incompatibility

**Investigation**:
```bash
# Check recent flag changes
curl https://api.coreflow360.com/api/feature-flags/recent-changes

# Check flag status
curl https://api.coreflow360.com/api/feature-flags
```

#### Collecting Evidence

**Logs to Collect**:
```bash
# 1. Application logs (last 1 hour)
wrangler tail --since 1h > logs-$(date +%Y%m%d-%H%M).txt

# 2. Error logs from Sentry
# Export from Sentry UI: https://sentry.io/...

# 3. Database query logs
wrangler d1 execute coreflow360-production \
  --command "SELECT * FROM query_log WHERE timestamp > NOW() - INTERVAL 1 HOUR"

# 4. Network traffic logs (Cloudflare Analytics)
# Export from Cloudflare dashboard

# 5. User session data (if relevant)
# Gather anonymized user session data related to errors
```

**Metrics to Record**:
- Error rate timeline (before, during, after)
- Response time timeline
- Affected endpoint distribution
- Geographic distribution of errors
- User agent distribution (if UI issue)

---

### Phase 5: Resolution (Varies)

**Goal**: Permanently fix the issue

#### Resolution Strategies

**For SEV1 Incidents** (Fastest path to resolution):

**1. Hotfix Deployment** (If rollback not sufficient):

```bash
# 1. Create hotfix branch
git checkout -b hotfix/authentication-fix

# 2. Make minimal fix
# Edit code to fix critical issue

# 3. Test locally
npm run test
npm run test:e2e

# 4. Deploy to staging
npm run deploy:staging

# 5. Verify fix on staging
curl -f https://staging.coreflow360.com/health

# 6. Deploy to production
npm run deploy:prod

# 7. Monitor closely (30 minutes)
# Watch error rates, response times, user reports
```

**2. Database Hotfix** (If data issue):

```bash
# 1. Create backup (if not already done)
wrangler d1 backup create coreflow360-production

# 2. Test fix on staging database
wrangler d1 execute coreflow360-staging --command "UPDATE ..."

# 3. Verify staging fix
# Test application functionality

# 4. Apply fix to production
wrangler d1 execute coreflow360-production --command "UPDATE ..."

# 5. Verify production fix
# Test application functionality
```

**3. Configuration Hotfix** (If configuration issue):

```bash
# 1. Update configuration
# Edit wrangler.toml or environment variables

# 2. Redeploy with updated config
wrangler deploy --env production

# 3. Verify fix
curl -f https://api.coreflow360.com/health
```

#### Verification

**Post-Fix Verification Checklist**:
- [ ] Health endpoint returns 200 OK
- [ ] Error rate < 0.1%
- [ ] Response times normal (P95 < 500ms)
- [ ] Critical user flows work (smoke test)
- [ ] No new errors in Sentry (last 15 minutes)
- [ ] Customer reports no longer coming in
- [ ] Monitoring dashboards show green

**Smoke Test Script**:
```bash
#!/bin/bash
# smoke-test.sh

echo "=== Smoke Test ==="

# 1. Health check
echo "1. Health check..."
curl -f https://api.coreflow360.com/health || echo "FAILED"

# 2. Authentication
echo "2. Authentication..."
TOKEN=$(curl -s -X POST https://api.coreflow360.com/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","password":"test123"}' | jq -r '.token')
[[ -n "$TOKEN" ]] && echo "OK" || echo "FAILED"

# 3. List resources (example: guidelines)
echo "3. List guidelines..."
curl -f -H "Authorization: Bearer $TOKEN" \
  https://api.coreflow360.com/api/compliance/guidelines || echo "FAILED"

# 4. Create resource
echo "4. Create guideline..."
curl -f -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  https://api.coreflow360.com/api/compliance/guidelines \
  -d '{"title":"Smoke Test","description":"Test","category":"data_privacy","severity":"low"}' \
  || echo "FAILED"

echo "=== Smoke Test Complete ==="
```

---

### Phase 6: Recovery (Post-Resolution)

**Goal**: Return to normal operations, monitor stability

#### Gradual Recovery

**For SEV1 Incidents** (After hotfix deployed):

**1. Monitor Intensively** (First 30 minutes):
```bash
# Every 5 minutes, check:
# - Error rates
# - Response times
# - User activity
# - Sentry errors

# Automated monitoring script
while true; do
  echo "=== $(date) ==="
  curl -s https://api.coreflow360.com/api/metrics/errors?last=5m | jq '.error_rate'
  curl -s https://api.coreflow360.com/api/metrics/response-times?last=5m | jq '.p95_ms'
  sleep 300  # 5 minutes
done
```

**2. Update Status Page** (After 30 min stability):
```bash
curl -X PATCH https://api.coreflow360.com/api/status-page/incidents/{INCIDENT_ID} \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "status": "monitoring",
    "message": "The issue has been resolved. We are monitoring the system for stability.",
    "updates": [
      {
        "timestamp": "2025-11-20T15:45:00Z",
        "message": "Issue resolved. Monitoring for stability."
      }
    ]
  }'
```

**3. Customer Communication**:

**Proactive Email** (Send to affected customers):
```
Subject: [Resolved] Service Disruption - Authentication

Hi [Customer Name],

We're writing to let you know that the authentication issue affecting
CoreFlow360 has been resolved.

Incident Summary:
- Start: 2:30 PM UTC
- End: 3:45 PM UTC
- Duration: 1 hour 15 minutes
- Impact: Users were unable to log in
- Root Cause: Recent deployment introduced a bug in JWT validation
- Resolution: Deployment rolled back, hotfix applied

We apologize for the inconvenience. All systems are now operational.

If you continue to experience issues, please contact support.

Best regards,
CoreFlow360 Team
```

**4. Declare All-Clear** (After 2 hours stability):
```bash
# Close incident on status page
curl -X PATCH https://api.coreflow360.com/api/status-page/incidents/{INCIDENT_ID} \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "status": "resolved",
    "message": "The issue has been fully resolved. All systems are operational.",
    "resolved_at": "2025-11-20T16:00:00Z"
  }'

# Close incident channel on Slack
# Post final update to #incident-2025-11-20-auth-down
```

---

## Communication Protocols

### Internal Communication

#### Incident Channel Template (Slack)

**Channel Name**: `#incident-YYYY-MM-DD-brief-description`

**Pin This Message**:
```
🚨 INCIDENT: Authentication System Down
Severity: SEV1
Start Time: 2025-11-20 14:30 UTC
Incident Commander: @john-doe
Status: Investigating → Mitigated → Monitoring → Resolved

Updates:
[14:35] Incident detected via Sentry alert
[14:40] Severity classified as SEV1, CTO notified
[14:45] Rollback initiated
[14:50] Rollback complete, testing in progress
[15:00] Authentication restored, monitoring for stability
[15:45] 45 minutes stable, updating status page
[16:00] All-clear declared, incident resolved

Root Cause: [TBD - will be documented in post-mortem]
Customers Affected: 100% (all users)
Duration: 1h 30m
```

**Update Frequency**:
- SEV1: Every 15 minutes minimum
- SEV2: Every 30 minutes minimum
- SEV3: Every 1 hour minimum

#### Stakeholder Notification

**Who to Notify**:

| Severity | Notify Immediately | Notify Within 1 Hour | Notify Next Business Day |
|----------|-------------------|---------------------|-------------------------|
| SEV1 | CTO, Engineering Lead, Product Manager, Customer Success Lead | CEO, Sales Lead | Legal (if data breach) |
| SEV2 | Engineering Lead, Product Manager | CTO, Customer Success Lead | CEO |
| SEV3 | Engineering Lead | Product Manager | - |
| SEV4 | - | - | Engineering Lead |

**Notification Template** (Email):
```
Subject: [SEV1] Production Incident - Authentication Down

Team,

We are currently experiencing a SEV1 production incident.

Summary:
- Issue: Authentication system completely down
- Impact: All users unable to log in
- Start Time: 2:30 PM UTC
- Estimated Resolution: 1-2 hours
- Incident Commander: John Doe

Current Status:
- Rollback in progress (ETA: 5 minutes)
- Status page updated: https://status.coreflow360.com
- Customer communication prepared

Next Update: 3:00 PM UTC (30 minutes)

Incident Channel: #incident-2025-11-20-auth-down

John Doe
Incident Commander
```

### External Communication

#### Status Page Updates

**Investigating**:
```
Title: Service Disruption - Authentication
Status: Investigating
Message: We are currently experiencing issues with user authentication.
Our engineering team is investigating the issue. We will provide updates
every 15 minutes.

Posted: 2:35 PM UTC
```

**Identified**:
```
Title: Service Disruption - Authentication
Status: Identified
Message: We have identified the issue as a recent deployment that affected
JWT validation. Our team is rolling back the deployment.

Updated: 2:45 PM UTC
```

**Monitoring**:
```
Title: Service Disruption - Authentication
Status: Monitoring
Message: The deployment has been rolled back and authentication is restored.
We are monitoring the system for stability.

Updated: 3:00 PM UTC
```

**Resolved**:
```
Title: Service Disruption - Authentication
Status: Resolved
Message: The authentication issue has been fully resolved. All systems are
now operational. We apologize for the inconvenience.

Resolved: 4:00 PM UTC
Duration: 1h 25m
```

#### Customer Email Communication

**When to Send**:
- SEV1: Always, to all affected customers
- SEV2: If > 25% of customers affected OR enterprise customers affected
- SEV3: Only if enterprise customers directly impacted
- SEV4: No proactive communication

**Email Template** (SEV1):
```
Subject: [Action Required] Service Disruption Resolved

Hi [Customer Name],

We experienced a service disruption today affecting user authentication.

What Happened:
At 2:30 PM UTC, a deployment introduced a bug that prevented users from
logging in. All users were affected for approximately 1 hour and 25 minutes.

What We Did:
- Immediately rolled back the deployment
- Applied a hotfix
- Restored full service by 4:00 PM UTC

What You Need to Do:
- No action required from your end
- All functionality has been restored
- If you experience any issues, please contact support

We sincerely apologize for the disruption and are committed to preventing
similar issues in the future.

For more details, please see our incident report: [link]

Best regards,
[Your Name]
CoreFlow360 Team
```

---

## Common Crisis Scenarios

### Scenario 1: Complete Application Outage

**Symptoms**:
- All users see 500 errors or blank pages
- Health endpoint fails
- 100% error rate

**Likely Causes**:
- Recent deployment broke critical code path
- Database completely inaccessible
- Cloudflare Workers outage
- Critical environment variable missing

**Immediate Response**:
```bash
# 1. Classify as SEV1
# 2. Create incident channel
# 3. Update status page
# 4. Check recent deployments
wrangler deployments list

# 5. Rollback immediately (don't investigate yet)
wrangler rollback <PREVIOUS_DEPLOYMENT_ID>

# 6. Verify restoration
curl -f https://api.coreflow360.com/health

# 7. If rollback doesn't help, check infrastructure
# - Cloudflare status: https://www.cloudflarestatus.com
# - Database health: wrangler d1 execute ... --command "SELECT 1"
```

**Recovery Timeline**: 5-15 minutes

---

### Scenario 2: Database Corruption

**Symptoms**:
- Data inconsistencies reported by users
- Foreign key violations
- Unexpected null values
- Transactions failing

**Likely Causes**:
- Bad database migration
- Race condition in code
- Direct database manipulation gone wrong

**Immediate Response**:
```bash
# 1. Classify as SEV1 (data integrity issue)
# 2. Enable maintenance mode (prevent further writes)
curl -X POST https://api.coreflow360.com/api/admin/maintenance-mode \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{"enabled": true}'

# 3. Create database backup immediately
wrangler d1 backup create coreflow360-production

# 4. Assess damage
wrangler d1 execute coreflow360-production \
  --command "SELECT COUNT(*) FROM affected_table WHERE column IS NULL"

# 5. Develop fix script (TEST ON STAGING FIRST)
# 6. Apply fix to production
# 7. Verify data integrity
# 8. Disable maintenance mode
```

**Recovery Timeline**: 1-4 hours

---

### Scenario 3: Payment Processing Failure

**Symptoms**:
- Stripe API calls failing
- Payment webhooks not processing
- Users cannot complete purchases

**Likely Causes**:
- Stripe API key expired or revoked
- Stripe webhook secret incorrect
- Network connectivity to Stripe
- Stripe service outage

**Immediate Response**:
```bash
# 1. Classify as SEV1 (revenue impact)
# 2. Check Stripe status
curl https://status.stripe.com/api/v2/status.json

# 3. Verify Stripe API credentials
curl https://api.stripe.com/v1/balance \
  -u $STRIPE_SECRET_KEY:

# 4. Check webhook endpoint
curl https://api.coreflow360.com/api/webhooks/stripe

# 5. If Stripe issue, communicate to users and wait
# 6. If our issue, fix immediately (likely config or code bug)
```

**Recovery Timeline**: 15 minutes - 2 hours (depending on cause)

---

### Scenario 4: Security Breach Detected

**Symptoms**:
- Unusual API access patterns
- Unauthorized data access detected
- Security monitoring alert
- Customer reports unauthorized access

**Immediate Response**:
```bash
# 1. Classify as SEV1
# 2. DO NOT post publicly yet (legal/PR considerations)
# 3. Notify CTO, CEO, Legal immediately

# 4. Contain the breach
# - Revoke compromised API keys
# - Force password resets for affected users
# - Enable stricter rate limiting
# - Block suspicious IP addresses

# 5. Preserve evidence
# - Export logs (DO NOT delete anything)
# - Screenshot monitoring dashboards
# - Export database access logs

# 6. Assess damage
# - What data was accessed?
# - How many users affected?
# - What systems compromised?

# 7. Legal obligations
# - GDPR breach notification (72 hours)
# - Customer notification
# - Regulatory notification (if applicable)
```

**Recovery Timeline**: Immediate containment (< 30 min), full investigation (days/weeks)

---

### Scenario 5: High Error Rate After Feature Rollout

**Symptoms**:
- Error rate 5-15% (not complete outage)
- Errors isolated to specific feature
- Started after feature flag enabled

**Likely Causes**:
- Bug in new feature code
- Unexpected edge case
- Performance issue under load
- Integration issue with backend

**Immediate Response**:
```bash
# 1. Classify as SEV2
# 2. Disable feature flag immediately
curl -X PATCH https://api.coreflow360.com/api/feature-flags/enableNewFeature \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{"enabled": false, "rolloutPercentage": 0}'

# 3. Verify error rate returns to normal
curl https://api.coreflow360.com/api/metrics/errors?last=5m

# 4. Investigate root cause in staging
# 5. Fix issue
# 6. Re-enable feature flag at lower percentage (1-5%)
# 7. Monitor closely
```

**Recovery Timeline**: 15-30 minutes (containment), hours/days (fix and re-rollout)

---

## Recovery Procedures

### Post-Incident Checklist

**Immediate Post-Resolution** (< 1 hour):
- [ ] Verify metrics normal (error rate, response times)
- [ ] Update status page (resolved)
- [ ] Send customer communication (if applicable)
- [ ] Close incident channel (Slack)
- [ ] Document timeline in incident tracker

**Within 24 Hours**:
- [ ] Schedule post-mortem meeting (within 48 hours)
- [ ] Gather all evidence (logs, metrics, screenshots)
- [ ] Identify root cause
- [ ] Create action items to prevent recurrence

**Within 48 Hours**:
- [ ] Conduct post-mortem meeting
- [ ] Document post-mortem (see template below)
- [ ] Assign action items with owners and due dates
- [ ] Share post-mortem with stakeholders

**Within 1 Week**:
- [ ] Complete high-priority action items
- [ ] Update runbooks with lessons learned
- [ ] Improve monitoring/alerting (if gaps identified)
- [ ] Conduct team retro (optional, for large incidents)

---

## Post-Incident Review

### Post-Mortem Template

**File**: `docs/post-mortems/YYYY-MM-DD-incident-brief-description.md`

```markdown
# Post-Mortem: [Date] - [Brief Description]

**Date**: 2025-11-20
**Authors**: John Doe (Incident Commander), Jane Smith (Engineering Lead)
**Status**: Draft / Final
**Severity**: SEV1

---

## Executive Summary

On November 20, 2025, CoreFlow360 experienced a complete authentication
outage lasting 1 hour and 25 minutes. All users were unable to log in,
resulting in 100% service disruption. The root cause was a bug in JWT
validation logic introduced in a recent deployment. The issue was resolved
by rolling back the deployment and applying a hotfix.

**Impact**:
- Duration: 1h 25m
- Users Affected: 100% (all users)
- Estimated Revenue Loss: $X
- Support Tickets Created: 47

---

## Timeline (UTC)

| Time | Event |
|------|-------|
| 14:25 | Deployment v1.2.3 completed |
| 14:30 | Sentry alert: Error rate spike detected |
| 14:32 | On-call engineer paged |
| 14:35 | Incident severity classified as SEV1 |
| 14:36 | Incident channel created, CTO notified |
| 14:38 | Status page updated |
| 14:40 | Root cause hypothesis: Recent deployment |
| 14:45 | Rollback initiated |
| 14:50 | Rollback complete, testing in progress |
| 14:55 | Authentication confirmed working |
| 15:00 | Monitoring for stability |
| 15:45 | 45 minutes stable, status page updated to "monitoring" |
| 16:00 | All-clear declared, incident resolved |

---

## Root Cause

The deployment v1.2.3 introduced a bug in the JWT validation middleware.
Specifically, the code attempted to access a property that was undefined
in production (but defined in staging due to different environment config).

**Code Change**:
```diff
# File: src/middleware/auth.ts
- const userId = decoded.user.id
+ const userId = decoded.userId  // Production JWT structure different
```

**Why It Wasn't Caught**:
- E2E tests passed on staging (different JWT structure)
- Unit tests mocked the JWT, so didn't catch the structure issue
- No production-like integration test environment

---

## Contributing Factors

1. **Insufficient Testing**: E2E tests did not use production-like JWT tokens
2. **Environment Drift**: Staging and production JWT structures differed
3. **Lack of Gradual Rollout**: Deployment was 100% immediately (no canary)
4. **Monitoring Gap**: No alert for "successful authentication rate"

---

## Impact Analysis

**User Impact**:
- 100% of users unable to log in for 1h 25m
- Support overwhelmed with 47 tickets in 1 hour
- Customer trust impacted

**Business Impact**:
- Estimated revenue loss: $X (based on hourly transaction volume)
- Brand reputation impact
- Engineering productivity lost (3 engineers focused on incident)

**Technical Impact**:
- No data loss
- No security breach
- No long-term system damage

---

## What Went Well

1. **Fast Detection**: Sentry alert triggered within 5 minutes
2. **Fast Response**: On-call engineer responded immediately
3. **Clear Communication**: Status page updated quickly, stakeholders notified
4. **Quick Mitigation**: Rollback completed in 20 minutes
5. **Good Coordination**: Team worked well together in incident channel

---

## What Didn't Go Well

1. **No Gradual Rollout**: Deployment hit 100% of users immediately
2. **Testing Gap**: E2E tests didn't catch the issue
3. **Environment Drift**: Staging and production configs differed
4. **No Monitoring**: No proactive alert for authentication failures

---

## Action Items

| ID | Action | Owner | Due Date | Priority | Status |
|----|--------|-------|----------|----------|--------|
| 1 | Implement canary deployments (5% → 25% → 50% → 100%) | John | 2025-11-27 | P0 | ✅ Done |
| 2 | Add "authentication success rate" monitoring | Jane | 2025-11-25 | P0 | 🏗️ In Progress |
| 3 | Align staging and production JWT structures | Mike | 2025-11-22 | P0 | ✅ Done |
| 4 | Add integration tests with production-like data | Sarah | 2025-11-30 | P1 | ⏳ Planned |
| 5 | Update deployment runbook with gradual rollout procedure | Alex | 2025-11-23 | P1 | ✅ Done |
| 6 | Conduct team training on incident response | Lisa | 2025-12-05 | P2 | ⏳ Planned |

---

## Lessons Learned

1. **Always Use Gradual Rollouts**: Even for "small" changes, use canary deployments
2. **Test with Production-Like Data**: Staging should mirror production as closely as possible
3. **Monitor Business Metrics**: Not just error rates, but success rates too
4. **Communication is Key**: Transparent, frequent updates reduce customer anxiety
5. **Fast Rollback > Perfect Fix**: In SEV1, rollback first, investigate later

---

## Questions

1. Why did staging tests pass but production failed?
   - **Answer**: Staging used different JWT structure due to environment config drift

2. Could this have been prevented?
   - **Answer**: Yes, with better integration tests and gradual rollout

3. Why wasn't there an alert for authentication failures?
   - **Answer**: Monitoring gap - only had error rate alerts, not success rate

---

## Appendix

### Metrics

- **MTTR** (Mean Time To Recovery): 1h 25m
- **MTTD** (Mean Time To Detect): 5 minutes
- **MTTA** (Mean Time To Acknowledge): 2 minutes
- **MTTI** (Mean Time To Investigate): 10 minutes
- **MTTM** (Mean Time To Mitigate): 20 minutes

### Supporting Documents

- Incident channel logs: [link to Slack export]
- Sentry errors: [link to Sentry]
- Deployment logs: [link to CI/CD]
- Customer communications: [link to folder]

---

**Review Status**: Reviewed by Engineering Lead, Product Manager, CTO
**Published**: 2025-11-22
**Next Review**: 2025-12-22 (1 month follow-up on action items)
```

---

## Crisis Management Best Practices

### 1. Stay Calm

- Panic leads to mistakes
- Take a deep breath before taking action
- Remember: Most incidents are recoverable

### 2. Communicate Frequently

- Over-communicate rather than under-communicate
- Set expectations on update frequency and stick to it
- Use clear, non-technical language for external communication

### 3. Document Everything

- Log all actions taken in the incident channel
- Record exact timestamps
- Capture screenshots of monitoring dashboards

### 4. Rollback First, Investigate Later

- For SEV1, fastest path to recovery is rollback
- Investigate root cause after service is restored
- Don't try to fix forward during active incident

### 5. Learn from Every Incident

- Conduct post-mortem for all SEV1 and SEV2 incidents
- Turn learnings into action items
- Update runbooks and monitoring based on gaps found

---

**Document Version**: 1.0
**Last Updated**: 2025-10-22
**Maintained By**: Engineering Team
**Review Cycle**: Quarterly

**For emergency assistance**: Page on-call engineer via PagerDuty or call [Emergency Phone]
