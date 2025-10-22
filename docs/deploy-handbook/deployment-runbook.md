# Deployment Runbook - Backend-to-UI Features

**Created**: 2025-10-22
**Purpose**: Operational guide for deploying backend-to-UI integration features
**Audience**: Engineering leads, DevOps engineers, on-call engineers

---

## Table of Contents

1. [Pre-Deployment Preparation](#pre-deployment-preparation)
2. [Deployment Procedures by Phase](#deployment-procedures-by-phase)
3. [Feature Flag Management](#feature-flag-management)
4. [Monitoring & Health Checks](#monitoring--health-checks)
5. [Rollback Procedures](#rollback-procedures)
6. [Incident Response](#incident-response)
7. [Post-Deployment Verification](#post-deployment-verification)

---

## Pre-Deployment Preparation

### 1. Pre-Flight Checklist (30 minutes before deployment)

**Environment Verification**:
```bash
# Verify staging environment health
curl -f https://staging.coreflow360.com/health
curl -f https://staging.coreflow360.com/api/status

# Verify production environment health
curl -f https://api.coreflow360.com/health
curl -f https://api.coreflow360.com/api/status

# Check database connection
wrangler d1 execute coreflow360-production --command "SELECT 1"

# Verify KV namespaces accessible
wrangler kv:namespace list
```

**Team Readiness**:
- [ ] Engineering lead available for next 2 hours
- [ ] On-call engineer identified and notified
- [ ] Product manager notified of deployment window
- [ ] Support team briefed on new feature (FAQ ready)
- [ ] Rollback plan reviewed and understood
- [ ] Monitoring dashboards open and ready

**Code Verification**:
```bash
# Ensure all tests pass
npm run test
npm run test:e2e

# Ensure linting clean
npm run lint

# Ensure TypeScript compiles
npm run type-check

# Ensure production build succeeds
npm run build
```

**Database Migration Verification** (if applicable):
```bash
# Test migration on staging (already done, verify)
wrangler d1 migrations list coreflow360-staging

# Create production database backup
wrangler d1 backup create coreflow360-production

# Verify backup created
wrangler d1 backup list coreflow360-production
```

**Feature Flag Setup**:
```bash
# Create feature flag (default: OFF)
# Example for Compliance Guidelines feature
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

# Verify flag created
curl https://api.coreflow360.com/api/feature-flags/enableComplianceGuidelines
```

---

## Deployment Procedures by Phase

### Phase 1A: Compliance Features (Sprint 34-35)

#### Feature: Compliance Guidelines Management (Story #1)

**Deployment Steps**:

1. **Deploy Backend Changes** (if any):
```bash
# Deploy backend updates
cd backend
npm run build
wrangler deploy --env production

# Verify deployment
curl -f https://api.coreflow360.com/api/compliance/guidelines
```

2. **Deploy Frontend Changes**:
```bash
# Build frontend with feature flag OFF
cd frontend
npm run build

# Deploy to Cloudflare Pages
wrangler pages publish dist --project-name=coreflow360-frontend --branch=main

# Verify deployment
curl -f https://coreflow360.com
```

3. **Database Migration** (if needed):
```bash
# Apply production migration
wrangler d1 migrations apply coreflow360-production

# Verify migration
wrangler d1 execute coreflow360-production \
  --command "SELECT * FROM compliance_guidelines LIMIT 1"
```

4. **Smoke Test (Feature Flag OFF)**:
```bash
# Verify application loads
curl -f https://coreflow360.com

# Verify existing features still work
npm run test:smoke
```

5. **Enable for Internal Users** (Beta Test):
```bash
# Enable for specific user IDs (internal team)
curl -X PATCH https://api.coreflow360.com/api/feature-flags/enableComplianceGuidelines \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "enabled": true,
    "rolloutType": "users",
    "allowedUsers": ["user-id-1", "user-id-2", "user-id-3"]
  }'

# Verify flag status
curl https://api.coreflow360.com/api/feature-flags/enableComplianceGuidelines
```

6. **Monitor Beta Usage** (24 hours):
```bash
# Check error rates
curl https://api.coreflow360.com/api/metrics/errors?feature=enableComplianceGuidelines

# Check usage metrics
curl https://api.coreflow360.com/api/metrics/usage?feature=enableComplianceGuidelines

# Check performance metrics
curl https://api.coreflow360.com/api/metrics/performance?feature=enableComplianceGuidelines
```

7. **Gradual Rollout - 10% Users**:
```bash
# Enable for 10% of users
curl -X PATCH https://api.coreflow360.com/api/feature-flags/enableComplianceGuidelines \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "enabled": true,
    "rolloutType": "percentage",
    "rolloutPercentage": 10
  }'
```

8. **Monitor 10% Rollout** (48 hours):
- Monitor error rates (target: <0.1%)
- Monitor performance (target: P95 < 500ms)
- Monitor user feedback (Support tickets, Sentry errors)
- Check business metrics (Usage, engagement)

9. **Gradual Rollout - 50% Users**:
```bash
# Enable for 50% of users
curl -X PATCH https://api.coreflow360.com/api/feature-flags/enableComplianceGuidelines \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "rolloutPercentage": 50
  }'
```

10. **Monitor 50% Rollout** (1 week):
- Continue monitoring all metrics
- Gather user feedback
- Identify any edge cases or issues

11. **Full Rollout - 100% Users**:
```bash
# Enable for 100% of users
curl -X PATCH https://api.coreflow360.com/api/feature-flags/enableComplianceGuidelines \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "rolloutPercentage": 100
  }'
```

12. **Feature Flag Cleanup** (2 weeks after 100%):
```bash
# After feature is stable, remove feature flag from code
# Create PR to remove feature flag checks
# After merge, delete feature flag
curl -X DELETE https://api.coreflow360.com/api/feature-flags/enableComplianceGuidelines \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

---

### Phase 1B: Finance & CRM Features (Sprint 36-37)

#### Feature: Invoice Approval Workflow (Story #5)

**Deployment Steps**:

Follow same procedure as Phase 1A with these specific considerations:

**Pre-Deployment**:
```bash
# Create feature flag
curl -X POST https://api.coreflow360.com/api/feature-flags \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "key": "enableInvoiceApproval",
    "name": "Invoice Approval Workflow",
    "enabled": false,
    "rolloutPercentage": 0
  }'

# Verify invoice-related database tables exist
wrangler d1 execute coreflow360-production \
  --command "SELECT COUNT(*) FROM invoices"
```

**Special Considerations for Invoice Approval**:
- Financial data requires extra validation
- Ensure approval state transitions are atomic (use transactions)
- Monitor for any double-approvals or race conditions
- Verify email notifications are sent correctly

**Rollout Timeline**:
- Internal beta: 3-5 finance users (48 hours monitoring)
- 10% rollout: Monitor for 1 week (financial features need longer validation)
- 50% rollout: Monitor for 1 week
- 100% rollout: Monitor for 2 weeks before cleanup

---

### Phase 2: Core Business Features (Sprint 38-40)

#### General Deployment Pattern

All Phase 2 features follow this standardized pattern:

1. **Week Before Deployment**:
   - [ ] Create feature flag
   - [ ] Complete code review and QA sign-off
   - [ ] Run full E2E test suite on staging
   - [ ] Prepare rollback plan
   - [ ] Brief support team

2. **Deployment Day**:
   - [ ] Create database backup
   - [ ] Deploy backend (if changes)
   - [ ] Deploy frontend (feature flag OFF)
   - [ ] Run smoke tests
   - [ ] Enable for internal users (beta)

3. **Beta Period** (24-48 hours):
   - [ ] Monitor error rates
   - [ ] Monitor performance metrics
   - [ ] Gather internal user feedback
   - [ ] Fix any critical issues before wider rollout

4. **Gradual Rollout**:
   - [ ] 10% (48 hours monitoring)
   - [ ] 50% (1 week monitoring)
   - [ ] 100% (2 weeks monitoring)
   - [ ] Cleanup feature flag (after stability confirmed)

---

## Feature Flag Management

### Feature Flag Lifecycle

```
Create (OFF) → Deploy (OFF) → Beta (specific users) → 10% → 50% → 100% → Remove
```

### Feature Flag Commands Reference

**Create Feature Flag**:
```bash
curl -X POST https://api.coreflow360.com/api/feature-flags \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "key": "enableFeatureName",
    "name": "Feature Display Name",
    "description": "Feature description",
    "enabled": false,
    "rolloutPercentage": 0
  }'
```

**Get Feature Flag Status**:
```bash
curl https://api.coreflow360.com/api/feature-flags/enableFeatureName
```

**Update Rollout Percentage**:
```bash
curl -X PATCH https://api.coreflow360.com/api/feature-flags/enableFeatureName \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "rolloutPercentage": 50
  }'
```

**Enable for Specific Users** (Beta Testing):
```bash
curl -X PATCH https://api.coreflow360.com/api/feature-flags/enableFeatureName \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "enabled": true,
    "rolloutType": "users",
    "allowedUsers": ["user-1", "user-2", "user-3"]
  }'
```

**Emergency Disable**:
```bash
curl -X PATCH https://api.coreflow360.com/api/feature-flags/enableFeatureName \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "enabled": false,
    "rolloutPercentage": 0
  }'
```

**Delete Feature Flag** (after cleanup):
```bash
curl -X DELETE https://api.coreflow360.com/api/feature-flags/enableFeatureName \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

---

## Monitoring & Health Checks

### Real-Time Monitoring Dashboard

**Open Before Deployment**:
1. Sentry: https://sentry.io/organizations/coreflow360/issues/
2. Cloudflare Analytics: https://dash.cloudflare.com/analytics
3. Custom Metrics Dashboard: https://coreflow360.com/admin/metrics

### Key Metrics to Monitor

**Error Rates**:
```bash
# Check frontend errors
curl https://api.coreflow360.com/api/metrics/frontend-errors?last=1h

# Check backend errors
curl https://api.coreflow360.com/api/metrics/backend-errors?last=1h

# Target: Error rate < 0.1% (1 error per 1000 requests)
```

**Performance Metrics**:
```bash
# Check API response times
curl https://api.coreflow360.com/api/metrics/response-times?last=1h

# Check page load times
curl https://api.coreflow360.com/api/metrics/page-load-times?last=1h

# Target: P95 response time < 500ms
```

**Usage Metrics**:
```bash
# Check feature adoption
curl https://api.coreflow360.com/api/metrics/feature-usage?feature=enableComplianceGuidelines&last=24h

# Check user engagement
curl https://api.coreflow360.com/api/metrics/user-engagement?last=24h
```

**Business Metrics**:
```bash
# Check conversion rates (if applicable)
curl https://api.coreflow360.com/api/metrics/conversions?feature=enableComplianceGuidelines&last=7d

# Check user satisfaction (support tickets)
curl https://api.coreflow360.com/api/metrics/support-tickets?feature=enableComplianceGuidelines&last=7d
```

### Health Check Endpoints

**Application Health**:
```bash
# Overall health
curl -f https://api.coreflow360.com/health
# Expected: {"status": "healthy", "timestamp": "..."}

# API health
curl -f https://api.coreflow360.com/api/status
# Expected: {"status": "ok", "version": "v4", ...}

# Database health
curl -f https://api.coreflow360.com/api/db/health
# Expected: {"status": "connected", "latency_ms": 10}

# Cache health
curl -f https://api.coreflow360.com/api/cache/health
# Expected: {"kv_cache": "connected", "session_cache": "connected"}
```

**Feature-Specific Health Checks**:
```bash
# Compliance API health
curl -f https://api.coreflow360.com/api/compliance/health

# Finance API health
curl -f https://api.coreflow360.com/api/finance/health

# CRM API health
curl -f https://api.coreflow360.com/api/crm/health
```

### Automated Alerts

**Configure Alerts** (before deployment):
```bash
# Create alert for high error rate
curl -X POST https://api.coreflow360.com/api/alerts \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "High Error Rate - Compliance Guidelines",
    "condition": "error_rate > 0.01",
    "feature": "enableComplianceGuidelines",
    "channels": ["slack", "email"],
    "recipients": ["on-call-engineer@coreflow360.com"]
  }'

# Create alert for slow response times
curl -X POST https://api.coreflow360.com/api/alerts \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Slow Response Times - Compliance Guidelines",
    "condition": "p95_response_time > 1000",
    "feature": "enableComplianceGuidelines",
    "channels": ["slack"],
    "recipients": ["engineering-team@coreflow360.com"]
  }'
```

---

## Rollback Procedures

### When to Rollback

Trigger immediate rollback if:
- Error rate > 1% (1 error per 100 requests)
- P95 response time > 2 seconds
- Critical bug affecting data integrity
- Customer-facing production incident (SEV1)

### Rollback Types

#### Type 1: Feature Flag Disable (Instant - < 2 minutes)

**Use when**: New feature is causing issues but core app is stable

```bash
# Instant disable via feature flag
curl -X PATCH https://api.coreflow360.com/api/feature-flags/enableComplianceGuidelines \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "enabled": false,
    "rolloutPercentage": 0
  }'

# Verify flag disabled
curl https://api.coreflow360.com/api/feature-flags/enableComplianceGuidelines
# Expected: {"enabled": false, "rolloutPercentage": 0}

# Verify feature no longer accessible
curl https://coreflow360.com/admin/compliance/guidelines
# Should redirect to home or show "Feature not available" message
```

**Post-Rollback**:
- Notify users via email/notification (if many users affected)
- Update status page: https://status.coreflow360.com
- Investigate issue in staging environment
- Schedule fix and re-deployment

#### Type 2: Frontend Rollback (Fast - < 10 minutes)

**Use when**: Frontend code has critical bug, backend is stable

```bash
# Get previous deployment ID
wrangler pages deployments list --project-name=coreflow360-frontend

# Rollback to previous deployment
wrangler pages deployments rollback <PREVIOUS_DEPLOYMENT_ID> \
  --project-name=coreflow360-frontend

# Verify rollback
curl -f https://coreflow360.com
```

**Post-Rollback**:
- Clear CDN cache (if applicable)
- Verify users see previous version
- Test critical user flows still work
- Investigate issue, fix, re-test, re-deploy

#### Type 3: Backend Rollback (Medium - < 20 minutes)

**Use when**: Backend API has critical bug

```bash
# Get previous deployment
wrangler deployments list

# Rollback to previous deployment
wrangler rollback <PREVIOUS_DEPLOYMENT_ID>

# Verify rollback
curl -f https://api.coreflow360.com/health
curl -f https://api.coreflow360.com/api/status
```

**Post-Rollback**:
- Test critical API endpoints
- Verify database consistency
- Check for any in-flight transactions that may have been affected
- Investigate issue in staging

#### Type 4: Database Rollback (Slow - < 60 minutes)

**Use when**: Database migration caused issues (RARE - avoid if possible)

```bash
# Stop accepting writes (enable maintenance mode)
curl -X POST https://api.coreflow360.com/api/admin/maintenance-mode \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{"enabled": true}'

# Restore from backup
wrangler d1 restore coreflow360-production <BACKUP_ID>

# Verify restoration
wrangler d1 execute coreflow360-production --command "SELECT COUNT(*) FROM compliance_guidelines"

# Re-enable application
curl -X POST https://api.coreflow360.com/api/admin/maintenance-mode \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{"enabled": false}'
```

**Post-Rollback**:
- Verify data integrity across all tables
- Test critical user flows end-to-end
- Notify users of potential data loss (if any)
- Conduct post-mortem to prevent future database rollbacks

### Rollback Decision Matrix

| Issue Severity | Error Rate | Response Time | Action | Timeline |
|---------------|------------|---------------|--------|----------|
| SEV1 (Critical) | >5% | >5s | Immediate rollback (Type 1 or 2) | <2 min |
| SEV2 (High) | 1-5% | 2-5s | Rollback within 15 min | <15 min |
| SEV3 (Medium) | 0.5-1% | 1-2s | Evaluate, likely rollback | <30 min |
| SEV4 (Low) | 0.1-0.5% | 0.5-1s | Monitor, fix forward | N/A |

---

## Incident Response

### Incident Response Team

**Primary Contact**:
- Engineering Lead: [Name] - [Phone] - [Email]

**On-Call Engineer**:
- Current: Check PagerDuty schedule
- Backup: [Name] - [Phone]

**Escalation Path**:
1. On-Call Engineer (15 min response time)
2. Engineering Lead (30 min response time)
3. CTO (1 hour response time)

### Incident Response Procedure

#### 1. Detect (Automated + Manual)

**Automated Detection**:
- Sentry error spike alert
- Cloudflare performance degradation alert
- Custom metrics alert

**Manual Detection**:
- Customer report (support ticket, email)
- Internal user report (Slack, email)
- Monitoring dashboard observation

#### 2. Assess (5 minutes)

**Quick Assessment**:
```bash
# Check error rates
curl https://api.coreflow360.com/api/metrics/errors?last=15m

# Check performance
curl https://api.coreflow360.com/api/metrics/response-times?last=15m

# Check recent deployments
wrangler deployments list --limit 5

# Check recent feature flag changes
curl https://api.coreflow360.com/api/feature-flags/recent-changes
```

**Severity Classification**:
- **SEV1**: Complete outage, data loss, security breach
- **SEV2**: Major feature broken, high error rates
- **SEV3**: Minor feature broken, some users affected
- **SEV4**: Small bug, minimal user impact

#### 3. Respond

**SEV1 Response** (Immediate):
1. Page on-call engineer immediately
2. Create incident channel: #incident-[date]-[description]
3. Update status page: https://status.coreflow360.com
4. Execute rollback (Type 1, 2, or 3 as appropriate)
5. Post-rollback verification
6. Customer communication (email, in-app notification)

**SEV2 Response** (15 minutes):
1. Notify on-call engineer
2. Create incident channel
3. Attempt quick fix OR execute rollback
4. Monitor for improvement
5. Customer communication (if many users affected)

**SEV3/SEV4 Response** (30-60 minutes):
1. Create bug ticket
2. Prioritize for next sprint
3. Monitor for escalation
4. Fix forward (no rollback needed)

#### 4. Communicate

**Internal Communication** (Slack #incident-xyz):
```
🚨 INCIDENT: [Brief description]
Severity: SEV1
Affected Feature: Compliance Guidelines
Impact: Unable to create new guidelines
Start Time: 2025-11-20 14:30 UTC
Status: Investigating
ETA: 30 minutes
```

**Customer Communication** (Status Page + Email):
```
Subject: Service Disruption - Compliance Guidelines Feature

We are currently experiencing issues with the Compliance Guidelines feature.
Users may be unable to create or edit guidelines.

Status: Investigating
Impact: Compliance Guidelines feature only
Workaround: Use existing guidelines, new ones can be created via API

We will update this notice every 15 minutes.

Next Update: 15:00 UTC
```

#### 5. Resolve

**Resolution Steps**:
1. Fix issue (rollback OR hotfix)
2. Verify resolution (smoke tests)
3. Monitor for stability (30 minutes)
4. Update status page (resolved)
5. Send customer communication (resolution email)

#### 6. Post-Mortem (Within 48 hours)

**Post-Mortem Template**:
```markdown
# Incident Post-Mortem: [Date] - [Feature]

## Summary
- **Incident Date**: 2025-11-20
- **Duration**: 45 minutes
- **Severity**: SEV2
- **Affected Users**: ~15% (estimated 200 users)

## Timeline
- 14:30 UTC: Incident detected via Sentry alert
- 14:35 UTC: On-call engineer paged
- 14:40 UTC: Issue identified (validation logic error)
- 14:50 UTC: Feature flag disabled
- 15:00 UTC: Hotfix deployed to staging
- 15:15 UTC: Hotfix deployed to production, flag re-enabled at 10%
- 15:45 UTC: Monitoring confirmed stability, incident resolved

## Root Cause
[Detailed technical explanation of what went wrong]

## Impact
- 200 users unable to create compliance guidelines for 45 minutes
- 12 support tickets created
- 5 failed guideline creation attempts
- No data loss

## Resolution
- Immediate: Feature flag disabled
- Permanent: Hotfix deployed with improved validation logic

## Action Items
- [ ] Add validation unit tests (Owner: [Name], Due: 2025-11-22)
- [ ] Add E2E test for this scenario (Owner: [Name], Due: 2025-11-22)
- [ ] Improve monitoring for validation errors (Owner: [Name], Due: 2025-11-25)
- [ ] Update runbook with this scenario (Owner: [Name], Due: 2025-11-23)

## Lessons Learned
- What went well: Fast detection, quick rollback, good communication
- What could improve: Better pre-deployment validation testing
- Preventive measures: Add validation testing to checklist
```

---

## Post-Deployment Verification

### Immediate Post-Deployment (< 1 hour)

**Health Checks**:
```bash
# Application health
curl -f https://api.coreflow360.com/health

# Feature health
curl -f https://api.coreflow360.com/api/compliance/health

# Error rates (should be minimal)
curl https://api.coreflow360.com/api/metrics/errors?last=1h
# Expected: error_rate < 0.001 (0.1%)

# Response times (should be fast)
curl https://api.coreflow360.com/api/metrics/response-times?last=1h
# Expected: p95 < 500ms
```

**Smoke Tests**:
```bash
# Run automated smoke tests
npm run test:smoke

# Manual smoke test checklist
- [ ] Homepage loads
- [ ] Login works
- [ ] Navigation works
- [ ] Existing features still work
- [ ] New feature accessible (if flag enabled)
```

### 24-Hour Post-Deployment

**Metrics Review**:
```bash
# Error rates over 24 hours
curl https://api.coreflow360.com/api/metrics/errors?last=24h

# Performance over 24 hours
curl https://api.coreflow360.com/api/metrics/response-times?last=24h

# Usage metrics
curl https://api.coreflow360.com/api/metrics/feature-usage?feature=enableComplianceGuidelines&last=24h
```

**User Feedback Review**:
- [ ] Check support tickets for issues
- [ ] Review Sentry errors
- [ ] Check user feedback forms
- [ ] Review analytics for drop-offs

**Decision Point**:
- [ ] ✅ Proceed to next rollout phase (10% → 50%)
- [ ] ⚠️ Hold at current level, investigate issues
- [ ] ❌ Rollback, critical issues found

### 1-Week Post-Deployment

**Comprehensive Review**:
- [ ] Review all metrics (errors, performance, usage)
- [ ] Analyze user behavior (adoption, engagement)
- [ ] Review business metrics (conversions, revenue impact)
- [ ] Gather qualitative feedback (user interviews, surveys)

**Optimization Opportunities**:
- [ ] Identify performance bottlenecks
- [ ] Identify UX friction points
- [ ] Identify feature requests
- [ ] Plan improvements for next sprint

---

## Deployment Checklists by Feature

### Compliance Guidelines (Story #1)

**Pre-Deployment**:
- [ ] Database table `compliance_guidelines` verified
- [ ] API endpoints tested (`/api/compliance/guidelines/*`)
- [ ] Feature flag `enableComplianceGuidelines` created
- [ ] E2E tests passing (Test Suite 1: 6 tests)
- [ ] Accessibility audit complete (Lighthouse ≥ 95)
- [ ] Support team briefed (FAQ prepared)
- [ ] Rollback plan documented

**Deployment**:
- [ ] Backend deployed (if changes)
- [ ] Frontend deployed (flag OFF)
- [ ] Smoke tests passed
- [ ] Beta enabled (internal users)
- [ ] 24-hour beta monitoring passed
- [ ] 10% rollout
- [ ] 48-hour monitoring passed
- [ ] 50% rollout
- [ ] 1-week monitoring passed
- [ ] 100% rollout
- [ ] 2-week stability confirmed

**Post-Deployment**:
- [ ] Feature flag removed from code (after 2 weeks)
- [ ] Documentation updated
- [ ] Training materials created
- [ ] Post-mortem completed (if issues)

### Invoice Approval Workflow (Story #5)

**Pre-Deployment**:
- [ ] Database tables verified (`invoices`, `invoice_approvals`)
- [ ] API endpoints tested (`/api/finance/invoices/*/approve`)
- [ ] Feature flag `enableInvoiceApproval` created
- [ ] Email notification system tested
- [ ] Transaction atomicity verified (race condition testing)
- [ ] E2E tests passing (Test Suite 5: 4 tests)
- [ ] Finance team briefed

**Deployment** (Extended timeline for financial features):
- [ ] Backend deployed
- [ ] Frontend deployed (flag OFF)
- [ ] Smoke tests passed
- [ ] Beta enabled (3-5 finance users)
- [ ] 48-hour beta monitoring passed
- [ ] 10% rollout
- [ ] 1-week monitoring passed (longer than standard)
- [ ] 50% rollout
- [ ] 1-week monitoring passed
- [ ] 100% rollout
- [ ] 2-week stability confirmed

**Post-Deployment**:
- [ ] Audit trail verified (all approvals logged)
- [ ] Email notifications working correctly
- [ ] No double-approvals detected
- [ ] Feature flag cleanup (after 2 weeks)

---

## Emergency Contacts

### Engineering Team

**Engineering Lead**: [Name]
- Phone: [Phone]
- Email: [Email]
- Slack: @engineering-lead

**On-Call Engineers**:
- Primary: [Check PagerDuty schedule]
- Backup: [Name] - [Phone]

### Executive Team

**CTO**: [Name]
- Phone: [Phone] (Emergencies only)
- Email: [Email]

### External Contacts

**Cloudflare Support**: [Support ticket system]
**Sentry Support**: [Email]

---

## Appendix

### Useful Commands Reference

**Cloudflare Workers**:
```bash
# Deploy
wrangler deploy

# Rollback
wrangler rollback <DEPLOYMENT_ID>

# View logs
wrangler tail

# List deployments
wrangler deployments list
```

**Cloudflare D1**:
```bash
# Execute query
wrangler d1 execute <DATABASE_NAME> --command "SELECT * FROM table LIMIT 5"

# Create backup
wrangler d1 backup create <DATABASE_NAME>

# List backups
wrangler d1 backup list <DATABASE_NAME>

# Restore backup
wrangler d1 restore <DATABASE_NAME> <BACKUP_ID>
```

**Cloudflare Pages**:
```bash
# Publish
wrangler pages publish <DIRECTORY>

# List deployments
wrangler pages deployments list

# Rollback
wrangler pages deployments rollback <DEPLOYMENT_ID>
```

**Health Checks**:
```bash
# Application health
curl -f https://api.coreflow360.com/health

# API status
curl -f https://api.coreflow360.com/api/status

# Database health
curl -f https://api.coreflow360.com/api/db/health
```

### Monitoring Dashboard URLs

- **Sentry**: https://sentry.io/organizations/coreflow360/
- **Cloudflare Analytics**: https://dash.cloudflare.com/analytics
- **Custom Metrics**: https://coreflow360.com/admin/metrics
- **Status Page**: https://status.coreflow360.com

---

**Document Version**: 1.0
**Last Updated**: 2025-10-22
**Maintained By**: Engineering Team
**Review Cycle**: Quarterly

**For questions or updates, contact**: engineering-lead@coreflow360.com
