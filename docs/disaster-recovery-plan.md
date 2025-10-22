# Disaster Recovery Plan

## Overview

This Disaster Recovery (DR) plan provides procedures for recovering CoreFlow360 V4 from catastrophic failures, ensuring business continuity and data protection with **Recovery Time Objective (RTO) < 4 hours** and **Recovery Point Objective (RPO) < 24 hours**.

---

## Disaster Scenarios

### Severity Classification

| Level | Scenario | RTO | RPO | Impact |
|-------|----------|-----|-----|--------|
| **DR-1 Critical** | Complete infrastructure failure | 2 hours | 24 hours | Total service outage |
| **DR-2 High** | Database corruption/loss | 4 hours | 24 hours | Data access failure |
| **DR-3 Medium** | Regional Cloudflare outage | 1 hour | 0 hours | Service degradation |
| **DR-4 Low** | Single component failure | 30 min | 0 hours | Partial functionality loss |

---

## Recovery Objectives

### RTO (Recovery Time Objective)

**Target**: Service restored within **4 hours** of disaster declaration

| Disaster Type | Target RTO | Acceptable RTO |
|---------------|------------|----------------|
| Infrastructure failure | 2 hours | 4 hours |
| Database corruption | 2 hours | 4 hours |
| Regional outage | 30 minutes | 1 hour |
| Code deployment failure | 15 minutes | 30 minutes |

### RPO (Recovery Point Objective)

**Target**: Data loss limited to **24 hours**

| Data Type | Backup Frequency | Max Data Loss |
|-----------|------------------|---------------|
| Transactional data | Daily | 24 hours |
| User data | Daily | 24 hours |
| Configuration | On change | 0 hours (git) |
| Logs | Real-time | 1 hour |

---

## DR-1: Complete Infrastructure Failure

### Scenario
Cloudflare Workers platform experiences complete outage or account suspension.

### Detection
- All health checks fail (100% error rate)
- Cloudflare dashboard inaccessible
- Workers return 502/503 errors globally

### Immediate Actions (0-15 minutes)

1. **Verify Disaster Scope**
```bash
# Check Cloudflare status
curl -s https://www.cloudflarestatus.com/api/v2/status.json | jq .

# Check if it's just our account
wrangler whoami

# Test alternative Cloudflare datacenter
curl -v https://[worker-name].[account].workers.dev/health
```

2. **Declare DR-1 Incident**
```markdown
🚨 DR-1 DECLARED - Complete Infrastructure Failure

**Time**: [timestamp]
**Scope**: All services down
**Impact**: 100% users affected
**Estimated RTO**: 2-4 hours

**Incident Commander**: [name]
**War Room**: #incident-dr1
```

3. **Activate Emergency Communication**
- Page entire engineering team
- Notify executive team
- Post status page update
- Send customer email notification

### Recovery Steps (15 minutes - 4 hours)

#### Option A: Restore on Cloudflare (if platform recovered)

```bash
# 1. Verify Cloudflare platform status
wrangler whoami

# 2. Deploy latest known-good version
git checkout production-backup-tag
wrangler deploy --env production

# 3. Verify deployment
./scripts/health-check.sh production

# 4. Run smoke tests
./scripts/smoke-test.sh production
```

#### Option B: Failover to Alternative Infrastructure

**Note**: This requires pre-configured backup infrastructure (not currently implemented).

```bash
# 1. Deploy to AWS Lambda (backup runtime)
cd backup-deployment/aws-lambda
npm run deploy:production

# 2. Update DNS to point to Lambda
# Change CNAME: api.coreflow360.com → [lambda-endpoint]

# 3. Verify failover
curl -v https://api.coreflow360.com/health

# 4. Monitor error rates
./scripts/performance-monitor.sh production 15
```

#### Option C: Restore from Complete Backup

```bash
# 1. Provision new Cloudflare account
wrangler login --new-account

# 2. Create resources
wrangler d1 create coreflow360-agents
wrangler kv:namespace create KV_CACHE
wrangler kv:namespace create KV_SESSION

# 3. Restore database
./scripts/restore-database.sh [latest-backup]

# 4. Configure secrets
./scripts/3-configure-secrets.sh

# 5. Deploy application
wrangler deploy --env production

# 6. Update DNS
# Point api.coreflow360.com to new worker

# 7. Verify recovery
./scripts/health-check.sh production
```

### Verification (4 hours - 4.5 hours)

```bash
# 1. Run comprehensive health check
./scripts/health-check.sh production

# 2. Run smoke tests
./scripts/smoke-test.sh production

# 3. Verify data integrity
./scripts/verify-data-integrity.sh

# 4. Check recent transactions
wrangler d1 execute coreflow360-agents --command "
  SELECT COUNT(*) as recent_transactions
  FROM ledger_entries
  WHERE created_at > datetime('now', '-1 hour')
" --env production

# 5. Monitor for 30 minutes
./scripts/performance-monitor.sh production 30
```

### Post-Recovery (4.5 hours+)

1. **Data Reconciliation**
   - Identify lost transactions (if RPO exceeded)
   - Notify affected customers
   - Manual data entry for critical transactions

2. **Root Cause Analysis**
   - What caused the failure?
   - Could it have been prevented?
   - Update DR plan based on learnings

3. **Post-Mortem**
   - Schedule within 48 hours
   - Document timeline
   - Create prevention action items

---

## DR-2: Database Corruption/Loss

### Scenario
D1 database becomes corrupted, deleted, or inaccessible.

### Detection
- Database queries return errors
- D1 dashboard shows 0 tables
- Health check reports "database unhealthy"

### Immediate Actions (0-10 minutes)

1. **Verify Database State**
```bash
# Check database exists
wrangler d1 list

# Try simple query
wrangler d1 execute coreflow360-agents --command "SELECT 1" --env production

# Check table count
wrangler d1 execute coreflow360-agents --command "
  SELECT COUNT(*) as table_count
  FROM sqlite_master
  WHERE type='table'
" --env production
```

2. **Declare DR-2 Incident**
```markdown
🚨 DR-2 DECLARED - Database Corruption

**Time**: [timestamp]
**Scope**: Data layer failure
**Impact**: All users affected (read/write)
**Estimated RTO**: 2-4 hours

**Incident Commander**: [name]
```

3. **Enable Read-Only Mode (if possible)**
```typescript
// Deploy emergency read-only mode
// Prevents further data corruption
export const isReadOnlyMode = true;
```

### Recovery Steps (10 minutes - 4 hours)

#### Option A: Restore from Latest Backup

```bash
# 1. Locate latest backup
ls -lh ~/backups/coreflow360-agents-*.sql.gz | tail -5

# 2. Verify backup integrity
gunzip -t ~/backups/coreflow360-agents-[date].sql.gz

# 3. Create new database (if corrupted)
wrangler d1 create coreflow360-agents-recovery

# 4. Restore backup
gunzip -c ~/backups/coreflow360-agents-[date].sql.gz | \
  wrangler d1 execute coreflow360-agents-recovery --file /dev/stdin --env production

# 5. Verify restoration
wrangler d1 execute coreflow360-agents-recovery --command "
  SELECT COUNT(*) FROM users;
  SELECT COUNT(*) FROM ledger_entries;
  SELECT COUNT(*) FROM businesses;
" --env production

# 6. Update wrangler.toml to use recovery database
# Edit: database_id = "[recovery-database-id]"

# 7. Deploy updated configuration
wrangler deploy --env production
```

#### Option B: Point-in-Time Recovery (if backup recent)

```bash
# 1. Get backup timestamp
BACKUP_TIME=$(ls -l ~/backups/coreflow360-agents-latest.sql.gz | awk '{print $6, $7, $8}')
echo "Backup from: $BACKUP_TIME"

# 2. Calculate data loss window
echo "Data loss: Transactions since $BACKUP_TIME"

# 3. Export recent transactions from logs
# (if captured in Analytics Engine)
wrangler analytics-engine query --sql "
  SELECT * FROM transaction_logs
  WHERE timestamp > '$BACKUP_TIME'
"

# 4. Restore backup (as in Option A)

# 5. Replay lost transactions
# Manual process - apply from logs/exports
```

### Verification

```bash
# 1. Verify table schemas
wrangler d1 execute coreflow360-agents --command "
  SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;
" --env production

# 2. Verify row counts match expectations
wrangler d1 execute coreflow360-agents --command "
  SELECT
    (SELECT COUNT(*) FROM users) as users,
    (SELECT COUNT(*) FROM businesses) as businesses,
    (SELECT COUNT(*) FROM ledger_entries) as ledger_entries;
" --env production

# 3. Test critical queries
./scripts/test-database-queries.sh

# 4. Run smoke tests
./scripts/smoke-test.sh production
```

---

## DR-3: Regional Cloudflare Outage

### Scenario
Specific Cloudflare region experiences outage, affecting subset of users.

### Detection
- Spike in 502/503 errors from specific geographic region
- Cloudflare status page reports regional issues
- Partial user complaints (specific locations)

### Immediate Actions (0-5 minutes)

1. **Verify Regional Issue**
```bash
# Test from multiple locations
curl -v https://api.coreflow360.com/health --resolve api.coreflow360.com:443:[cloudflare-anycast-ip]

# Check Cloudflare status
curl -s https://www.cloudflarestatus.com/api/v2/status.json | jq '.status.indicator'
```

2. **Assess Impact**
```bash
# Check error rate by region (if available in analytics)
# Estimate affected user percentage
```

### Recovery Steps (5 minutes - 1 hour)

#### Option A: Wait for Cloudflare Recovery

- Monitor Cloudflare status page
- Provide status updates every 15 minutes
- No action required (Cloudflare auto-routes around outage)

#### Option B: Route Around Affected Region

```bash
# Configure custom routing via Cloudflare dashboard
# Temporarily disable affected datacenter

# Or via API
curl -X PATCH "https://api.cloudflare.com/client/v4/zones/{zone_id}/settings/routing" \
  -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"value":"performance"}' # Switch to performance routing
```

---

## DR-4: Code Deployment Failure

### Scenario
Deployment introduces critical bug that breaks production.

### Detection
- Error rate spike immediately after deployment
- Health checks fail post-deployment
- User reports of errors

### Immediate Actions (0-5 minutes)

1. **Verify Deployment Issue**
```bash
# Check recent deployments
wrangler deployments list --env production

# Check error logs
wrangler tail coreflow360-v4-prod --env production | grep ERROR
```

2. **Immediate Rollback**
```bash
# Use pre-deployment rollback tag
git checkout pre-deploy-[timestamp]

# Rollback deployment
wrangler deploy --env production

# Verify rollback
./scripts/health-check.sh production
```

### Recovery Steps (5 minutes - 30 minutes)

```bash
# 1. Identify problematic code
git diff pre-deploy-[timestamp] HEAD

# 2. Fix issue
# Edit affected files

# 3. Test fix
npm test
npm run type-check

# 4. Deploy fix
npm run build
wrangler deploy --env production

# 5. Monitor
./scripts/performance-monitor.sh production 15
```

---

## Backup Strategy

### Automated Daily Backups

```bash
# Configured in crontab
0 2 * * * /path/to/scripts/backup-database.sh

# Backup includes:
# - Full database dump (SQL)
# - Gzip compression
# - R2 upload
# - 30-day retention
# - Integrity verification
```

### Manual Backup (Pre-Major Changes)

```bash
# Before major deployment
./scripts/backup-database.sh

# Tag backup
git tag -a backup-$(date +%Y%m%d-%H%M%S) -m "Pre-deployment backup"
git push origin --tags
```

### Backup Verification

```bash
# Monthly backup restoration test
# Restore to staging environment
./scripts/restore-database.sh [latest-backup] staging

# Verify data integrity
./scripts/verify-data-integrity.sh staging

# Document test results
echo "Backup test $(date): PASS" >> backup-test-log.txt
```

---

## Communication Plan

### Internal Communication

**Slack Channels**:
- `#incident-critical` - DR-1 incidents
- `#incident-high` - DR-2 incidents
- `#incidents` - All other incidents

**Escalation Path**:
1. On-call engineer (0-5 min)
2. Engineering lead (5-15 min)
3. CTO (15-30 min)
4. CEO (30+ min for DR-1/DR-2)

### External Communication

**Status Page**: `https://status.coreflow360.com`

**Email Templates**:

```html
<!-- Initial Notification -->
Subject: Service Disruption - CoreFlow360

We are currently experiencing technical difficulties affecting all
CoreFlow360 services. Our team is actively working on a resolution.

Affected Services: All
Started: [timestamp]
Estimated Resolution: [estimate]

We will provide updates every 30 minutes.

Status Page: https://status.coreflow360.com
Support: support@coreflow360.com
```

```html
<!-- Recovery Notification -->
Subject: Service Restored - CoreFlow360

We have restored all CoreFlow360 services. All systems are operating normally.

Outage Duration: [duration]
Root Cause: [brief summary]
Data Loss: [none/minimal/details]

We apologize for the disruption and are taking steps to prevent recurrence.

Full post-mortem will be published within 48 hours.
```

---

## Testing & Drills

### Quarterly DR Drills

**Schedule**: First Monday of each quarter

**Drill Types**:
1. **Tabletop Exercise** (Q1, Q3) - Walk through scenarios
2. **Live Failover Test** (Q2) - Actual restoration to staging
3. **Full DR Simulation** (Q4) - Complete infrastructure recovery

### Drill Checklist

- [ ] Schedule drill (notify team 2 weeks advance)
- [ ] Prepare scenario details
- [ ] Assign incident commander
- [ ] Execute drill
- [ ] Time all recovery steps
- [ ] Document lessons learned
- [ ] Update DR plan
- [ ] Share results with team

---

## Recovery Resources

### Required Access

- [ ] Cloudflare account (admin access)
- [ ] GitHub repository (write access)
- [ ] Backup storage (R2 bucket access)
- [ ] DNS management (Cloudflare dashboard)
- [ ] Wrangler CLI (installed and authenticated)
- [ ] Emergency contact list
- [ ] Slack admin access

### Required Tools

```bash
# Local development machine
wrangler --version  # ≥3.0.0
git --version       # ≥2.40.0
node --version      # ≥22.0.0
jq --version        # ≥1.6

# Scripts
./scripts/backup-database.sh
./scripts/restore-database.sh
./scripts/health-check.sh
./scripts/smoke-test.sh
./scripts/deploy-production.sh
```

### Documentation Links

- [Deployment Checklist](./DEPLOYMENT_CHECKLIST.md)
- [Incident Response Playbook](./incident-response-playbook.md)
- [Troubleshooting Guide](./troubleshooting-guide.md)
- [Monitoring Alerts](./monitoring-alerts.md)

---

## Metrics & SLA

### Recovery Metrics

Track for each DR incident:

| Metric | Target | Measurement |
|--------|--------|-------------|
| **Detection Time** | <5 min | Alert to human acknowledgment |
| **Assessment Time** | <10 min | Acknowledgment to DR declaration |
| **Recovery Time** | <4 hours | DR declaration to service restored |
| **Verification Time** | <30 min | Service restored to fully validated |
| **Data Loss** | <24 hours | Timestamp of last backup to failure |

### Annual SLA Targets

- **Availability**: 99.9% uptime (8.77 hours downtime/year)
- **Successful DR Drills**: 4/4 (100%)
- **Mean Time to Recovery (MTTR)**: <2 hours
- **Maximum Data Loss**: 0 incidents >24 hours

---

## Continuous Improvement

### Post-DR Review

Within 48 hours of each DR incident:

1. **Timeline Documentation**
   - When was incident detected?
   - When was DR declared?
   - What recovery steps were taken?
   - When was service restored?
   - When was data validated?

2. **Root Cause Analysis**
   - What caused the disaster?
   - Could it have been prevented?
   - Were there warning signs?

3. **Response Evaluation**
   - Did team follow DR plan?
   - Were RTO/RPO met?
   - What worked well?
   - What could be improved?

4. **Action Items**
   - Update DR plan
   - Implement prevention measures
   - Improve monitoring/alerting
   - Additional automation

### Annual DR Plan Review

**Schedule**: January each year

- [ ] Review all DR scenarios
- [ ] Update contact information
- [ ] Verify backup procedures
- [ ] Test restoration process
- [ ] Update RTO/RPO targets
- [ ] Review metrics from past year
- [ ] Update based on infrastructure changes

---

**Last Updated**: 2025-10-21
**Next Review**: 2026-01-21
**Owner**: Engineering Team
**Approved by**: CTO

---

**Status**: 🟢 Active and Tested
