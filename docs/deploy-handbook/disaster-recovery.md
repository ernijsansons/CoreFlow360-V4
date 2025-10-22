# Disaster Recovery & Backup Procedures

**Created**: 2025-10-22
**Purpose**: Comprehensive backup and disaster recovery plan
**Audience**: DevOps engineers, engineering leads, on-call engineers
**RTO Target**: 4 hours | **RPO Target**: 1 hour

---

## Table of Contents

1. [Overview](#overview)
2. [Backup Strategy](#backup-strategy)
3. [Database Backup & Recovery](#database-backup--recovery)
4. [Application Recovery](#application-recovery)
5. [Data Recovery](#data-recovery)
6. [Disaster Scenarios](#disaster-scenarios)
7. [Recovery Testing](#recovery-testing)
8. [Business Continuity](#business-continuity)

---

## Overview

### Recovery Objectives

**RTO (Recovery Time Objective)**: 4 hours
- Maximum acceptable time to restore service after disaster

**RPO (Recovery Point Objective)**: 1 hour
- Maximum acceptable data loss (how far back we can restore)

### Disaster Recovery Tiers

| Tier | Scenario | RTO | RPO | Priority |
|------|----------|-----|-----|----------|
| **Critical** | Complete outage, data center failure | 4 hours | 1 hour | P0 |
| **High** | Database corruption, major data loss | 8 hours | 4 hours | P1 |
| **Medium** | Partial service degradation | 24 hours | 24 hours | P2 |
| **Low** | Non-critical service offline | 72 hours | 72 hours | P3 |

### Disaster Recovery Team

**Incident Commander**: Engineering Lead
**Database Recovery**: Backend Engineer
**Application Recovery**: DevOps Engineer
**Communication**: Product Manager
**Executive Liaison**: CTO

---

## Backup Strategy

### Backup Schedule

**Database Backups**:
- **Automated Daily**: 2:00 AM UTC (Cloudflare D1 automatic backups)
- **Manual Pre-Deployment**: Before every production deployment
- **Weekly Full Snapshot**: Sunday 00:00 UTC
- **Retention**: 30 days

**Code Repository**:
- **Git**: All code in GitHub (redundant copies on developer machines)
- **Deployment History**: Last 50 deployments kept in Cloudflare

**Configuration**:
- **Infrastructure as Code**: wrangler.toml in git
- **Environment Variables**: Documented in deployment handbook
- **Secrets**: Stored in Cloudflare (backed up to secure vault)

**User-Uploaded Content** (if applicable):
- **Cloudflare R2**: Daily snapshots
- **Retention**: 90 days

---

### Backup Verification

**Daily Verification** (Automated):
```bash
#!/bin/bash
# scripts/verify-backup.sh

# Check that backup exists
BACKUP_DATE=$(date +%Y-%m-%d)
BACKUP_COUNT=$(wrangler d1 backup list coreflow360-production | grep "$BACKUP_DATE" | wc -l)

if [ "$BACKUP_COUNT" -eq 0 ]; then
  echo "❌ ERROR: No backup found for $BACKUP_DATE"
  # Send alert
  curl -X POST $SLACK_WEBHOOK_URL \
    -d "{\"text\":\"❌ Database backup missing for $BACKUP_DATE\"}"
  exit 1
else
  echo "✅ Backup verified for $BACKUP_DATE"
  exit 0
fi
```

**Weekly Verification** (Manual):
- [ ] Restore backup to staging environment
- [ ] Verify data integrity
- [ ] Test critical queries
- [ ] Document verification in log

---

## Database Backup & Recovery

### 1. Create Manual Backup

**Before Critical Operations** (deployments, migrations):

```bash
# Create backup with descriptive name
wrangler d1 backup create coreflow360-production \
  --name "pre-migration-$(date +%Y%m%d-%H%M)"

# Save backup ID
BACKUP_ID=$(wrangler d1 backup list coreflow360-production | head -n 2 | tail -n 1 | awk '{print $1}')
echo "Backup ID: $BACKUP_ID"

# Verify backup created
wrangler d1 backup list coreflow360-production | grep "$BACKUP_ID"
```

**Checklist**:
- [ ] Backup ID saved to deployment notes
- [ ] Backup verified (appears in list)
- [ ] Team notified of backup creation
- [ ] Backup timestamp recorded

---

### 2. Restore Database from Backup

**Full Database Restore** (Complete data loss scenario):

```bash
# ⚠️ WARNING: This will replace ALL data in production database

# Step 1: Enable maintenance mode
curl -X POST https://api.coreflow360.com/api/admin/maintenance-mode \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{"enabled": true, "message": "Database restoration in progress"}'

# Step 2: List available backups
wrangler d1 backup list coreflow360-production

# Step 3: Choose backup to restore (most recent or specific)
BACKUP_ID="<backup-id-from-list>"

# Step 4: Restore database
wrangler d1 restore coreflow360-production $BACKUP_ID

# Step 5: Verify restoration
wrangler d1 execute coreflow360-production \
  --command "SELECT COUNT(*) as total FROM compliance_guidelines"

# Step 6: Test critical queries
wrangler d1 execute coreflow360-production \
  --command "SELECT * FROM users LIMIT 1"

wrangler d1 execute coreflow360-production \
  --command "SELECT * FROM businesses LIMIT 1"

# Step 7: Disable maintenance mode
curl -X POST https://api.coreflow360.com/api/admin/maintenance-mode \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{"enabled": false}'

# Step 8: Monitor application
# - Check error rates
# - Check user reports
# - Monitor for 30 minutes
```

**Estimated Time**: 30-60 minutes

---

### 3. Partial Data Recovery

**Restore Specific Table** (Selective recovery):

```bash
# Step 1: Create backup of current state (just in case)
wrangler d1 backup create coreflow360-production --name "pre-restore-$(date +%Y%m%d-%H%M)"

# Step 2: Export table from backup to SQL file
wrangler d1 export coreflow360-production --output backup-export.sql --backup-id $BACKUP_ID

# Step 3: Extract specific table data
# Manually edit backup-export.sql to keep only the table you need

# Step 4: Import specific table (careful - may overwrite existing data)
wrangler d1 import coreflow360-production backup-export-filtered.sql

# Step 5: Verify data
wrangler d1 execute coreflow360-production \
  --command "SELECT COUNT(*) FROM compliance_guidelines"
```

---

### 4. Point-in-Time Recovery

**Recover Data as of Specific Time**:

Cloudflare D1 backups are snapshots, not continuous. To recover to a specific time:

1. **Identify closest backup** before the incident
2. **Restore that backup** to staging
3. **Replay transactions** from audit log if needed
4. **Merge data** carefully into production

```bash
# Step 1: List backups around incident time
wrangler d1 backup list coreflow360-production

# Step 2: Restore to staging for analysis
wrangler d1 restore coreflow360-staging $BACKUP_ID

# Step 3: Compare staging vs production
# Identify missing/corrupted data

# Step 4: Export missing data from staging
wrangler d1 execute coreflow360-staging \
  --command "SELECT * FROM compliance_guidelines WHERE created_at > '2025-10-22 10:00:00'" \
  --output missing-data.json

# Step 5: Import missing data to production (carefully)
# Convert JSON to SQL INSERT statements
# Review and execute manually
```

---

## Application Recovery

### 1. Rollback Deployment

**Immediate Rollback** (application not functioning):

```bash
# List recent deployments
wrangler deployments list --limit 10

# Identify last known good deployment
GOOD_DEPLOYMENT_ID="<deployment-id>"

# Rollback backend
wrangler rollback $GOOD_DEPLOYMENT_ID

# Rollback frontend
wrangler pages deployments list --project-name=coreflow360-frontend
wrangler pages deployments rollback <FRONTEND_DEPLOYMENT_ID> \
  --project-name=coreflow360-frontend

# Verify rollback
curl -f https://api.coreflow360.com/health
curl -f https://coreflow360.com

# Monitor for 30 minutes
# Check error rates, response times, user reports
```

**Estimated Time**: 5-15 minutes

---

### 2. Redeploy from Source

**Complete Redeployment** (deployment history lost):

```bash
# Step 1: Clone repository (if needed)
git clone https://github.com/your-org/coreflow360-v4.git
cd coreflow360-v4

# Step 2: Checkout last known good commit
git checkout <COMMIT_HASH>
# Or use latest main if confident
git checkout main
git pull origin main

# Step 3: Install dependencies
npm ci

# Step 4: Run tests
npm run test
npm run test:e2e

# Step 5: Deploy backend
wrangler deploy --env production

# Step 6: Deploy frontend
cd frontend
npm ci
npm run build
wrangler pages publish dist --project-name=coreflow360-frontend --branch=production

# Step 7: Verify deployment
curl -f https://api.coreflow360.com/health
curl -f https://coreflow360.com

# Step 8: Run smoke tests
npm run test:smoke
```

**Estimated Time**: 20-30 minutes

---

### 3. Environment Variables Recovery

**Restore Secrets** (secrets lost or corrupted):

```bash
# List current secrets
wrangler secret list

# Re-add missing secrets (from secure vault documentation)
wrangler secret put JWT_SECRET
# Paste value from vault

wrangler secret put ANTHROPIC_API_KEY
# Paste value from vault

wrangler secret put OPENAI_API_KEY
# Paste value from vault

# ... repeat for all secrets

# Verify application starts
curl -f https://api.coreflow360.com/health
```

**Secret Vault Locations**:
- Engineering Lead: Secure password manager
- DevOps Lead: Secure password manager
- CTO: Secure backup location

---

## Data Recovery

### 1. Accidental Deletion Recovery

**User Accidentally Deleted Critical Data**:

```bash
# Step 1: Identify when deletion occurred
# Check audit logs
wrangler d1 execute coreflow360-production \
  --command "SELECT * FROM audit_log WHERE action = 'DELETE' AND resource = 'compliance_guideline' ORDER BY timestamp DESC LIMIT 10"

# Step 2: Find backup before deletion
wrangler d1 backup list coreflow360-production

# Step 3: Restore backup to staging
wrangler d1 restore coreflow360-staging $BACKUP_ID

# Step 4: Export deleted record from staging
wrangler d1 execute coreflow360-staging \
  --command "SELECT * FROM compliance_guidelines WHERE id = '<deleted-id>'" \
  --json > deleted-record.json

# Step 5: Re-insert record into production
# Convert JSON to SQL INSERT
# Carefully review and execute
```

---

### 2. Data Corruption Recovery

**Database Corruption Detected**:

```bash
# Step 1: Identify scope of corruption
# Run data integrity checks
wrangler d1 execute coreflow360-production \
  --command "PRAGMA integrity_check"

# Step 2: Enable maintenance mode
curl -X POST https://api.coreflow360.com/api/admin/maintenance-mode \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{"enabled": true}'

# Step 3: Create emergency backup
wrangler d1 backup create coreflow360-production \
  --name "emergency-corruption-$(date +%Y%m%d-%H%M)"

# Step 4: Restore from last known good backup
wrangler d1 restore coreflow360-production $GOOD_BACKUP_ID

# Step 5: Verify data integrity
wrangler d1 execute coreflow360-production \
  --command "PRAGMA integrity_check"

# Step 6: Test application
# Run critical queries
# Verify user can login and access data

# Step 7: Disable maintenance mode
curl -X POST https://api.coreflow360.com/api/admin/maintenance-mode \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{"enabled": false}'
```

---

### 3. Malicious Data Modification Recovery

**Unauthorized Data Changes Detected**:

```bash
# Step 1: Investigate via audit logs
wrangler d1 execute coreflow360-production \
  --command "SELECT * FROM audit_log WHERE timestamp > '<suspicious-time>' ORDER BY timestamp DESC"

# Step 2: Identify affected records
# From audit log, get list of modified resource IDs

# Step 3: Restore specific records from backup
# Follow "Partial Data Recovery" procedure above

# Step 4: Revoke compromised credentials
# Change passwords, rotate API keys, invalidate JWT tokens

# Step 5: Investigate security breach
# Follow security incident response plan (security-hardening.md)
```

---

## Disaster Scenarios

### Scenario 1: Complete Cloudflare Outage

**Symptom**: Cloudflare is down, application inaccessible

**Recovery Steps**:

1. **Verify Outage** (5 minutes):
```bash
# Check Cloudflare status
curl https://www.cloudflarestatus.com/api/v2/status.json

# Check if it's global or regional
ping your-worker-domain.workers.dev
```

2. **Communication** (10 minutes):
- Update status page (if hosted elsewhere)
- Post to Twitter/social media
- Email customers (if Cloudflare email working)

3. **Wait for Restoration**:
- Cloudflare SLA: 99.99% uptime
- Typical outage: < 1 hour
- Monitor Cloudflare status page

4. **Post-Outage Verification**:
```bash
# Verify all services restored
curl -f https://api.coreflow360.com/health
curl -f https://coreflow360.com

# Check error rates
curl https://api.coreflow360.com/api/metrics/errors?last=15m

# Run smoke tests
npm run test:smoke
```

**Estimated Downtime**: Dependent on Cloudflare (typically < 1 hour)

---

### Scenario 2: Database Completely Lost

**Symptom**: D1 database unrecoverable

**Recovery Steps**:

1. **Assess Situation** (15 minutes):
```bash
# Try to access database
wrangler d1 execute coreflow360-production --command "SELECT 1"

# Check for backups
wrangler d1 backup list coreflow360-production

# Contact Cloudflare support
```

2. **Restore from Latest Backup** (30-60 minutes):
```bash
# Get latest backup
LATEST_BACKUP=$(wrangler d1 backup list coreflow360-production | head -n 2 | tail -n 1 | awk '{print $1}')

# Restore
wrangler d1 restore coreflow360-production $LATEST_BACKUP

# Verify
wrangler d1 execute coreflow360-production \
  --command "SELECT COUNT(*) as users FROM users"
```

3. **Calculate Data Loss** (15 minutes):
```bash
# Find timestamp of backup
wrangler d1 backup list coreflow360-production | grep $LATEST_BACKUP

# Calculate data loss window
# If backup was from 2:00 AM and incident at 3:00 PM, data loss = 13 hours
```

4. **Notify Users** (if significant data loss):
```
Subject: Service Restoration - Data Loss Notice

We experienced a database failure and had to restore from backup.

Data Loss Window: [Start Time] to [End Time]
Affected: Data created/modified during this window may be lost

Actions taken: Database restored, monitoring in place
Next steps: We are investigating to prevent recurrence

We apologize for this inconvenience.
```

**Estimated RTO**: 1-2 hours
**Estimated RPO**: Up to 24 hours (if daily backup)

---

### Scenario 3: Ransomware Attack

**Symptom**: Data encrypted by ransomware, ransom demanded

**Recovery Steps**:

1. **DO NOT PAY RANSOM**

2. **Immediate Containment** (15 minutes):
```bash
# Disable all external access
# Revoke all API keys
# Force password reset for all users
# Enable maintenance mode

curl -X POST https://api.coreflow360.com/api/admin/maintenance-mode \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{"enabled": true, "message": "Security incident - service temporarily unavailable"}'
```

3. **Assess Damage** (30 minutes):
```bash
# Check what's encrypted
wrangler d1 execute coreflow360-production \
  --command "SELECT * FROM compliance_guidelines LIMIT 5"

# Check backups (ensure they're not encrypted)
wrangler d1 backup list coreflow360-production
```

4. **Restore from Clean Backup** (1-2 hours):
```bash
# Find backup before ransomware (may be days old)
CLEAN_BACKUP_ID="<pre-ransomware-backup>"

# Restore
wrangler d1 restore coreflow360-production $CLEAN_BACKUP_ID
```

5. **Security Investigation** (ongoing):
- Follow security incident response plan
- Identify entry point
- Patch vulnerabilities
- Engage cybersecurity firm if needed

6. **Legal & Compliance** (ongoing):
- Notify legal team
- File report with authorities
- Notify affected customers (GDPR requirement)
- Contact cyber insurance

**Estimated RTO**: 4-8 hours
**Estimated RPO**: Potentially days (if recent backups compromised)

---

### Scenario 4: Accidental Production Deletion

**Symptom**: Engineer accidentally deletes production environment

**Recovery Steps**:

1. **Stop Further Damage** (immediate):
```bash
# Revoke engineer's access immediately
# Prevent additional deletions
```

2. **Assess What's Deleted** (15 minutes):
```bash
# Check what still exists
wrangler deployments list
wrangler d1 list
wrangler kv:namespace list
```

3. **Recreate Infrastructure** (30-60 minutes):
```bash
# Recreate D1 database
wrangler d1 create coreflow360-production

# Recreate KV namespaces
wrangler kv:namespace create KV_CACHE
wrangler kv:namespace create KV_SESSION

# Update wrangler.toml with new IDs
```

4. **Restore Data** (30-60 minutes):
```bash
# Restore database from backup
wrangler d1 restore coreflow360-production $LATEST_BACKUP

# Redeploy application
wrangler deploy --env production
```

5. **Reconfigure Secrets** (15 minutes):
```bash
# Re-add all secrets
wrangler secret put JWT_SECRET
wrangler secret put ANTHROPIC_API_KEY
# ... etc
```

6. **Verify Restoration** (30 minutes):
```bash
# Test all critical functionality
npm run test:smoke

# Monitor for issues
```

**Estimated RTO**: 2-4 hours

---

## Recovery Testing

### Quarterly DR Drill

**Schedule**: Last Friday of each quarter

**Drill Procedure**:

1. **Preparation** (1 week before):
- [ ] Notify team of drill date and time
- [ ] Prepare drill scenario
- [ ] Document expected outcomes

2. **Execution** (2 hours):
```bash
# Create test environment
wrangler d1 create coreflow360-dr-test

# Restore latest production backup to test environment
wrangler d1 restore coreflow360-dr-test $LATEST_BACKUP

# Deploy application to test environment
wrangler deploy --env dr-test

# Test critical functionality
# - User login
# - Create/read/update/delete operations
# - Critical reports

# Measure recovery time (RTO)
START_TIME=$(date +%s)
# ... perform recovery ...
END_TIME=$(date +%s)
RECOVERY_TIME=$((END_TIME - START_TIME))
echo "Recovery Time: $RECOVERY_TIME seconds"
```

3. **Post-Drill Review** (1 hour):
- [ ] Document what worked well
- [ ] Identify issues encountered
- [ ] Update recovery procedures
- [ ] Train team on improvements

4. **Cleanup**:
```bash
# Delete test environment
wrangler d1 delete coreflow360-dr-test
```

---

## Business Continuity

### Communication Plan

**During Disaster**:

1. **Internal Communication**:
   - Slack: #incident channel
   - Email: All-hands update every 2 hours
   - Status: Update internal status page

2. **External Communication**:
   - Status page: Update every 30 minutes
   - Twitter: Major updates
   - Email: Customer notification if >2 hour outage

**Templates**:

**Status Page Update**:
```
🔴 Major Outage

We are currently experiencing a service outage affecting all users.

Started: 14:30 UTC
Impact: Complete service unavailable
Status: Investigating

Our team is actively working to restore service.

Next update: 15:00 UTC
```

**Customer Email**:
```
Subject: Service Outage - [Date]

We are writing to inform you of a service outage that occurred on [Date].

Outage Duration: [Start] to [End]
Impact: [Description]
Cause: [Brief explanation]
Resolution: [What we did]

Data Status: All customer data is secure. [No data loss / Data loss: X hours]

We sincerely apologize for this disruption and are taking steps to prevent future occurrences.

If you have any questions, please contact support@coreflow360.com

Best regards,
CoreFlow360 Team
```

---

### Backup Checklist

**Daily** (Automated):
- [ ] Database backup created (2:00 AM UTC)
- [ ] Backup verification script runs (2:15 AM UTC)
- [ ] Backup retention policy enforced (keep 30 days)

**Weekly** (Manual):
- [ ] Restore backup to staging
- [ ] Verify data integrity
- [ ] Document verification

**Monthly**:
- [ ] Review backup strategy
- [ ] Test recovery procedures
- [ ] Update documentation

**Quarterly**:
- [ ] Full DR drill
- [ ] Update recovery procedures
- [ ] Train team

**Annually**:
- [ ] Comprehensive DR test
- [ ] Review and update DR plan
- [ ] Audit compliance

---

## Contact Information

### Disaster Recovery Team

**Incident Commander**:
- Name: [Engineering Lead]
- Phone: [Phone]
- Email: [Email]

**Database Recovery**:
- Name: [Backend Engineer]
- Phone: [Phone]
- Email: [Email]

**Application Recovery**:
- Name: [DevOps Engineer]
- Phone: [Phone]
- Email: [Email]

### External Contacts

**Cloudflare Support**:
- Phone: Enterprise support number
- Email: Enterprise support email
- Portal: https://dash.cloudflare.com/support

**Cyber Insurance**:
- Provider: [Insurance Company]
- Policy #: [Policy Number]
- Emergency Contact: [Phone]

---

## Recovery Metrics

### Track Recovery Performance

| Metric | Target | Last Drill | Status |
|--------|--------|------------|--------|
| RTO (Recovery Time Objective) | 4 hours | 3.5 hours | ✅ |
| RPO (Recovery Point Objective) | 1 hour | 24 hours | ⚠️ |
| Backup Success Rate | 100% | 99.7% | ✅ |
| Recovery Test Success Rate | 100% | 100% | ✅ |

**Action Items from Last Drill**:
- [ ] Improve RPO: Investigate continuous backup solution
- [ ] Document recovery procedures for new team members
- [ ] Set up automated recovery testing

---

**Document Version**: 1.0
**Last Updated**: 2025-10-22
**Last DR Drill**: [Date]
**Next DR Drill**: [Date]
**Review Cycle**: Quarterly

**Hope for the best, prepare for the worst!** 🛡️
