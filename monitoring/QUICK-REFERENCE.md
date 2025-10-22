# CoreFlow360 V4 - Monitoring Quick Reference

**Quick access guide for on-call engineers**

---

## Production URLs

```
Backend:  https://coreflow360-v4-prod.ernijs-ansons.workers.dev
Frontend: https://production.coreflow360-frontend.pages.dev
Health:   https://coreflow360-v4-prod.ernijs-ansons.workers.dev/health
```

---

## Emergency Commands

### Check System Health
```bash
curl https://coreflow360-v4-prod.ernijs-ansons.workers.dev/health
```

### View Live Logs
```bash
wrangler tail coreflow360-v4-prod --env production --format pretty
```

### Rollback Deployment
```bash
wrangler rollback --name coreflow360-v4-prod --message "Emergency rollback"
```

### Check Database
```bash
wrangler d1 execute coreflow360-agents --env production --command "SELECT 1"
```

---

## Alert Priority Response Times

| Priority | Response | Resolution | Notification |
|----------|----------|------------|-------------|
| **P0 Critical** | 5 min | 1 hour | PagerDuty + SMS + Slack |
| **P1 High** | 15 min | 4 hours | Slack + Email |
| **P2 Medium** | 1 hour | 24 hours | Slack |
| **P3 Low** | 4 hours | 7 days | Slack |

---

## Common Alert Responses

### Worker Down (P0)
1. Check health endpoint
2. View logs: `wrangler tail coreflow360-v4-prod --env production`
3. Check recent deployments: `wrangler deployments list`
4. Rollback if needed

### High Error Rate (P0)
1. Check Sentry: https://sentry.io/organizations/coreflow360/
2. View error distribution in logs
3. Identify affected endpoints
4. Deploy hotfix or rollback

### Database Unavailable (P0)
1. Check D1 status: https://www.cloudflarestatus.com/
2. Test connectivity: `wrangler d1 execute coreflow360-agents --command "SELECT 1"`
3. Enable degraded mode if needed
4. Queue writes for later

### Auth Failure Spike (P0)
1. Query failure patterns from logs
2. Check for distributed attack
3. Block suspicious IPs via WAF
4. Notify security team

### High Response Times (P1)
1. Check database query performance
2. Review cache hit rates
3. Identify slow endpoints
4. Optimize or add caching

---

## Key Metrics Targets

| Metric | Target | Alert Threshold |
|--------|--------|-----------------|
| API P95 Response | <200ms | >300ms |
| Error Rate | <0.1% | >1% |
| Cache Hit Rate | >80% | <60% |
| DB Query P95 | <50ms | >100ms |
| Worker CPU | <50ms | >100ms |
| Daily AI Cost | $120 | $80 warning, $120 critical |

---

## Escalation Chain

1. **On-Call Engineer** → Deploy fixes, restart services
2. **On-Call Lead** (after 30 min P0, 1 hr P1) → Architecture decisions
3. **Engineering Manager** (after 1 hr P0, 4 hrs P1) → Resource allocation
4. **CTO** (prolonged outages) → Business decisions

---

## Notification Channels

- **PagerDuty:** https://coreflow360.pagerduty.com/
- **Slack:** #production-alerts
- **Email:** oncall@coreflow360.com
- **SMS:** Configured in PagerDuty

---

## Useful Queries

### Recent Errors
```sql
SELECT timestamp, module, error_type, error_message, COUNT(*) as count
FROM log_entries
WHERE level='ERROR' AND timestamp > datetime('now', '-1 hour')
GROUP BY error_type, error_message
ORDER BY count DESC
LIMIT 20;
```

### Slow Endpoints
```sql
SELECT path, COUNT(*) as requests, AVG(latency_ms) as avg_latency
FROM log_entries
WHERE timestamp > datetime('now', '-1 hour')
GROUP BY path
ORDER BY avg_latency DESC
LIMIT 20;
```

### Active Alerts
```sql
SELECT id, title, severity, triggered_at
FROM alerts
WHERE status='firing'
ORDER BY severity, triggered_at DESC;
```

### AI Cost Today
```sql
SELECT ai_provider, ai_model, SUM(cost_cents)/100.0 as cost_usd
FROM cost_tracking
WHERE timestamp > datetime('now', 'start of day')
GROUP BY ai_provider, ai_model
ORDER BY cost_usd DESC;
```

---

## Cloudflare Resources

### Dashboard
https://dash.cloudflare.com/

### Account Details
- **Account ID:** d2897bdebfa128919bd89b265e6a712e
- **Worker:** coreflow360-v4-prod
- **D1 DB:** coreflow360-agents (c56bb204-78bc-4357-a704-419aa9f11e6f)

### Support
- **Phone:** +1 888 99 FLARE
- **Email:** enterprise-support@cloudflare.com
- **Status:** https://www.cloudflarestatus.com/

---

## Quick Diagnostics

### Is the worker responding?
```bash
curl -v https://coreflow360-v4-prod.ernijs-ansons.workers.dev/health
```
**Expected:** 200 OK with health status

### Are requests being processed?
```bash
wrangler tail coreflow360-v4-prod --env production | head -20
```
**Expected:** Request logs appearing in real-time

### Is the database accessible?
```bash
wrangler d1 execute coreflow360-agents --env production --command "SELECT datetime('now')"
```
**Expected:** Current timestamp returned

### Are users authenticated?
```bash
curl -H "Authorization: Bearer test_token" \
  https://coreflow360-v4-prod.ernijs-ansons.workers.dev/api/user/profile
```
**Expected:** 401 (auth working) or 200 (valid token)

---

## Communication Templates

### P0 Incident Started
```
🚨 P0 INCIDENT STARTED
Service: [service name]
Impact: [description]
Started: [time]
Team: Working on resolution
Updates: Every 15 minutes
```

### P0 Incident Resolved
```
✅ P0 INCIDENT RESOLVED
Service: [service name]
Duration: [X hours Y minutes]
Resolution: [brief description]
Postmortem: Will be shared within 24 hours
```

### Maintenance Window
```
🔧 SCHEDULED MAINTENANCE
Window: [date/time]
Duration: [expected]
Impact: [description]
Updates: [frequency]
```

---

## File Locations

All monitoring files located at:
```
C:\Users\ernij\OneDrive\Documents\CoreFlow360 V4\monitoring\
```

**Key Files:**
- `production-monitoring-config.json` - Metrics and thresholds
- `alerting-rules.json` - Alert configuration
- `observability-dashboard-spec.json` - Dashboard definitions
- `PRODUCTION-RUNBOOK.md` - Detailed procedures (24 KB)
- `MONITORING-IMPLEMENTATION-GUIDE.md` - Setup guide (21 KB)

---

## After-Hours Emergency

If unable to resolve within SLA:

1. **Escalate to on-call lead**
2. **Page backup on-call if no response**
3. **Document all actions taken**
4. **Keep stakeholders updated**

**Remember:** When in doubt, escalate early!

---

**Print this page and keep it handy during on-call shifts**
