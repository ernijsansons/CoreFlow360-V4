# Production Runbooks

**Purpose**: Step-by-step incident response procedures for CoreFlow360 V4 production environment

**Last Updated**: 2025-10-21

---

## 📚 Available Runbooks

### 🔴 Critical Severity

#### [Agent Down](./agent-down.md)
**When to use**: Agent health check failing, returns non-200 or "unhealthy" status

**Response time**: <5 minutes
**Common causes**:
- API key issues (40%)
- Database connection problems (30%)
- Memory/CPU limits (15%)
- Bad deployment (10%)
- Infrastructure issues (5%)

**Quick fix**: Redeploy agent
```bash
wrangler deploy --env production --name <agent-name>
```

---

### 🟠 High Priority

#### [High Error Rate](./high-error-rate.md)
**When to use**: Error rate >10% for >5 minutes

**Response time**: <10 minutes
**Common causes**:
- API rate limiting (35%)
- Invalid input data (25%)
- Database errors (20%)
- AI model errors (15%)
- Resource limits (5%)

**Quick fix**: Enable circuit breaker
```bash
wrangler secret put ERROR_THRESHOLD --env production
# Value: "0.15"
wrangler deploy --env production
```

---

### 🟡 Medium Priority

#### [Cost Spike](./cost-spike.md)
**When to use**: AI or infrastructure costs exceed 2x baseline for >1 hour

**Response time**: <1 hour
**Common causes**:
- Excessive retries (40%)
- Large context windows (30%)
- Model selection issues (15%)
- Attack/abuse (10%)
- Legitimate growth (5%)

**Quick fix**: Reduce retries and context
```bash
wrangler secret put MAX_RETRIES --env production  # Value: "1"
wrangler secret put MAX_CONTEXT_TOKENS --env production  # Value: "4000"
wrangler deploy --env production
```

---

#### [Slow Response Time](./slow-response.md)
**When to use**: P95 response time >3x target for >10 minutes

**Response time**: <15 minutes
**Common causes**:
- AI API latency (50%)
- Database slowdown (25%)
- Cold start issues (15%)
- High concurrent load (8%)
- CPU-intensive operations (2%)

**Quick fix**: Enable aggressive caching
```bash
wrangler secret put CACHE_AGGRESSIVE --env production  # Value: "true"
wrangler secret put MAX_TOKENS --env production  # Value: "1000"
wrangler deploy --env production
```

---

## 🚨 Emergency Response

### Incident Response Checklist

#### 1. Alert Received (0-2 min)
- [ ] Acknowledge alert in PagerDuty/Slack
- [ ] Open runbook for incident type
- [ ] Note start time for SLA tracking

#### 2. Initial Assessment (2-5 min)
- [ ] Verify alert is real (not false positive)
- [ ] Identify affected components
- [ ] Check impact (users, requests, revenue)
- [ ] Determine severity level

#### 3. Investigation (5-15 min)
- [ ] Follow runbook diagnosis steps
- [ ] Check logs for patterns
- [ ] Identify root cause
- [ ] Document findings

#### 4. Resolution (15-30 min)
- [ ] Apply quick fix from runbook
- [ ] Verify fix worked
- [ ] Monitor for 5-10 minutes
- [ ] Document resolution

#### 5. Post-Incident (30-60 min)
- [ ] Create incident report
- [ ] Update monitoring/alerts
- [ ] Create follow-up tasks
- [ ] Notify stakeholders
- [ ] Update runbook if needed

---

## 📞 Escalation Matrix

### Response Times by Severity

| Severity | Acknowledgment | Initial Response | Resolution Target |
|----------|---------------|------------------|-------------------|
| 🔴 Critical | <2 min | <5 min | <30 min |
| 🟠 High | <5 min | <10 min | <1 hour |
| 🟡 Medium | <15 min | <30 min | <4 hours |
| 🟢 Low | <1 hour | <4 hours | <24 hours |

### Escalation Path

```
Level 1: On-Call Engineer
  ↓ (if unresolved in 15 min for critical, 30 min for high)
Level 2: Engineering Lead
  ↓ (if unresolved in 30 min for critical, 1 hour for high)
Level 3: CTO + Senior Leadership
```

### Contact Information

**On-Call Engineer**:
- PagerDuty: [Configure rotation]
- Slack: `@oncall`
- Phone: [Configure]

**Engineering Lead**:
- Slack: `@eng-lead`
- Phone: [Configure]
- Email: eng-lead@coreflow360.com

**CTO**:
- Slack: `@cto`
- Phone: [Emergency only]
- Email: cto@coreflow360.com

---

## 🛠️ Common Commands

### Health Checks
```bash
# Check all agents
for agent in qualification-agent chat-support-agent finance-agent onboarding-agent knowledge-base-agent; do
  echo "=== $agent ==="
  curl https://api.coreflow360.com/agents/$agent/health
done

# Run full validation
bash scripts/validate-deployment-success.sh --env production
```

### Logs & Monitoring
```bash
# View real-time logs
wrangler tail coreflow360-v4-prod --env production --format pretty

# Filter for errors
wrangler tail coreflow360-v4-prod --env production | grep -i error

# View specific agent logs
wrangler tail coreflow360-v4-prod --env production | grep "agent-name"
```

### Quick Fixes
```bash
# Redeploy all agents
bash scripts/deploy-production-agents.sh --env production

# Redeploy specific agent
wrangler deploy --env production --name <agent-name>

# Rollback to previous version
wrangler rollback coreflow360-v4-prod --env production

# Update secret
wrangler secret put <SECRET_NAME> --env production
```

### Database Operations
```bash
# Test database connection
wrangler d1 execute coreflow360-main --remote --command "SELECT 1;"

# Check table status
wrangler d1 execute coreflow360-main --remote --command \
  "SELECT name FROM sqlite_master WHERE type='table';"

# Add index
wrangler d1 execute coreflow360-main --remote --command \
  "CREATE INDEX IF NOT EXISTS idx_name ON table(column);"

# Vacuum database
wrangler d1 execute coreflow360-main --remote --command "VACUUM;"
```

---

## 📊 Monitoring Dashboards

### Primary Dashboards
- **Operations**: https://dash.coreflow360.com/agents/operations
- **Business Metrics**: https://dash.coreflow360.com/agents/business
- **Cost Analysis**: https://dash.coreflow360.com/agents/costs

### Cloudflare Dashboards
- **Workers Analytics**: https://dash.cloudflare.com/
- **D1 Database**: https://dash.cloudflare.com/
- **Logs**: wrangler tail

### Third-Party Monitoring
- **Sentry**: [Configure URL]
- **Datadog**: [Configure URL]
- **PagerDuty**: [Configure URL]

---

## 📝 Incident Templates

### Incident Report Template
```markdown
# Incident Report: [Title]

**Date**: [YYYY-MM-DD HH:MM UTC]
**Severity**: [Critical/High/Medium/Low]
**Duration**: [X minutes/hours]
**Status**: [Investigating/Resolved/Monitoring]

## Impact
- Affected users: [count or percentage]
- Affected agents: [list]
- Request failures: [count]
- Revenue impact: [$X]

## Timeline
- [HH:MM] - Alert triggered
- [HH:MM] - Investigation started
- [HH:MM] - Root cause identified
- [HH:MM] - Fix applied
- [HH:MM] - Incident resolved

## Root Cause
[Detailed technical explanation]

## Resolution
[What fixed the issue]

## Preventive Measures
- [ ] [Action item 1]
- [ ] [Action item 2]
- [ ] [Action item 3]

## Follow-up Tasks
- [ ] [Engineering task]
- [ ] [Documentation update]
- [ ] [Monitoring improvement]
```

---

## 🎓 Training & Onboarding

### New Team Member Checklist
- [ ] Read all 4 runbooks
- [ ] Get access to Cloudflare dashboard
- [ ] Get access to Slack channels
- [ ] Get added to PagerDuty rotation
- [ ] Practice incident response in staging
- [ ] Shadow on-call engineer for 1 week
- [ ] Complete first on-call shift with backup

### Runbook Drills (Monthly)
- [ ] Simulate agent down scenario
- [ ] Practice rollback procedure
- [ ] Test escalation chain
- [ ] Review recent incidents
- [ ] Update runbooks with learnings

---

## 📚 Additional Resources

### Documentation
- [Production Monitoring Guide](../../PRODUCTION_MONITORING_GUIDE.md)
- [Deployment Guide](../../DEPLOYMENT_COMPLETE_GUIDE.md)
- [Architecture Overview](../../CLAUDE.md)

### External Resources
- [Cloudflare Workers Docs](https://developers.cloudflare.com/workers/)
- [Cloudflare D1 Docs](https://developers.cloudflare.com/d1/)
- [Anthropic API Docs](https://docs.anthropic.com/)
- [Wrangler CLI Docs](https://developers.cloudflare.com/workers/wrangler/)

### Status Pages
- [Cloudflare Status](https://www.cloudflarestatus.com/)
- [Anthropic Status](https://status.anthropic.com/)

---

## 🔄 Runbook Maintenance

### Review Schedule
- **Weekly**: Review new incidents and update as needed
- **Monthly**: Full runbook review and drill
- **Quarterly**: Update escalation contacts and procedures
- **Annually**: Major revision based on year's incidents

### Update Process
1. Identify gap or improvement during incident
2. Document proposed change
3. Review with team
4. Update runbook
5. Test updated procedure
6. Train team on changes

### Version Control
All runbooks are version controlled in git:
```bash
# View runbook history
git log -- docs/runbooks/

# See what changed
git diff HEAD~1 docs/runbooks/agent-down.md
```

---

## ✅ Pre-Deployment Verification

Before deploying new agents or major changes:

- [ ] All runbooks reviewed and updated
- [ ] Emergency contacts verified
- [ ] Monitoring alerts configured
- [ ] Escalation path tested
- [ ] Rollback procedure tested
- [ ] Team trained on new components

---

**Questions or improvements?**
Contact: eng-lead@coreflow360.com or #engineering on Slack

---

*Last Updated: 2025-10-21*
*Version: 1.0.0*
*Next Review: 2025-11-21*
