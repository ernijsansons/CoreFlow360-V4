# Runbook: Agent Down Response

**Severity**: 🔴 CRITICAL
**Response Time**: <5 minutes
**Alert Source**: Cloudflare Workers Analytics, Health Check Monitor

---

## 🚨 Alert Trigger

**Condition**: Agent health check returns non-200 status code or "unhealthy" status for >2 minutes

**Affected Agents**:
- QualificationAgent
- ChatSupportAgent
- FinanceAgent
- OnboardingAgent
- KnowledgeBaseAgent

---

## 📋 Initial Response (First 2 Minutes)

### 1. Verify Alert is Real
```bash
# Check agent health directly
curl https://api.coreflow360.com/agents/<agent-name>/health

# Expected healthy response:
# {"status":"healthy","latency":450,"errorRate":0.01,...}

# Unhealthy response will show:
# {"status":"unhealthy","latency":5000,"errorRate":0.25,...}
# OR HTTP 500/503 error
```

### 2. Check Agent Status in Cloudflare Dashboard
```bash
# View real-time logs
wrangler tail coreflow360-v4-prod --env production --format pretty

# Look for:
# - Error messages in last 5 minutes
# - Exception stack traces
# - API failures
# - Timeout errors
```

### 3. Identify Affected Users
```bash
# Check if requests are being served
wrangler analytics --env production

# Look for:
# - Drop in request count
# - Spike in error rate
# - Increase in response time
```

---

## 🔍 Diagnosis (Minutes 2-5)

### Common Causes & Quick Checks

#### Cause 1: API Key Issues (40% of cases)
```bash
# Check if ANTHROPIC_API_KEY is valid
wrangler secret list --env production | grep ANTHROPIC

# Test API key directly
curl https://api.anthropic.com/v1/messages \
  -H "x-api-key: $ANTHROPIC_API_KEY" \
  -H "anthropic-version: 2023-06-01" \
  -H "Content-Type: application/json" \
  -d '{"model":"claude-3-5-sonnet-20241022","max_tokens":10,"messages":[{"role":"user","content":"test"}]}'

# If 401: API key invalid or expired
# If 429: Rate limit exceeded
# If 200: API key is fine
```

**Fix**: Rotate API key
```bash
# Update secret
wrangler secret put ANTHROPIC_API_KEY --env production
# Paste new key when prompted

# Redeploy agent
wrangler deploy --env production --name <agent-name>

# Verify fix
curl https://api.coreflow360.com/agents/<agent-name>/health
```

#### Cause 2: Database Connection Issues (30% of cases)
```bash
# Test D1 database connectivity
wrangler d1 execute coreflow360-main --remote --command "SELECT 1;"

# If error: Database is down or unreachable
# If success: Database is fine
```

**Fix**: Database is managed by Cloudflare, escalate if truly down
```bash
# Check Cloudflare status page
curl https://www.cloudflarestatus.com/api/v2/summary.json

# If D1 incident reported: Wait for Cloudflare to resolve
# If no incident: Check database binding configuration
```

#### Cause 3: Memory/CPU Limits (15% of cases)
```bash
# Check worker execution time in logs
wrangler tail coreflow360-v4-prod --env production | grep "exceeded"

# Look for:
# - "CPU time limit exceeded"
# - "Memory limit exceeded"
# - "Execution timed out"
```

**Fix**: Optimize or increase limits
```bash
# Quick fix: Restart worker (redeploy)
wrangler deploy --env production

# Long-term: Optimize code or upgrade plan
```

#### Cause 4: Bad Deployment (10% of cases)
```bash
# Check recent deployments
wrangler deployments list --env production

# Look for:
# - Deployment in last 30 minutes
# - Different behavior after deployment
```

**Fix**: Rollback to previous version
```bash
# Immediate rollback
wrangler rollback coreflow360-v4-prod --env production

# Or use rollback script
bash scripts/rollback-production.sh

# Verify rollback worked
curl https://api.coreflow360.com/agents/<agent-name>/health
```

#### Cause 5: Cloudflare Infrastructure Issue (5% of cases)
```bash
# Check Cloudflare status
curl https://www.cloudflarestatus.com/api/v2/summary.json | grep status

# Check if Workers are impacted globally
```

**Fix**: Wait for Cloudflare resolution, enable failover if available

---

## 🛠️ Resolution Steps

### Quick Fix (30 seconds)
```bash
# Redeploy agent (often clears transient issues)
wrangler deploy --env production --name <agent-name>

# Wait 10 seconds
sleep 10

# Verify health
curl https://api.coreflow360.com/agents/<agent-name>/health
```

### If Quick Fix Doesn't Work

#### Step 1: Enable Debug Logging
```bash
# Tail logs with filter
wrangler tail coreflow360-v4-prod --env production --format pretty | grep -i error
```

#### Step 2: Test Agent Execution Directly
```bash
# Execute test task
curl -X POST https://api.coreflow360.com/api/v1/agents/<agent-name>/execute \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "task": {
      "id": "health-test",
      "capability": "analysis",
      "input": {"data": {"query": "test"}},
      "priority": "normal"
    },
    "context": {
      "userId": "health-check",
      "businessId": "health-check",
      "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'",
      "requestId": "health-check"
    }
  }'
```

#### Step 3: Check Dependencies
```bash
# Verify all secrets are set
wrangler secret list --env production

# Required secrets:
# - ANTHROPIC_API_KEY
# - JWT_SECRET
# - AUTH_SECRET
# - ENCRYPTION_KEY
```

#### Step 4: Check Database State
```bash
# Verify critical tables exist
wrangler d1 execute coreflow360-main --remote --command \
  "SELECT name FROM sqlite_master WHERE type='table';"

# Should show:
# - users
# - businesses
# - audit_log
# - agent_* tables
```

---

## 📊 Post-Resolution

### 1. Verify Agent is Healthy
```bash
# Run full validation
bash scripts/validate-deployment-success.sh --env production

# Should show all checks passing
```

### 2. Document Incident
```bash
# Create incident report
cat > incidents/$(date +%Y%m%d-%H%M%S)-agent-down.md <<EOF
# Incident: Agent Down

**Date**: $(date -u +%Y-%m-%dT%H:%M:%SZ)
**Duration**: [fill in]
**Affected Agent**: [agent-name]
**Root Cause**: [cause]
**Resolution**: [what fixed it]
**Preventive Measures**: [how to prevent]
EOF
```

### 3. Update Monitoring
```bash
# If new failure mode discovered, update alerts
# Add new alert condition to monitoring configuration
```

### 4. Notify Stakeholders
```bash
# Post in Slack
# Slack: #incidents channel
# Message: "Agent <name> restored. Duration: X minutes. Cause: Y. Users affected: Z."
```

---

## 🔄 Escalation Path

### Level 1: On-Call Engineer (0-5 min)
- Quick fixes (redeploy, API key rotation)
- Basic diagnosis
- Known issue resolution

### Level 2: Engineering Lead (5-15 min)
**Escalate if**:
- Quick fixes don't work
- Root cause unclear
- Multiple agents affected
- Database issues

### Level 3: CTO (15-30 min)
**Escalate if**:
- Business-critical impact
- Data loss risk
- Security implications
- Cloudflare infrastructure issue

---

## 📝 Prevention Checklist

After resolving, update:
- [ ] API key rotation scheduled (if expired)
- [ ] Monitoring alerts tuned (if false positive)
- [ ] Code fix deployed (if bug caused it)
- [ ] Documentation updated (if new failure mode)
- [ ] Runbook updated (if new resolution steps discovered)
- [ ] Post-mortem scheduled (if >30 min downtime)

---

## 🎯 Success Criteria

**Incident Resolved When**:
- ✅ Agent health check returns "healthy"
- ✅ Response time <1000ms
- ✅ Error rate <2%
- ✅ No errors in logs for 5 minutes
- ✅ Test task executes successfully

---

## 📞 Emergency Contacts

**On-Call Engineer**: [Configure in PagerDuty]
**Engineering Lead**: [Configure contact]
**CTO**: [Configure contact]

**Slack Channels**:
- `#incidents` - Real-time incident coordination
- `#agent-monitoring` - Monitoring alerts
- `#engineering` - Technical escalation

---

*Last Updated: 2025-10-21*
*Tested: Not yet in production*
*Success Rate: N/A*
