# Runbook: High Error Rate Response

**Severity**: 🟠 HIGH PRIORITY
**Response Time**: <10 minutes
**Alert Source**: Cloudflare Workers Analytics, Error Rate Monitor

---

## 🚨 Alert Trigger

**Condition**: Agent error rate >10% for >5 minutes (sustained errors)

**Thresholds**:
- **Normal**: <2% error rate
- **Warning**: 2-5% error rate
- **High**: 5-10% error rate
- **Critical**: >10% error rate

---

## 📋 Initial Response (First 3 Minutes)

### 1. Identify Affected Agent(s)
```bash
# Check error rates for all agents
for agent in qualification-agent chat-support-agent finance-agent onboarding-agent knowledge-base-agent; do
  echo "=== $agent ==="
  curl -s https://api.coreflow360.com/agents/$agent/health | grep errorRate
done

# Output shows which agents have elevated errors
```

### 2. Check Recent Error Logs
```bash
# View last 100 errors
wrangler tail coreflow360-v4-prod --env production --format pretty | grep -i error | head -100

# Look for patterns:
# - Same error message repeated
# - Errors from specific capability
# - Errors at specific times
# - API-related errors
```

### 3. Determine Error Pattern
```bash
# Count errors by type
wrangler tail coreflow360-v4-prod --env production --format json | \
  grep error | \
  jq -r '.message' | \
  sort | uniq -c | sort -rn | head -10

# Shows top 10 error types
```

---

## 🔍 Common Error Patterns

### Pattern 1: API Rate Limiting (35% of cases)

**Symptoms**:
- Error messages: "429 Too Many Requests"
- Error messages: "Rate limit exceeded"
- Errors spike during high traffic

**Diagnosis**:
```bash
# Check Anthropic API usage
curl -s https://api.coreflow360.com/api/v1/analytics/ai-usage | \
  jq '.hourly_requests'

# Look for:
# - Requests near rate limit
# - Sudden spike in usage
```

**Fix**:
```bash
# Option 1: Enable rate limiting on our side
# Update environment variable
wrangler secret put AI_RATE_LIMIT --env production
# Set value: "50" (requests per minute)

# Option 2: Implement request queuing
# (Code change required - escalate to engineering)

# Option 3: Upgrade Anthropic tier
# (Business decision - escalate to management)
```

**Temporary Workaround**:
```bash
# Reduce concurrent agent executions
# Edit wrangler.toml and redeploy with lower concurrency
# [env.production]
# limits = { concurrency = 10 }  # Reduce from default

wrangler deploy --env production
```

---

### Pattern 2: Invalid Input Data (25% of cases)

**Symptoms**:
- Error messages: "Validation failed"
- Error messages: "Invalid input format"
- Errors occur on specific task types

**Diagnosis**:
```bash
# Find failed tasks in logs
wrangler tail coreflow360-v4-prod --env production --format json | \
  grep "Validation failed" | \
  jq '.task.input' | head -5

# Identify malformed inputs
```

**Fix**:
```bash
# If pattern identified, add input validation
# (Code change required)

# Temporary: Add input sanitization at API level
# Update API route to reject invalid formats early
```

**Immediate Action**:
```bash
# Document problematic input patterns
cat > incidents/invalid-inputs-$(date +%Y%m%d).json <<EOF
{
  "date": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "pattern": "describe pattern here",
  "examples": [
    "paste examples from logs"
  ]
}
EOF

# Create issue for engineering
# Title: "Add validation for [pattern] in [agent]"
```

---

### Pattern 3: Database Errors (20% of cases)

**Symptoms**:
- Error messages: "Database query failed"
- Error messages: "D1 timeout"
- Error messages: "SQLITE_BUSY"

**Diagnosis**:
```bash
# Check database query performance
wrangler d1 execute coreflow360-main --remote --command \
  "SELECT * FROM audit_log ORDER BY created_at DESC LIMIT 100;"

# Slow response = database issue
# Fast response = application-level issue
```

**Fix**:
```bash
# Check for long-running queries
wrangler tail coreflow360-v4-prod --env production | grep "D1"

# If SQLITE_BUSY errors:
# - Database locked by long transaction
# - Too many concurrent writes

# Solution: Add retry logic with exponential backoff
# (Code change required - escalate)

# Temporary: Reduce concurrent database operations
# Update worker to batch writes
```

**Immediate Action**:
```bash
# Clear any stuck locks (if safe to do so)
# Redeploy to reset database connections
wrangler deploy --env production
```

---

### Pattern 4: AI Model Errors (15% of cases)

**Symptoms**:
- Error messages: "AI model timeout"
- Error messages: "Claude API error"
- Error messages: "Invalid model response"

**Diagnosis**:
```bash
# Check Anthropic API status
curl https://status.anthropic.com/api/v2/summary.json | jq .

# Check our AI integration
wrangler tail coreflow360-v4-prod --env production | \
  grep "Claude" | grep -i error
```

**Fix**:
```bash
# If Anthropic API issue:
# - Check status.anthropic.com
# - Enable fallback to GPT-4 (if configured)

# If timeout issue:
# - Increase timeout in agent configuration
# - Add retry logic

# If invalid response:
# - Add response validation
# - Add fallback response generation
```

**Temporary Workaround**:
```bash
# Enable fallback model
wrangler secret put ENABLE_AI_FALLBACK --env production
# Set value: "true"

wrangler deploy --env production
```

---

### Pattern 5: Memory/Resource Limits (5% of cases)

**Symptoms**:
- Error messages: "Memory limit exceeded"
- Error messages: "CPU time exceeded"
- Errors on large inputs

**Diagnosis**:
```bash
# Check worker execution metrics
wrangler tail coreflow360-v4-prod --env production | \
  grep -E "(memory|cpu|exceeded)"

# Look for:
# - Specific task sizes that fail
# - Specific agents affected
```

**Fix**:
```bash
# Option 1: Optimize code (long-term)
# - Profile memory usage
# - Optimize large data processing

# Option 2: Add input size limits (immediate)
# Update API to reject inputs >X KB

# Option 3: Upgrade Workers plan
# (Business decision - higher memory limits)
```

---

## 🛠️ Resolution Steps

### Step 1: Immediate Mitigation (1-2 min)

```bash
# If errors are cascading, enable circuit breaker
# Set error threshold in environment
wrangler secret put ERROR_THRESHOLD --env production
# Value: "0.15" (15% error rate triggers circuit breaker)

# Circuit breaker will:
# - Return cached responses when possible
# - Return friendly error messages
# - Prevent cascade failures
```

### Step 2: Identify Root Cause (3-5 min)

```bash
# Create error analysis report
cat > incidents/error-analysis-$(date +%Y%m%d-%H%M%S).txt <<EOF
Error Analysis Report
=====================
Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)
Duration: [ongoing/X minutes]

Error Pattern:
$(wrangler tail coreflow360-v4-prod --env production | grep -i error | head -20)

Affected Agents:
[list agents with >5% error rate]

Common Error Messages:
[top 3 error messages]

Root Cause Hypothesis:
[best guess based on patterns]
EOF
```

### Step 3: Apply Fix (2-5 min)

Based on root cause, apply appropriate fix from patterns above.

### Step 4: Verify Fix (1-2 min)

```bash
# Monitor error rate for 2 minutes
for i in {1..12}; do
  echo "Check $i/12 ($(date +%H:%M:%S)):"
  curl -s https://api.coreflow360.com/agents/status | \
    jq '.agents[] | {name: .name, errorRate: .errorRate}'
  sleep 10
done

# Error rate should decrease to <5% within 2 minutes
```

---

## 📊 Post-Resolution

### 1. Document Incident
```bash
# Create detailed incident report
cat > incidents/high-error-rate-$(date +%Y%m%d-%H%M%S).md <<EOF
# Incident: High Error Rate

**Date**: $(date -u +%Y-%m-%dT%H:%M:%SZ)
**Duration**: [X minutes]
**Peak Error Rate**: [X%]
**Affected Agents**: [list]

## Root Cause
[Detailed explanation]

## Resolution
[What fixed it]

## Impact
- Requests affected: [count]
- Users affected: [count]
- Business impact: [description]

## Preventive Measures
- [ ] [Action item 1]
- [ ] [Action item 2]

## Timeline
- [HH:MM] - Alert triggered
- [HH:MM] - Investigation started
- [HH:MM] - Root cause identified
- [HH:MM] - Fix applied
- [HH:MM] - Error rate normalized
EOF
```

### 2. Update Monitoring
```bash
# If new error pattern discovered, add specific alert
# Example: Alert for specific error messages

# Update monitoring configuration
# Add pattern-specific thresholds
```

### 3. Create Follow-up Tasks
```bash
# Code improvements
# - Add better error handling
# - Add input validation
# - Optimize performance

# Monitoring improvements
# - Add specific error pattern alerts
# - Improve error message clarity
# - Add error categorization
```

---

## 🔄 Escalation Path

### Level 1: On-Call Engineer (0-10 min)
- Pattern identification
- Known error patterns
- Configuration fixes
- Temporary mitigations

### Level 2: Engineering Lead (10-20 min)
**Escalate if**:
- Unknown error pattern
- Code changes required
- Database performance issues
- Multiple mitigation attempts failed

### Level 3: CTO (20-30 min)
**Escalate if**:
- System-wide impact
- Business-critical functions affected
- External API issues
- Major architectural changes needed

---

## 📝 Prevention Checklist

- [ ] Error pattern documented
- [ ] Monitoring alert tuned
- [ ] Code fix scheduled (if needed)
- [ ] Input validation improved
- [ ] Rate limiting configured
- [ ] Circuit breaker tested
- [ ] Team notified of pattern
- [ ] Runbook updated

---

## 🎯 Success Criteria

**Incident Resolved When**:
- ✅ Error rate <2% for all agents
- ✅ No new errors of same type
- ✅ Root cause identified and documented
- ✅ Fix applied and verified
- ✅ Monitoring shows stable metrics

---

## 📈 Error Rate Targets

| Agent | Normal | Warning | Critical |
|-------|--------|---------|----------|
| QualificationAgent | <1% | 1-5% | >5% |
| ChatSupportAgent | <2% | 2-5% | >5% |
| FinanceAgent | <0.5% | 0.5-2% | >2% |
| OnboardingAgent | <3% | 3-7% | >7% |
| KnowledgeBaseAgent | <1% | 1-5% | >5% |

---

*Last Updated: 2025-10-21*
*Tested: Not yet in production*
*Success Rate: N/A*
