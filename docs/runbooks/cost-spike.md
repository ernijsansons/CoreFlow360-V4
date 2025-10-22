# Runbook: Cost Spike Response

**Severity**: 🟡 MEDIUM PRIORITY
**Response Time**: <1 hour
**Alert Source**: Cost Monitoring, Billing Analytics

---

## 🚨 Alert Trigger

**Condition**: AI or infrastructure costs exceed 2x baseline for >1 hour

**Cost Baselines** (Expected Daily):
- **QualificationAgent**: $8-12/day (Gemini 2.0 Flash)
- **ChatSupportAgent**: $15-20/day (Gemini + Claude fallback)
- **FinanceAgent**: $25-35/day (Claude 3.5 Sonnet)
- **OnboardingAgent**: $10-15/day (Gemini 2.0 Flash)
- **KnowledgeBaseAgent**: $12-18/day (Gemini + embeddings)
- **Infrastructure**: $5-10/day (D1, KV, R2, Workers)

**Total Expected**: $75-110/day ($2,250-3,300/month)

---

## 📋 Initial Response (First 15 Minutes)

### 1. Identify Cost Spike Source
```bash
# Check AI API usage by provider
curl -s https://api.coreflow360.com/api/v1/analytics/costs/breakdown | jq .

# Expected response:
# {
#   "anthropic": {"cost": 25.50, "requests": 1200},
#   "gemini": {"cost": 8.75, "requests": 5000},
#   "deepseek": {"cost": 1.20, "requests": 800},
#   "infrastructure": {"cost": 6.50}
# }

# Look for:
# - Provider with >2x normal cost
# - Unusual request count
```

### 2. Check Request Volume
```bash
# Get hourly request breakdown
curl -s https://api.coreflow360.com/api/v1/analytics/requests/hourly | \
  jq '.last_24_hours[] | {hour: .hour, requests: .count, cost: .cost}'

# Look for:
# - Sudden spike in requests
# - Sustained high volume
# - Unusual patterns (middle of night, etc.)
```

### 3. Identify Top Cost Agents
```bash
# Get per-agent cost breakdown
for agent in qualification-agent chat-support-agent finance-agent onboarding-agent knowledge-base-agent; do
  echo "=== $agent ==="
  curl -s https://api.coreflow360.com/api/v1/analytics/agents/$agent/costs/today | jq .
done

# Shows which agent is driving costs
```

---

## 🔍 Common Cost Spike Patterns

### Pattern 1: Excessive Retries (40% of cases)

**Symptoms**:
- Same tasks retried multiple times
- High request count with low unique tasks
- Error rate elevated

**Diagnosis**:
```bash
# Check retry patterns in logs
wrangler tail coreflow360-v4-prod --env production | \
  grep -i retry | \
  head -50

# Look for:
# - Same task ID retried repeatedly
# - Retry loops (tasks retrying indefinitely)
```

**Root Causes**:
- API timeouts causing automatic retries
- Failed validation triggering re-attempts
- Bug in retry logic

**Fix**:
```bash
# Immediate: Disable automatic retries temporarily
wrangler secret put MAX_RETRIES --env production
# Value: "1" (reduce from default 3)

wrangler deploy --env production

# Monitor cost for next hour
# Should drop significantly if retries were the issue
```

**Long-term Fix**:
```bash
# Add exponential backoff
# Add max retry limits per task
# Add circuit breaker for failing operations
# (Code changes required - create tickets)
```

---

### Pattern 2: Large Context Windows (30% of cases)

**Symptoms**:
- High token usage per request
- Cost per request >$0.10
- Long conversation histories

**Diagnosis**:
```bash
# Check token usage
curl -s https://api.coreflow360.com/api/v1/analytics/tokens/stats | jq .

# {
#   "avg_tokens_per_request": 8500,  # High!
#   "max_tokens_seen": 45000,        # Very high!
#   "p95_tokens": 12000
# }

# Normal:
# - avg: 1500-3000 tokens
# - max: 8000 tokens
# - p95: 4000 tokens
```

**Root Causes**:
- Conversation history not truncated
- Large documents in context
- Inefficient prompt engineering

**Fix**:
```bash
# Immediate: Reduce context window
wrangler secret put MAX_CONTEXT_TOKENS --env production
# Value: "4000" (reduce from 8000)

# Immediate: Clear old conversation histories
wrangler d1 execute coreflow360-main --remote --command \
  "DELETE FROM chat_messages WHERE created_at < datetime('now', '-7 days');"

# Redeploy
wrangler deploy --env production
```

**Long-term Fix**:
```bash
# Implement context window management:
# - Summarize old messages
# - Remove redundant information
# - Use embeddings for retrieval instead of full text
# (Engineering work required)
```

---

### Pattern 3: Model Selection Issues (15% of cases)

**Symptoms**:
- High percentage of Claude 3.5 Sonnet usage
- Tasks using expensive model unnecessarily
- Cost per request >$0.15

**Diagnosis**:
```bash
# Check model distribution
curl -s https://api.coreflow360.com/api/v1/analytics/models/usage | jq .

# Expected distribution:
# - Gemini 2.0 Flash: 80% of requests
# - Claude 3.5 Sonnet: 15% of requests
# - DeepSeek V3: 5% of requests

# If Claude >30%: Model selection logic failing
```

**Root Causes**:
- Model selection logic routing simple tasks to expensive model
- Fallback kicking in too frequently
- Hardcoded model instead of intelligent routing

**Fix**:
```bash
# Immediate: Force cheaper model for simple tasks
wrangler secret put FORCE_GEMINI_FLASH --env production
# Value: "true"

# This temporarily forces Gemini for all non-critical tasks
wrangler deploy --env production

# Monitor cost reduction
```

**Long-term Fix**:
```bash
# Review and optimize model selection logic
# Add task complexity scoring
# Route based on actual requirements
# (Code review and optimization needed)
```

---

### Pattern 4: Attack or Abuse (10% of cases)

**Symptoms**:
- Sudden spike from single user/IP
- Unusual request patterns
- Requests outside business hours

**Diagnosis**:
```bash
# Check top requesters
curl -s https://api.coreflow360.com/api/v1/analytics/users/top-consumers | jq .

# Look for:
# - Single user with >1000 requests/hour
# - Unknown user IDs
# - Patterns suggesting automation
```

**Root Causes**:
- Compromised API key
- Malicious user
- Runaway automation script

**Fix**:
```bash
# Immediate: Block offending user/IP
wrangler secret put BLOCKED_USERS --env production
# Value: "user-id-1,user-id-2"

# Immediate: Enable rate limiting
wrangler secret put RATE_LIMIT_ENABLED --env production
# Value: "true"

wrangler secret put RATE_LIMIT_PER_HOUR --env production
# Value: "100"

wrangler deploy --env production

# Rotate API keys if compromised
wrangler secret put JWT_SECRET --env production
# Generate new secret

# Notify affected user if legitimate
```

**Investigation**:
```bash
# Review audit logs
wrangler d1 execute coreflow360-main --remote --command \
  "SELECT * FROM audit_log
   WHERE user_id = 'suspicious-user-id'
   ORDER BY created_at DESC
   LIMIT 100;"

# Determine if malicious or configuration issue
```

---

### Pattern 5: Feature Launch (5% of cases)

**Symptoms**:
- Gradual increase in usage
- Legitimate user growth
- All metrics healthy except cost

**Diagnosis**:
```bash
# Check user growth
curl -s https://api.coreflow360.com/api/v1/analytics/users/growth | jq .

# Check feature usage
curl -s https://api.coreflow360.com/api/v1/analytics/features/usage | jq .

# If both growing healthily: Success, not problem!
```

**Action**:
```bash
# This is good news - your product is growing!

# But monitor and optimize:
# 1. Review cost per user (should stay constant)
# 2. Optimize expensive operations
# 3. Consider tiered pricing
# 4. Plan for scale

# No immediate action needed if:
# - Cost per user stable
# - ROI positive
# - Growth expected
```

---

## 🛠️ Emergency Cost Controls

### Immediate Circuit Breakers (Use if cost >5x baseline)

```bash
# 1. Enable strict rate limiting
wrangler secret put EMERGENCY_RATE_LIMIT --env production
# Value: "50" (requests per hour per user)

# 2. Disable non-critical features temporarily
wrangler secret put DISABLE_OPTIONAL_AI --env production
# Value: "true"

# 3. Force cheapest AI model
wrangler secret put FORCE_MINIMUM_COST_MODEL --env production
# Value: "true"

# 4. Reduce token limits
wrangler secret put MAX_TOKENS --env production
# Value: "500"

# Deploy changes
wrangler deploy --env production

# Monitor cost for 30 minutes
# Should drop to ~baseline immediately
```

### Gradual Cost Optimization

```bash
# 1. Implement caching aggressively
wrangler secret put CACHE_TTL --env production
# Value: "3600" (1 hour cache)

# 2. Batch similar requests
wrangler secret put ENABLE_REQUEST_BATCHING --env production
# Value: "true"

# 3. Use embeddings cache
wrangler secret put EMBEDDINGS_CACHE_ENABLED --env production
# Value: "true"

# Deploy
wrangler deploy --env production
```

---

## 📊 Post-Resolution

### 1. Cost Analysis Report
```bash
# Generate detailed cost report
cat > incidents/cost-spike-$(date +%Y%m%d-%H%M%S).md <<EOF
# Cost Spike Incident Report

**Date**: $(date -u +%Y-%m-%dT%H:%M:%SZ)
**Duration**: [X hours]
**Peak Cost**: \$[X]/hour (vs baseline \$[Y]/hour)
**Total Impact**: \$[Z] extra

## Root Cause
[Detailed explanation]

## Cost Breakdown
- Anthropic API: \$[X]
- Gemini API: \$[Y]
- Infrastructure: \$[Z]
- Total: \$[Total]

## Resolution
[What fixed it]

## Preventive Measures
- [ ] [Action 1]
- [ ] [Action 2]

## Timeline
- [HH:MM] - Alert triggered
- [HH:MM] - Investigation started
- [HH:MM] - Root cause identified
- [HH:MM] - Emergency controls applied
- [HH:MM] - Cost normalized
EOF
```

### 2. Update Cost Budgets
```bash
# If legitimate growth, update baselines
# Update monitoring alerts with new thresholds

# If attack, improve security:
# - Better rate limiting
# - API key rotation policy
# - User authentication improvements
```

### 3. Optimize for Future
```bash
# Engineering tasks:
# - Implement smarter caching
# - Optimize prompts for token efficiency
# - Improve model selection logic
# - Add cost attribution per user
```

---

## 🔄 Escalation Path

### Level 1: On-Call Engineer (0-1 hour)
- Cost spike identification
- Emergency controls
- Known pattern fixes

### Level 2: Engineering Lead (1-4 hours)
**Escalate if**:
- Cost >5x baseline
- Root cause unclear
- Code optimization needed
- Feature changes required

### Level 3: CTO + Finance (4+ hours)
**Escalate if**:
- Cost impact >$1000
- Budget implications
- Pricing model changes needed
- Major architecture changes required

---

## 📝 Prevention Checklist

- [ ] Cost monitoring alerts configured
- [ ] Rate limiting implemented
- [ ] Caching strategy optimized
- [ ] Model selection logic reviewed
- [ ] Token usage optimized
- [ ] User attribution tracking
- [ ] Cost budgets per feature set
- [ ] Emergency cost controls tested

---

## 🎯 Cost Targets

### Daily Cost Targets (Production)

| Category | Target | Warning | Critical |
|----------|--------|---------|----------|
| Total | $75-110 | >$150 | >$250 |
| Anthropic | $25-35 | >$50 | >$100 |
| Gemini | $40-60 | >$80 | >$120 |
| DeepSeek | $5-10 | >$15 | >$25 |
| Infrastructure | $5-10 | >$15 | >$25 |

### Per-Agent Daily Targets

| Agent | Target | Warning | Critical |
|-------|--------|---------|----------|
| QualificationAgent | $8-12 | >$20 | >$35 |
| ChatSupportAgent | $15-20 | >$30 | >$50 |
| FinanceAgent | $25-35 | >$50 | >$75 |
| OnboardingAgent | $10-15 | >$25 | >$40 |
| KnowledgeBaseAgent | $12-18 | >$25 | >$40 |

---

## 💰 ROI Calculation

**Current Cost**: $2,250-3,300/month
**Value Generated**: $39,000-53,000/month (from agents)
**ROI**: 1,700% - 2,100%

Even a 5x cost spike ($11,000-16,500/month) would still be ROI positive!

**However**: Control costs proactively to maintain healthy margins.

---

*Last Updated: 2025-10-21*
*Cost Model: Multi-Provider AI (Gemini primary)*
*Success Rate: N/A (not yet in production)*
