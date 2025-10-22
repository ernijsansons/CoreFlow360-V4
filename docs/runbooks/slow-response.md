# Runbook: Slow Response Time

**Severity**: 🟡 MEDIUM PRIORITY
**Response Time**: <15 minutes
**Alert Source**: Performance Monitoring, Response Time Analytics

---

## 🚨 Alert Trigger

**Condition**: P95 response time >3000ms for >10 minutes

**Response Time Targets**:
- **QualificationAgent**: <500ms (p95)
- **ChatSupportAgent**: <800ms (p95)
- **FinanceAgent**: <1000ms (p95)
- **OnboardingAgent**: <1500ms (p95)
- **KnowledgeBaseAgent**: <600ms (p95)

**Alert Thresholds**:
- **Warning**: 2x target for 5 minutes
- **Critical**: 3x target for 10 minutes

---

## 📋 Initial Response (First 5 Minutes)

### 1. Identify Affected Agent(s)
```bash
# Check response times for all agents
for agent in qualification-agent chat-support-agent finance-agent onboarding-agent knowledge-base-agent; do
  echo "=== $agent ==="
  curl -s https://api.coreflow360.com/agents/$agent/health | \
    jq '{name: .name, latency: .latency, target: .target}'
done

# Output shows which agents are slow
```

### 2. Check Current Load
```bash
# Get request rate
curl -s https://api.coreflow360.com/api/v1/analytics/requests/rate | jq .

# {
#   "requests_per_minute": 250,
#   "concurrent_executions": 45,
#   "queue_depth": 12
# }

# High load indicators:
# - requests_per_minute >500
# - concurrent_executions >100
# - queue_depth >50
```

### 3. Quick Latency Breakdown
```bash
# Get latency by component
curl -s https://api.coreflow360.com/api/v1/analytics/latency/breakdown | jq .

# {
#   "api_overhead": 50ms,
#   "database_queries": 200ms,
#   "ai_model_calls": 2500ms,  # Likely culprit if high
#   "business_logic": 100ms
# }
```

---

## 🔍 Common Slow Response Patterns

### Pattern 1: AI API Latency (50% of cases)

**Symptoms**:
- Latency spike correlates with AI calls
- No database slowdown
- Error rate normal

**Diagnosis**:
```bash
# Check Anthropic/Gemini API latency
wrangler tail coreflow360-v4-prod --env production | \
  grep "AI response time" | \
  tail -20

# Look for:
# - Response times >2000ms
# - Timeouts
# - Slow model responses
```

**Root Causes**:
- Anthropic/Gemini API experiencing slowdown
- Large prompts requiring more processing
- Model overloaded during peak hours

**Fix**:
```bash
# Option 1: Reduce prompt size
wrangler secret put MAX_PROMPT_TOKENS --env production
# Value: "2000" (reduce from 4000)

# Option 2: Increase timeout and enable caching
wrangler secret put AI_TIMEOUT_MS --env production
# Value: "10000" (10 seconds)

wrangler secret put ENABLE_RESPONSE_CACHE --env production
# Value: "true"

# Option 3: Add parallel processing for independent requests
# (Code change required)

wrangler deploy --env production
```

**Temporary Workaround**:
```bash
# Use faster model temporarily
wrangler secret put TEMPORARY_FAST_MODEL --env production
# Value: "gemini-2.0-flash-exp" (faster than Sonnet)

wrangler deploy --env production

# Monitor latency - should improve within 2 minutes
```

---

### Pattern 2: Database Slowdown (25% of cases)

**Symptoms**:
- Database query time elevated
- D1 response slow
- Affects all agents equally

**Diagnosis**:
```bash
# Test database response time
time wrangler d1 execute coreflow360-main --remote --command "SELECT COUNT(*) FROM users;"

# Normal: <100ms
# Slow: 500-1000ms
# Critical: >1000ms

# Check for slow queries in logs
wrangler tail coreflow360-v4-prod --env production | \
  grep "D1 query" | \
  grep -E "(slow|[0-9]{4,}ms)"
```

**Root Causes**:
- Missing indexes on frequently queried columns
- Large table scans
- Too many concurrent connections
- Database lock contention

**Fix**:
```bash
# Immediate: Add indexes for slow queries
wrangler d1 execute coreflow360-main --remote --command \
  "CREATE INDEX IF NOT EXISTS idx_audit_log_user_id ON audit_log(user_id);"

wrangler d1 execute coreflow360-main --remote --command \
  "CREATE INDEX IF NOT EXISTS idx_chat_messages_session_id ON chat_messages(session_id);"

# Check common slow queries and index them
```

**Optimization**:
```bash
# Enable query caching
wrangler secret put DB_CACHE_ENABLED --env production
# Value: "true"

wrangler secret put DB_CACHE_TTL --env production
# Value: "300" (5 minutes)

wrangler deploy --env production
```

**Long-term Fix**:
```bash
# Analyze query patterns
wrangler d1 execute coreflow360-main --remote --command \
  "SELECT * FROM sqlite_stat1;"

# Optimize slow queries
# Add compound indexes where needed
# Consider denormalization for read-heavy tables
```

---

### Pattern 3: Cold Start Issues (15% of cases)

**Symptoms**:
- First request slow, subsequent fast
- Happens after idle periods
- P50 fast, P95 slow (high variance)

**Diagnosis**:
```bash
# Check response time distribution
curl -s https://api.coreflow360.com/api/v1/analytics/latency/percentiles | jq .

# {
#   "p50": 450ms,   # Fast
#   "p95": 2500ms,  # Slow - indicates cold starts
#   "p99": 4000ms   # Very slow
# }

# If p95/p50 ratio >4: Cold start problem
```

**Root Causes**:
- Workers spinning down during idle
- Database connections not pooled
- Cache cleared

**Fix**:
```bash
# Option 1: Keep workers warm with cron
# Add to wrangler.toml:
# [triggers]
# crons = ["*/5 * * * *"]  # Ping every 5 minutes

# Option 2: Optimize cold start performance
# - Lazy load dependencies
# - Cache connections
# - Precompute common responses

# Option 3: Use Durable Objects for persistence
# (Architecture change - long-term)
```

**Immediate Action**:
```bash
# Create warm-up cron job
cat > src/routes/warmup.ts <<EOF
export async function warmup(env: Env) {
  // Ping all agents to keep warm
  const agents = ['qualification', 'chat-support', 'finance', 'onboarding', 'knowledge-base'];
  await Promise.all(agents.map(agent =>
    fetch(\`https://api.coreflow360.com/agents/\${agent}-agent/health\`)
  ));
  return new Response('OK');
}
EOF

# Deploy
wrangler deploy --env production
```

---

### Pattern 4: High Concurrent Load (8% of cases)

**Symptoms**:
- Latency correlates with request volume
- All components slower
- Queue depth increasing

**Diagnosis**:
```bash
# Check concurrent executions
curl -s https://api.coreflow360.com/api/v1/analytics/concurrency | jq .

# {
#   "current_concurrent": 95,
#   "max_concurrent": 100,  # Near limit!
#   "queued_requests": 45,
#   "avg_queue_time": 1200ms
# }

# If at concurrency limit: Need to scale
```

**Root Causes**:
- Traffic spike
- Slow-running tasks blocking others
- Insufficient concurrency limits

**Fix**:
```bash
# Immediate: Increase concurrency limit
# Edit wrangler.toml:
# [env.production]
# limits = { concurrency = 200 }  # Increase from 100

wrangler deploy --env production

# Immediate: Add request queuing with priority
wrangler secret put ENABLE_REQUEST_QUEUE --env production
# Value: "true"

wrangler secret put QUEUE_PRIORITY_ENABLED --env production
# Value: "true"

# High-priority requests (FinanceAgent) processed first
```

**Load Shedding** (if overwhelming):
```bash
# Enable graceful degradation
wrangler secret put ENABLE_LOAD_SHEDDING --env production
# Value: "true"

wrangler secret put LOAD_SHEDDING_THRESHOLD --env production
# Value: "0.9" (Shed at 90% capacity)

# Returns 503 for low-priority requests when overloaded
wrangler deploy --env production
```

---

### Pattern 5: Memory/CPU Intensive Operations (2% of cases)

**Symptoms**:
- Specific tasks very slow
- CPU time warnings in logs
- Memory usage high

**Diagnosis**:
```bash
# Check for CPU time warnings
wrangler tail coreflow360-v4-prod --env production | \
  grep -i "cpu\|memory"

# Look for:
# - "CPU time exceeded" warnings
# - Large data processing operations
# - Complex computations
```

**Root Causes**:
- Inefficient algorithms
- Processing large datasets
- Unoptimized code paths

**Fix**:
```bash
# Immediate: Add size limits
wrangler secret put MAX_INPUT_SIZE --env production
# Value: "50000" (50KB max input)

# Immediate: Offload heavy processing
# Use Queues for async processing
# Use Durable Objects for stateful processing

wrangler deploy --env production
```

**Long-term Optimization**:
```bash
# Profile code to find hotspots
# Optimize algorithms
# Cache expensive computations
# Use streaming where possible
```

---

## 🛠️ Quick Optimization Checklist

### Immediate Actions (< 5 min)

```bash
# 1. Enable aggressive caching
wrangler secret put CACHE_AGGRESSIVE --env production
# Value: "true"

# 2. Reduce AI token limits
wrangler secret put MAX_TOKENS --env production
# Value: "1000"

# 3. Enable parallel processing
wrangler secret put PARALLEL_REQUESTS --env production
# Value: "true"

# 4. Increase timeouts
wrangler secret put REQUEST_TIMEOUT --env production
# Value: "15000"

# Deploy
wrangler deploy --env production
```

### Database Optimization (< 10 min)

```bash
# Add critical indexes
wrangler d1 execute coreflow360-main --remote --command "
  CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
  CREATE INDEX IF NOT EXISTS idx_businesses_user ON businesses(user_id);
  CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at);
  CREATE INDEX IF NOT EXISTS idx_chat_session ON chat_messages(session_id, created_at);
"

# Vacuum database
wrangler d1 execute coreflow360-main --remote --command "VACUUM;"

# Analyze for query planner
wrangler d1 execute coreflow360-main --remote --command "ANALYZE;"
```

---

## 📊 Post-Resolution

### 1. Performance Report
```bash
# Generate performance analysis
cat > incidents/slow-response-$(date +%Y%m%d-%H%M%S).md <<EOF
# Performance Incident Report

**Date**: $(date -u +%Y-%m-%dT%H:%M:%SZ)
**Duration**: [X minutes]
**Peak Latency**: [Xms] (vs target [Yms])
**Affected Agents**: [list]

## Root Cause
[Detailed explanation]

## Latency Breakdown
- API overhead: [X]ms
- Database: [Y]ms
- AI calls: [Z]ms
- Business logic: [W]ms

## Resolution
[What fixed it]

## Performance Improvements
- Before: p95 = [X]ms
- After: p95 = [Y]ms
- Improvement: [Z]%

## Preventive Measures
- [ ] [Action 1]
- [ ] [Action 2]
EOF
```

### 2. Update Performance Baselines
```bash
# If permanent improvement, update targets
# Update monitoring alerts with new baselines
```

### 3. Optimization Tasks
```bash
# Create tickets for:
# - Code optimization
# - Database tuning
# - Caching improvements
# - Architecture enhancements
```

---

## 🔄 Escalation Path

### Level 1: On-Call Engineer (0-15 min)
- Quick diagnostics
- Cache/config optimizations
- Known performance fixes

### Level 2: Engineering Lead (15-60 min)
**Escalate if**:
- Performance degradation >50%
- Root cause unclear
- Code optimization needed
- Database performance issues

### Level 3: CTO + Architecture (60+ min)
**Escalate if**:
- Architectural changes needed
- Scalability limits reached
- Major refactoring required

---

## 📝 Prevention Checklist

- [ ] Performance baselines documented
- [ ] Monitoring alerts configured
- [ ] Caching strategy optimized
- [ ] Database indexes created
- [ ] Load testing completed
- [ ] Auto-scaling configured
- [ ] Performance budget defined
- [ ] Code profiling regular

---

## 🎯 Performance Targets

### Response Time Targets (P95)

| Agent | Target | Warning | Critical |
|-------|--------|---------|----------|
| QualificationAgent | <500ms | >1000ms | >2000ms |
| ChatSupportAgent | <800ms | >1600ms | >3000ms |
| FinanceAgent | <1000ms | >2000ms | >3500ms |
| OnboardingAgent | <1500ms | >3000ms | >5000ms |
| KnowledgeBaseAgent | <600ms | >1200ms | >2500ms |

### Component Latency Targets

| Component | Target | Maximum |
|-----------|--------|---------|
| API overhead | <50ms | <100ms |
| Database queries | <100ms | <300ms |
| AI model calls | <1000ms | <3000ms |
| Business logic | <50ms | <150ms |

---

## 💡 Performance Optimization Tips

### Caching Strategy
1. **Cache AI responses** for identical inputs (30-60 min TTL)
2. **Cache database queries** for read-heavy data (5-10 min TTL)
3. **Cache embeddings** for knowledge base (24 hour TTL)

### Database Optimization
1. **Add indexes** for all WHERE clauses
2. **Use compound indexes** for multi-column queries
3. **Denormalize** read-heavy tables
4. **Batch writes** where possible

### AI Call Optimization
1. **Reduce prompt size** - remove unnecessary context
2. **Use streaming** for long responses
3. **Batch similar requests** together
4. **Cache embeddings** aggressively

---

*Last Updated: 2025-10-21*
*Tested: Not yet in production*
*Performance Model: Multi-tier caching + optimized AI calls*
