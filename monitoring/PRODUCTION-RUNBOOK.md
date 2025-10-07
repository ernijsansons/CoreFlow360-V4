# CoreFlow360 V4 - Production Runbook

**Version:** 1.0.0
**Last Updated:** 2025-10-06
**Platform:** Cloudflare Workers + Pages
**Environment:** Production

---

## Table of Contents

1. [Quick Reference](#quick-reference)
2. [System Overview](#system-overview)
3. [Alert Response Procedures](#alert-response-procedures)
4. [Common Issues & Resolutions](#common-issues--resolutions)
5. [Troubleshooting Guides](#troubleshooting-guides)
6. [Escalation Procedures](#escalation-procedures)
7. [Emergency Contacts](#emergency-contacts)

---

## Quick Reference

### Production URLs
- **Backend API:** https://coreflow360-v4-prod.ernijs-ansons.workers.dev
- **Frontend:** https://production.coreflow360-frontend.pages.dev
- **Monitoring Dashboard:** https://dash.cloudflare.com/
- **Sentry:** https://sentry.io/organizations/coreflow360/

### Key Commands
```bash
# Check worker status
curl https://coreflow360-v4-prod.ernijs-ansons.workers.dev/health

# View worker logs (requires wrangler)
wrangler tail coreflow360-v4-prod --env production

# Check database status
wrangler d1 execute coreflow360-agents --env production --command "SELECT 1"

# View recent deployments
wrangler deployments list --name coreflow360-v4-prod
```

### SLA Targets
| Priority | Response Time | Resolution Time |
|----------|--------------|-----------------|
| P0 Critical | 5 minutes | 1 hour |
| P1 High | 15 minutes | 4 hours |
| P2 Medium | 1 hour | 24 hours |
| P3 Low | 4 hours | 7 days |

---

## System Overview

### Architecture Components

#### Cloudflare Workers
- **Production Worker:** coreflow360-v4-prod
- **CPU Limit:** 50ms per request (soft), 128MB memory
- **Concurrency:** Unbounded (auto-scaling)
- **Regions:** Global edge network

#### D1 Databases
- **Primary:** coreflow360-agents (c56bb204-78bc-4357-a704-419aa9f11e6f)
- **Analytics:** mustbeviral-db (4cdeab75-a1b4-477e-a92c-de996065578c)
- **Limits:** 5M reads/day, 1M writes/day

#### KV Namespaces
- **KV_CACHE:** General application cache
- **KV_SESSION:** User sessions
- **KV_AUTH:** Authentication tokens
- **AGENT_CACHE:** AI agent response cache
- **AGENT_MEMORY:** AI agent persistent memory

#### R2 Buckets
- **R2_DOCUMENTS:** Document storage
- **R2_BACKUPS:** Database backups

### Monitoring Stack
- **Cloudflare Analytics:** Real-time metrics
- **Sentry:** Error tracking and performance monitoring
- **Custom Telemetry:** D1-based observability system

---

## Alert Response Procedures

### P0 CRITICAL Alerts

#### ALERT: Worker Service Down

**Symptoms:**
- Health check endpoint returning 500 or timing out
- No traffic being processed
- User reports of complete service unavailability

**Immediate Actions (5 min response):**

1. **Verify the issue:**
   ```bash
   # Check worker status
   curl -v https://coreflow360-v4-prod.ernijs-ansons.workers.dev/health

   # Check Cloudflare dashboard
   # Navigate to Workers & Pages > coreflow360-v4-prod
   ```

2. **Check recent deployments:**
   ```bash
   wrangler deployments list --name coreflow360-v4-prod

   # If recent deployment looks suspicious, rollback:
   wrangler rollback --name coreflow360-v4-prod --message "Rolling back due to P0 incident"
   ```

3. **View live logs:**
   ```bash
   wrangler tail coreflow360-v4-prod --env production --format pretty
   ```

4. **Check Cloudflare status:**
   - Visit: https://www.cloudflarestatus.com/
   - Check for platform-wide issues

**Resolution Steps:**

- **If deployment issue:** Rollback to last known good version
- **If code error:** Check Sentry for error patterns, deploy hotfix
- **If Cloudflare issue:** Monitor status page, communicate with users
- **If resource exhaustion:** Check CPU/memory metrics, optimize or scale

**Post-Incident:**
- Document root cause
- Update postmortem template
- Schedule retrospective within 48 hours

---

#### ALERT: D1 Database Unavailable

**Symptoms:**
- Database queries timing out
- 500 errors on endpoints requiring DB access
- D1 availability metric below 99%

**Immediate Actions:**

1. **Verify database status:**
   ```bash
   # Test database connectivity
   wrangler d1 execute coreflow360-agents --env production --command "SELECT 1"

   # Check database metrics
   wrangler d1 info coreflow360-agents --env production
   ```

2. **Check Cloudflare D1 status:**
   - https://www.cloudflarestatus.com/
   - Look for D1-specific incidents

3. **Review recent migrations:**
   ```bash
   wrangler d1 migrations list coreflow360-agents --env production
   ```

4. **Check for long-running queries:**
   - Review telemetry logs for slow queries
   - Check `database_query_time` metric for spikes

**Resolution Steps:**

- **If Cloudflare outage:** Wait for resolution, enable degraded mode if available
- **If migration issue:** Rollback migration if safe
- **If connection pool exhausted:** Restart worker to reset connections
- **If query performance:** Identify and kill long-running queries, add indexes

**Degraded Mode:**
If database is unavailable for >15 minutes:
1. Enable read-only mode
2. Serve cached data where possible
3. Queue writes for later processing
4. Communicate status to users

---

#### ALERT: Authentication Failure Spike

**Symptoms:**
- Sudden spike in authentication failures (>50 in 5 min)
- Multiple failed login attempts from same IP
- Possible credential stuffing attack

**Immediate Actions:**

1. **Analyze failure patterns:**
   ```bash
   # Query recent auth failures
   wrangler d1 execute DB --env production --command \
     "SELECT ip_address, COUNT(*) as attempts, reason
      FROM log_entries
      WHERE level='ERROR' AND module='auth'
        AND timestamp > datetime('now', '-15 minutes')
      GROUP BY ip_address, reason
      ORDER BY attempts DESC
      LIMIT 20"
   ```

2. **Check for distributed attack:**
   - Review IP distribution in logs
   - Check if attempts are geographically distributed
   - Look for patterns in usernames being targeted

3. **Enable enhanced protection:**
   - Increase rate limits temporarily
   - Enable CAPTCHA on login page
   - Block suspicious IP ranges via WAF

4. **Notify security team:**
   - Send incident report to security@coreflow360.com
   - Include IP addresses, attempt counts, patterns

**Resolution Steps:**

- **If credential stuffing:** Block attacking IPs, notify affected users, force password resets
- **If DDoS:** Enable Cloudflare DDoS protection, adjust rate limits
- **If legitimate spike:** Investigate root cause (password reset campaign, etc.)

**Preventive Actions:**
- Enable MFA for all affected accounts
- Review and strengthen rate limiting rules
- Add additional monitoring for attack patterns

---

#### ALERT: High Error Rate (>5%)

**Symptoms:**
- API error rate above 5%
- Multiple endpoints returning errors
- User experience severely degraded

**Immediate Actions:**

1. **Identify error sources:**
   ```bash
   # View error distribution
   wrangler tail coreflow360-v4-prod --env production | grep ERROR
   ```

2. **Check Sentry for error grouping:**
   - Visit Sentry dashboard
   - Look for error spikes by type
   - Identify common stack traces

3. **Analyze affected endpoints:**
   - Query telemetry for endpoints with high error rates
   - Determine if specific to certain operations

4. **Check dependencies:**
   - AI provider status (Anthropic, OpenAI)
   - External API status
   - Database availability

**Resolution Steps:**

- **If code regression:** Identify commit, rollback deployment
- **If external dependency:** Enable fallbacks, communicate degradation
- **If rate limiting:** Adjust limits or implement backoff
- **If data issue:** Identify and fix bad data, add validation

**Mitigation:**
1. Deploy hotfix if code issue
2. Enable circuit breakers for failing services
3. Implement graceful degradation
4. Communicate status to users

---

### P1 HIGH Alerts

#### ALERT: API Response Time High (P95 >300ms)

**Symptoms:**
- API responses slower than acceptable
- User complaints about sluggish performance
- P95 latency above 300ms for 5+ minutes

**Investigation Steps:**

1. **Identify slow endpoints:**
   - Check observability dashboard for endpoint-specific latency
   - Review `api_response_time` metric by endpoint

2. **Analyze database queries:**
   ```bash
   # Query slow database operations
   wrangler d1 execute DB --env production --command \
     "SELECT query_type, table, AVG(latency_ms) as avg_latency, COUNT(*) as count
      FROM log_entries
      WHERE timestamp > datetime('now', '-1 hour')
        AND latency_ms > 100
      GROUP BY query_type, table
      ORDER BY avg_latency DESC"
   ```

3. **Check cache performance:**
   - Review `cache_hit_rate` metric
   - Identify cache misses causing DB queries

4. **Review AI agent calls:**
   - Check if AI agent invocations are causing delays
   - Review AI provider latency metrics

**Resolution Steps:**

- **If database slow:** Add indexes, optimize queries, review execution plans
- **If cache issues:** Warm cache, increase cache TTL, fix cache invalidation
- **If AI latency:** Implement timeout, use faster model, add caching
- **If worker CPU:** Optimize hot code paths, implement lazy loading

**Optimization Actions:**
1. Add query caching for repeated operations
2. Implement request coalescing for duplicate calls
3. Add database indexes for slow queries
4. Consider using Workers KV for frequently accessed data

---

#### ALERT: Cache Hit Rate Low (<60%)

**Symptoms:**
- Cache hit rate below target of 80%
- Increased database load
- Slower response times

**Investigation Steps:**

1. **Analyze cache patterns:**
   - Review cache metrics by namespace
   - Identify which cache types have low hit rates

2. **Check cache TTL settings:**
   - Verify TTL values are appropriate
   - Look for premature cache evictions

3. **Review cache invalidation:**
   - Check if cache is being invalidated too frequently
   - Identify patterns in cache misses

**Resolution Steps:**

- **If TTL too short:** Increase TTL for stable data
- **If cache eviction:** Increase cache size or implement tiered caching
- **If invalidation excessive:** Review invalidation logic, use fine-grained keys
- **If new traffic patterns:** Warm cache for new patterns

**Optimization:**
1. Implement cache warming on deployment
2. Add predictive caching for common queries
3. Use cache tags for efficient invalidation
4. Monitor cache size and eviction rates

---

#### ALERT: Worker CPU Usage High (>100ms)

**Symptoms:**
- Worker CPU time exceeding 100ms
- Potential timeout risks
- Performance degradation

**Investigation Steps:**

1. **Profile worker performance:**
   - Review Sentry performance traces
   - Identify CPU-intensive operations

2. **Check for expensive operations:**
   - Large JSON parsing
   - Complex calculations
   - Inefficient loops

3. **Review recent code changes:**
   - Check if new features added expensive operations
   - Review deployment timeline vs CPU spike

**Resolution Steps:**

- **If JSON parsing:** Implement streaming parsing, reduce payload size
- **If calculations:** Move to async processing, use Workers KV for results
- **If loops:** Optimize algorithms, implement pagination
- **If AI processing:** Move to background queue, implement batching

**Optimization:**
1. Use Web Workers for CPU-intensive tasks
2. Implement request batching
3. Add result caching
4. Consider Durable Objects for stateful operations

---

### P2 MEDIUM Alerts

#### ALERT: KV Storage Usage High (>85%)

**Symptoms:**
- KV namespace approaching storage limits
- Potential data loss risk if limit exceeded

**Investigation Steps:**

1. **Check namespace usage:**
   ```bash
   # List KV namespaces and sizes
   wrangler kv:namespace list
   ```

2. **Identify large keys:**
   - Review stored data patterns
   - Look for large cached objects

3. **Check data retention:**
   - Verify TTL is set correctly
   - Identify expired data not being cleaned up

**Resolution Steps:**

- **If old data:** Implement cleanup job to remove expired entries
- **If large objects:** Compress data, move to R2, reduce cache size
- **If retention issue:** Adjust TTL, implement LRU eviction
- **If legitimate growth:** Request limit increase from Cloudflare

**Prevention:**
1. Implement automatic cleanup jobs
2. Add monitoring for storage growth
3. Set appropriate TTLs on all keys
4. Consider data compression for large objects

---

## Common Issues & Resolutions

### Issue: Intermittent 500 Errors

**Symptoms:**
- Random 500 errors across various endpoints
- Errors not consistently reproducible
- No clear pattern in logs

**Troubleshooting:**

1. **Check for race conditions:**
   - Review concurrent request handling
   - Look for shared state issues

2. **Review error logs in Sentry:**
   - Group errors by stack trace
   - Look for common patterns

3. **Check external dependencies:**
   - Verify all external services are responding
   - Look for timeout errors

**Solutions:**
- Add retry logic with exponential backoff
- Implement circuit breakers for external calls
- Add request ID tracking for debugging
- Improve error logging with context

---

### Issue: Slow Database Queries

**Symptoms:**
- Database queries taking >100ms consistently
- P95 query time elevated
- User complaints about slow page loads

**Troubleshooting:**

1. **Identify slow queries:**
   ```sql
   SELECT query_type, table, AVG(latency_ms), COUNT(*)
   FROM log_entries
   WHERE latency_ms > 100
     AND timestamp > datetime('now', '-1 hour')
   GROUP BY query_type, table
   ORDER BY AVG(latency_ms) DESC
   ```

2. **Check indexes:**
   ```sql
   -- List indexes on table
   SELECT * FROM sqlite_master WHERE type='index' AND tbl_name='your_table'
   ```

3. **Review query patterns:**
   - Look for N+1 query problems
   - Identify missing joins
   - Check for full table scans

**Solutions:**
- Add indexes for commonly filtered/joined columns
- Implement query batching
- Add caching layer for frequently accessed data
- Optimize SQL queries (use EXPLAIN)

---

### Issue: Memory Leaks

**Symptoms:**
- Worker memory usage increasing over time
- Eventual crashes or slowdowns
- Errors related to memory limits

**Troubleshooting:**

1. **Review memory usage patterns:**
   - Check `worker_memory_usage` metric over time
   - Look for gradual increases

2. **Check for resource cleanup:**
   - Verify connections are closed
   - Ensure event listeners are removed
   - Check for retained references

3. **Review caching logic:**
   - Look for unbounded cache growth
   - Check cache eviction policies

**Solutions:**
- Implement proper resource cleanup
- Add memory monitoring
- Use WeakMap for cached objects
- Implement cache size limits
- Consider using Durable Objects for persistent state

---

## Troubleshooting Guides

### Debugging Worker Issues

**Step 1: Enable Detailed Logging**
```bash
# Tail logs with full context
wrangler tail coreflow360-v4-prod --env production --format json > logs.json
```

**Step 2: Reproduce Locally**
```bash
# Run worker in local development mode
wrangler dev --env production --remote

# Test specific endpoint
curl -X POST http://localhost:8787/api/endpoint -H "Content-Type: application/json" -d '{"test":"data"}'
```

**Step 3: Check Sentry for Errors**
- Visit Sentry dashboard
- Filter by environment=production
- Review error groupings and stack traces

**Step 4: Review Recent Changes**
```bash
# Check recent deployments
git log --oneline -10

# Compare with production
git diff production HEAD
```

---

### Debugging Database Issues

**Step 1: Verify Connectivity**
```bash
wrangler d1 execute coreflow360-agents --env production --command "SELECT datetime('now')"
```

**Step 2: Check Query Performance**
```sql
-- Get query execution plan
EXPLAIN QUERY PLAN
SELECT * FROM your_table WHERE condition;

-- Check table statistics
SELECT * FROM sqlite_stat1 WHERE tbl='your_table';
```

**Step 3: Review Recent Migrations**
```bash
wrangler d1 migrations list coreflow360-agents --env production
```

**Step 4: Analyze Slow Queries**
```sql
-- Find queries taking >100ms in last hour
SELECT
  module,
  capability,
  AVG(latency_ms) as avg_latency,
  COUNT(*) as count
FROM log_entries
WHERE timestamp > datetime('now', '-1 hour')
  AND latency_ms > 100
GROUP BY module, capability
ORDER BY avg_latency DESC
LIMIT 20;
```

---

### Debugging Cache Issues

**Step 1: Check Cache Hit Rate**
```bash
# Query cache metrics
wrangler kv:key get "cache_metrics:hit_rate" --namespace-id=62253644abcf4ce78558fbd764b366fb
```

**Step 2: Verify Cache Keys**
```bash
# List cache keys
wrangler kv:key list --namespace-id=62253644abcf4ce78558fbd764b366fb --prefix="user:"
```

**Step 3: Test Cache Operations**
```bash
# Set test key
wrangler kv:key put "test:key" "test value" --namespace-id=62253644abcf4ce78558fbd764b366fb

# Get test key
wrangler kv:key get "test:key" --namespace-id=62253644abcf4ce78558fbd764b366fb

# Delete test key
wrangler kv:key delete "test:key" --namespace-id=62253644abcf4ce78558fbd764b366fb
```

**Step 4: Review Cache TTL Settings**
- Check code for TTL configuration
- Verify cache expiration is working correctly
- Look for premature evictions

---

## Escalation Procedures

### When to Escalate

#### P0 Critical - Immediate Escalation
- Service completely down for >15 minutes
- Security breach detected
- Data loss or corruption
- Unable to resolve within 30 minutes

#### P1 High - Escalate after 1 hour
- Performance degradation persisting >1 hour
- High error rates not resolved
- Database issues affecting multiple services

#### P2 Medium - Escalate after 4 hours
- Resource issues not resolved
- Cache performance degradation
- Non-critical functionality impaired

### Escalation Chain

**Level 1: On-Call Engineer**
- Primary contact for all alerts
- Response time: 5 minutes (P0), 15 minutes (P1)
- Authority: Deploy hotfixes, restart services, rollback

**Level 2: On-Call Lead**
- Escalated after 30 minutes (P0) or 1 hour (P1)
- Authority: Architecture decisions, service degradation approvals
- Contact: oncall-lead@coreflow360.com

**Level 3: Engineering Manager**
- Escalated after 1 hour (P0) or 4 hours (P1)
- Authority: Resource allocation, external vendor contact
- Contact: eng-manager@coreflow360.com

**Level 4: CTO**
- Escalated for prolonged outages or major incidents
- Authority: Business decisions, customer communication
- Contact: cto@coreflow360.com

### External Vendor Escalation

**Cloudflare Enterprise Support**
- Phone: +1 888 99 FLARE (+1 888 993 5273)
- Email: enterprise-support@cloudflare.com
- Portal: https://support.cloudflare.com/
- Account ID: d2897bdebfa128919bd89b265e6a712e

**Anthropic Support (AI Services)**
- Email: support@anthropic.com
- Dashboard: https://console.anthropic.com/
- Status: https://status.anthropic.com/

**OpenAI Support (AI Services)**
- Dashboard: https://platform.openai.com/
- Status: https://status.openai.com/

---

## Emergency Contacts

### On-Call Schedule
**Primary On-Call:** See PagerDuty schedule
**Backup On-Call:** See PagerDuty schedule

### Notification Channels
- **Slack:** #production-alerts
- **PagerDuty:** https://coreflow360.pagerduty.com/
- **Email:** oncall@coreflow360.com
- **SMS:** Configured in PagerDuty

### Key Personnel
| Role | Name | Contact | Availability |
|------|------|---------|-------------|
| CTO | TBD | TBD | 24/7 for P0 |
| VP Engineering | TBD | TBD | Business hours |
| Lead DevOps | TBD | TBD | On-call rotation |
| Security Lead | TBD | TBD | 24/7 for security |

---

## Post-Incident Procedures

### Immediate Actions (Within 1 hour of resolution)
1. **Update status page**
2. **Send all-clear notification**
3. **Document timeline in incident log**
4. **Create draft postmortem**

### Follow-Up Actions (Within 24 hours)
1. **Complete postmortem document**
2. **Schedule postmortem meeting**
3. **Create action items in tracking system**
4. **Update runbook with learnings**

### Postmortem Template
```markdown
# Incident Postmortem

## Incident Summary
- **Date:** YYYY-MM-DD
- **Duration:** X hours Y minutes
- **Severity:** P0/P1/P2
- **Impact:** Description of user impact

## Timeline
- HH:MM - Event 1
- HH:MM - Event 2
- ...

## Root Cause
Detailed explanation of what caused the incident

## Resolution
Steps taken to resolve the incident

## Action Items
1. [ ] Action item 1 (Owner, Due date)
2. [ ] Action item 2 (Owner, Due date)

## Lessons Learned
What went well, what didn't, what we learned
```

---

## Maintenance Windows

### Scheduled Maintenance
- **Standard Window:** Sunday 2:00 AM - 6:00 AM UTC
- **Emergency Window:** Any time with 2-hour notice
- **Notification:** 48 hours advance notice via email/Slack

### Pre-Maintenance Checklist
- [ ] Notify users 48 hours in advance
- [ ] Update status page
- [ ] Test rollback procedures
- [ ] Verify backup strategy
- [ ] Prepare runbook for maintenance steps
- [ ] Assign on-call coverage

### During Maintenance
- [ ] Update status page with progress
- [ ] Monitor error rates and performance
- [ ] Execute changes incrementally
- [ ] Verify each step before proceeding
- [ ] Keep communication channel open

### Post-Maintenance
- [ ] Verify all services operational
- [ ] Monitor for 2 hours post-maintenance
- [ ] Update status page - all clear
- [ ] Document any issues encountered
- [ ] Send completion notification

---

## Useful Queries

### Recent Errors
```sql
SELECT
  timestamp,
  module,
  capability,
  error_type,
  error_message,
  COUNT(*) as occurrences
FROM log_entries
WHERE level = 'ERROR'
  AND timestamp > datetime('now', '-1 hour')
GROUP BY error_type, error_message
ORDER BY occurrences DESC
LIMIT 20;
```

### Performance by Endpoint
```sql
SELECT
  path,
  COUNT(*) as requests,
  AVG(latency_ms) as avg_latency,
  MIN(latency_ms) as min_latency,
  MAX(latency_ms) as max_latency
FROM log_entries
WHERE timestamp > datetime('now', '-1 hour')
  AND path IS NOT NULL
GROUP BY path
ORDER BY requests DESC
LIMIT 20;
```

### Active Alerts
```sql
SELECT
  id,
  title,
  severity,
  status,
  triggered_at,
  metric_value,
  threshold_value
FROM alerts
WHERE status = 'firing'
ORDER BY severity, triggered_at DESC;
```

### AI Cost Summary
```sql
SELECT
  ai_provider,
  ai_model,
  SUM(prompt_tokens) as total_prompt_tokens,
  SUM(completion_tokens) as total_completion_tokens,
  SUM(cost_cents) / 100.0 as total_cost_usd,
  COUNT(*) as invocations
FROM cost_tracking
WHERE timestamp > datetime('now', '-24 hours')
GROUP BY ai_provider, ai_model
ORDER BY total_cost_usd DESC;
```

---

## Additional Resources

### Documentation
- **Architecture Docs:** /docs/architecture.md
- **API Reference:** /docs/api-reference.md
- **Deployment Guide:** /docs/deployment.md

### Dashboards
- **Cloudflare Dashboard:** https://dash.cloudflare.com/
- **Sentry:** https://sentry.io/organizations/coreflow360/
- **Custom Observability:** /observability/dashboard

### Status Pages
- **Cloudflare Status:** https://www.cloudflarestatus.com/
- **Anthropic Status:** https://status.anthropic.com/
- **OpenAI Status:** https://status.openai.com/

---

**Document Ownership:** DevOps Team
**Review Schedule:** Monthly
**Last Review:** 2025-10-06
**Next Review:** 2025-11-06
