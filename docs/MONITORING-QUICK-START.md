# Monitoring Quick Start - CoreFlow360 V4

## 15-Minute Setup to Production Monitoring

Get comprehensive monitoring running in 15 minutes. This guide covers essential metrics, alerts, and dashboards for production operations.

**Production URLs to Monitor:**
- Backend API: https://coreflow360-v4-prod.ernijs-ansons.workers.dev
- Frontend App: https://production.coreflow360-frontend.pages.dev
- Health Check: https://coreflow360-v4-prod.ernijs-ansons.workers.dev/health

## Quick Setup Checklist

```bash
□ Cloudflare Analytics enabled (2 min)
□ Sentry error tracking configured (3 min)
□ Uptime monitoring active (2 min)
□ Custom dashboards created (5 min)
□ Alert rules configured (3 min)
```

## Step 1: Cloudflare Analytics (2 minutes)

### Enable Analytics

1. **Login to Cloudflare Dashboard**
   ```
   URL: https://dash.cloudflare.com
   Navigate to: Your Zone → Analytics
   ```

2. **Enable Web Analytics**
   ```bash
   # Add tracking script to frontend
   <script defer src='https://static.cloudflareinsights.com/beacon.min.js'
           data-cf-beacon='{"token": "YOUR_TOKEN"}'></script>
   ```

3. **Configure Workers Analytics**
   ```
   Navigate to: Workers → Your Worker → Analytics
   Enable: Request Analytics
   Enable: Exception Logging
   ```

### Key Metrics to Track

| Metric | Target | Alert Threshold |
|--------|--------|-----------------|
| Request Count | - | > 10000/min |
| Error Rate | < 0.1% | > 1% |
| P95 Response Time | < 100ms | > 500ms |
| Cache Hit Rate | > 80% | < 60% |
| Bandwidth Usage | - | > 100GB/day |

## Step 2: Sentry Error Tracking (3 minutes)

### Quick Configuration

1. **Create Sentry Project**
   ```
   URL: https://sentry.io
   Create Project → JavaScript → React
   Project Name: coreflow360-production
   ```

2. **Install Sentry SDK**
   ```bash
   # Already included in project
   # Just need to configure
   ```

3. **Configure Environment Variables**
   ```bash
   # Add to Wrangler secrets
   wrangler secret put SENTRY_DSN
   # Paste: https://xxx@xxx.ingest.sentry.io/xxx

   wrangler secret put SENTRY_ENVIRONMENT
   # Enter: production
   ```

4. **Initialize in Frontend**
   ```javascript
   // frontend/src/main.tsx
   import * as Sentry from "@sentry/react";

   Sentry.init({
     dsn: import.meta.env.VITE_SENTRY_DSN,
     environment: "production",
     tracesSampleRate: 0.1,
     integrations: [
       new Sentry.BrowserTracing(),
       new Sentry.Replay()
     ],
   });
   ```

### Error Alert Rules

Create these alerts in Sentry:

1. **Critical Error Surge**
   - Condition: Error count > 100 in 5 minutes
   - Action: Email + Slack + PagerDuty

2. **New Error Type**
   - Condition: First occurrence of error
   - Action: Email to dev team

3. **Performance Degradation**
   - Condition: P95 > 1 second
   - Action: Email + Dashboard alert

## Step 3: Uptime Monitoring (2 minutes)

### Option A: Cloudflare Health Checks

```bash
# Configure in Cloudflare Dashboard
Navigate to: Traffic → Health Checks
Click: Create

Configuration:
- Name: API Health Check
- Type: HTTPS
- Host: coreflow360-v4-prod.ernijs-ansons.workers.dev
- Path: /health
- Port: 443
- Interval: 60 seconds
- Timeout: 10 seconds
- Retries: 2
- Expected Response: 200 OK
- Alert Email: ops@coreflow360.com
```

### Option B: External Monitoring (Better)

**Using Uptime Robot (Free)**

```bash
# Create monitors at https://uptimerobot.com

Monitor 1: API Endpoint
- URL: https://coreflow360-v4-prod.ernijs-ansons.workers.dev/health
- Check Interval: 5 minutes
- Alert: Immediate

Monitor 2: Frontend App
- URL: https://production.coreflow360-frontend.pages.dev
- Check Interval: 5 minutes
- Alert: After 2 failures

Monitor 3: API Response
- URL: https://coreflow360-v4-prod.ernijs-ansons.workers.dev/api/v1/status
- Keyword: "operational"
- Alert: If keyword not found
```

### Status Page Setup

```bash
# Create public status page
URL: https://status.coreflow360.com

Components:
- API: Operational
- Web App: Operational
- AI Agents: Operational
- Database: Operational
- Payment Processing: Operational
```

## Step 4: Custom Dashboards (5 minutes)

### Cloudflare Dashboard

Create custom dashboard with these widgets:

```javascript
// Dashboard configuration
{
  "name": "CoreFlow360 Production",
  "widgets": [
    {
      "type": "timeseries",
      "title": "Request Volume",
      "metric": "requests",
      "period": "1h"
    },
    {
      "type": "gauge",
      "title": "Error Rate",
      "metric": "error_rate",
      "thresholds": {
        "green": [0, 0.1],
        "yellow": [0.1, 1],
        "red": [1, 100]
      }
    },
    {
      "type": "heatmap",
      "title": "Response Times",
      "metric": "response_time_p95",
      "buckets": [0, 50, 100, 200, 500, 1000]
    },
    {
      "type": "counter",
      "title": "Active Users",
      "metric": "unique_visitors",
      "period": "realtime"
    }
  ]
}
```

### Grafana Dashboard (Advanced)

Import this dashboard JSON:

```json
{
  "dashboard": {
    "title": "CoreFlow360 V4 Production",
    "panels": [
      {
        "title": "API Performance",
        "targets": [
          {
            "expr": "rate(http_requests_total[5m])",
            "legendFormat": "Requests/sec"
          },
          {
            "expr": "histogram_quantile(0.95, http_request_duration_seconds)",
            "legendFormat": "P95 Latency"
          }
        ]
      },
      {
        "title": "Business Metrics",
        "targets": [
          {
            "expr": "sum(active_users)",
            "legendFormat": "Active Users"
          },
          {
            "expr": "sum(rate(transactions_total[1h]))",
            "legendFormat": "Transactions/hour"
          }
        ]
      },
      {
        "title": "AI Agent Activity",
        "targets": [
          {
            "expr": "sum(ai_agent_tasks_completed)",
            "legendFormat": "Tasks Completed"
          },
          {
            "expr": "avg(ai_agent_efficiency)",
            "legendFormat": "Average Efficiency %"
          }
        ]
      }
    ]
  }
}
```

## Step 5: Alert Configuration (3 minutes)

### Critical Alerts

Configure these alerts immediately:

#### 1. Service Down Alert

```yaml
name: Service Down
condition: health_check_failure
threshold: 2 consecutive failures
channels:
  - email: ops@coreflow360.com
  - sms: +1-555-ONCALL
  - slack: #alerts-critical
priority: P1
```

#### 2. High Error Rate

```yaml
name: High Error Rate
condition: error_rate > 1%
duration: 5 minutes
channels:
  - email: dev@coreflow360.com
  - slack: #alerts-errors
priority: P2
```

#### 3. Performance Degradation

```yaml
name: Slow Response Times
condition: p95_response_time > 500ms
duration: 10 minutes
channels:
  - email: dev@coreflow360.com
  - slack: #alerts-performance
priority: P3
```

#### 4. Database Issues

```yaml
name: Database Connection Failures
condition: db_connection_errors > 10
duration: 1 minute
channels:
  - email: ops@coreflow360.com
  - pagerduty: database-team
priority: P1
```

#### 5. Payment Failures

```yaml
name: Payment Processing Errors
condition: payment_failure_rate > 5%
duration: 5 minutes
channels:
  - email: finance@coreflow360.com
  - slack: #alerts-payments
  - sms: +1-555-FINANCE
priority: P1
```

### Alert Routing Rules

```javascript
// Alert routing configuration
const alertRouting = {
  P1: {
    immediate: ["email", "sms", "slack", "pagerduty"],
    escalation: {
      after: "10m",
      to: "manager"
    }
  },
  P2: {
    immediate: ["email", "slack"],
    escalation: {
      after: "30m",
      to: "senior-dev"
    }
  },
  P3: {
    immediate: ["slack"],
    escalation: {
      after: "1h",
      to: "dev-team"
    }
  }
};
```

## Essential Metrics to Track

### Application Metrics

| Metric | Description | Good | Warning | Critical |
|--------|-------------|------|---------|----------|
| Uptime | Service availability | > 99.9% | > 99% | < 99% |
| Response Time (P50) | Median response time | < 50ms | < 100ms | > 200ms |
| Response Time (P95) | 95th percentile | < 100ms | < 500ms | > 1s |
| Error Rate | Failed requests | < 0.1% | < 1% | > 5% |
| Throughput | Requests per second | - | - | < 10 RPS |

### Business Metrics

| Metric | Description | Target | Alert |
|--------|-------------|--------|-------|
| Active Users | Currently logged in | - | < 10 |
| New Signups | Daily registrations | > 10/day | < 5/day |
| Conversion Rate | Trial to paid | > 20% | < 10% |
| Revenue | Daily revenue | > $1000 | < $500 |
| Churn Rate | Monthly churn | < 5% | > 10% |

### Infrastructure Metrics

| Metric | Description | Normal | Warning | Critical |
|--------|-------------|--------|---------|----------|
| CPU Usage | Worker CPU utilization | < 50% | < 80% | > 90% |
| Memory Usage | Worker memory | < 60% | < 80% | > 90% |
| Database Connections | Active connections | < 80% | < 90% | > 95% |
| Cache Hit Rate | KV cache efficiency | > 80% | > 60% | < 50% |
| Bandwidth | Daily usage | < 100GB | < 500GB | > 1TB |

## Monitoring Commands

### Quick Health Checks

```bash
# Check API health
curl -s https://coreflow360-v4-prod.ernijs-ansons.workers.dev/health | jq '.'

# Check frontend
curl -I https://production.coreflow360-frontend.pages.dev

# Check response times
curl -w "@curl-format.txt" -o /dev/null -s \
  https://coreflow360-v4-prod.ernijs-ansons.workers.dev/api/v1/status

# Monitor real-time logs
wrangler tail --env production

# Check error rate
curl -s https://coreflow360-v4-prod.ernijs-ansons.workers.dev/api/v1/metrics \
  | jq '.error_rate'
```

### Debugging Commands

```bash
# Get detailed metrics
curl -s https://coreflow360-v4-prod.ernijs-ansons.workers.dev/api/v1/metrics/detailed \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq '.'

# Check AI agent status
curl -s https://coreflow360-v4-prod.ernijs-ansons.workers.dev/api/v1/agents/health \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq '.'

# Database health
curl -s https://coreflow360-v4-prod.ernijs-ansons.workers.dev/api/v1/db/health \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq '.'

# Cache statistics
curl -s https://coreflow360-v4-prod.ernijs-ansons.workers.dev/api/v1/cache/stats \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq '.'
```

## Troubleshooting Guide

### High Error Rate

```bash
# 1. Check recent errors
wrangler tail --env production --format json | grep ERROR

# 2. Check Sentry for details
# Navigate to: https://sentry.io/organizations/coreflow360/issues/

# 3. Review error patterns
curl -s https://coreflow360-v4-prod.ernijs-ansons.workers.dev/api/v1/errors/summary \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq '.'

# 4. Check specific service
curl -s https://coreflow360-v4-prod.ernijs-ansons.workers.dev/api/v1/health/detailed | jq '.'
```

### Performance Issues

```bash
# 1. Check slow queries
curl -s https://coreflow360-v4-prod.ernijs-ansons.workers.dev/api/v1/metrics/slow-queries \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq '.'

# 2. Review cache performance
curl -s https://coreflow360-v4-prod.ernijs-ansons.workers.dev/api/v1/cache/performance \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq '.'

# 3. Check AI agent performance
curl -s https://coreflow360-v4-prod.ernijs-ansons.workers.dev/api/v1/agents/performance \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq '.'
```

### Database Issues

```bash
# 1. Check connection pool
curl -s https://coreflow360-v4-prod.ernijs-ansons.workers.dev/api/v1/db/connections \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq '.'

# 2. Review slow queries
curl -s https://coreflow360-v4-prod.ernijs-ansons.workers.dev/api/v1/db/slow-queries \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq '.'

# 3. Check replication lag
curl -s https://coreflow360-v4-prod.ernijs-ansons.workers.dev/api/v1/db/replication \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq '.'
```

## Dashboard Access URLs

### Primary Dashboards

| Dashboard | URL | Purpose |
|-----------|-----|---------|
| Cloudflare Analytics | https://dash.cloudflare.com | Traffic and performance |
| Sentry | https://sentry.io/coreflow360 | Error tracking |
| Status Page | https://status.coreflow360.com | Public status |
| Uptime Robot | https://uptimerobot.com | Uptime monitoring |
| Custom Dashboard | https://monitoring.coreflow360.com | Internal metrics |

### Mobile Monitoring

Download apps for on-the-go monitoring:
- **Cloudflare**: iOS/Android app
- **Sentry**: iOS/Android app
- **Uptime Robot**: iOS/Android app
- **PagerDuty**: iOS/Android app (if configured)

## Daily Monitoring Checklist

### Morning (9 AM)

```bash
□ Check overnight alerts
□ Review error rate trend
□ Check backup completion
□ Review AI agent performance
□ Check payment processing
```

### Afternoon (2 PM)

```bash
□ Review performance metrics
□ Check user activity patterns
□ Monitor resource usage
□ Review slow query log
□ Check cache hit rates
```

### Evening (6 PM)

```bash
□ Daily metrics summary
□ Error rate for the day
□ Customer issues review
□ Performance bottlenecks
□ Plan for tomorrow
```

## Weekly Reports

Generate these reports every Monday:

```bash
# 1. Performance Report
curl -s https://coreflow360-v4-prod.ernijs-ansons.workers.dev/api/v1/reports/weekly-performance \
  -H "Authorization: Bearer $ADMIN_TOKEN" > performance-report.json

# 2. Error Summary
curl -s https://coreflow360-v4-prod.ernijs-ansons.workers.dev/api/v1/reports/weekly-errors \
  -H "Authorization: Bearer $ADMIN_TOKEN" > error-report.json

# 3. Business Metrics
curl -s https://coreflow360-v4-prod.ernijs-ansons.workers.dev/api/v1/reports/weekly-business \
  -H "Authorization: Bearer $ADMIN_TOKEN" > business-report.json
```

## Escalation Matrix

| Severity | Response Time | Who to Contact | How |
|----------|--------------|----------------|------|
| P1 - Critical | Immediate | On-call Engineer | Phone + Slack |
| P2 - Major | 15 minutes | Dev Team Lead | Slack + Email |
| P3 - Minor | 1 hour | Dev Team | Slack |
| P4 - Low | Next business day | Dev Team | Email |

### On-Call Rotation

```yaml
schedule:
  week1: engineer1@coreflow360.com
  week2: engineer2@coreflow360.com
  week3: engineer3@coreflow360.com
  week4: engineer4@coreflow360.com

backup:
  primary: lead@coreflow360.com
  secondary: cto@coreflow360.com
```

## Quick Reference Card

Print and keep handy:

```
===========================================
COREFLOW360 V4 - MONITORING QUICK REFERENCE
===========================================

HEALTH CHECK:
https://coreflow360-v4-prod.ernijs-ansons.workers.dev/health

LOGS:
wrangler tail --env production

METRICS:
https://dash.cloudflare.com

ERRORS:
https://sentry.io/coreflow360

STATUS:
https://status.coreflow360.com

ON-CALL:
Primary: +1-555-ONCALL
Backup: +1-555-BACKUP

CRITICAL ISSUES:
1. Service down: Restart workers
2. High errors: Check Sentry
3. Slow response: Check cache
4. Database issues: Check connections
5. Payment failures: Check Stripe

SUPPORT:
Email: support@coreflow360.com
Slack: #ops-emergency
===========================================
```

---

**Setup Time:** 15 minutes
**Maintenance:** 30 minutes/day
**Last Updated:** October 2024

Remember: Good monitoring prevents fires. Great monitoring prevents smoke.