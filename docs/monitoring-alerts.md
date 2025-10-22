# Monitoring & Alerts Configuration

**Purpose**: Proactive monitoring and alerting for CoreFlow360 V4
**Tools**: Cloudflare Analytics, Sentry, Custom Webhooks

---

## Table of Contents

1. [Alert Thresholds](#alert-thresholds)
2. [Cloudflare Analytics Setup](#cloudflare-analytics-setup)
3. [Error Tracking (Sentry)](#error-tracking-sentry)
4. [Custom Alerts](#custom-alerts)
5. [Incident Response](#incident-response)
6. [On-Call Procedures](#on-call-procedures)

---

## Alert Thresholds

### Critical Alerts (P0 - Immediate Response Required)

| Metric | Threshold | Action |
|--------|-----------|--------|
| Error Rate | >5% | Page on-call engineer |
| Response Time P95 | >500ms | Investigate immediately |
| Uptime | <99% | Page on-call engineer |
| Database Errors | >10/min | Page database team |
| Security Events | Any | Page security team |

### High Priority (P1 - Response within 1 hour)

| Metric | Threshold | Action |
|--------|-----------|--------|
| Error Rate | >2% | Notify engineering team |
| Response Time P95 | >300ms | Investigate performance |
| Cache Hit Rate | <50% | Investigate cache |
| Failed Logins | >50/min | Security investigation |
| Memory Usage | >500MB | Investigate memory leaks |

### Medium Priority (P2 - Response within 4 hours)

| Metric | Threshold | Action |
|--------|-----------|--------|
| Error Rate | >1% | Review logs |
| Response Time P95 | >200ms | Performance review |
| Cache Hit Rate | <70% | Optimize caching |
| Slow Queries | >100ms | Database optimization |

---

## Cloudflare Analytics Setup

### Enable Analytics Engine

```bash
# Verify Analytics Engine is bound
wrangler kv:namespace list --env production

# Check analytics data
curl https://api.coreflow360.com/api/v1/analytics/overview
```

### Analytics Dashboards

**1. Create Performance Dashboard:**
```typescript
// Access via Cloudflare Dashboard
const dashboardUrl = `https://dash.cloudflare.com/${accountId}/workers/services/view/${workerId}/production/analytics`;

// Or via API
const response = await fetch('/api/v1/analytics/dashboard-url');
const { dashboardUrls } = await response.json();
console.log('Performance:', dashboardUrls.performance);
```

**2. Custom Metrics:**
```typescript
// Track custom metrics
if (c.env.ANALYTICS_ENGINE) {
  c.env.ANALYTICS_ENGINE.writeDataPoint({
    blobs: ['custom_metric', 'event_type', 'category'],
    doubles: [Date.now(), metricValue],
    indexes: ['custom', 'metrics']
  });
}
```

### Query Analytics Data

**GraphQL API:**
```graphql
query {
  viewer {
    accounts(filter: { accountTag: "your-account-id" }) {
      workersInvocationsAdaptive(
        limit: 100
        filter: {
          datetime_geq: "2025-10-21T00:00:00Z"
          datetime_leq: "2025-10-21T23:59:59Z"
        }
      ) {
        sum {
          requests
          errors
        }
        quantiles {
          cpuTimeP50
          cpuTimeP95
          cpuTimeP99
        }
      }
    }
  }
}
```

---

## Error Tracking (Sentry)

### Sentry Configuration

**1. Install Sentry SDK:**
```bash
npm install @sentry/cloudflare
```

**2. Initialize Sentry:**
```typescript
// src/index.ts
import * as Sentry from '@sentry/cloudflare';

Sentry.init({
  dsn: env.SENTRY_DSN,
  environment: env.ENVIRONMENT,
  tracesSampleRate: 1.0,

  beforeSend(event, hint) {
    // Filter sensitive data
    if (event.request?.headers?.authorization) {
      delete event.request.headers.authorization;
    }
    return event;
  }
});
```

**3. Capture Errors:**
```typescript
try {
  await riskyOperation();
} catch (error) {
  Sentry.captureException(error, {
    tags: {
      endpoint: c.req.path,
      method: c.req.method,
      businessId: c.get('businessId')
    },
    contexts: {
      operation: {
        name: 'riskyOperation',
        duration: performance.now() - startTime
      }
    }
  });
  throw error;
}
```

### Error Alert Rules

**Sentry Alert Conditions:**

1. **High Error Rate:**
   - Condition: >10 errors in 5 minutes
   - Action: Email + Slack notification
   - Severity: High

2. **New Error Type:**
   - Condition: First occurrence of error
   - Action: Slack notification
   - Severity: Medium

3. **Regression:**
   - Condition: Error reappears after being resolved
   - Action: Email + Slack notification
   - Severity: High

**Sentry Integration:**
```javascript
// .sentryclirc
[defaults]
url = https://sentry.io/
org = coreflow360
project = coreflow360-v4

[auth]
token = your-auth-token
```

---

## Custom Alerts

### Webhook Configuration

**1. Create Webhook Endpoint:**
```typescript
// src/routes/webhooks/alerts.ts
import { Hono } from 'hono';

const app = new Hono();

app.post('/alert', async (c) => {
  const alert = await c.req.json();

  // Validate webhook signature
  const signature = c.req.header('X-Alert-Signature');
  if (!validateSignature(signature, alert)) {
    return c.json({ error: 'Invalid signature' }, 401);
  }

  // Process alert
  await processAlert(alert);

  return c.json({ success: true });
});

async function processAlert(alert: Alert) {
  const { severity, metric, value, threshold } = alert;

  // Send to Slack
  await sendSlackAlert({
    channel: '#alerts',
    severity,
    message: `Alert: ${metric} is ${value} (threshold: ${threshold})`
  });

  // Page on-call if critical
  if (severity === 'critical') {
    await pageOnCall(alert);
  }
}
```

**2. Slack Webhook:**
```typescript
async function sendSlackAlert(params: SlackAlertParams) {
  const { channel, severity, message } = params;

  const color = {
    critical: '#ff0000',
    high: '#ff9900',
    medium: '#ffcc00',
    low: '#00ff00'
  }[severity];

  await fetch(env.SLACK_WEBHOOK_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      channel,
      attachments: [{
        color,
        title: `${severity.toUpperCase()} Alert`,
        text: message,
        footer: 'CoreFlow360 Monitoring',
        ts: Math.floor(Date.now() / 1000)
      }]
    })
  });
}
```

### Performance Alerts

**Monitor Response Time:**
```typescript
// Middleware to track slow responses
api.use('*', async (c, next) => {
  const start = performance.now();
  await next();
  const duration = performance.now() - start;

  // Alert on slow responses
  if (duration > 500) {
    await sendAlert({
      severity: 'high',
      metric: 'response_time',
      value: duration,
      threshold: 500,
      endpoint: c.req.path
    });
  }
});
```

**Monitor Error Rate:**
```typescript
// Track error rate per minute
let errorCount = 0;
let requestCount = 0;

setInterval(() => {
  const errorRate = (errorCount / requestCount) * 100;

  if (errorRate > 5) {
    sendAlert({
      severity: 'critical',
      metric: 'error_rate',
      value: errorRate,
      threshold: 5
    });
  }

  // Reset counters
  errorCount = 0;
  requestCount = 0;
}, 60000); // Every minute
```

---

## Incident Response

### Incident Severity Levels

**P0 - Critical (Outage)**
- **Response Time**: Immediate
- **Examples**: System down, data loss, security breach
- **Actions**:
  1. Page on-call engineer
  2. Create incident war room (Slack #incidents)
  3. Start incident timeline
  4. Notify stakeholders
  5. Begin mitigation

**P1 - High (Major Impact)**
- **Response Time**: <1 hour
- **Examples**: High error rate, slow performance, feature broken
- **Actions**:
  1. Notify engineering team
  2. Investigate root cause
  3. Implement hot-fix if needed
  4. Monitor for improvement

**P2 - Medium (Partial Impact)**
- **Response Time**: <4 hours
- **Examples**: Minor bugs, degraded performance
- **Actions**:
  1. Create ticket
  2. Investigate during business hours
  3. Schedule fix in next deployment

### Incident Response Checklist

**1. Detect & Triage (0-5 minutes)**
- [ ] Alert received and acknowledged
- [ ] Severity assessed
- [ ] On-call engineer paged (if P0/P1)
- [ ] Initial investigation started

**2. Investigate (5-30 minutes)**
- [ ] Check recent deployments
- [ ] Review error logs
- [ ] Check Cloudflare Analytics
- [ ] Identify root cause
- [ ] Document findings

**3. Mitigate (30-60 minutes)**
- [ ] Implement fix or rollback
- [ ] Test fix in staging (if time permits)
- [ ] Deploy to production
- [ ] Verify resolution
- [ ] Monitor metrics

**4. Communicate (Throughout)**
- [ ] Post in #incidents channel
- [ ] Update status page (if public-facing)
- [ ] Notify affected users (if needed)
- [ ] Update stakeholders
- [ ] Close incident when resolved

**5. Post-Mortem (Within 48 hours)**
- [ ] Write incident report
- [ ] Identify preventive measures
- [ ] Create action items
- [ ] Schedule review meeting
- [ ] Update runbooks

---

## On-Call Procedures

### On-Call Rotation

**Schedule:**
- **Primary On-Call**: Week-long rotation
- **Secondary On-Call**: Backup engineer
- **Escalation**: Engineering manager

**Tool**: PagerDuty

**Rotation Schedule:**
```
Week 1: Engineer A (Primary), Engineer B (Secondary)
Week 2: Engineer B (Primary), Engineer C (Secondary)
Week 3: Engineer C (Primary), Engineer A (Secondary)
```

### Escalation Path

1. **Primary On-Call** (5 minutes)
   - If no response → escalate

2. **Secondary On-Call** (5 minutes)
   - If no response → escalate

3. **Engineering Manager** (Immediate)
   - If no response → escalate

4. **CTO** (Critical only)

### On-Call Checklist

**Before Your Shift:**
- [ ] Test PagerDuty notifications
- [ ] Review recent incidents
- [ ] Ensure laptop/phone charged
- [ ] Review runbooks
- [ ] Check access to all systems

**During Your Shift:**
- [ ] Respond to alerts within 5 minutes
- [ ] Follow incident response procedures
- [ ] Document all actions
- [ ] Update stakeholders
- [ ] Handoff open incidents

**After Your Shift:**
- [ ] Complete incident reports
- [ ] Update runbooks if needed
- [ ] Handoff to next engineer
- [ ] Submit on-call feedback

---

## Alert Configuration Examples

### Example 1: High Error Rate

```yaml
# Cloudflare Workers Alert
name: high-error-rate
condition:
  metric: error_rate
  threshold: 5
  window: 5m
  operator: greater_than
actions:
  - type: webhook
    url: https://api.coreflow360.com/webhooks/alert
  - type: email
    to: engineering@coreflow360.com
  - type: pagerduty
    severity: high
```

### Example 2: Slow Response Time

```yaml
name: slow-response-time
condition:
  metric: response_time_p95
  threshold: 500
  window: 10m
  operator: greater_than
actions:
  - type: slack
    channel: '#performance'
  - type: email
    to: backend-team@coreflow360.com
```

### Example 3: Database Errors

```yaml
name: database-errors
condition:
  metric: database_errors
  threshold: 10
  window: 1m
  operator: greater_than
actions:
  - type: pagerduty
    severity: critical
  - type: slack
    channel: '#incidents'
```

---

## Monitoring Dashboard URLs

```typescript
const MONITORING_URLS = {
  cloudflare: {
    analytics: `https://dash.cloudflare.com/${accountId}/workers/services/${workerId}/production/analytics`,
    logs: `https://dash.cloudflare.com/${accountId}/workers/services/${workerId}/production/logs`,
    performance: `https://dash.cloudflare.com/${accountId}/workers/services/${workerId}/production/performance`,
  },
  sentry: `https://sentry.io/organizations/coreflow360/issues/`,
  performance: `https://app.coreflow360.com/admin/performance`,
};
```

---

## Quick Commands

### Check System Health
```bash
# Overall health
curl https://api.coreflow360.com/health

# API health
curl https://api.coreflow360.com/api/v1/health

# Analytics overview
curl https://api.coreflow360.com/api/v1/analytics/overview
```

### View Real-Time Logs
```bash
# All logs
wrangler tail --env production

# Filter errors only
wrangler tail --env production | grep ERROR

# Save to file
wrangler tail --env production > logs-$(date +%Y%m%d-%H%M%S).txt
```

### Check Alert Status
```bash
# Via API
curl https://api.coreflow360.com/api/v1/alerts/status

# Via Cloudflare
wrangler analytics view --env production
```

---

**Last Updated**: 2025-10-21
**Maintained By**: DevOps Team
**Review Cycle**: Monthly
**On-Call Rotation**: Weekly
