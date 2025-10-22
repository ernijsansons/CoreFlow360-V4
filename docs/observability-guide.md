# Observability Guide

## Overview

This guide covers observability implementation for CoreFlow360 V4, including logging, monitoring, tracing, and alerting strategies for production operations.

## Observability Pillars

### 1. Metrics
Quantitative measurements of system behavior over time.

### 2. Logs
Structured event records for debugging and auditing.

### 3. Traces
Request flow tracking across distributed systems.

### 4. Alerts
Automated notifications for anomalous conditions.

---

## Metrics Collection

### Core Application Metrics

#### API Performance Metrics

```typescript
// src/middleware/metrics.ts
import { MiddlewareHandler } from 'hono';
import type { Env } from '../types/env';

export function metricsMiddleware(): MiddlewareHandler<{ Bindings: Env }> {
  return async (c, next) => {
    const startTime = Date.now();
    const path = c.req.path;
    const method = c.req.method;

    try {
      await next();

      const duration = Date.now() - startTime;
      const status = c.res.status;

      // Send to Analytics Engine
      c.env.ANALYTICS_ENGINE?.writeDataPoint({
        blobs: [method, path, status.toString()],
        doubles: [Date.now(), duration],
        indexes: ['api_requests'],
      });

      // Set response headers for monitoring
      c.res.headers.set('X-Response-Time', `${duration}ms`);
    } catch (error) {
      const duration = Date.now() - startTime;

      // Log error metric
      c.env.ANALYTICS_ENGINE?.writeDataPoint({
        blobs: [method, path, 'error', (error as Error).message],
        doubles: [Date.now(), duration],
        indexes: ['api_errors'],
      });

      throw error;
    }
  };
}
```

#### Business Metrics

```typescript
// Track business-critical events
export function trackBusinessMetric(
  env: Env,
  event: string,
  value: number,
  metadata: Record<string, string> = {}
) {
  env.ANALYTICS_ENGINE?.writeDataPoint({
    blobs: [
      event,
      metadata.userId || 'anonymous',
      metadata.businessId || '',
      JSON.stringify(metadata),
    ],
    doubles: [Date.now(), value],
    indexes: ['business_events'],
  });
}

// Usage examples
trackBusinessMetric(env, 'user_registered', 1, { plan: 'pro' });
trackBusinessMetric(env, 'invoice_created', invoice.total, { businessId: invoice.businessId });
trackBusinessMetric(env, 'ai_agent_task_completed', taskDuration, { agentType: 'finance' });
```

#### Database Metrics

```typescript
// src/shared/db/metrics.ts
export async function trackQuery(
  env: Env,
  query: string,
  duration: number,
  rowCount: number
) {
  env.ANALYTICS_ENGINE?.writeDataPoint({
    blobs: [
      'database_query',
      query.substring(0, 100), // First 100 chars
      rowCount.toString(),
    ],
    doubles: [Date.now(), duration],
    indexes: ['db_queries'],
  });

  // Alert on slow queries
  if (duration > 100) {
    console.warn(`Slow query detected: ${query} (${duration}ms)`);
  }
}
```

### Frontend Metrics

#### Core Web Vitals

```typescript
// frontend/src/lib/performance.ts
import { onCLS, onFID, onLCP, onFCP, onTTFB, onINP } from 'web-vitals';
import type { Metric } from 'web-vitals';

function sendToAnalytics(metric: Metric) {
  const body = JSON.stringify({
    name: metric.name,
    value: metric.value,
    rating: metric.rating,
    delta: metric.delta,
    id: metric.id,
    navigationType: metric.navigationType,
  });

  // Use sendBeacon for reliability
  if (navigator.sendBeacon) {
    navigator.sendBeacon('/api/analytics/web-vitals', body);
  } else {
    fetch('/api/analytics/web-vitals', {
      method: 'POST',
      body,
      keepalive: true,
      headers: { 'Content-Type': 'application/json' },
    });
  }
}

// Track all Core Web Vitals
export function initPerformanceTracking() {
  onLCP(sendToAnalytics);
  onFID(sendToAnalytics);
  onCLS(sendToAnalytics);
  onFCP(sendToAnalytics);
  onTTFB(sendToAnalytics);
  onINP(sendToAnalytics);
}
```

#### Custom Frontend Metrics

```typescript
// Track user interactions
export function trackInteraction(
  action: string,
  category: string,
  label?: string,
  value?: number
) {
  fetch('/api/analytics/event', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      action,
      category,
      label,
      value,
      timestamp: Date.now(),
      url: window.location.pathname,
    }),
  });
}

// Usage
trackInteraction('click', 'button', 'create-invoice');
trackInteraction('submit', 'form', 'user-registration');
trackInteraction('view', 'page', 'dashboard', Date.now() - pageLoadTime);
```

---

## Structured Logging

### Log Levels

| Level | Usage | Examples |
|-------|-------|----------|
| **ERROR** | System errors requiring immediate attention | Database connection failed, API request failed |
| **WARN** | Warnings that don't stop execution | Deprecated API usage, slow query, high memory |
| **INFO** | Important business events | User registered, payment processed, deployment started |
| **DEBUG** | Detailed debugging information | Request/response details, function entry/exit |

### Log Format

```typescript
// src/shared/logger.ts
export interface LogEntry {
  level: 'ERROR' | 'WARN' | 'INFO' | 'DEBUG';
  timestamp: string;
  component: string;
  message: string;
  context?: Record<string, any>;
  error?: {
    name: string;
    message: string;
    stack?: string;
  };
  userId?: string;
  businessId?: string;
  requestId?: string;
  performance?: {
    duration: number;
    memoryUsed?: number;
  };
}

export class Logger {
  constructor(private config: { component: string }) {}

  private log(level: LogEntry['level'], message: string, context?: Record<string, any>) {
    const entry: LogEntry = {
      level,
      timestamp: new Date().toISOString(),
      component: this.config.component,
      message,
      context,
    };

    // Structured logging to console
    console.log(JSON.stringify(entry));

    // Send to external logging service
    this.sendToExternalLogger(entry);
  }

  error(message: string, error?: Error, context?: Record<string, any>) {
    this.log('ERROR', message, {
      ...context,
      error: error ? {
        name: error.name,
        message: error.message,
        stack: error.stack,
      } : undefined,
    });
  }

  warn(message: string, context?: Record<string, any>) {
    this.log('WARN', message, context);
  }

  info(message: string, context?: Record<string, any>) {
    this.log('INFO', message, context);
  }

  debug(message: string, context?: Record<string, any>) {
    if (process.env.LOG_LEVEL === 'debug') {
      this.log('DEBUG', message, context);
    }
  }

  private sendToExternalLogger(entry: LogEntry) {
    // Send to Sentry, Datadog, etc.
    // Implementation depends on your logging service
  }
}
```

### Logging Best Practices

#### ✅ DO

```typescript
// Include relevant context
logger.info('User registered', {
  userId: user.id,
  email: user.email,
  plan: user.plan,
  registrationMethod: 'email',
});

// Log errors with full context
logger.error('Payment processing failed', error, {
  userId: user.id,
  amount: payment.amount,
  paymentMethod: payment.method,
  stripePaymentIntentId: payment.stripeId,
});

// Use structured data
logger.info('API request completed', {
  method: 'POST',
  path: '/api/invoices',
  statusCode: 201,
  duration: 125,
  userId: req.userId,
});
```

#### ❌ DON'T

```typescript
// Avoid unstructured logs
console.log('User registered');

// Don't log sensitive data
logger.info('User logged in', {
  password: user.password, // ❌ Never log passwords
  creditCard: user.ccNumber, // ❌ Never log payment info
});

// Avoid concatenated strings
logger.info('User ' + userId + ' created invoice ' + invoiceId); // Use structured logging instead
```

---

## Distributed Tracing

### Request ID Propagation

```typescript
// src/middleware/tracing.ts
import { MiddlewareHandler } from 'hono';
import { randomUUID } from 'crypto';

export function tracingMiddleware(): MiddlewareHandler {
  return async (c, next) => {
    // Generate or extract request ID
    const requestId = c.req.header('X-Request-ID') || randomUUID();

    // Store in context
    c.set('requestId', requestId);

    // Add to response headers
    c.res.headers.set('X-Request-ID', requestId);

    // Log request start
    console.log(JSON.stringify({
      event: 'request_start',
      requestId,
      method: c.req.method,
      path: c.req.path,
      timestamp: new Date().toISOString(),
    }));

    await next();

    // Log request end
    console.log(JSON.stringify({
      event: 'request_end',
      requestId,
      statusCode: c.res.status,
      timestamp: new Date().toISOString(),
    }));
  };
}
```

### Span Tracking

```typescript
// Track operation spans
export class Span {
  private startTime: number;

  constructor(
    private name: string,
    private requestId: string,
    private parentSpanId?: string
  ) {
    this.startTime = Date.now();
  }

  finish(tags?: Record<string, any>) {
    const duration = Date.now() - this.startTime;

    console.log(JSON.stringify({
      event: 'span',
      name: this.name,
      requestId: this.requestId,
      parentSpanId: this.parentSpanId,
      duration,
      tags,
      timestamp: new Date().toISOString(),
    }));
  }
}

// Usage
async function processInvoice(invoice: Invoice, requestId: string) {
  const span = new Span('process_invoice', requestId);

  try {
    // Processing logic
    const result = await createInvoiceInDB(invoice);

    span.finish({
      invoiceId: result.id,
      success: true,
    });

    return result;
  } catch (error) {
    span.finish({
      error: (error as Error).message,
      success: false,
    });
    throw error;
  }
}
```

---

## Alerting

### Alert Configuration

```typescript
// src/observability/alerts.ts
export interface AlertRule {
  name: string;
  condition: (metrics: Metrics) => boolean;
  severity: 'critical' | 'high' | 'medium' | 'low';
  message: (metrics: Metrics) => string;
  cooldown: number; // minutes
}

export const alertRules: AlertRule[] = [
  {
    name: 'high_error_rate',
    condition: (m) => m.errorRate > 0.05,
    severity: 'critical',
    message: (m) => `Error rate ${(m.errorRate * 100).toFixed(2)}% exceeds 5% threshold`,
    cooldown: 15,
  },
  {
    name: 'slow_response_time',
    condition: (m) => m.avgResponseTime > 500,
    severity: 'high',
    message: (m) => `Average response time ${m.avgResponseTime}ms exceeds 500ms`,
    cooldown: 30,
  },
  {
    name: 'low_cache_hit_rate',
    condition: (m) => m.cacheHitRate < 0.60,
    severity: 'medium',
    message: (m) => `Cache hit rate ${(m.cacheHitRate * 100).toFixed(0)}% below 60%`,
    cooldown: 60,
  },
  {
    name: 'database_slow_queries',
    condition: (m) => m.avgDbQueryTime > 100,
    severity: 'high',
    message: (m) => `Database queries averaging ${m.avgDbQueryTime}ms (>100ms threshold)`,
    cooldown: 30,
  },
  {
    name: 'ai_agent_failures',
    condition: (m) => m.aiAgentFailureRate > 0.10,
    severity: 'high',
    message: (m) => `AI agent failure rate ${(m.aiAgentFailureRate * 100).toFixed(1)}% exceeds 10%`,
    cooldown: 15,
  },
];
```

### Alert Channels

#### Slack

```typescript
export async function sendSlackAlert(
  webhook: string,
  severity: string,
  message: string,
  context?: Record<string, any>
) {
  const colors = {
    critical: 'danger',
    high: 'warning',
    medium: '#ffcc00',
    low: 'good',
  };

  const emojis = {
    critical: '🚨',
    high: '⚠️',
    medium: '📊',
    low: 'ℹ️',
  };

  await fetch(webhook, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      text: `${emojis[severity]} ${severity.toUpperCase()} Alert`,
      attachments: [{
        color: colors[severity],
        title: message,
        fields: Object.entries(context || {}).map(([key, value]) => ({
          title: key,
          value: String(value),
          short: true,
        })),
        footer: 'CoreFlow360 Monitoring',
        ts: Math.floor(Date.now() / 1000),
      }],
    }),
  });
}
```

#### Email

```typescript
export async function sendEmailAlert(
  to: string[],
  severity: string,
  message: string,
  context?: Record<string, any>
) {
  // Using SendGrid or similar
  const response = await fetch('https://api.sendgrid.com/v3/mail/send', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${process.env.SENDGRID_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      personalizations: [{ to: to.map(email => ({ email })) }],
      from: { email: 'alerts@coreflow360.com' },
      subject: `[${severity.toUpperCase()}] ${message}`,
      content: [{
        type: 'text/html',
        value: generateAlertEmailHTML(severity, message, context),
      }],
    }),
  });
}
```

#### PagerDuty (for P0/P1 incidents)

```typescript
export async function sendPagerDutyAlert(
  integrationKey: string,
  severity: string,
  message: string,
  context?: Record<string, any>
) {
  await fetch('https://events.pagerduty.com/v2/enqueue', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      routing_key: integrationKey,
      event_action: 'trigger',
      payload: {
        summary: message,
        severity: severity === 'critical' ? 'critical' : 'error',
        source: 'coreflow360-production',
        custom_details: context,
      },
    }),
  });
}
```

---

## Dashboards

### Grafana Dashboard Configuration

```json
{
  "dashboard": {
    "title": "CoreFlow360 V4 - Production Overview",
    "panels": [
      {
        "title": "API Response Time (P50, P95, P99)",
        "targets": [
          {
            "expr": "histogram_quantile(0.50, rate(api_request_duration_ms_bucket[5m]))",
            "legendFormat": "P50"
          },
          {
            "expr": "histogram_quantile(0.95, rate(api_request_duration_ms_bucket[5m]))",
            "legendFormat": "P95"
          },
          {
            "expr": "histogram_quantile(0.99, rate(api_request_duration_ms_bucket[5m]))",
            "legendFormat": "P99"
          }
        ]
      },
      {
        "title": "Error Rate",
        "targets": [
          {
            "expr": "sum(rate(api_errors_total[5m])) / sum(rate(api_requests_total[5m]))",
            "legendFormat": "Error Rate %"
          }
        ]
      },
      {
        "title": "Cache Hit Rate",
        "targets": [
          {
            "expr": "sum(rate(cache_hits_total[5m])) / (sum(rate(cache_hits_total[5m])) + sum(rate(cache_misses_total[5m])))",
            "legendFormat": "Hit Rate %"
          }
        ]
      }
    ]
  }
}
```

### Custom Dashboard (HTML)

See `scripts/performance-monitor.sh` for auto-generated HTML dashboards with Chart.js visualization.

---

## Query Analysis

### Analyzing Logs

```bash
# Using wrangler tail
wrangler tail coreflow360-v4-prod --env production --format pretty

# Filter by error level
wrangler tail coreflow360-v4-prod --env production | grep ERROR

# Filter by user ID
wrangler tail coreflow360-v4-prod --env production | grep "userId.*user-123"

# Count error types
wrangler tail coreflow360-v4-prod --env production | grep ERROR | awk '{print $5}' | sort | uniq -c
```

### Analyzing Metrics

```typescript
// Query Analytics Engine (via API)
export async function queryMetrics(
  env: Env,
  startTime: number,
  endTime: number,
  metric: string
) {
  // Cloudflare Analytics Engine queries
  // Note: Actual implementation depends on your Cloudflare setup
  const query = `
    SELECT
      toStartOfInterval(timestamp, INTERVAL 5 MINUTE) as time,
      AVG(double1) as value
    FROM analytics_events
    WHERE
      timestamp >= ${startTime}
      AND timestamp <= ${endTime}
      AND blob1 = '${metric}'
    GROUP BY time
    ORDER BY time
  `;

  // Execute query via Cloudflare API
  // Return results
}
```

---

## Performance Budgets

### Define Budgets

```typescript
// src/observability/budgets.ts
export const performanceBudgets = {
  api: {
    p50ResponseTime: 100,  // ms
    p95ResponseTime: 200,  // ms
    p99ResponseTime: 500,  // ms
    errorRate: 0.01,       // 1%
  },
  database: {
    avgQueryTime: 20,      // ms
    p95QueryTime: 50,      // ms
  },
  cache: {
    hitRate: 0.80,         // 80%
  },
  frontend: {
    lcp: 2500,             // ms
    fid: 100,              // ms
    cls: 0.1,              // unitless
  },
};
```

### Budget Enforcement

```typescript
export async function checkBudgets(metrics: Metrics): Promise<BudgetViolation[]> {
  const violations: BudgetViolation[] = [];

  if (metrics.p95ResponseTime > performanceBudgets.api.p95ResponseTime) {
    violations.push({
      metric: 'p95ResponseTime',
      actual: metrics.p95ResponseTime,
      budget: performanceBudgets.api.p95ResponseTime,
      severity: 'high',
    });
  }

  // Check other budgets...

  return violations;
}
```

---

## Best Practices

### 1. Log Sampling

For high-traffic endpoints, sample logs to reduce volume:

```typescript
const SAMPLE_RATE = 0.1; // 10%

if (Math.random() < SAMPLE_RATE || isError) {
  logger.info('Request processed', context);
}
```

### 2. Metric Aggregation

Aggregate metrics before sending to reduce data points:

```typescript
// Batch metrics every 60 seconds
const metricsBatch: Metric[] = [];

setInterval(() => {
  if (metricsBatch.length > 0) {
    sendMetricsBatch(metricsBatch);
    metricsBatch.length = 0;
  }
}, 60000);
```

### 3. Correlation IDs

Always propagate correlation IDs across services:

```typescript
// In every service call
fetch('/api/external-service', {
  headers: {
    'X-Request-ID': requestId,
    'X-Correlation-ID': correlationId,
  },
});
```

### 4. Gradual Rollout Monitoring

Monitor new deployments closely:

```bash
# Monitor first 15 minutes after deployment
./scripts/performance-monitor.sh production 15

# Check for anomalies
./scripts/health-check.sh production
```

---

## Troubleshooting

### High Latency Investigation

1. Check recent deployments
2. Analyze slow query logs
3. Check cache hit rate
4. Review external API response times
5. Examine database connection pool

### Error Rate Spike

1. Check error distribution (which endpoints?)
2. Review recent code changes
3. Check external service status
4. Examine rate limiting logs
5. Verify authentication system

### Memory Leaks

1. Monitor Workers memory usage
2. Check for unclosed connections
3. Review Durable Object lifecycle
4. Examine cache size
5. Profile memory allocation

---

## Related Documentation

- [Monitoring & Alerts](./monitoring-alerts.md)
- [Incident Response Playbook](./incident-response-playbook.md)
- [Performance Optimization Roadmap](./performance-optimization-roadmap.md)
- [Troubleshooting Guide](./troubleshooting-guide.md)

---

**Last Updated**: 2025-10-21
**Next Review**: 2026-01-21
**Owner**: Engineering Team
