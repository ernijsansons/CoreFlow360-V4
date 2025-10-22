# Monitoring & Alerting Setup Guide

**Created**: 2025-10-22
**Purpose**: Configure comprehensive monitoring and alerting for production systems
**Audience**: DevOps engineers, SRE teams, on-call engineers

---

## Table of Contents

1. [Overview](#overview)
2. [Sentry Error Tracking](#sentry-error-tracking)
3. [Cloudflare Analytics](#cloudflare-analytics)
4. [Custom Metrics Dashboard](#custom-metrics-dashboard)
5. [Alerting Configuration](#alerting-configuration)
6. [Log Management](#log-management)
7. [Uptime Monitoring](#uptime-monitoring)
8. [Performance Monitoring](#performance-monitoring)

---

## Overview

### Monitoring Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                   Application Layer                         │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐                  │
│  │ Frontend │  │ Backend  │  │ Database │                  │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘                  │
└───────┼─────────────┼─────────────┼────────────────────────┘
        │             │             │
        ▼             ▼             ▼
┌─────────────────────────────────────────────────────────────┐
│                   Monitoring & Observability                │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│  │  Sentry  │  │Cloudflare│  │  Custom  │  │  Uptime  │   │
│  │  Errors  │  │Analytics │  │ Metrics  │  │  Monitor │   │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘   │
└───────┼─────────────┼─────────────┼─────────────┼──────────┘
        │             │             │             │
        └─────────────┴─────────────┴─────────────┘
                           │
                           ▼
              ┌────────────────────────┐
              │   Alerting Channels    │
              │  ┌──────┐  ┌──────┐   │
              │  │Slack │  │Email │   │
              │  └──────┘  └──────┘   │
              │  ┌──────┐  ┌──────┐   │
              │  │ SMS  │  │PagerD│   │
              │  └──────┘  └──────┘   │
              └────────────────────────┘
```

### Metrics to Track

**1. Application Health**:
- Error rate (errors per minute)
- Response time (P50, P95, P99)
- Request rate (requests per minute)
- Success rate (%)

**2. Business Metrics**:
- Feature usage (compliance guidelines created, invoices processed)
- User activity (active users, login rate)
- Conversion metrics (trial to paid, feature adoption)

**3. Infrastructure Metrics**:
- Worker CPU usage
- Database query performance
- KV cache hit rate
- CDN cache hit rate

**4. Security Metrics**:
- Failed login attempts
- Unauthorized access attempts
- API rate limit violations
- Suspicious activity patterns

---

## Sentry Error Tracking

### 1. Sentry Project Setup

**Sign up**: https://sentry.io

**Create Projects**:
1. `coreflow360-frontend` - Frontend React application
2. `coreflow360-backend` - Backend Cloudflare Workers

### 2. Frontend Integration

**Install Sentry SDK**:
```bash
cd frontend
npm install @sentry/react @sentry/vite-plugin
```

**Configure Sentry** (`frontend/src/lib/sentry.ts`):

```typescript
import * as Sentry from '@sentry/react'
import { BrowserTracing } from '@sentry/tracing'

export function initSentry() {
  Sentry.init({
    dsn: import.meta.env.VITE_SENTRY_DSN,
    environment: import.meta.env.VITE_ENVIRONMENT || 'development',

    // Performance Monitoring
    integrations: [
      new BrowserTracing({
        tracePropagationTargets: ['localhost', /^https:\/\/.*\.coreflow360\.com/],
      }),
    ],

    // Performance monitoring sample rate (100% in production)
    tracesSampleRate: import.meta.env.PROD ? 1.0 : 0.1,

    // Error sampling (capture all errors in production)
    sampleRate: 1.0,

    // Release tracking
    release: import.meta.env.VITE_RELEASE_VERSION,

    // User context
    beforeSend(event, hint) {
      // Filter out sensitive data
      if (event.request) {
        delete event.request.cookies
      }
      return event
    },

    // Ignore specific errors
    ignoreErrors: [
      // Browser extensions
      'top.GLOBALS',
      // Network errors users can't control
      'Network request failed',
      'NetworkError',
    ],
  })
}
```

**Initialize in App** (`frontend/src/main.tsx`):

```typescript
import { initSentry } from './lib/sentry'

// Initialize Sentry before React
initSentry()

import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App'

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
)
```

**Add Error Boundary**:

```typescript
import * as Sentry from '@sentry/react'

const SentryErrorBoundary = Sentry.ErrorBoundary

function App() {
  return (
    <SentryErrorBoundary fallback={<ErrorFallback />}>
      <Router>
        {/* Your app */}
      </Router>
    </SentryErrorBoundary>
  )
}

function ErrorFallback() {
  return (
    <div className="error-page">
      <h1>Something went wrong</h1>
      <p>We've been notified and are working on a fix.</p>
      <button onClick={() => window.location.reload()}>
        Reload Page
      </button>
    </div>
  )
}
```

### 3. Backend Integration

**Install Sentry SDK**:
```bash
npm install @sentry/node @sentry/tracing
```

**Configure Sentry** (`src/lib/sentry.ts`):

```typescript
import * as Sentry from '@sentry/node'
import { ProfilingIntegration } from '@sentry/profiling-node'

export function initSentry(env: Env) {
  Sentry.init({
    dsn: env.SENTRY_DSN,
    environment: env.ENVIRONMENT,

    // Performance monitoring
    tracesSampleRate: 1.0,

    // Profiling
    profilesSampleRate: 1.0,
    integrations: [
      new ProfilingIntegration(),
    ],

    // Release tracking
    release: env.RELEASE_VERSION,
  })
}
```

**Add to Worker** (`src/index.ts`):

```typescript
import { Hono } from 'hono'
import * as Sentry from '@sentry/node'
import { initSentry } from './lib/sentry'

const app = new Hono()

// Sentry middleware
app.use('*', async (c, next) => {
  const transaction = Sentry.startTransaction({
    op: 'http.request',
    name: `${c.req.method} ${c.req.path}`,
  })

  try {
    await next()
  } catch (error) {
    Sentry.captureException(error, {
      contexts: {
        request: {
          method: c.req.method,
          url: c.req.url,
          headers: c.req.header(),
        },
      },
    })
    throw error
  } finally {
    transaction.finish()
  }
})

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext) {
    initSentry(env)
    return app.fetch(request, env, ctx)
  },
}
```

### 4. Sentry Alerts

**Configure in Sentry Dashboard**:

1. **Error Rate Alert**:
   - Condition: Error count > 10 in 5 minutes
   - Action: Send to Slack #incidents
   - Frequency: Every 5 minutes

2. **New Error Alert**:
   - Condition: New unique error appears
   - Action: Send to Slack #engineering
   - Frequency: Immediately

3. **Performance Degradation**:
   - Condition: P95 response time > 2 seconds for 10 minutes
   - Action: Send to Slack #incidents, email on-call engineer
   - Frequency: Every 10 minutes

---

## Cloudflare Analytics

### 1. Enable Analytics

**Cloudflare Dashboard** → Analytics → Enable

**Available Metrics**:
- Requests (total, cached, uncached)
- Bandwidth
- Unique visitors
- Threats blocked
- Status codes (2xx, 3xx, 4xx, 5xx)
- Response time

### 2. Workers Analytics API

**Fetch Analytics Programmatically**:

```typescript
interface WorkersAnalytics {
  errors: number
  requests: number
  duration: {
    avg: number
    p50: number
    p95: number
    p99: number
  }
}

async function getWorkersAnalytics(
  accountId: string,
  scriptName: string,
  apiToken: string,
  since: string = '-1h'
): Promise<WorkersAnalytics> {
  const url = `https://api.cloudflare.com/client/v4/accounts/${accountId}/workers/scripts/${scriptName}/analytics`

  const response = await fetch(url, {
    headers: {
      'Authorization': `Bearer ${apiToken}`,
      'Content-Type': 'application/json',
    },
  })

  const data = await response.json()
  return data.result
}

// Usage
const analytics = await getWorkersAnalytics(
  'your-account-id',
  'coreflow360-production',
  'your-api-token',
  '-15m'
)

console.log(`Error rate: ${analytics.errors / analytics.requests}`)
console.log(`P95 response time: ${analytics.duration.p95}ms`)
```

### 3. GraphQL Analytics API

**More Flexible Queries**:

```graphql
query WorkerAnalytics($accountTag: String!, $filter: Filter!) {
  viewer {
    accounts(filter: { accountTag: $accountTag }) {
      workersInvocationsAdaptive(
        filter: $filter
        limit: 1000
        orderBy: [datetime_DESC]
      ) {
        datetime: dimensions {
          datetime
        }
        metrics {
          requests
          errors
          cpuTime
          duration
        }
      }
    }
  }
}
```

---

## Custom Metrics Dashboard

### 1. Metrics Collection API

**Create Metrics Service** (`src/services/metrics.service.ts`):

```typescript
import { Env } from '../types'

export interface Metric {
  name: string
  value: number
  timestamp: number
  tags?: Record<string, string>
}

export class MetricsService {
  constructor(private env: Env) {}

  /**
   * Track a metric
   */
  async track(metric: Metric): Promise<void> {
    // Store in KV for quick retrieval
    const key = `metric:${metric.name}:${metric.timestamp}`
    await this.env.KV_METRICS.put(key, JSON.stringify(metric), {
      expirationTtl: 86400 * 30, // 30 days
    })

    // Also store in D1 for long-term analysis
    await this.env.DB_MAIN.prepare(`
      INSERT INTO metrics (name, value, timestamp, tags)
      VALUES (?, ?, ?, ?)
    `).bind(
      metric.name,
      metric.value,
      metric.timestamp,
      JSON.stringify(metric.tags || {})
    ).run()
  }

  /**
   * Get metrics for a time range
   */
  async getMetrics(
    name: string,
    since: number,
    until?: number
  ): Promise<Metric[]> {
    const query = until
      ? `SELECT * FROM metrics WHERE name = ? AND timestamp >= ? AND timestamp <= ? ORDER BY timestamp DESC`
      : `SELECT * FROM metrics WHERE name = ? AND timestamp >= ? ORDER BY timestamp DESC`

    const result = until
      ? await this.env.DB_MAIN.prepare(query).bind(name, since, until).all()
      : await this.env.DB_MAIN.prepare(query).bind(name, since).all()

    return result.results as Metric[]
  }

  /**
   * Get aggregated metrics
   */
  async getAggregated(
    name: string,
    since: number,
    interval: '1m' | '5m' | '15m' | '1h' | '1d' = '5m'
  ): Promise<{ timestamp: number; avg: number; min: number; max: number; count: number }[]> {
    const intervalSeconds = {
      '1m': 60,
      '5m': 300,
      '15m': 900,
      '1h': 3600,
      '1d': 86400,
    }[interval]

    const result = await this.env.DB_MAIN.prepare(`
      SELECT
        (timestamp / ?) * ? as interval_start,
        AVG(value) as avg,
        MIN(value) as min,
        MAX(value) as max,
        COUNT(*) as count
      FROM metrics
      WHERE name = ? AND timestamp >= ?
      GROUP BY interval_start
      ORDER BY interval_start DESC
    `).bind(intervalSeconds, intervalSeconds, name, since).all()

    return result.results.map(row => ({
      timestamp: row.interval_start as number,
      avg: row.avg as number,
      min: row.min as number,
      max: row.max as number,
      count: row.count as number,
    }))
  }
}
```

### 2. Track Custom Metrics

**Example: Track Feature Usage**:

```typescript
import { MetricsService } from './services/metrics.service'

// In your API handler
app.post('/api/compliance/guidelines', async (c) => {
  const metrics = new MetricsService(c.env)

  // ... create guideline ...

  // Track metric
  await metrics.track({
    name: 'compliance.guideline.created',
    value: 1,
    timestamp: Date.now(),
    tags: {
      user_id: user.id,
      category: guideline.category,
    },
  })

  return c.json({ success: true })
})
```

**Example: Track Response Times**:

```typescript
// Middleware to track response times
app.use('*', async (c, next) => {
  const start = Date.now()
  await next()
  const duration = Date.now() - start

  const metrics = new MetricsService(c.env)
  await metrics.track({
    name: 'api.response_time',
    value: duration,
    timestamp: Date.now(),
    tags: {
      method: c.req.method,
      path: c.req.path,
      status: c.res.status.toString(),
    },
  })
})
```

### 3. Metrics Dashboard API

**Create Endpoints** (`src/routes/admin/metrics.ts`):

```typescript
import { Hono } from 'hono'
import { MetricsService } from '../../services/metrics.service'

const app = new Hono()

// Get error rate (last 15 minutes)
app.get('/errors', async (c) => {
  const metrics = new MetricsService(c.env)
  const since = Date.now() - 15 * 60 * 1000

  const errors = await metrics.getMetrics('api.error', since)
  const requests = await metrics.getMetrics('api.request', since)

  const errorRate = errors.length / requests.length

  return c.json({
    error_rate: errorRate,
    total_errors: errors.length,
    total_requests: requests.length,
  })
})

// Get response times (last 15 minutes, 1-minute buckets)
app.get('/response-times', async (c) => {
  const metrics = new MetricsService(c.env)
  const since = Date.now() - 15 * 60 * 1000

  const data = await metrics.getAggregated('api.response_time', since, '1m')

  return c.json({
    p50_ms: median(data.map(d => d.avg)),
    p95_ms: percentile(data.map(d => d.max), 95),
    p99_ms: percentile(data.map(d => d.max), 99),
    buckets: data,
  })
})

// Get feature usage (last 24 hours)
app.get('/feature-usage', async (c) => {
  const feature = c.req.query('feature') || 'compliance.guideline.created'
  const metrics = new MetricsService(c.env)
  const since = Date.now() - 24 * 60 * 60 * 1000

  const data = await metrics.getAggregated(feature, since, '1h')

  return c.json({
    feature,
    total_usage: data.reduce((sum, d) => sum + d.count, 0),
    hourly_buckets: data,
  })
})

export default app
```

### 4. Frontend Dashboard

**Create Dashboard Component** (`frontend/src/pages/admin/MetricsDashboard.tsx`):

```typescript
import { useQuery } from '@tanstack/react-query'
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend } from 'recharts'

export function MetricsDashboard() {
  const { data: errorRate } = useQuery({
    queryKey: ['metrics', 'errors'],
    queryFn: () => fetch('/api/admin/metrics/errors').then(r => r.json()),
    refetchInterval: 60000, // Refresh every minute
  })

  const { data: responseTimes } = useQuery({
    queryKey: ['metrics', 'response-times'],
    queryFn: () => fetch('/api/admin/metrics/response-times').then(r => r.json()),
    refetchInterval: 60000,
  })

  return (
    <div className="metrics-dashboard">
      <h1>Metrics Dashboard</h1>

      {/* Error Rate Card */}
      <div className="metric-card">
        <h2>Error Rate (Last 15 min)</h2>
        <div className="metric-value">
          {(errorRate?.error_rate * 100).toFixed(2)}%
        </div>
        <div className="metric-detail">
          {errorRate?.total_errors} errors / {errorRate?.total_requests} requests
        </div>
      </div>

      {/* Response Time Card */}
      <div className="metric-card">
        <h2>Response Times</h2>
        <div className="metric-value">
          P95: {responseTimes?.p95_ms}ms
        </div>
        <div className="metric-detail">
          P50: {responseTimes?.p50_ms}ms | P99: {responseTimes?.p99_ms}ms
        </div>
      </div>

      {/* Response Time Chart */}
      <div className="chart-container">
        <h2>Response Time Trend</h2>
        <LineChart width={800} height={300} data={responseTimes?.buckets || []}>
          <CartesianGrid strokeDasharray="3 3" />
          <XAxis dataKey="timestamp" />
          <YAxis />
          <Tooltip />
          <Legend />
          <Line type="monotone" dataKey="avg" stroke="#8884d8" name="Average" />
          <Line type="monotone" dataKey="max" stroke="#ff0000" name="Max" />
        </LineChart>
      </div>
    </div>
  )
}
```

---

## Alerting Configuration

### 1. Alert Rules

**Create Alert Service** (`src/services/alert.service.ts`):

```typescript
export interface AlertRule {
  id: string
  name: string
  metric: string
  condition: string // e.g., "error_rate > 0.01"
  threshold: number
  duration: number // seconds
  channels: ('slack' | 'email' | 'sms' | 'pagerduty')[]
  enabled: boolean
}

export class AlertService {
  constructor(private env: Env) {}

  /**
   * Check if alert should be triggered
   */
  async checkAlert(rule: AlertRule): Promise<boolean> {
    const metrics = new MetricsService(this.env)
    const since = Date.now() - rule.duration * 1000

    const data = await metrics.getMetrics(rule.metric, since)

    // Calculate metric value based on condition
    let value: number
    if (rule.condition.includes('error_rate')) {
      const errors = data.filter(m => m.tags?.type === 'error').length
      value = errors / data.length
    } else if (rule.condition.includes('p95')) {
      value = percentile(data.map(d => d.value), 95)
    } else {
      value = data.reduce((sum, d) => sum + d.value, 0) / data.length
    }

    // Check condition
    return this.evaluateCondition(rule.condition, value, rule.threshold)
  }

  /**
   * Send alert to configured channels
   */
  async sendAlert(rule: AlertRule, value: number): Promise<void> {
    const message = `🚨 Alert: ${rule.name}\n\nCondition: ${rule.condition}\nCurrent Value: ${value}\nThreshold: ${rule.threshold}`

    for (const channel of rule.channels) {
      switch (channel) {
        case 'slack':
          await this.sendSlackAlert(message)
          break
        case 'email':
          await this.sendEmailAlert(message)
          break
        case 'sms':
          await this.sendSMSAlert(message)
          break
        case 'pagerduty':
          await this.sendPagerDutyAlert(message)
          break
      }
    }
  }

  private async sendSlackAlert(message: string): Promise<void> {
    await fetch(this.env.SLACK_WEBHOOK_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        text: message,
        channel: '#incidents',
      }),
    })
  }

  private async sendEmailAlert(message: string): Promise<void> {
    // Use SendGrid or similar
    // Implementation details...
  }

  private async sendSMSAlert(message: string): Promise<void> {
    // Use Twilio or similar
    // Implementation details...
  }

  private async sendPagerDutyAlert(message: string): Promise<void> {
    await fetch('https://events.pagerduty.com/v2/enqueue', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        routing_key: this.env.PAGERDUTY_ROUTING_KEY,
        event_action: 'trigger',
        payload: {
          summary: message,
          severity: 'critical',
          source: 'CoreFlow360 Monitoring',
        },
      }),
    })
  }

  private evaluateCondition(condition: string, value: number, threshold: number): boolean {
    if (condition.includes('>')) return value > threshold
    if (condition.includes('<')) return value < threshold
    if (condition.includes('>=')) return value >= threshold
    if (condition.includes('<=')) return value <= threshold
    if (condition.includes('==')) return value === threshold
    return false
  }
}
```

### 2. Alert Cron Job

**Create Scheduled Worker** (using Cloudflare Cron Triggers):

```typescript
// In wrangler.toml
[triggers]
crons = ["*/5 * * * *"]  # Every 5 minutes

// In src/index.ts
export default {
  async scheduled(event: ScheduledEvent, env: Env, ctx: ExecutionContext) {
    const alertService = new AlertService(env)

    // Define alert rules
    const rules: AlertRule[] = [
      {
        id: 'high-error-rate',
        name: 'High Error Rate',
        metric: 'api.error',
        condition: 'error_rate > 0.01',
        threshold: 0.01,
        duration: 300, // 5 minutes
        channels: ['slack', 'email'],
        enabled: true,
      },
      {
        id: 'slow-response-time',
        name: 'Slow Response Time',
        metric: 'api.response_time',
        condition: 'p95 > 2000',
        threshold: 2000,
        duration: 600, // 10 minutes
        channels: ['slack'],
        enabled: true,
      },
    ]

    // Check all rules
    for (const rule of rules) {
      if (!rule.enabled) continue

      const shouldAlert = await alertService.checkAlert(rule)
      if (shouldAlert) {
        await alertService.sendAlert(rule, /* value */ 0)
      }
    }
  },
}
```

---

## Log Management

### 1. Structured Logging

**Create Logger** (`src/lib/logger.ts`):

```typescript
export enum LogLevel {
  DEBUG = 'debug',
  INFO = 'info',
  WARN = 'warn',
  ERROR = 'error',
}

export interface LogContext {
  user_id?: string
  business_id?: string
  request_id?: string
  [key: string]: any
}

export class Logger {
  constructor(
    private level: LogLevel = LogLevel.INFO,
    private context: LogContext = {}
  ) {}

  debug(message: string, data?: any) {
    this.log(LogLevel.DEBUG, message, data)
  }

  info(message: string, data?: any) {
    this.log(LogLevel.INFO, message, data)
  }

  warn(message: string, data?: any) {
    this.log(LogLevel.WARN, message, data)
  }

  error(message: string, error?: Error, data?: any) {
    this.log(LogLevel.ERROR, message, { ...data, error: error?.stack })
  }

  private log(level: LogLevel, message: string, data?: any) {
    const logEntry = {
      timestamp: new Date().toISOString(),
      level,
      message,
      context: this.context,
      data,
    }

    // Output to console (captured by Cloudflare logs)
    console.log(JSON.stringify(logEntry))

    // Optionally send to external logging service
    // this.sendToLogService(logEntry)
  }
}

// Usage
const logger = new Logger(LogLevel.INFO, {
  user_id: 'user-123',
  request_id: 'req-abc',
})

logger.info('User created guideline', { guideline_id: 'guid-456' })
logger.error('Failed to save guideline', new Error('Database error'))
```

### 2. View Logs

**Cloudflare Dashboard**:
```
Workers → Your Worker → Logs → Real-time Logs
```

**Wrangler CLI**:
```bash
# Tail logs in real-time
wrangler tail

# Filter logs by status
wrangler tail --status error

# Filter logs by method
wrangler tail --method POST

# Filter logs by header
wrangler tail --header "X-Custom-Header: value"
```

---

## Uptime Monitoring

### 1. External Uptime Monitor

**Recommended Services**:
- **UptimeRobot** (free, 5-minute checks)
- **Pingdom** (paid, 1-minute checks)
- **StatusCake** (free tier available)

**Endpoints to Monitor**:
- `https://coreflow360.com` (Homepage - 200 OK)
- `https://api.coreflow360.com/health` (API Health - 200 OK)
- `https://api.coreflow360.com/api/status` (API Status - 200 OK)

### 2. UptimeRobot Configuration

**Setup**:
1. Sign up at https://uptimerobot.com
2. Add Monitor → HTTP(s)
3. Configure:
   - **URL**: https://api.coreflow360.com/health
   - **Monitoring Interval**: 5 minutes
   - **Alert Contacts**: Email, Slack webhook

**Slack Integration**:
```
Settings → Alert Contacts → Add Alert Contact
→ Web-Hook
→ URL: https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK
→ POST Value: {"text": "*monitorFriendlyName* is *alertTypeFriendlyName*"}
```

---

## Performance Monitoring

### 1. Real User Monitoring (RUM)

**Frontend Performance Tracking**:

```typescript
// Track page load time
window.addEventListener('load', () => {
  const perfData = performance.getEntriesByType('navigation')[0] as PerformanceNavigationTiming

  // Send to analytics
  fetch('/api/analytics/performance', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      type: 'page_load',
      metrics: {
        dns: perfData.domainLookupEnd - perfData.domainLookupStart,
        tcp: perfData.connectEnd - perfData.connectStart,
        request: perfData.responseStart - perfData.requestStart,
        response: perfData.responseEnd - perfData.responseStart,
        dom: perfData.domContentLoadedEventEnd - perfData.domContentLoadedEventStart,
        total: perfData.loadEventEnd - perfData.fetchStart,
      },
    }),
  })
})

// Track Core Web Vitals
import { getCLS, getFID, getFCP, getLCP, getTTFB } from 'web-vitals'

function sendToAnalytics(metric: any) {
  fetch('/api/analytics/web-vitals', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(metric),
  })
}

getCLS(sendToAnalytics)
getFID(sendToAnalytics)
getFCP(sendToAnalytics)
getLCP(sendToAnalytics)
getTTFB(sendToAnalytics)
```

### 2. Backend Performance Tracking

**Track Database Query Performance**:

```typescript
class DatabaseMetrics {
  async trackQuery<T>(queryName: string, queryFn: () => Promise<T>): Promise<T> {
    const start = Date.now()

    try {
      const result = await queryFn()
      const duration = Date.now() - start

      // Track successful query
      await this.track({
        name: 'db.query.duration',
        value: duration,
        tags: { query: queryName, status: 'success' },
      })

      return result
    } catch (error) {
      const duration = Date.now() - start

      // Track failed query
      await this.track({
        name: 'db.query.duration',
        value: duration,
        tags: { query: queryName, status: 'error' },
      })

      throw error
    }
  }
}

// Usage
const metrics = new DatabaseMetrics(env)
const guidelines = await metrics.trackQuery('list_guidelines', async () => {
  return await db.prepare('SELECT * FROM compliance_guidelines').all()
})
```

---

## Monitoring Checklist

**Initial Setup** (One-time):
- [ ] Sentry project created (frontend + backend)
- [ ] Cloudflare Analytics enabled
- [ ] Custom metrics database schema created
- [ ] Alert rules configured
- [ ] Uptime monitors configured (UptimeRobot)
- [ ] Slack webhook configured for alerts
- [ ] PagerDuty integration configured (if needed)

**Daily Monitoring** (Automated):
- [ ] Check Sentry dashboard for new errors
- [ ] Review Cloudflare Analytics (request rate, error rate)
- [ ] Check uptime monitor status
- [ ] Review alert history (any alerts triggered?)

**Weekly Review**:
- [ ] Analyze error trends in Sentry
- [ ] Review performance metrics (response time trends)
- [ ] Check feature usage metrics
- [ ] Update alert thresholds if needed

**Monthly Review**:
- [ ] Review and refine alert rules
- [ ] Analyze long-term performance trends
- [ ] Update monitoring documentation
- [ ] Test alert channels (send test alerts)

---

## Best Practices

1. **Monitor What Matters**: Focus on metrics that impact users (error rate, response time, uptime)
2. **Set Realistic Thresholds**: Avoid alert fatigue - only alert on actionable issues
3. **Context is Key**: Always include context in logs (user_id, business_id, request_id)
4. **Trend Over Time**: Look for trends, not just point-in-time values
5. **Test Alerts**: Regularly test alert channels to ensure they work when needed

---

**Document Version**: 1.0
**Last Updated**: 2025-10-22
**Maintained By**: DevOps Team
**Review Cycle**: Monthly
