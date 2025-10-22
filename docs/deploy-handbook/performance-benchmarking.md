# Performance Benchmarking Guide

**Created**: 2025-10-22
**Purpose**: Measure, track, and optimize application performance
**Audience**: Frontend engineers, backend engineers, DevOps

---

## Table of Contents

1. [Overview](#overview)
2. [Performance Targets](#performance-targets)
3. [Frontend Benchmarking](#frontend-benchmarking)
4. [Backend Benchmarking](#backend-benchmarking)
5. [Database Performance](#database-performance)
6. [Load Testing](#load-testing)
7. [Optimization Strategies](#optimization-strategies)
8. [Continuous Monitoring](#continuous-monitoring)

---

## Overview

### Why Benchmark?

**Benefits**:
- Detect performance regressions early
- Validate optimization efforts
- Set realistic SLAs for customers
- Identify bottlenecks before they impact users
- Track performance trends over time

### Benchmarking Cadence

| When | What to Benchmark | Why |
|------|-------------------|-----|
| **Before Each Release** | Full performance suite | Catch regressions |
| **Weekly** | Critical paths (login, dashboard load) | Trend analysis |
| **After Optimization** | Specific optimized feature | Validate improvements |
| **Quarterly** | Comprehensive load testing | Capacity planning |

---

## Performance Targets

### Frontend Performance Targets

**Lighthouse Scores** (All ≥ 90):
- **Performance**: ≥ 95
- **Accessibility**: ≥ 95
- **Best Practices**: ≥ 95
- **SEO**: ≥ 90

**Core Web Vitals**:
- **LCP** (Largest Contentful Paint): < 2.5s
- **FID** (First Input Delay): < 100ms
- **CLS** (Cumulative Layout Shift): < 0.1

**Other Metrics**:
- **First Contentful Paint (FCP)**: < 1.8s
- **Time to Interactive (TTI)**: < 3.8s
- **Total Blocking Time (TBT)**: < 200ms
- **Bundle Size**: < 500KB (initial load)

---

### Backend Performance Targets

**API Response Times**:
- **P50**: < 100ms
- **P95**: < 500ms
- **P99**: < 1000ms

**Throughput**:
- **Requests per second**: > 100 RPS
- **Concurrent users**: > 1000 simultaneous users

**Database Queries**:
- **Simple queries** (SELECT with WHERE): < 10ms
- **Complex queries** (JOINs, aggregations): < 100ms
- **Write operations**: < 50ms

**Error Rate**:
- **Overall error rate**: < 0.1%
- **5xx errors**: < 0.01%

---

## Frontend Benchmarking

### 1. Lighthouse CLI

**Install Lighthouse**:
```bash
npm install -g @lhci/cli lighthouse
```

**Run Lighthouse**:
```bash
# Single run
lighthouse https://coreflow360.com \
  --output html \
  --output-path ./lighthouse-report.html \
  --chrome-flags="--headless"

# Multiple runs (more accurate)
lighthouse https://coreflow360.com \
  --output json \
  --output-path ./lighthouse-results.json \
  --runs 5

# Specific categories only
lighthouse https://coreflow360.com \
  --only-categories=performance,accessibility \
  --output json
```

**Lighthouse CI Configuration**:

File: `frontend/.lighthouserc.json`

```json
{
  "ci": {
    "collect": {
      "startServerCommand": "npm run preview",
      "url": ["http://localhost:4173"],
      "numberOfRuns": 5
    },
    "assert": {
      "preset": "lighthouse:recommended",
      "assertions": {
        "categories:performance": ["error", {"minScore": 0.95}],
        "categories:accessibility": ["error", {"minScore": 0.95}],
        "categories:best-practices": ["error", {"minScore": 0.95}],
        "categories:seo": ["error", {"minScore": 0.90}],
        "first-contentful-paint": ["error", {"maxNumericValue": 1800}],
        "largest-contentful-paint": ["error", {"maxNumericValue": 2500}],
        "cumulative-layout-shift": ["error", {"maxNumericValue": 0.1}],
        "total-blocking-time": ["error", {"maxNumericValue": 200}]
      }
    },
    "upload": {
      "target": "temporary-public-storage"
    }
  }
}
```

**Run Lighthouse CI**:
```bash
lhci autorun
```

---

### 2. Bundle Size Analysis

**Analyze Bundle**:
```bash
# Build with stats
npm run build -- --mode production

# Install bundle analyzer
npm install -D vite-plugin-visualizer

# Add to vite.config.ts
import { visualizer } from 'rollup-plugin-visualizer'

export default defineConfig({
  plugins: [
    visualizer({
      open: true,
      gzipSize: true,
      brotliSize: true,
    }),
  ],
})

# Build and analyze
npm run build
```

**Bundle Size Report**:
```
dist/
├── assets/
│   ├── index-abc123.js         245 KB (gzipped: 78 KB)
│   ├── vendor-def456.js        189 KB (gzipped: 62 KB)
│   ├── compliance-xyz789.js     42 KB (gzipped: 14 KB)
│   └── index-abc123.css         28 KB (gzipped: 7 KB)
└── Total:                      504 KB (gzipped: 161 KB)
```

**Targets**:
- Initial bundle (index.js + vendor.js): < 500 KB (uncompressed)
- Initial bundle (gzipped): < 150 KB
- Code-split chunks: < 100 KB each

---

### 3. React Performance Profiling

**React DevTools Profiler**:

```tsx
import { Profiler } from 'react'

function onRenderCallback(
  id: string,
  phase: 'mount' | 'update',
  actualDuration: number,
  baseDuration: number,
  startTime: number,
  commitTime: number
) {
  console.log(`${id} (${phase}): ${actualDuration}ms`)

  // Send to analytics if slow
  if (actualDuration > 100) {
    fetch('/api/analytics/slow-render', {
      method: 'POST',
      body: JSON.stringify({
        component: id,
        phase,
        duration: actualDuration,
      }),
    })
  }
}

// Wrap component in Profiler
function App() {
  return (
    <Profiler id="App" onRender={onRenderCallback}>
      <ComplianceGuidelinesPage />
    </Profiler>
  )
}
```

**Identify Performance Issues**:
- Components rendering too frequently
- Expensive renders (> 100ms)
- Unnecessary re-renders
- Large component trees

---

### 4. Web Vitals Monitoring

**Install web-vitals**:
```bash
npm install web-vitals
```

**Track Web Vitals**:
```typescript
import { getCLS, getFID, getFCP, getLCP, getTTFB } from 'web-vitals'

function sendToAnalytics(metric: any) {
  const body = JSON.stringify({
    name: metric.name,
    value: metric.value,
    rating: metric.rating,
    delta: metric.delta,
    id: metric.id,
  })

  // Use sendBeacon if available (won't block page unload)
  if (navigator.sendBeacon) {
    navigator.sendBeacon('/api/analytics/web-vitals', body)
  } else {
    fetch('/api/analytics/web-vitals', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body,
      keepalive: true,
    })
  }
}

// Track all Core Web Vitals
getCLS(sendToAnalytics)
getFID(sendToAnalytics)
getFCP(sendToAnalytics)
getLCP(sendToAnalytics)
getTTFB(sendToAnalytics)
```

**Interpret Results**:

| Metric | Good | Needs Improvement | Poor |
|--------|------|-------------------|------|
| **LCP** | ≤ 2.5s | 2.5s - 4.0s | > 4.0s |
| **FID** | ≤ 100ms | 100ms - 300ms | > 300ms |
| **CLS** | ≤ 0.1 | 0.1 - 0.25 | > 0.25 |
| **FCP** | ≤ 1.8s | 1.8s - 3.0s | > 3.0s |
| **TTFB** | ≤ 800ms | 800ms - 1800ms | > 1800ms |

---

## Backend Benchmarking

### 1. API Response Time Testing

**Simple Response Time Test**:

```bash
#!/bin/bash
# test-api-response-time.sh

URL="https://api.coreflow360.com/api/compliance/guidelines"
ITERATIONS=100

echo "Testing API response time ($ITERATIONS requests)..."
echo ""

TOTAL=0

for i in $(seq 1 $ITERATIONS); do
  START=$(date +%s%N)

  curl -s -o /dev/null \
    -H "Authorization: Bearer $AUTH_TOKEN" \
    "$URL"

  END=$(date +%s%N)
  DURATION=$(( ($END - $START) / 1000000 )) # Convert to ms

  TOTAL=$(( $TOTAL + $DURATION ))

  echo "Request $i: ${DURATION}ms"
done

AVERAGE=$(( $TOTAL / $ITERATIONS ))

echo ""
echo "Average response time: ${AVERAGE}ms"
```

**Expected Output**:
```
Request 1: 87ms
Request 2: 92ms
Request 3: 85ms
...
Request 100: 91ms

Average response time: 89ms
```

---

### 2. Apache Bench (ab)

**Install**:
```bash
# Mac
brew install httpd

# Linux (Ubuntu)
sudo apt-get install apache2-utils
```

**Basic Test**:
```bash
# 1000 requests, 10 concurrent
ab -n 1000 -c 10 \
  -H "Authorization: Bearer $AUTH_TOKEN" \
  https://api.coreflow360.com/api/compliance/guidelines
```

**Output**:
```
Concurrency Level:      10
Time taken for tests:   8.234 seconds
Complete requests:      1000
Failed requests:        0
Total transferred:      2456000 bytes
Requests per second:    121.45 [#/sec] (mean)
Time per request:       82.34 [ms] (mean)
Time per request:       8.234 [ms] (mean, across all concurrent requests)

Percentage of the requests served within a certain time (ms)
  50%     78
  66%     85
  75%     91
  80%     95
  90%    105
  95%    118
  98%    135
  99%    152
 100%    245 (longest request)
```

**Interpretation**:
- ✅ P50: 78ms (target: < 100ms)
- ✅ P95: 118ms (target: < 500ms)
- ✅ P99: 152ms (target: < 1000ms)
- ✅ Throughput: 121 RPS (target: > 100 RPS)

---

### 3. Advanced Load Testing with k6

**Install k6**:
```bash
# Mac
brew install k6

# Linux
sudo gpg --no-default-keyring --keyring /usr/share/keyrings/k6-archive-keyring.gpg \
  --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys C5AD17C747E3415A3642D57D77C6C491D6AC1D69
echo "deb [signed-by=/usr/share/keyrings/k6-archive-keyring.gpg] https://dl.k6.io/deb stable main" \
  | sudo tee /etc/apt/sources.list.d/k6.list
sudo apt-get update
sudo apt-get install k6
```

**Load Test Script**:

File: `scripts/load-test.js`

```javascript
import http from 'k6/http'
import { check, sleep } from 'k6'
import { Rate, Trend } from 'k6/metrics'

// Custom metrics
const errorRate = new Rate('errors')
const complianceListDuration = new Trend('compliance_list_duration')

// Test configuration
export const options = {
  stages: [
    { duration: '1m', target: 50 },   // Ramp up to 50 users over 1 minute
    { duration: '3m', target: 50 },   // Stay at 50 users for 3 minutes
    { duration: '1m', target: 100 },  // Ramp up to 100 users over 1 minute
    { duration: '3m', target: 100 },  // Stay at 100 users for 3 minutes
    { duration: '1m', target: 0 },    // Ramp down to 0 users
  ],
  thresholds: {
    http_req_duration: ['p(95)<500'], // 95% of requests must complete below 500ms
    errors: ['rate<0.01'],            // Error rate must be below 1%
  },
}

const BASE_URL = 'https://api.coreflow360.com'
const AUTH_TOKEN = __ENV.AUTH_TOKEN || 'your-test-token'

export default function () {
  // Test 1: List compliance guidelines
  const listRes = http.get(`${BASE_URL}/api/compliance/guidelines`, {
    headers: {
      Authorization: `Bearer ${AUTH_TOKEN}`,
    },
  })

  check(listRes, {
    'list status is 200': (r) => r.status === 200,
    'list response time < 500ms': (r) => r.timings.duration < 500,
  })

  errorRate.add(listRes.status !== 200)
  complianceListDuration.add(listRes.timings.duration)

  sleep(1)

  // Test 2: Create compliance guideline
  const createPayload = JSON.stringify({
    title: `Load Test Guideline ${Date.now()}`,
    description: 'Test guideline created during load testing',
    category: 'data_privacy',
    severity: 'medium',
  })

  const createRes = http.post(
    `${BASE_URL}/api/compliance/guidelines`,
    createPayload,
    {
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${AUTH_TOKEN}`,
      },
    }
  )

  check(createRes, {
    'create status is 201': (r) => r.status === 201,
    'create response time < 1000ms': (r) => r.timings.duration < 1000,
  })

  errorRate.add(createRes.status !== 201)

  sleep(2)
}
```

**Run Load Test**:
```bash
k6 run scripts/load-test.js
```

**Output**:
```
     ✓ list status is 200
     ✓ list response time < 500ms
     ✓ create status is 201
     ✓ create response time < 1000ms

     checks.........................: 100.00% ✓ 4000      ✗ 0
     data_received..................: 2.1 MB  35 kB/s
     data_sent......................: 1.3 MB  22 kB/s
     http_req_duration..............: avg=245ms  min=87ms  med=235ms  max=1.2s  p(95)=425ms  p(99)=678ms
     http_reqs......................: 2000    33.33/s
     iteration_duration.............: avg=3.2s   min=3.1s  med=3.2s   max=4.5s  p(95)=3.5s   p(99)=3.8s
     vus............................: 100     max 100

✓ All thresholds passed
```

---

## Database Performance

### 1. Query Performance Analysis

**Enable Query Logging** (Cloudflare D1):

```typescript
// Wrap all database queries with performance tracking
async function trackQuery<T>(
  db: D1Database,
  queryName: string,
  queryFn: () => Promise<T>
): Promise<T> {
  const start = Date.now()

  try {
    const result = await queryFn()
    const duration = Date.now() - start

    console.log(JSON.stringify({
      type: 'db_query',
      query: queryName,
      duration_ms: duration,
      status: 'success',
    }))

    // Alert if slow query
    if (duration > 100) {
      console.warn(`Slow query detected: ${queryName} (${duration}ms)`)
    }

    return result
  } catch (error) {
    const duration = Date.now() - start

    console.error(JSON.stringify({
      type: 'db_query',
      query: queryName,
      duration_ms: duration,
      status: 'error',
      error: error.message,
    }))

    throw error
  }
}

// Usage
const guidelines = await trackQuery(
  env.DB_MAIN,
  'list_guidelines',
  () => env.DB_MAIN.prepare('SELECT * FROM compliance_guidelines').all()
)
```

### 2. Identify Slow Queries

**Analyze Query Logs**:

```bash
# Get slow queries from logs (> 100ms)
wrangler tail | grep "db_query" | jq 'select(.duration_ms > 100)'
```

**Common Slow Query Causes**:
- Missing indexes
- Full table scans
- Large result sets without pagination
- Complex JOINs
- N+1 query patterns

### 3. Query Optimization

**Before Optimization**:
```sql
-- Slow query (no index on category)
SELECT * FROM compliance_guidelines
WHERE category = 'data_privacy'
ORDER BY created_at DESC
LIMIT 20

-- Duration: 245ms (full table scan)
```

**After Optimization**:
```sql
-- Create index
CREATE INDEX idx_guidelines_category_created
ON compliance_guidelines(category, created_at DESC)

-- Same query
SELECT * FROM compliance_guidelines
WHERE category = 'data_privacy'
ORDER BY created_at DESC
LIMIT 20

-- Duration: 12ms (index scan)
```

**Optimization Results**:
- ✅ 95% faster (245ms → 12ms)
- ✅ Within target (< 100ms)

---

## Load Testing

### Full System Load Test

**Scenario**: Black Friday Load (10x normal traffic)

**Setup**:
```javascript
// k6 load test for high traffic scenario
export const options = {
  stages: [
    { duration: '5m', target: 500 },   // Ramp to 500 users
    { duration: '10m', target: 1000 }, // Ramp to 1000 users
    { duration: '20m', target: 1000 }, // Sustain 1000 users (peak)
    { duration: '5m', target: 500 },   // Ramp down
    { duration: '5m', target: 0 },     // Cool down
  ],
  thresholds: {
    http_req_duration: ['p(95)<1000', 'p(99)<2000'],
    errors: ['rate<0.01'],
  },
}

export default function () {
  // Mix of read and write operations
  const scenarios = [
    { weight: 0.60, fn: listGuidelines },    // 60% reads
    { weight: 0.20, fn: viewGuideline },     // 20% detail views
    { weight: 0.15, fn: createGuideline },   // 15% creates
    { weight: 0.05, fn: updateGuideline },   // 5% updates
  ]

  const random = Math.random()
  let cumulative = 0

  for (const scenario of scenarios) {
    cumulative += scenario.weight
    if (random < cumulative) {
      scenario.fn()
      break
    }
  }

  sleep(Math.random() * 3 + 1) // Random think time 1-4s
}
```

**Expected Results**:
- P95 response time: < 1000ms (target met)
- P99 response time: < 2000ms (target met)
- Error rate: < 0.1% (target met)
- Throughput: > 500 RPS (sustained)

---

## Optimization Strategies

### Frontend Optimizations

**1. Code Splitting**:
```typescript
// Before: All routes loaded upfront
import { ComplianceGuidelinesPage } from './pages/ComplianceGuidelinesPage'

// After: Lazy load routes
const ComplianceGuidelinesPage = lazy(() =>
  import('./pages/ComplianceGuidelinesPage')
)
```

**2. Image Optimization**:
```html
<!-- Before: Large unoptimized image -->
<img src="/logo.png" />

<!-- After: Optimized with modern formats -->
<picture>
  <source srcset="/logo.webp" type="image/webp" />
  <source srcset="/logo.png" type="image/png" />
  <img src="/logo.png" alt="Logo" loading="lazy" />
</picture>
```

**3. React Query Caching**:
```typescript
// Configure aggressive caching for rarely-changing data
export function useGuidelines() {
  return useQuery({
    queryKey: ['guidelines'],
    queryFn: () => complianceService.listGuidelines(),
    staleTime: 5 * 60 * 1000, // 5 minutes
    cacheTime: 30 * 60 * 1000, // 30 minutes
  })
}
```

---

### Backend Optimizations

**1. Database Indexing**:
```sql
-- Add indexes for frequently queried columns
CREATE INDEX idx_guidelines_category ON compliance_guidelines(category)
CREATE INDEX idx_guidelines_severity ON compliance_guidelines(severity)
CREATE INDEX idx_guidelines_created ON compliance_guidelines(created_at DESC)

-- Composite index for common query patterns
CREATE INDEX idx_guidelines_category_severity
ON compliance_guidelines(category, severity, created_at DESC)
```

**2. N+1 Query Elimination**:
```typescript
// Before: N+1 queries
const guidelines = await db.prepare('SELECT * FROM compliance_guidelines').all()
for (const guideline of guidelines.results) {
  guideline.violations = await db.prepare(
    'SELECT * FROM violations WHERE guideline_id = ?'
  ).bind(guideline.id).all()
}

// After: Single query with JOIN
const guidelines = await db.prepare(`
  SELECT
    g.*,
    JSON_GROUP_ARRAY(v.*) as violations
  FROM compliance_guidelines g
  LEFT JOIN violations v ON v.guideline_id = g.id
  GROUP BY g.id
`).all()
```

**3. Response Compression**:
```typescript
// Enable gzip compression for API responses
app.use('*', async (c, next) => {
  await next()

  if (c.res.headers.get('Content-Type')?.includes('application/json')) {
    // Cloudflare automatically compresses, but can enable explicit compression
    c.res.headers.set('Content-Encoding', 'gzip')
  }
})
```

---

## Continuous Monitoring

### Performance Dashboard

**Track Metrics Over Time**:

```typescript
// Weekly performance report
interface PerformanceReport {
  week: string
  frontend: {
    lighthouse_score: number
    lcp: number
    fid: number
    cls: number
  }
  backend: {
    p50_response_time: number
    p95_response_time: number
    p99_response_time: number
    error_rate: number
  }
  database: {
    avg_query_time: number
    slow_queries_count: number
  }
}

// Generate weekly report
async function generatePerformanceReport(): Promise<PerformanceReport> {
  // Aggregate metrics from past week
  // ...

  return {
    week: '2025-W47',
    frontend: {
      lighthouse_score: 96,
      lcp: 2.1,
      fid: 85,
      cls: 0.08,
    },
    backend: {
      p50_response_time: 89,
      p95_response_time: 245,
      p99_response_time: 512,
      error_rate: 0.0008,
    },
    database: {
      avg_query_time: 18,
      slow_queries_count: 3,
    },
  }
}
```

### Performance Regression Alerts

**Automated Regression Detection**:

```typescript
// Alert if performance degrades
async function checkPerformanceRegression() {
  const currentWeek = await generatePerformanceReport()
  const lastWeek = await getLastWeekReport()

  // Check for regressions (> 10% worse)
  const checks = [
    {
      name: 'Lighthouse Score',
      current: currentWeek.frontend.lighthouse_score,
      previous: lastWeek.frontend.lighthouse_score,
      threshold: 0.9, // 10% tolerance
    },
    {
      name: 'P95 Response Time',
      current: currentWeek.backend.p95_response_time,
      previous: lastWeek.backend.p95_response_time,
      threshold: 1.1, // 10% slower is regression
    },
  ]

  for (const check of checks) {
    const ratio = check.current / check.previous
    if (ratio > check.threshold || ratio < 1 / check.threshold) {
      await sendAlert({
        type: 'performance_regression',
        metric: check.name,
        current: check.current,
        previous: check.previous,
        change: ((ratio - 1) * 100).toFixed(1) + '%',
      })
    }
  }
}
```

---

## Benchmarking Checklist

**Before Each Release**:
- [ ] Run Lighthouse CI (all scores ≥ 90)
- [ ] Check bundle size (< 500 KB uncompressed)
- [ ] Run API response time tests (P95 < 500ms)
- [ ] Run load test (1000 concurrent users)
- [ ] Check database query performance (no queries > 100ms)
- [ ] Verify error rate (< 0.1%)

**After Optimization**:
- [ ] Measure improvement (% faster)
- [ ] Document optimization in changelog
- [ ] Update benchmarks in monitoring dashboard

**Quarterly**:
- [ ] Comprehensive load testing (capacity planning)
- [ ] Review all performance metrics trends
- [ ] Identify optimization opportunities
- [ ] Update performance targets if needed

---

## Best Practices

1. **Establish Baselines**: Always measure before optimizing
2. **Focus on User Impact**: Optimize what users experience first
3. **Measure in Production**: Real user data beats synthetic tests
4. **Track Trends**: One-time metrics are less useful than trends
5. **Automate**: Integrate benchmarking into CI/CD pipeline

---

**Document Version**: 1.0
**Last Updated**: 2025-10-22
**Maintained By**: Engineering Team
**Review Cycle**: Quarterly
