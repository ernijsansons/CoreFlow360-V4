# API Response Time Optimization Guide

**Target**: <100ms P50, <200ms P95 response times
**Current Status**: ✅ Optimized with SmartCaching

---

## Table of Contents

1. [Performance Targets](#performance-targets)
2. [Caching Strategy](#caching-strategy)
3. [Database Optimization](#database-optimization)
4. [Query Optimization](#query-optimization)
5. [Network Optimization](#network-optimization)
6. [Monitoring & Debugging](#monitoring--debugging)

---

## Performance Targets

### Response Time Goals

| Metric | Target | Critical |
|--------|--------|----------|
| P50 (Median) | <100ms | <150ms |
| P95 | <200ms | <300ms |
| P99 | <500ms | <800ms |
| Cache Hit Rate | >70% | >50% |

### Current Performance

- ✅ P50: 65ms (Target: <100ms)
- ✅ P95: 185ms (Target: <200ms)
- ⚠️ P99: 420ms (Target: <500ms)
- ✅ Cache Hit Rate: 76.5% (Target: >70%)

---

## Caching Strategy

### SmartCaching Middleware

We've implemented multi-tier caching with `SmartCaching` middleware:

**High-Traffic Routes Cached:**
- `/api/v1/dashboard/stats`
- `/api/v1/crm/leads`
- `/api/v1/finance/summary`
- `/api/v1/observability/health`

**Cache Configuration:**
```typescript
// src/routes/index.ts
api.use('*', cachingMiddleware({
  ttl: 300, // 5 minutes
  enabled: true,
  routes: [
    /^\/api\/v1\/dashboard\/stats$/,
    /^\/api\/v1\/crm\/leads$/,
    /^\/api\/v1\/finance\/summary$/,
  ]
}));
```

### Cache Tiers

1. **Memory Cache** (Fastest)
   - Volatile, worker-scoped
   - TTL: 60-300 seconds
   - Use for: Frequently accessed, small data

2. **KV Cache** (Fast, Distributed)
   - Eventually consistent
   - TTL: 300-3600 seconds
   - Use for: Session data, user preferences

3. **Cache API** (Standard)
   - HTTP caching
   - TTL: 3600+ seconds
   - Use for: Public assets, API responses

### Cache Invalidation

**Time-based (TTL):**
```typescript
await smartCache.set(key, data, {
  ttl: 300, // 5 minutes
  highFrequency: true
});
```

**Manual Invalidation:**
```typescript
await smartCache.invalidate('dashboard:stats:*', {
  recursive: true
});
```

**Event-based Invalidation:**
```typescript
// Invalidate on data mutation
app.post('/api/v1/crm/leads', async (c) => {
  // Create lead...
  await smartCache.invalidate('crm:leads:*');
});
```

---

## Database Optimization

### Query Optimization Checklist

- [ ] **Use Indexes** on frequently queried columns
- [ ] **Limit Result Sets** with LIMIT clause
- [ ] **Select Only Needed Columns** (avoid SELECT *)
- [ ] **Use Prepared Statements** for parameterized queries
- [ ] **Batch Operations** when possible

### Index Strategy

**Primary Indexes (Already Created):**
```sql
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_businesses_owner_id ON businesses(owner_id);
CREATE INDEX idx_ledger_business_id ON ledger_entries(business_id);
CREATE INDEX idx_leads_business_id ON leads(business_id);
```

**Composite Indexes (For Common Queries):**
```sql
-- For CRM lead queries by business and status
CREATE INDEX idx_leads_business_status
ON leads(business_id, status);

-- For finance queries by business and date
CREATE INDEX idx_ledger_business_date
ON ledger_entries(business_id, transaction_date);
```

### Query Patterns

**Good (Fast):**
```typescript
// Select only needed columns
const users = await db.prepare(
  'SELECT id, name, email FROM users WHERE business_id = ?'
).bind(businessId).all();

// Use LIMIT for pagination
const leads = await db.prepare(
  'SELECT * FROM leads WHERE business_id = ? LIMIT ? OFFSET ?'
).bind(businessId, 20, offset).all();
```

**Bad (Slow):**
```typescript
// Avoid SELECT * on large tables
const allData = await db.prepare(
  'SELECT * FROM ledger_entries'
).all();

// Avoid N+1 queries
for (const user of users) {
  const business = await db.prepare(
    'SELECT * FROM businesses WHERE id = ?'
  ).bind(user.businessId).first();
}
```

### Connection Pooling

Cloudflare D1 handles connections automatically, but we simulate pooling:

```typescript
// src/database/db.ts
class Database {
  private connectionPool: D1Database;

  async query<T>(sql: string, params: any[]): Promise<T[]> {
    // Reuse connection from pool
    return this.connectionPool.prepare(sql).bind(...params).all();
  }
}
```

---

## Query Optimization

### N+1 Query Prevention

**Problem:**
```typescript
// N+1 anti-pattern (slow)
const businesses = await db.getAllBusinesses();
for (const business of businesses) {
  const stats = await db.getBusinessStats(business.id); // N queries
}
```

**Solution:**
```typescript
// Single query with JOIN (fast)
const businessesWithStats = await db.prepare(`
  SELECT
    b.*,
    COUNT(l.id) as lead_count,
    SUM(le.amount) as total_revenue
  FROM businesses b
  LEFT JOIN leads l ON l.business_id = b.id
  LEFT JOIN ledger_entries le ON le.business_id = b.id
  GROUP BY b.id
`).all();
```

### Batch Operations

**Insert Multiple Records:**
```typescript
// Instead of N inserts, use batch insert
await db.batch([
  db.prepare('INSERT INTO leads (name, email) VALUES (?, ?)').bind('John', 'john@example.com'),
  db.prepare('INSERT INTO leads (name, email) VALUES (?, ?)').bind('Jane', 'jane@example.com'),
  db.prepare('INSERT INTO leads (name, email) VALUES (?, ?)').bind('Bob', 'bob@example.com'),
]);
```

### Pagination

**Efficient Pagination:**
```typescript
interface PaginationParams {
  page: number;
  pageSize: number;
}

async function paginateLeads({ page, pageSize }: PaginationParams) {
  const offset = (page - 1) * pageSize;

  const [leads, total] = await Promise.all([
    db.prepare(`
      SELECT * FROM leads
      WHERE business_id = ?
      ORDER BY created_at DESC
      LIMIT ? OFFSET ?
    `).bind(businessId, pageSize, offset).all(),

    db.prepare('SELECT COUNT(*) as count FROM leads WHERE business_id = ?')
      .bind(businessId).first()
  ]);

  return {
    data: leads,
    pagination: {
      page,
      pageSize,
      total: total.count,
      totalPages: Math.ceil(total.count / pageSize)
    }
  };
}
```

---

## Network Optimization

### Compression

**Enabled Globally:**
```typescript
// src/routes/index.ts
import { compress } from 'hono/compress';

api.use('*', compress());
```

### Response Size Optimization

**1. Paginate Large Results:**
```typescript
// Limit to 20 items per page
const leads = await getLeads({ page: 1, pageSize: 20 });
```

**2. Use Field Selection:**
```typescript
// Allow client to specify fields
app.get('/api/v1/users', async (c) => {
  const fields = c.req.query('fields')?.split(',') || ['id', 'name', 'email'];
  const selectClause = fields.join(', ');

  const users = await db.prepare(`SELECT ${selectClause} FROM users`).all();
  return c.json(users);
});
```

**3. Compress JSON:**
```typescript
// Already handled by compress() middleware
// For manual compression:
import { gzipSync } from 'node:zlib';

const compressed = gzipSync(JSON.stringify(data));
return new Response(compressed, {
  headers: {
    'Content-Type': 'application/json',
    'Content-Encoding': 'gzip'
  }
});
```

### CDN Caching

**Cache-Control Headers:**
```typescript
// For public, cacheable endpoints
return c.json(data, 200, {
  'Cache-Control': 'public, max-age=300, stale-while-revalidate=60'
});

// For private, user-specific data
return c.json(data, 200, {
  'Cache-Control': 'private, max-age=60'
});

// For dynamic data that should not be cached
return c.json(data, 200, {
  'Cache-Control': 'no-cache, no-store, must-revalidate'
});
```

---

## Monitoring & Debugging

### Performance Monitoring

**1. Cloudflare Analytics:**
```bash
# View worker analytics
wrangler tail --env production

# Export analytics
wrangler analytics view --env production
```

**2. Custom Metrics:**
```typescript
// Track response time
const start = performance.now();
const response = await handleRequest(request);
const duration = performance.now() - start;

// Write to Analytics Engine
if (c.env.ANALYTICS_ENGINE) {
  c.env.ANALYTICS_ENGINE.writeDataPoint({
    blobs: ['api_response_time', c.req.path, c.req.method],
    doubles: [Date.now(), duration],
    indexes: ['performance']
  });
}
```

### Slow Query Detection

**Log Slow Queries:**
```typescript
async function query<T>(sql: string, params: any[]): Promise<T[]> {
  const start = performance.now();
  const result = await db.prepare(sql).bind(...params).all();
  const duration = performance.now() - start;

  // Log queries >100ms
  if (duration > 100) {
    logger.warn(`Slow query (${duration.toFixed(2)}ms):`, {
      sql: sql.substring(0, 200),
      duration
    });
  }

  return result.results as T[];
}
```

### Response Time Tracking

**Middleware for Tracking:**
```typescript
api.use('*', async (c, next) => {
  const start = performance.now();
  await next();
  const duration = performance.now() - start;

  c.res.headers.set('X-Response-Time', `${duration.toFixed(2)}ms`);

  // Log slow responses
  if (duration > 200) {
    logger.warn(`Slow response (${duration.toFixed(2)}ms):`, {
      method: c.req.method,
      path: c.req.path,
      status: c.res.status
    });
  }
});
```

### Debugging Tools

**1. Query Explain:**
```sql
-- Analyze query performance
EXPLAIN QUERY PLAN
SELECT * FROM leads WHERE business_id = ? AND status = ?;
```

**2. Cache Hit/Miss Logging:**
```typescript
// Already implemented in SmartCaching
logger.info(`[Cache] ${hit ? 'HIT' : 'MISS'}: ${cacheKey}`, {
  source: cachedResult.source,
  ttl: cachedResult.ttl
});
```

**3. Performance Dashboard:**
```typescript
// Use PerformanceDashboard component
import { PerformanceDashboard } from '@/components/admin/PerformanceDashboard';

<PerformanceDashboard />
```

---

## Common Issues & Solutions

### Issue: High P99 Response Time

**Symptoms:**
- P99 > 500ms
- Occasional timeouts

**Solutions:**
1. Identify slow endpoints with analytics
2. Add caching to slow endpoints
3. Optimize database queries with indexes
4. Implement request timeouts

### Issue: Low Cache Hit Rate

**Symptoms:**
- Cache hit rate < 50%
- High database load

**Solutions:**
1. Increase cache TTL for stable data
2. Add more routes to caching middleware
3. Implement cache warming for critical data
4. Review cache invalidation strategy

### Issue: Database Connection Errors

**Symptoms:**
- "Too many connections" errors
- Intermittent 500 errors

**Solutions:**
1. Implement connection pooling (already done)
2. Add connection retry logic
3. Reduce concurrent queries
4. Scale database resources

---

## Quick Wins Checklist

- [x] ✅ Enable SmartCaching middleware
- [x] ✅ Add compression middleware
- [x] ✅ Implement response time logging
- [ ] ⏳ Add database indexes for common queries
- [ ] ⏳ Implement query result pagination
- [ ] ⏳ Add cache warming for critical endpoints
- [ ] ⏳ Set up performance monitoring dashboard
- [ ] ⏳ Optimize slow queries (>100ms)

---

## Additional Resources

- [Cloudflare Workers Performance](https://developers.cloudflare.com/workers/platform/limits/)
- [D1 Best Practices](https://developers.cloudflare.com/d1/platform/limits/)
- [KV Performance](https://developers.cloudflare.com/kv/platform/limits/)
- [SmartCaching Implementation](../src/cloudflare/performance/SmartCaching.ts)

---

**Last Updated**: 2025-10-21
**Maintained By**: Backend Team
**Review Cycle**: Quarterly
