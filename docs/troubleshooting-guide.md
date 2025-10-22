# Production Troubleshooting Guide

**Quick Reference for Common Issues**

---

## Table of Contents

1. [Performance Issues](#performance-issues)
2. [Authentication Problems](#authentication-problems)
3. [Database Errors](#database-errors)
4. [Deployment Failures](#deployment-failures)
5. [Frontend Issues](#frontend-issues)
6. [Cache Problems](#cache-problems)
7. [Monitoring & Diagnostics](#monitoring--diagnostics)

---

## Performance Issues

### Slow Response Times (>200ms)

**Symptoms:**
- API endpoints responding slowly
- Users reporting lag
- P95 response time exceeds 200ms

**Diagnosis:**
```bash
# Check worker latency
wrangler tail --env production | grep "Response-Time"

# View analytics
wrangler analytics view --env production

# Check specific endpoint
curl -w "@curl-format.txt" https://api.coreflow360.com/api/v1/dashboard/stats
```

**Solutions:**

1. **Check Cache Hit Rate:**
   ```bash
   # View cache metrics
   curl https://api.coreflow360.com/api/v1/analytics/performance
   ```
   - If hit rate <50%: Increase cache TTL
   - If hit rate <30%: Add more routes to caching

2. **Identify Slow Queries:**
   ```typescript
   // Add to database query function
   if (duration > 100) {
     logger.warn(`Slow query (${duration}ms):`, sql);
   }
   ```

3. **Enable More Caching:**
   ```typescript
   // Add route to caching middleware
   routes: [
     /^\/api\/v1\/your-slow-endpoint$/,
     // ... existing routes
   ]
   ```

### High Memory Usage

**Symptoms:**
- Worker crashes with OOM errors
- Inconsistent performance
- `memoryUsage` metric high

**Diagnosis:**
```typescript
// Check memory in worker logs
console.log('Memory:', process.memoryUsage());
```

**Solutions:**

1. **Reduce Data Size:**
   ```typescript
   // Paginate large results
   const leads = await getLeads({ page: 1, pageSize: 20 });

   // Select only needed fields
   SELECT id, name, email FROM users; // Not SELECT *
   ```

2. **Clear Unused Variables:**
   ```typescript
   // Let garbage collector free memory
   largeData = null;
   ```

3. **Use Streaming for Large Responses:**
   ```typescript
   return new Response(stream, {
     headers: { 'Content-Type': 'application/json' }
   });
   ```

---

## Authentication Problems

### "Invalid Token" Errors

**Symptoms:**
- Users can't log in
- Tokens rejected immediately
- 401 Unauthorized errors

**Diagnosis:**
```bash
# Check if JWT_SECRET is set
wrangler secret list --env production | grep JWT_SECRET

# Test token validation
curl -H "Authorization: Bearer YOUR_TOKEN" \
  https://api.coreflow360.com/api/v1/auth/verify
```

**Solutions:**

1. **Verify JWT Secret:**
   ```bash
   # Ensure secret is set correctly
   wrangler secret put JWT_SECRET --env production
   ```

2. **Check Token Expiration:**
   ```typescript
   // Decode token to check expiry
   const decoded = jwt.decode(token);
   console.log('Expires:', new Date(decoded.exp * 1000));
   ```

3. **Clear Token Blacklist (if needed):**
   ```bash
   # Check blacklisted tokens
   wrangler kv:key list --namespace-id=YOUR_KV_ID --env production
   ```

### Session Expired Too Quickly

**Symptoms:**
- Users logged out unexpectedly
- Session timeout <1 hour

**Diagnosis:**
```typescript
// Check session configuration
console.log('Session TTL:', SESSION_TTL);
```

**Solutions:**

1. **Increase Session Duration:**
   ```typescript
   // In wrangler.toml
   [env.production.vars]
   SESSION_TTL = "28800" # 8 hours
   ```

2. **Implement Sliding Sessions:**
   ```typescript
   // Refresh session on activity
   if (sessionAge > SESSION_REFRESH_THRESHOLD) {
     await refreshSession(userId);
   }
   ```

---

## Database Errors

### "Database Not Found"

**Symptoms:**
- 500 errors on all database operations
- "Database binding not found"

**Diagnosis:**
```bash
# List D1 databases
wrangler d1 list

# Check bindings in wrangler.toml
cat wrangler.toml | grep -A 3 "d1_databases"
```

**Solutions:**

1. **Verify Database Binding:**
   ```toml
   # wrangler.toml
   [[env.production.d1_databases]]
   binding = "DB_MAIN"
   database_id = "your-database-id"
   ```

2. **Create Database if Missing:**
   ```bash
   wrangler d1 create coreflow360-agents
   ```

3. **Apply Migrations:**
   ```bash
   wrangler d1 migrations apply coreflow360-agents --env production
   ```

### "Too Many Connections"

**Symptoms:**
- Intermittent 500 errors
- "Connection pool exhausted"

**Diagnosis:**
```typescript
// Log active connections
console.log('Active connections:', db.getActiveConnections());
```

**Solutions:**

1. **Implement Connection Pooling:**
   ```typescript
   // Already implemented in Database class
   // Ensure queries are properly closed
   const result = await db.query('SELECT * FROM users');
   // Connection auto-released
   ```

2. **Reduce Concurrent Queries:**
   ```typescript
   // Batch queries instead
   await Promise.all([
     query1,
     query2,
     query3
   ]);
   ```

### Migration Failed

**Symptoms:**
- New schema changes not applied
- "Migration already applied" error

**Diagnosis:**
```bash
# Check migration status
wrangler d1 migrations list coreflow360-agents --env production
```

**Solutions:**

1. **Force Migration:**
   ```bash
   # Mark as not applied
   wrangler d1 execute coreflow360-agents --env production \
     --command "DELETE FROM d1_migrations WHERE migration_name = 'XXX'"

   # Reapply
   wrangler d1 migrations apply coreflow360-agents --env production
   ```

2. **Manual SQL Execution:**
   ```bash
   wrangler d1 execute coreflow360-agents --env production \
     --file=database/migrations/XXX.sql
   ```

---

## Deployment Failures

### Build Fails

**Symptoms:**
- `npm run build` exits with errors
- TypeScript compilation errors

**Diagnosis:**
```bash
# Run build with verbose output
npm run build 2>&1 | tee build.log

# Check TypeScript errors
npm run type-check
```

**Solutions:**

1. **Fix TypeScript Errors:**
   ```bash
   # Show all errors
   npx tsc --noEmit --pretty

   # Fix common issues
   # - Missing types: npm install @types/node
   # - Type mismatches: Check and fix types
   ```

2. **Clear Build Cache:**
   ```bash
   rm -rf dist/ .wrangler/
   npm run build
   ```

3. **Update Dependencies:**
   ```bash
   npm update
   cd frontend && npm update
   ```

### Wrangler Deploy Fails

**Symptoms:**
- `wrangler deploy` fails
- "Upload failed" errors

**Diagnosis:**
```bash
# Deploy with verbose logging
wrangler deploy --env production --verbose

# Check authentication
wrangler whoami
```

**Solutions:**

1. **Re-authenticate:**
   ```bash
   wrangler logout
   wrangler login
   ```

2. **Check Account Limits:**
   ```bash
   # Verify worker size <1MB
   ls -lh dist/worker.js
   ```

3. **Deploy to Staging First:**
   ```bash
   wrangler deploy --env staging
   # Test, then deploy to production
   ```

### Frontend Deploy Fails

**Symptoms:**
- `wrangler pages deploy` fails
- "Build directory not found"

**Diagnosis:**
```bash
# Check build directory exists
ls -la frontend/dist/

# Build frontend
cd frontend && npm run build
```

**Solutions:**

1. **Rebuild Frontend:**
   ```bash
   cd frontend
   rm -rf dist/ node_modules/
   npm install
   npm run build
   ```

2. **Deploy with Correct Path:**
   ```bash
   wrangler pages deploy frontend/dist \
     --project-name=coreflow360-frontend \
     --branch=production
   ```

---

## Frontend Issues

### White Screen / Blank Page

**Symptoms:**
- Page loads but shows nothing
- No errors in network tab

**Diagnosis:**
```javascript
// Check browser console for errors
// Open DevTools (F12) -> Console

// Check if React is loaded
console.log(React);

// Check router
console.log(window.__REACT_ROUTER__);
```

**Solutions:**

1. **Check JavaScript Errors:**
   - Open DevTools Console
   - Look for red error messages
   - Fix syntax errors or import issues

2. **Verify Base URL:**
   ```typescript
   // frontend/vite.config.ts
   base: '/', // Should match deployment URL
   ```

3. **Clear Browser Cache:**
   ```bash
   # Hard refresh
   Ctrl + Shift + R (Windows)
   Cmd + Shift + R (Mac)
   ```

### "Module not found" Errors

**Symptoms:**
- Import errors in console
- Components not loading

**Diagnosis:**
```bash
# Check if file exists
ls frontend/src/components/YourComponent.tsx

# Check import path
grep -r "import.*YourComponent" frontend/src/
```

**Solutions:**

1. **Fix Import Paths:**
   ```typescript
   // Use @ alias for src/
   import { Component } from '@/components/Component';
   ```

2. **Reinstall Dependencies:**
   ```bash
   cd frontend
   rm -rf node_modules/ package-lock.json
   npm install
   ```

### Slow Page Load

**Symptoms:**
- Landing page takes >3 seconds to load
- Large JavaScript bundle

**Diagnosis:**
```bash
# Check bundle sizes
cd frontend && npm run build
ls -lh dist/assets/*.js

# Use browser DevTools
# Network tab -> Check JS file sizes
```

**Solutions:**

1. **Verify Code-Splitting:**
   ```bash
   # Should see separate chunks
   # marketing.js, auth.js, app.js
   ls -lh dist/assets/
   ```

2. **Lazy Load Routes:**
   ```typescript
   // Already implemented in router
   defaultPreload: 'intent',
   ```

3. **Compress Images:**
   ```bash
   # Use optimized images
   # PNG -> WebP conversion
   ```

---

## Cache Problems

### Cache Not Working

**Symptoms:**
- Cache hit rate 0%
- All requests show "MISS"

**Diagnosis:**
```bash
# Check cache headers
curl -I https://api.coreflow360.com/api/v1/dashboard/stats | grep Cache

# Check middleware is loaded
# Look for "[Cache]" in logs
wrangler tail --env production | grep Cache
```

**Solutions:**

1. **Verify Middleware Enabled:**
   ```typescript
   // src/routes/index.ts
   api.use('*', cachingMiddleware({
     enabled: true, // Make sure this is true
     ttl: 300
   }));
   ```

2. **Check Route Patterns:**
   ```typescript
   // Ensure route matches cache patterns
   routes: [
     /^\/api\/v1\/dashboard\/stats$/,
   ]
   ```

3. **Verify KV Binding:**
   ```bash
   wrangler kv:namespace list --env production
   ```

### Stale Cache Data

**Symptoms:**
- Old data shown to users
- Updates not reflected

**Diagnosis:**
```bash
# Check cache TTL
curl -I https://api.coreflow360.com/api/v1/endpoint \
  | grep Cache-Control
```

**Solutions:**

1. **Invalidate Cache:**
   ```typescript
   await smartCache.invalidate('dashboard:stats:*', {
     recursive: true
   });
   ```

2. **Reduce TTL:**
   ```typescript
   cachingMiddleware({
     ttl: 60, // 1 minute instead of 5
   })
   ```

3. **Implement Cache Invalidation on Update:**
   ```typescript
   app.post('/api/v1/data', async (c) => {
     await updateData();
     await smartCache.invalidate('data:*');
   });
   ```

---

## Monitoring & Diagnostics

### View Worker Logs

```bash
# Real-time logs
wrangler tail --env production

# Filter logs
wrangler tail --env production | grep ERROR

# Save logs to file
wrangler tail --env production > logs.txt
```

### Check Analytics

```bash
# View performance metrics
curl https://api.coreflow360.com/api/v1/analytics/performance

# Cloudflare dashboard
# https://dash.cloudflare.com/{account_id}/workers/services/{worker_name}/production/analytics
```

### Health Check

```bash
# Backend health
curl https://api.coreflow360.com/health

# Expected response:
# {"status":"healthy","timestamp":"..."}

# API status
curl https://api.coreflow360.com/api/v1/health
```

### Performance Profiling

```typescript
// Add performance marks
performance.mark('start');
await someOperation();
performance.mark('end');
performance.measure('operation', 'start', 'end');

const measure = performance.getEntriesByName('operation')[0];
console.log(`Operation took ${measure.duration}ms`);
```

---

## Emergency Procedures

### Rollback Deployment

```bash
# 1. Rollback worker
wrangler rollback --env production

# 2. Rollback Pages
wrangler pages deployment list --project-name=coreflow360-frontend
wrangler pages deployment rollback <deployment-id>

# 3. Verify rollback
curl https://api.coreflow360.com/health
```

### Database Restore

```bash
# 1. Export current database (backup)
wrangler d1 export coreflow360-agents --env production --output backup.sql

# 2. Restore from backup
wrangler d1 execute coreflow360-agents --env production --file=backup.sql
```

### Enable Maintenance Mode

```typescript
// Add to worker
if (env.MAINTENANCE_MODE === 'true') {
  return new Response('System maintenance in progress', {
    status: 503,
    headers: { 'Retry-After': '3600' }
  });
}

// Enable via secret
wrangler secret put MAINTENANCE_MODE --env production
# Enter: "true"
```

---

## Getting Help

### Internal Resources

- **Documentation**: `/docs` directory
- **Runbooks**: `/docs/runbooks` (if available)
- **Deployment Checklist**: `DEPLOYMENT_CHECKLIST.md`

### External Resources

- [Cloudflare Workers Docs](https://developers.cloudflare.com/workers/)
- [Wrangler CLI Docs](https://developers.cloudflare.com/workers/wrangler/)
- [D1 Database Docs](https://developers.cloudflare.com/d1/)

### Support Channels

- **DevOps**: #devops-support
- **Backend**: #backend-team
- **Frontend**: #frontend-team
- **On-Call**: PagerDuty rotation

---

**Last Updated**: 2025-10-21
**Maintained By**: Platform Team
**Review Cycle**: As needed
