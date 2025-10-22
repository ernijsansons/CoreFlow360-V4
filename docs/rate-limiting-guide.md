# Rate Limiting Configuration Guide

**Purpose**: Prevent abuse and ensure fair resource allocation
**Implementation**: Enterprise Rate Limiter + Cloudflare Rate Limiting

---

## Table of Contents

1. [Overview](#overview)
2. [Rate Limit Rules](#rate-limit-rules)
3. [Implementation](#implementation)
4. [Configuration](#configuration)
5. [Monitoring](#monitoring)
6. [Bypass & Whitelisting](#bypass--whitelisting)

---

## Overview

### Why Rate Limiting?

**Protects Against:**
- DDoS attacks
- Brute force login attempts
- API abuse
- Resource exhaustion
- Scraping/data harvesting

**Benefits:**
- Fair resource allocation
- Improved system stability
- Cost control
- Security enhancement

### Rate Limiting Layers

1. **Cloudflare Edge** - Network-level protection
2. **Worker Rate Limiter** - Application-level control
3. **Enterprise Rate Limiter** - Business logic enforcement

---

## Rate Limit Rules

### Authentication Endpoints

**Login Endpoint:**
```typescript
'/api/v1/auth/login': {
  requests: 5,        // Maximum 5 requests
  window: 60,         // Per 60 seconds (1 minute)
  blockDuration: 900  // Block for 15 minutes after exceeding
}
```

**Rationale:**
- Prevents brute force attacks
- 5 attempts allows for typos
- 15-minute block deters automated attacks

**Register Endpoint:**
```typescript
'/api/v1/auth/register': {
  requests: 3,        // Maximum 3 requests
  window: 60,         // Per 60 seconds
  blockDuration: 1800 // Block for 30 minutes
}
```

**Rationale:**
- Prevents spam account creation
- Lower limit than login (registration is one-time)
- Longer block duration for registration abuse

**Password Reset:**
```typescript
'/api/v1/auth/reset-password': {
  requests: 3,
  window: 300,        // Per 5 minutes
  blockDuration: 3600 // Block for 1 hour
}
```

### API Endpoints

**Default API Rate Limit:**
```typescript
'/api/v1/*': {
  requests: 100,      // 100 requests
  window: 60,         // Per minute
  blockDuration: 60   // Block for 1 minute
}
```

**High-Traffic Endpoints:**
```typescript
'/api/v1/dashboard/stats': {
  requests: 200,      // 200 requests per minute
  window: 60,
  perUser: true       // Per-user limit (not per IP)
}
```

**Resource-Intensive Endpoints:**
```typescript
'/api/v1/reports/generate': {
  requests: 10,       // Only 10 requests
  window: 3600,       // Per hour
  blockDuration: 3600 // Block for 1 hour
}
```

### Public Endpoints

**Landing Page:**
```typescript
'/': {
  requests: 1000,     // High limit for public access
  window: 60
}
```

**Static Assets:**
```typescript
'/assets/*': {
  requests: 10000,    // Very high limit
  window: 60
}
```

---

## Implementation

### Enterprise Rate Limiter

**Basic Usage:**
```typescript
import { EnterpriseRateLimiter } from '@/security/enterprise-rate-limiter';

// Initialize
const rateLimiter = new EnterpriseRateLimiter(env.RATE_LIMITER_DO);

// Check limit
const result = await rateLimiter.checkLimit(clientIp, {
  endpoint: '/api/v1/auth/login',
  businessId: businessId,
  userId: userId
});

if (!result.allowed) {
  return c.json({
    error: 'Rate limit exceeded',
    retryAfter: result.retryAfter,
    limit: result.limit,
    remaining: 0
  }, 429);
}
```

### Middleware Integration

**Global Rate Limiting:**
```typescript
// src/routes/index.ts
import { rateLimitMiddleware } from '@/middleware/rate-limit';

api.use('*', rateLimitMiddleware({
  rules: {
    '/api/v1/auth/login': { requests: 5, window: 60 },
    '/api/v1/auth/register': { requests: 3, window: 60 },
    '/api/v1/*': { requests: 100, window: 60 }
  }
}));
```

**Per-Route Rate Limiting:**
```typescript
// Specific endpoint
app.post('/api/v1/auth/login',
  rateLimit({ requests: 5, window: 60 }),
  async (c) => {
    // Login logic...
  }
);
```

### Custom Rate Limit Logic

**Adaptive Rate Limiting:**
```typescript
async function getAdaptiveLimit(userId: string): Promise<number> {
  const userTier = await getUserTier(userId);

  const limits = {
    free: 100,
    pro: 1000,
    enterprise: 10000
  };

  return limits[userTier] || limits.free;
}

// Apply adaptive limit
const limit = await getAdaptiveLimit(userId);
const result = await rateLimiter.checkLimit(clientIp, {
  customLimit: limit
});
```

**Burst Allowance:**
```typescript
// Allow burst of 10 requests, then 100/minute
const burstConfig = {
  burst: 10,          // Initial burst allowance
  sustained: 100,     // Sustained rate
  window: 60
};

const result = await rateLimiter.checkLimit(clientIp, burstConfig);
```

---

## Configuration

### Environment Variables

```bash
# Rate Limiter Configuration
RATE_LIMIT_ENABLED=true
RATE_LIMIT_DEFAULT_REQUESTS=100
RATE_LIMIT_DEFAULT_WINDOW=60

# Whitelist
RATE_LIMIT_WHITELIST=192.168.1.100,10.0.0.1

# Custom limits for user tiers
RATE_LIMIT_FREE=100
RATE_LIMIT_PRO=1000
RATE_LIMIT_ENTERPRISE=10000
```

### Wrangler Configuration

```toml
# wrangler.toml
[env.production.vars]
RATE_LIMIT_ENABLED = "true"
RATE_LIMIT_DEFAULT_REQUESTS = "100"
RATE_LIMIT_DEFAULT_WINDOW = "60"

[[env.production.durable_objects.bindings]]
name = "RATE_LIMITER_DO"
class_name = "AdvancedRateLimiterDO"

[[env.production.kv_namespaces]]
binding = "KV_RATE_LIMIT_METRICS"
id = "your-kv-namespace-id"
```

### Rate Limit Rules File

**Create `config/rate-limits.json`:**
```json
{
  "auth": {
    "/api/v1/auth/login": {
      "requests": 5,
      "window": 60,
      "blockDuration": 900,
      "message": "Too many login attempts. Please try again in 15 minutes."
    },
    "/api/v1/auth/register": {
      "requests": 3,
      "window": 60,
      "blockDuration": 1800,
      "message": "Too many registration attempts. Please try again in 30 minutes."
    }
  },
  "api": {
    "/api/v1/dashboard/stats": {
      "requests": 200,
      "window": 60,
      "perUser": true
    },
    "/api/v1/reports/generate": {
      "requests": 10,
      "window": 3600,
      "message": "Report generation limit reached. Please try again in 1 hour."
    }
  },
  "default": {
    "requests": 100,
    "window": 60,
    "message": "Rate limit exceeded. Please slow down."
  }
}
```

---

## Monitoring

### Rate Limit Metrics

**Track Rate Limit Events:**
```typescript
// Log rate limit hits
if (!result.allowed) {
  logger.warn('Rate limit exceeded', {
    ip: clientIp,
    endpoint: request.url,
    limit: result.limit,
    window: result.window
  });

  // Write to analytics
  if (env.ANALYTICS_ENGINE) {
    env.ANALYTICS_ENGINE.writeDataPoint({
      blobs: ['rate_limit_exceeded', endpoint, clientIp],
      doubles: [Date.now(), 1],
      indexes: ['security', 'rate_limit']
    });
  }
}
```

**Dashboard Metrics:**
```typescript
// Get rate limit statistics
app.get('/api/v1/admin/rate-limits/stats', async (c) => {
  const stats = await getRateLimitStats();

  return c.json({
    totalRequests: stats.total,
    blocked: stats.blocked,
    blockRate: (stats.blocked / stats.total) * 100,
    topBlockedIPs: stats.topIPs,
    topBlockedEndpoints: stats.topEndpoints
  });
});
```

### Alert on High Block Rate

```typescript
// Alert if >10% of requests are blocked
if ((blocked / total) > 0.1) {
  await sendAlert({
    severity: 'high',
    metric: 'rate_limit_block_rate',
    value: (blocked / total) * 100,
    threshold: 10,
    message: 'High rate limit block rate detected - possible attack'
  });
}
```

---

## Bypass & Whitelisting

### IP Whitelisting

**Whitelist Trusted IPs:**
```typescript
const WHITELISTED_IPS = [
  '192.168.1.100',  // Office IP
  '10.0.0.1',       // VPN Gateway
  '203.0.113.0/24'  // Partner API
];

function isWhitelisted(ip: string): boolean {
  return WHITELISTED_IPS.some(whitelistedIp => {
    if (whitelistedIp.includes('/')) {
      return ipInCIDR(ip, whitelistedIp);
    }
    return ip === whitelistedIp;
  });
}

// Skip rate limiting for whitelisted IPs
if (isWhitelisted(clientIp)) {
  return next();
}
```

### API Key Bypass

**Bypass for Authenticated API Keys:**
```typescript
// Check for API key
const apiKey = c.req.header('X-API-Key');

if (apiKey && await isValidAPIKey(apiKey)) {
  // Apply higher limits for API keys
  const result = await rateLimiter.checkLimit(apiKey, {
    requests: 10000, // Much higher limit
    window: 60
  });
}
```

### User Tier Bypass

**Different Limits by Subscription:**
```typescript
const tierLimits = {
  free: 100,
  pro: 1000,
  enterprise: Infinity // No limit
};

const userTier = await getUserTier(userId);
const limit = tierLimits[userTier];

if (limit === Infinity) {
  return next(); // Skip rate limiting
}
```

---

## Response Headers

### Rate Limit Headers

**Include Rate Limit Info in Response:**
```typescript
return c.json(data, 200, {
  'X-RateLimit-Limit': String(result.limit),
  'X-RateLimit-Remaining': String(result.remaining),
  'X-RateLimit-Reset': String(result.resetTime),
  'X-RateLimit-Window': String(result.window)
});
```

**On Rate Limit Exceeded:**
```typescript
return c.json({
  error: 'Rate limit exceeded',
  message: 'Too many requests. Please try again later.',
  retryAfter: result.retryAfter
}, 429, {
  'X-RateLimit-Limit': String(result.limit),
  'X-RateLimit-Remaining': '0',
  'X-RateLimit-Reset': String(result.resetTime),
  'Retry-After': String(result.retryAfter)
});
```

---

## Testing Rate Limits

### Manual Testing

```bash
# Test login rate limit (5 requests/minute)
for i in {1..6}; do
  curl -X POST https://api.coreflow360.com/api/v1/auth/login \
    -H "Content-Type: application/json" \
    -d '{"email":"test@example.com","password":"wrong"}' \
    -w "\nStatus: %{http_code}\n"
  echo "Request $i"
done

# Expected: First 5 succeed (or fail auth), 6th returns 429
```

### Automated Testing

```typescript
// test/rate-limit.test.ts
import { describe, it, expect } from 'vitest';

describe('Rate Limiting', () => {
  it('should block after 5 login attempts', async () => {
    const requests = Array(6).fill(null).map(() =>
      fetch('/api/v1/auth/login', {
        method: 'POST',
        body: JSON.stringify({ email: 'test@example.com', password: 'wrong' })
      })
    );

    const responses = await Promise.all(requests);
    const lastResponse = responses[responses.length - 1];

    expect(lastResponse.status).toBe(429);
    expect(lastResponse.headers.get('Retry-After')).toBeTruthy();
  });

  it('should reset after window expires', async () => {
    // Make 5 requests
    await Promise.all(Array(5).fill(null).map(() =>
      fetch('/api/v1/auth/login', { method: 'POST', body: '{}' })
    ));

    // Wait for window to expire (60 seconds)
    await new Promise(resolve => setTimeout(resolve, 61000));

    // Should be allowed again
    const response = await fetch('/api/v1/auth/login', {
      method: 'POST',
      body: '{}'
    });

    expect(response.status).not.toBe(429);
  });
});
```

---

## Best Practices

### 1. Use Appropriate Limits
- **Too Low**: Frustrates legitimate users
- **Too High**: Doesn't prevent abuse
- **Rule of Thumb**: 10x normal usage

### 2. Provide Clear Feedback
```typescript
// Good error message
{
  "error": "Rate limit exceeded",
  "message": "You've made too many requests. Please wait 15 minutes.",
  "retryAfter": 900,
  "limit": 5,
  "window": 60
}

// Bad error message
{
  "error": "Too many requests"
}
```

### 3. Log Rate Limit Events
```typescript
logger.warn('Rate limit exceeded', {
  ip: clientIp,
  endpoint: request.url,
  userAgent: request.headers.get('User-Agent'),
  timestamp: new Date().toISOString()
});
```

### 4. Monitor Trends
- Track blocked IPs over time
- Identify potential attacks early
- Adjust limits based on usage patterns

### 5. Implement Gradually
- Start with high limits
- Monitor usage patterns
- Gradually tighten limits
- Communicate changes to users

---

## Troubleshooting

### Issue: Legitimate Users Being Blocked

**Diagnosis:**
```bash
# Check rate limit logs
wrangler tail --env production | grep "Rate limit"

# Identify blocked IPs
curl https://api.coreflow360.com/api/v1/admin/rate-limits/blocked-ips
```

**Solutions:**
1. Increase limits for that endpoint
2. Whitelist specific IPs
3. Implement API key authentication for higher limits

### Issue: Limits Not Working

**Diagnosis:**
```typescript
// Check if rate limiter is enabled
console.log('Rate limit enabled:', env.RATE_LIMIT_ENABLED);

// Check DO binding
console.log('Rate limiter DO:', env.RATE_LIMITER_DO);
```

**Solutions:**
1. Verify DO binding in wrangler.toml
2. Check KV namespace is created
3. Ensure middleware is registered

---

## Rate Limit Summary

| Endpoint | Requests | Window | Block Duration |
|----------|----------|--------|----------------|
| Login | 5 | 1 min | 15 min |
| Register | 3 | 1 min | 30 min |
| Password Reset | 3 | 5 min | 1 hour |
| API Default | 100 | 1 min | 1 min |
| Dashboard Stats | 200 | 1 min | 1 min |
| Report Generation | 10 | 1 hour | 1 hour |
| Public Pages | 1000 | 1 min | - |

---

**Last Updated**: 2025-10-21
**Maintained By**: Security Team
**Review Cycle**: Quarterly
