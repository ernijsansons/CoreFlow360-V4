# Cache Service Documentation

This directory contains caching implementations for CoreFlow360 V4.

## Available Caching Systems

### 1. Simple CacheService (`cache-service.ts`)
A lightweight 2-layer cache implementation as originally specified.

**Features:**
- L1: Edge Cache API (fastest)
- L2: KV Storage (distributed)
- Simple TTL management
- Pattern-based invalidation
- Bulk operations

**Use Cases:**
- Simple applications
- Educational purposes
- Lightweight scenarios
- Quick prototyping

### 2. SmartCaching (`../cloudflare/performance/SmartCaching.ts`)
Enterprise-grade 4-layer intelligent caching system.

**Features:**
- Memory + KV + Cache API + R2
- Intelligent strategy selection
- Advanced analytics
- Multi-tier promotion
- Production-ready error handling

**Use Cases:**
- Production applications
- High-performance scenarios
- Complex caching needs
- Enterprise features

## Usage Examples

### Simple CacheService

```typescript
import { createCacheService } from './cache-service';

// Initialize
const cacheService = createCacheService(env.CACHE);

// Basic operations
await cacheService.set('user:123', userData, 'user-data');
const user = await cacheService.get('user:123');

// Check existence
const exists = await cacheService.has('user:123');

// Invalidate patterns
await cacheService.invalidate('user:*');

// Bulk operations
await cacheService.setMany({
  'user:1': user1Data,
  'user:2': user2Data
}, 'user-data');

const users = await cacheService.getMany(['user:1', 'user:2']);
```

### TTL Configuration

The simple CacheService uses content-type based TTL:

```typescript
const ttls = {
  'user-data': 60,        // 1 minute
  'financial': 300,       // 5 minutes
  'analytics': 3600,      // 1 hour
  'static': 86400,        // 1 day
  'config': 604800        // 1 week
};
```

### Cache Statistics

```typescript
const stats = await cacheService.getStats();
console.log('L1 Hits:', stats.l1Hits);
console.log('L2 Hits:', stats.l2Hits);
console.log('Hit Rate:', stats.hitRate);
```

### Cache Information

```typescript
const info = await cacheService.getInfo('user:123');
if (info) {
  console.log('Source:', info.source);
  console.log('TTL:', info.ttl);
  console.log('Size:', info.size);
}
```

## Integration Options

### Option 1: Use Simple CacheService for Basic Needs

```typescript
import { createCacheService } from './cache/cache-service';

const simpleCache = createCacheService(env.CACHE);
await simpleCache.set('session:abc', sessionData, 'user-data');
```

### Option 2: Use SmartCaching for Advanced Features

```typescript
import { SmartCaching } from './cloudflare/performance/SmartCaching';

const smartCache = new SmartCaching(env);
await smartCache.set('analytics:report', reportData, {
  highFrequency: true,
  ttl: 3600
});
```

### Option 3: Use Both Based on Use Case

```typescript
// Simple cache for basic user data
const userCache = createCacheService(env.CACHE);
await userCache.set('user:profile', profile, 'user-data');

// Smart cache for complex analytics
const analyticsCache = new SmartCaching(env);
await analyticsCache.set('analytics:dashboard', dashboard, {
  userSpecific: true,
  highFrequency: true
});
```

## Performance Comparison

| Feature | Simple CacheService | SmartCaching |
|---------|-------------------|--------------|
| **Layers** | 2 (Cache API + KV) | 4 (Memory + KV + Cache API + R2) |
| **Strategy** | Fixed | Intelligent |
| **Complexity** | Low | High |
| **Performance** | Good | Excellent |
| **Features** | Basic | Enterprise |
| **Size** | ~200 lines | ~560 lines |

## When to Use Each

### Use Simple CacheService When:
- Building simple applications
- Learning cache concepts
- Need lightweight solution
- Want predictable behavior
- Debugging cache issues

### Use SmartCaching When:
- Building production applications
- Need high performance
- Want automatic optimization
- Require advanced analytics
- Building enterprise features

## Best Practices

1. **Choose the Right Tool**: Use Simple CacheService for basic needs, SmartCaching for production
2. **TTL Selection**: Match TTL to data volatility
3. **Key Naming**: Use consistent, hierarchical key patterns
4. **Invalidation**: Use specific keys when possible, patterns sparingly
5. **Monitoring**: Track cache hit rates and performance
6. **Testing**: Test cache behavior under load
7. **Error Handling**: Always handle cache failures gracefully

## Migration Path

If you start with Simple CacheService and need to upgrade:

```typescript
// Before (Simple)
const cache = createCacheService(env.CACHE);
await cache.set('data', value, 'analytics');

// After (Smart)
const cache = new SmartCaching(env);
await cache.set('data', value, { ttl: 3600 });
```

The interfaces are similar but SmartCaching offers more configuration options.