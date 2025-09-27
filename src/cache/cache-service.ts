import type { KVNamespace } from '@cloudflare/workers-types';

export class CacheService {
  constructor(
    private kv: KVNamespace,
    private cacheApi?: Cache
  ) {}

  // Multi-layer cache check
  async get(key: string): Promise<any> {
    // L1: Edge Cache API (fastest)
    if (this.cacheApi) {
      const cached = await this.cacheApi.match(key);
      if (cached) {
        return cached.json();
      }
    }

    // L2: KV (distributed)
    const kvData = await this.kv.get(key, { type: 'json' });
    if (kvData) {
      // Promote to L1 if cache available
      if (this.cacheApi) {
        await this.cacheApi.put(
          key,
          new Response(JSON.stringify(kvData))
        );
      }
      return kvData;
    }

    return null;
  }

  // Set data in both cache layers
  async set(key: string, data: any, contentType: string = 'default'): Promise<void> {
    const ttl = this.getTTL(contentType);

    // Set in KV with TTL
    await this.kv.put(key, JSON.stringify(data), {
      expirationTtl: ttl
    });

    // Set in Cache API with appropriate headers
    const response = new Response(JSON.stringify(data), {
      headers: {
        'Content-Type': 'application/json',
        'Cache-Control': `max-age=${ttl}`,
        'X-Cache-Timestamp': Date.now().toString(),
        'X-Cache-TTL': ttl.toString()
      }
    });

    if (this.cacheApi) {
      await this.cacheApi.put(key, response);
    }
  }

  // Smart cache invalidation with performance optimizations
  async invalidate(pattern: string, options: { businessId?: string; tags?: string[] } = {}): Promise<void> {
    const startTime = performance.now();
    const operations: Promise<void>[] = [];

    // Parallel invalidation for better performance
    if (pattern.includes('*')) {
      const prefix = pattern.replace('*', '');
      
      // KV invalidation
      operations.push(this.invalidateKVPattern(prefix, options.businessId));
      
      // Cache API invalidation
      operations.push(this.invalidateCacheAPIPattern(prefix));
    } else {
      // Direct key deletion
      operations.push(
        this.kv.delete(pattern),
        this.invalidateCacheAPIKey(pattern)
      );
    }

    // Execute all invalidations in parallel
    await Promise.allSettled(operations);
    
    // Performance tracking
    const duration = performance.now() - startTime;
    if (duration > 100) { // Log slow invalidations
      console.warn(`Slow cache invalidation: ${pattern} took ${duration}ms`);
    }
  }

  private async invalidateKVPattern(prefix: string, businessId?: string): Promise<void> {
    const batchSize = 100; // Process in batches for better performance
    let cursor: string | undefined;
    
    do {
      const result = await this.kv.list({ 
        prefix: businessId ? `${businessId}:${prefix}` : prefix,
        cursor,
        limit: batchSize
      });
      
      // Delete in parallel batches
      const deletions = result.keys.map((key: any) => this.kv.delete(key.name));
      await Promise.allSettled(deletions);
      
      cursor = result.list_complete ? undefined : result.cursor;
    } while (cursor);
  }

  private async invalidateCacheAPIPattern(prefix: string): Promise<void> {
    try {
      const cache = await caches.open('default');
      const keys = await cache.keys();
      
      const deletions = keys
        .filter((request: any) => request.url.includes(prefix))
        .map((request: any) => cache.delete(request));
        
      await Promise.allSettled(deletions);
    } catch (error: any) {
      console.error('Cache API invalidation failed:', error);
    }
  }

  private async invalidateCacheAPIKey(key: string): Promise<void> {
    try {
      const cache = await caches.open('default');
      await cache.delete(key);
    } catch (error: any) {
      console.error(`Cache API key deletion failed for ${key}:`, error);
    }
  }

  // Check if key exists in cache
  async has(key: string): Promise<boolean> {
    // Check Cache API first
    if (this.cacheApi) {
      const cached = await this.cacheApi.match(key);
      if (cached) {
        return true;
      }
    }

    // Check KV
    const kvData = await this.kv.get(key);
    return kvData !== null;
  }

  // Enhanced cache statistics with real-time tracking
  private static stats = {
    l1Hits: 0,
    l2Hits: 0,
    misses: 0,
    totalRequests: 0,
    totalResponseTime: 0,
    lastReset: Date.now()
  };

  async getStats(): Promise<CacheStats> {
    const timeSinceReset = Date.now() - CacheService.stats.lastReset;
    const hours = timeSinceReset / (1000 * 60 * 60);
    
    return {
      l1Hits: CacheService.stats.l1Hits,
      l2Hits: CacheService.stats.l2Hits,
      misses: CacheService.stats.misses,
      totalRequests: CacheService.stats.totalRequests,
      hitRate: CacheService.stats.totalRequests > 0 ? 
        ((CacheService.stats.l1Hits + CacheService.stats.l2Hits) / CacheService.stats.totalRequests) * 100 : 0,
      avgResponseTime: CacheService.stats.totalRequests > 0 ? 
        CacheService.stats.totalResponseTime / CacheService.stats.totalRequests : 0,
      requestsPerHour: hours > 0 ? CacheService.stats.totalRequests / hours : 0,
      uptime: timeSinceReset
    };
  }

  private trackCacheHit(source: 'l1' | 'l2', responseTime: number): void {
    CacheService.stats.totalRequests++;
    CacheService.stats.totalResponseTime += responseTime;
    
    if (source === 'l1') {
      CacheService.stats.l1Hits++;
    } else {
      CacheService.stats.l2Hits++;
    }
  }

  private trackCacheMiss(responseTime: number): void {
    CacheService.stats.totalRequests++;
    CacheService.stats.totalResponseTime += responseTime;
    CacheService.stats.misses++;
  }

  static resetStats(): void {
    CacheService.stats = {
      l1Hits: 0,
      l2Hits: 0,
      misses: 0,
      totalRequests: 0,
      totalResponseTime: 0,
      lastReset: Date.now()
    };
  }

  // TTL based on content type
  getTTL(contentType: string): number {
    const ttls: Record<string, number> = {
      'user-data': 60,        // 1 minute
      'financial': 300,       // 5 minutes
      'analytics': 3600,      // 1 hour
      'static': 86400,        // 1 day
      'config': 604800        // 1 week
    };
    return ttls[contentType] || 300;
  }

  // Clear all cache data (useful for debugging)
  async clear(): Promise<void> {
    // Clear Cache API
    const cacheNames = await caches.keys();
    for (const name of cacheNames) {
      await caches.delete(name);
    }

    // Clear KV (list all keys and delete)
    // Note: This is expensive and should be used sparingly
    let cursor: string | undefined;
    let listComplete = false;
    do {
      const result = await this.kv.list({ cursor });
      for (const key of result.keys) {
        await this.kv.delete(key.name);
      }
      listComplete = result.list_complete;
      cursor = listComplete ? undefined : cursor;
    } while (!listComplete);
  }

  // Get cache info for a specific key
  async getInfo(key: string): Promise<CacheInfo | null> {
    // Check Cache API
    if (this.cacheApi) {
      const cached = await this.cacheApi.match(key);
      if (cached) {
        return {
          key,
          source: 'cache-api',
          timestamp: cached.headers.get('X-Cache-Timestamp') || 'unknown',
          ttl: parseInt(cached.headers.get('X-Cache-TTL') || '0'),
          size: cached.headers.get('Content-Length') || 'unknown'
        };
      }
    }

    // Check KV
    const kvData = await this.kv.get(key, { type: 'json' });
    if (kvData) {
      // For KV, we don't have detailed metadata by default
      return {
        key,
        source: 'kv',
        timestamp: 'unknown',
        ttl: 0, // KV TTL is not easily retrievable
        size: JSON.stringify(kvData).length.toString()
      };
    }

    return null;
  }

  // Bulk operations
  async getMany(keys: string[]): Promise<Record<string, any>> {
    const results: Record<string, any> = {};

    // Process in parallel for better performance
    const promises = keys.map(async (key: any) => {
      const value = await this.get(key);
      if (value !== null) {
        results[key] = value;
      }
    });

    await Promise.all(promises);
    return results;
  }

  async setMany(entries: Record<string, any>, contentType: string = 'default'): Promise<void> {
    const promises = Object.entries(entries).map(([key, value]) =>
      this.set(key, value, contentType)
    );

    await Promise.all(promises);
  }

  async deleteMany(keys: string[]): Promise<void> {
    const promises = keys.map((key: any) => this.invalidate(key));
    await Promise.all(promises);
  }
}

// Type definitions
export interface CacheStats {
  l1Hits: number;
  l2Hits: number;
  misses: number;
  totalRequests: number;
  hitRate: number;
  avgResponseTime: number;
  requestsPerHour: number;
  uptime: number;
}

export interface CacheInfo {
  key: string;
  source: 'cache-api' | 'kv';
  timestamp: string;
  ttl: number;
  size: string;
}

// Factory function for easy instantiation
export function createCacheService(kv: KVNamespace, cacheApi?: Cache): CacheService {
  return new CacheService(kv, cacheApi);
}

// Utility functions
export class CacheUtils {
  static generateKey(prefix: string, ...parts: string[]): string {
    return `${prefix}:${parts.join(':')}`;
  }

  static isExpired(timestamp: string, ttl: number): boolean {
    const cacheTime = parseInt(timestamp);
    const now = Date.now();
    return (now - cacheTime) > (ttl * 1000);
  }

  static formatSize(bytes: number): string {
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    if (bytes === 0) return '0 Bytes';
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return Math.round(bytes / Math.pow(1024, i) * 100) / 100 + ' ' + sizes[i];
  }
}