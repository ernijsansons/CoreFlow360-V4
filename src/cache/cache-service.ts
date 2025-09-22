import type { KVNamespace } from '@cloudflare/workers-types';

export class CacheService {
  constructor(
    private kv: KVNamespace,
    private cacheApi: Cache = caches.default
  ) {}

  // Multi-layer cache check
  async get(key: string): Promise<any> {
    // L1: Edge Cache API (fastest)
    const cached = await this.cacheApi.match(key);
    if (cached) {
      return cached.json();
    }

    // L2: KV (distributed)
    const kvData = await this.kv.get(key, 'json');
    if (kvData) {
      // Promote to L1
      await this.cacheApi.put(
        key,
        new Response(JSON.stringify(kvData))
      );
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

    await this.cacheApi.put(key, response);
  }

  // Smart cache invalidation
  async invalidate(pattern: string): Promise<void> {
    // Clear from Cache API
    const cacheNames = await caches.keys();
    for (const name of cacheNames) {
      const cache = await caches.open(name);

      if (pattern.includes('*')) {
        // Pattern matching - Cache API doesn't support this natively
        // For simplicity, we'll just clear the whole cache for wildcard patterns
        const keys = await cache.keys();
        const prefix = pattern.replace('*', '');

        for (const request of keys) {
          if (request.url.includes(prefix)) {
            await cache.delete(request);
          }
        }
      } else {
        // Direct key deletion
        await cache.delete(pattern);
      }
    }

    // Clear from KV (use list with prefix)
    if (pattern.includes('*')) {
      const prefix = pattern.replace('*', '');
      const keys = await this.kv.list({ prefix });
      for (const key of keys.keys) {
        await this.kv.delete(key.name);
      }
    } else {
      await this.kv.delete(pattern);
    }
  }

  // Check if key exists in cache
  async has(key: string): Promise<boolean> {
    // Check Cache API first
    const cached = await this.cacheApi.match(key);
    if (cached) {
      return true;
    }

    // Check KV
    const kvData = await this.kv.get(key);
    return kvData !== null;
  }

  // Get cache statistics
  async getStats(): Promise<CacheStats> {
    // This is a simplified implementation
    // In a real scenario, you'd track metrics over time
    return {
      l1Hits: 0,    // Would track Cache API hits
      l2Hits: 0,    // Would track KV hits
      misses: 0,    // Would track cache misses
      totalRequests: 0,
      hitRate: 0,
      avgResponseTime: 0
    };
  }

  // TTL based on content type
  getTTL(contentType: string): number {
    const ttls = {
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
    do {
      const result = await this.kv.list({ cursor });
      for (const key of result.keys) {
        await this.kv.delete(key.name);
      }
      cursor = result.cursor;
    } while (cursor);
  }

  // Get cache info for a specific key
  async getInfo(key: string): Promise<CacheInfo | null> {
    // Check Cache API
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
    const promises = keys.map(async (key) => {
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
    const promises = keys.map(key => this.invalidate(key));
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