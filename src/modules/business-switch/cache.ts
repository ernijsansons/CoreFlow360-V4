import type { BusinessMembership, BusinessContext, CachedMembership } from './types';

const CACHE_VERSION = 1;
const DEFAULT_TTL = 60; // 60 seconds
const PREFETCH_THRESHOLD = 10; // Prefetch if expires in 10 seconds

export // TODO: Consider splitting BusinessCacheManager into smaller, focused classes
class BusinessCacheManager {
  private kv: KVNamespace;
  private memoryCache: Map<string, CachedMembership> = new Map();

  constructor(kv: KVNamespace) {
    this.kv = kv;
  }

  /**
   * Get cached business memberships for a user
   */
  async getCachedMemberships(
    userId: string,
    forceRefresh = false
  ): Promise<{ data: BusinessMembership[] | null; cacheHit: boolean; readTimeMs: number }> {
    const startTime = performance.now();
    const cacheKey = this.getMembershipCacheKey(userId);

    if (!forceRefresh) {
      // Check memory cache first (fastest)
      const memCached = this.memoryCache.get(cacheKey);
      if (memCached && memCached.expiresAt > Date.now()) {
        return {
          data: [memCached.data],
          cacheHit: true,
          readTimeMs: performance.now() - startTime,
        };
      }

      // Check KV cache
      try {
        const cached = await this.kv.get<BusinessMembership[]>(cacheKey, 'json');
        if (cached) {
          return {
            data: cached,
            cacheHit: true,
            readTimeMs: performance.now() - startTime,
          };
        }
      } catch (error) {
      }
    }

    return {
      data: null,
      cacheHit: false,
      readTimeMs: performance.now() - startTime,
    };
  }

  /**
   * Cache business memberships
   */
  async cacheMemberships(
    userId: string,
    memberships: BusinessMembership[],
    ttl: number = DEFAULT_TTL
  ): Promise<number> {
    const startTime = performance.now();
    const cacheKey = this.getMembershipCacheKey(userId);

    try {
      // Store in KV with TTL
      await this.kv.put(cacheKey, JSON.stringify(memberships), {
        expirationTtl: ttl,
        metadata: {
          version: CACHE_VERSION,
          cachedAt: Date.now(),
        },
      });

      // Also update memory cache for the primary business
      const primary = memberships.find(m => m.isPrimary);
      if (primary) {
        this.memoryCache.set(cacheKey, {
          data: primary,
          cachedAt: Date.now(),
          expiresAt: Date.now() + ttl * 1000,
          version: CACHE_VERSION,
        });
      }

      // Limit memory cache size
      if (this.memoryCache.size > 100) {
        const oldestKey = this.memoryCache.keys().next().value;
        if (oldestKey) {
          this.memoryCache.delete(oldestKey);
        }
      }

      return performance.now() - startTime;
    } catch (error) {
      return performance.now() - startTime;
    }
  }

  /**
   * Get cached business context
   */
  async getCachedContext(
    businessId: string,
    userId: string
  ): Promise<{ data: BusinessContext | null; cacheHit: boolean; readTimeMs: number }> {
    const startTime = performance.now();
    const cacheKey = this.getContextCacheKey(businessId, userId);

    try {
      const cached = await this.kv.get<BusinessContext>(cacheKey, 'json');
      if (cached) {
        return {
          data: cached,
          cacheHit: true,
          readTimeMs: performance.now() - startTime,
        };
      }
    } catch (error) {
    }

    return {
      data: null,
      cacheHit: false,
      readTimeMs: performance.now() - startTime,
    };
  }

  /**
   * Cache business context
   */
  async cacheContext(
    businessId: string,
    userId: string,
    context: BusinessContext,
    ttl: number = DEFAULT_TTL
  ): Promise<number> {
    const startTime = performance.now();
    const cacheKey = this.getContextCacheKey(businessId, userId);

    try {
      await this.kv.put(cacheKey, JSON.stringify(context), {
        expirationTtl: ttl,
        metadata: {
          version: CACHE_VERSION,
          cachedAt: Date.now(),
        },
      });

      return performance.now() - startTime;
    } catch (error) {
      return performance.now() - startTime;
    }
  }

  /**
   * Invalidate user's business cache
   */
  async invalidateUserCache(userId: string): Promise<void> {
    const membershipKey = this.getMembershipCacheKey(userId);

    // Clear from KV
    await this.kv.delete(membershipKey);

    // Clear from memory
    this.memoryCache.delete(membershipKey);

    // Also clear all context caches for this user
    // Note: In production, we'd need to track which contexts to clear
  }

  /**
   * Invalidate business context cache
   */
  async invalidateBusinessCache(businessId: string): Promise<void> {
    // In production, we'd need to clear all user contexts for this business
    // For now, we'll rely on TTL expiration
  }

  /**
   * Warm up cache for user
   */
  async warmupCache(
    userId: string,
    memberships: BusinessMembership[],
    contexts: Map<string, BusinessContext>
  ): Promise<void> {
    // Cache memberships
    await this.cacheMemberships(userId, memberships);

    // Cache each context
    const promises: Promise<any>[] = [];
    contexts.forEach((context, businessId) => {
      promises.push(this.cacheContext(businessId, userId, context));
    });

    await Promise.all(promises);
  }

  /**
   * Check if cache needs prefetch
   */
  shouldPrefetch(cachedAt: number, ttl: number): boolean {
    const expiresAt = cachedAt + ttl * 1000;
    const timeUntilExpiry = expiresAt - Date.now();
    return timeUntilExpiry < PREFETCH_THRESHOLD * 1000;
  }

  /**
   * Get cache statistics
   */
  getCacheStats(): {
    memoryCacheSize: number;
    memoryCacheKeys: string[];
  } {
    return {
      memoryCacheSize: this.memoryCache.size,
      memoryCacheKeys: Array.from(this.memoryCache.keys()),
    };
  }

  // Cache key generators
  private getMembershipCacheKey(userId: string): string {
    return `business:memberships:${userId}`;
  }

  private getContextCacheKey(businessId: string, userId: string): string {
    return `business:context:${businessId}:${userId}`;
  }

  /**
   * Batch cache operations for performance
   */
  async batchCacheRead(keys: string[]): Promise<Map<string, any>> {
    const results = new Map<string, any>();

    // KV doesn't support batch reads natively, so we use Promise.all
    const promises = keys.map(async (key) => {
      try {
        const value = await this.kv.get(key, 'json');
        if (value) {
          results.set(key, value);
        }
      } catch (error) {
      }
    });

    await Promise.all(promises);
    return results;
  }

  /**
   * Implement cache stampede protection
   */
  private readonly inFlightRequests = new Map<string, Promise<any>>();

  async getWithStampedeProtection<T>(
    key: string,
    loader: () => Promise<T>,
    ttl: number = DEFAULT_TTL
  ): Promise<T> {
    // Check if there's already a request in flight for this key
    const inFlight = this.inFlightRequests.get(key);
    if (inFlight) {
      return inFlight;
    }

    // Check cache
    const cached = await this.kv.get<T>(key, 'json');
    if (cached) {
      return cached;
    }

    // Load data with stampede protection
    const loadPromise = loader().then(async (data) => {
      // Cache the result
      await this.kv.put(key, JSON.stringify(data), {
        expirationTtl: ttl,
      });

      // Clear from in-flight
      this.inFlightRequests.delete(key);

      return data;
    }).catch((error) => {
      // Clear from in-flight on error
      this.inFlightRequests.delete(key);
      throw error;
    });

    // Track in-flight request
    this.inFlightRequests.set(key, loadPromise);

    return loadPromise;
  }
}