import type { KVNamespace } from '@cloudflare/workers-types';

export class CacheService {
  private performanceMetrics = {
    hits: 0,
    misses: 0,
    l1Hits: 0,
    l2Hits: 0,
    invalidations: 0,
    totalRequests: 0,
    totalResponseTime: 0,
    lastReset: Date.now()
  };

  private warmupQueue: Set<string> = new Set();
  private priorityCache: Map<string, { priority: number; lastAccess: number }> = new Map();
  private readonly MAX_PRIORITY_CACHE_SIZE = 500;
  private readonly WARM_UP_BATCH_SIZE = 50;

  constructor(
    private kv: KVNamespace,
    private cacheApi?: Cache
  ) {
    this.startBackgroundTasks();
  }

  // Multi-layer cache check with intelligent priority management
  async get(key: string, options: { priority?: number; warmUp?: boolean } = {}): Promise<any> {
    const startTime = performance.now();
    this.performanceMetrics.totalRequests++;

    try {
      // Update priority cache access tracking
      this.updatePriorityCache(key, options.priority || 1);

      // L1: Edge Cache API (fastest)
      if (this.cacheApi) {
        const cached = await this.cacheApi.match(key);
        if (cached) {
          this.trackCacheHit('l1', performance.now() - startTime);
          const data = await cached.json();

          // Check if data is stale and needs warm-up
          if (options.warmUp && this.shouldWarmUp(cached)) {
            this.scheduleWarmUp(key);
          }

          return data;
        }
      }

      // L2: KV (distributed)
      const kvData = await this.kv.get(key, { type: 'json' });
      if (kvData) {
        this.trackCacheHit('l2', performance.now() - startTime);

        // Promote to L1 if cache available and high priority
        const priority = this.priorityCache.get(key)?.priority || 1;
        if (this.cacheApi && priority >= 3) {
          await this.promoteToL1(key, kvData);
        }

        return kvData;
      }

      // Cache miss
      this.trackCacheMiss(performance.now() - startTime);
      return null;
    } catch (error) {
      console.error('Cache get error:', error);
      this.trackCacheMiss(performance.now() - startTime);
      return null;
    }
  }

  /**
   * Promote data to L1 cache for faster access
   */
  private async promoteToL1(key: string, data: any): Promise<void> {
    try {
      const response = new Response(JSON.stringify(data), {
        headers: {
          'Content-Type': 'application/json',
          'X-Cache-Promoted': 'true',
          'X-Cache-Timestamp': Date.now().toString()
        }
      });

      if (this.cacheApi) {
        await this.cacheApi.put(key, response);
      }
    } catch (error) {
      console.warn('Failed to promote to L1 cache:', error);
    }
  }

  /**
   * Check if cached data should be warmed up
   */
  private shouldWarmUp(response: Response): boolean {
    const timestamp = response.headers.get('X-Cache-Timestamp');
    if (!timestamp) return false;

    const age = Date.now() - parseInt(timestamp);
    const maxAge = parseInt(response.headers.get('X-Cache-TTL') || '300000');

    // Warm up when cache is 75% expired
    return age > (maxAge * 0.75);
  }

  /**
   * Schedule cache warm-up for background processing
   */
  private scheduleWarmUp(key: string): void {
    if (this.warmupQueue.size < 100) { // Limit queue size
      this.warmupQueue.add(key);
    }
  }

  // Set data in both cache layers with intelligent optimization
  async set(key: string, data: any, options: {
    contentType?: string;
    priority?: number;
    compress?: boolean;
    tags?: string[];
  } = {}): Promise<void> {
    const { contentType = 'default', priority = 1, compress = false, tags = [] } = options;
    const ttl = this.getTTL(contentType);
    const timestamp = Date.now();

    try {
      // Prepare data with optional compression
      let serializedData = JSON.stringify(data);
      if (compress && serializedData.length > 1024) {
        // In a real implementation, you'd use compression here
        // For now, we'll just add a header to indicate it should be compressed
        serializedData = this.simulateCompression(serializedData);
      }

      // Update priority cache
      this.updatePriorityCache(key, priority);

      // Set in KV with metadata
      const kvData = {
        data,
        metadata: {
          contentType,
          priority,
          timestamp,
          tags,
          compressed: compress
        }
      };

      await this.kv.put(key, JSON.stringify(kvData), {
        expirationTtl: ttl
      });

      // Set in Cache API with enhanced headers
      const response = new Response(serializedData, {
        headers: {
          'Content-Type': 'application/json',
          'Cache-Control': `max-age=${ttl}`,
          'X-Cache-Timestamp': timestamp.toString(),
          'X-Cache-TTL': ttl.toString(),
          'X-Cache-Priority': priority.toString(),
          'X-Cache-Tags': tags.join(','),
          'X-Cache-Compressed': compress.toString()
        }
      });

      // Only cache high-priority items in L1 if space is limited
      if (this.cacheApi && (priority >= 3 || this.priorityCache.size < this.MAX_PRIORITY_CACHE_SIZE)) {
        await this.cacheApi.put(key, response);
      }
    } catch (error) {
      console.error('Cache set error:', error);
      throw error;
    }
  }

  /**
   * Simulate compression (in real implementation, use actual compression)
   */
  private simulateCompression(data: string): string {
    // This is a placeholder - in production you'd use actual compression
    return data;
  }

  /**
   * Update priority cache with LRU eviction
   */
  private updatePriorityCache(key: string, priority: number): void {
    const existing = this.priorityCache.get(key);
    const newPriority = existing ? Math.max(existing.priority, priority) : priority;

    this.priorityCache.set(key, {
      priority: newPriority,
      lastAccess: Date.now()
    });

    // Evict least recently used items if cache is full
    if (this.priorityCache.size > this.MAX_PRIORITY_CACHE_SIZE) {
      this.evictLeastRecentlyUsed();
    }
  }

  /**
   * Evict least recently used items from priority cache
   */
  private evictLeastRecentlyUsed(): void {
    const entries = Array.from(this.priorityCache.entries());
    entries.sort((a, b) => a[1].lastAccess - b[1].lastAccess);

    // Remove oldest 10% of entries
    const toRemove = Math.floor(entries.length * 0.1);
    for (let i = 0; i < toRemove; i++) {
      this.priorityCache.delete(entries[i][0]);
    }
  }

  // Smart cache invalidation with performance optimizations and tag support
  async invalidate(pattern: string, options: { businessId?: string; tags?: string[]; priority?: number } = {}): Promise<void> {
    const startTime = performance.now();
    this.performanceMetrics.invalidations++;

    const operations: Promise<void>[] = [];

    // Tag-based invalidation
    if (options.tags && options.tags.length > 0) {
      operations.push(this.invalidateByTags(options.tags));
    }

    // Priority-based invalidation
    if (options.priority !== undefined) {
      operations.push(this.invalidateByPriority(options.priority));
    }

    // Pattern-based invalidation
    if (pattern.includes('*')) {
      const prefix = pattern.replace('*', '');

      // KV invalidation with business ID scoping
      operations.push(this.invalidateKVPattern(prefix, options.businessId));

      // Cache API invalidation
      operations.push(this.invalidateCacheAPIPattern(prefix));
    } else {
      // Direct key deletion
      operations.push(
        this.kv.delete(pattern),
        this.invalidateCacheAPIKey(pattern)
      );

      // Remove from priority cache
      this.priorityCache.delete(pattern);
    }

    // Execute all invalidations in parallel
    const results = await Promise.allSettled(operations);

    // Log failed invalidations
    const failures = results.filter(result => result.status === 'rejected');
    if (failures.length > 0) {
      console.warn('Some cache invalidations failed:', failures);
    }

    // Performance tracking
    const duration = performance.now() - startTime;
    if (duration > 100) {
      console.warn(`Slow cache invalidation: ${pattern} took ${duration}ms`);
    }
  }

  /**
   * Invalidate cache entries by tags
   */
  private async invalidateByTags(tags: string[]): Promise<void> {
    try {
      let cursor: string | undefined;
      const operations: Promise<void>[] = [];

      do {
        const result = await this.kv.list({ cursor, limit: 100 });

        for (const key of result.keys) {
          operations.push(this.checkAndInvalidateByTag(key.name, tags));
        }

        cursor = result.list_complete ? undefined : result.cursor;
      } while (cursor && operations.length < 1000); // Limit operations

      await Promise.allSettled(operations);
    } catch (error) {
      console.error('Tag-based invalidation failed:', error);
    }
  }

  /**
   * Check if key should be invalidated based on tags
   */
  private async checkAndInvalidateByTag(key: string, tags: string[]): Promise<void> {
    try {
      const data = await this.kv.get(key, { type: 'json' }) as any;
      if (data && data.metadata && data.metadata.tags) {
        const keyTags = data.metadata.tags;
        const hasMatchingTag = tags.some(tag => keyTags.includes(tag));

        if (hasMatchingTag) {
          await Promise.all([
            this.kv.delete(key),
            this.invalidateCacheAPIKey(key)
          ]);
          this.priorityCache.delete(key);
        }
      }
    } catch (error) {
      // Ignore individual key errors
    }
  }

  /**
   * Invalidate cache entries with priority less than specified
   */
  private async invalidateByPriority(minPriority: number): Promise<void> {
    const keysToInvalidate: string[] = [];

    for (const [key, metadata] of this.priorityCache.entries()) {
      if (metadata.priority < minPriority) {
        keysToInvalidate.push(key);
      }
    }

    const operations = keysToInvalidate.map(key => this.invalidate(key));
    await Promise.allSettled(operations);
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

  async getStats(): Promise<EnhancedCacheStats> {
    const timeSinceReset = Date.now() - this.performanceMetrics.lastReset;
    const hours = timeSinceReset / (1000 * 60 * 60);
    const totalRequests = this.performanceMetrics.hits + this.performanceMetrics.misses;

    return {
      l1Hits: this.performanceMetrics.l1Hits,
      l2Hits: this.performanceMetrics.l2Hits,
      totalHits: this.performanceMetrics.hits,
      misses: this.performanceMetrics.misses,
      totalRequests,
      hitRate: totalRequests > 0 ? (this.performanceMetrics.hits / totalRequests) * 100 : 0,
      l1HitRate: totalRequests > 0 ? (this.performanceMetrics.l1Hits / totalRequests) * 100 : 0,
      l2HitRate: totalRequests > 0 ? (this.performanceMetrics.l2Hits / totalRequests) * 100 : 0,
      avgResponseTime: totalRequests > 0 ? this.performanceMetrics.totalResponseTime / totalRequests : 0,
      requestsPerHour: hours > 0 ? totalRequests / hours : 0,
      invalidations: this.performanceMetrics.invalidations,
      priorityCacheSize: this.priorityCache.size,
      warmupQueueSize: this.warmupQueue.size,
      uptime: timeSinceReset,
      memoryUsage: this.estimateMemoryUsage()
    };
  }

  /**
   * Estimate memory usage of cache
   */
  private estimateMemoryUsage(): number {
    // Rough estimation based on cache sizes
    const priorityCacheMemory = this.priorityCache.size * 100; // ~100 bytes per entry
    const warmupQueueMemory = this.warmupQueue.size * 50; // ~50 bytes per entry
    return priorityCacheMemory + warmupQueueMemory;
  }

  private trackCacheHit(source: 'l1' | 'l2', responseTime: number): void {
    this.performanceMetrics.hits++;
    this.performanceMetrics.totalResponseTime += responseTime;

    if (source === 'l1') {
      this.performanceMetrics.l1Hits++;
    } else {
      this.performanceMetrics.l2Hits++;
    }
  }

  private trackCacheMiss(responseTime: number): void {
    this.performanceMetrics.misses++;
    this.performanceMetrics.totalResponseTime += responseTime;
  }

  resetStats(): void {
    this.performanceMetrics = {
      hits: 0,
      misses: 0,
      l1Hits: 0,
      l2Hits: 0,
      invalidations: 0,
      totalRequests: 0,
      totalResponseTime: 0,
      lastReset: Date.now()
    };
  }

  /**
   * Start background tasks for cache optimization
   */
  private startBackgroundTasks(): void {
    // Process warm-up queue every 30 seconds
    setInterval(() => {
      this.processWarmUpQueue();
    }, 30000);

    // Clean up priority cache every 5 minutes
    setInterval(() => {
      this.cleanupPriorityCache();
    }, 300000);

    // Log performance metrics every 10 minutes
    setInterval(() => {
      this.logPerformanceMetrics();
    }, 600000);
  }

  /**
   * Process items in warm-up queue
   */
  private async processWarmUpQueue(): Promise<void> {
    if (this.warmupQueue.size === 0) return;

    const batch = Array.from(this.warmupQueue).slice(0, this.WARM_UP_BATCH_SIZE);
    this.warmupQueue.clear();

    const warmUpOperations = batch.map(key => this.warmUpKey(key));
    await Promise.allSettled(warmUpOperations);
  }

  /**
   * Warm up a specific cache key
   */
  private async warmUpKey(key: string): Promise<void> {
    try {
      // This would typically refresh the cache by calling the original data source
      // For now, we'll just touch the key to update its timestamp
      const data = await this.kv.get(key, { type: 'json' });
      if (data) {
        const typedData = data as any;
        await this.set(key, typedData.data, {
          contentType: typedData.metadata?.contentType || 'default',
          priority: typedData.metadata?.priority || 1,
          tags: typedData.metadata?.tags || []
        });
      }
    } catch (error) {
      console.warn(`Failed to warm up cache key ${key}:`, error);
    }
  }

  /**
   * Clean up expired entries in priority cache
   */
  private cleanupPriorityCache(): void {
    const now = Date.now();
    const maxAge = 24 * 60 * 60 * 1000; // 24 hours
    let cleaned = 0;

    for (const [key, metadata] of this.priorityCache.entries()) {
      if (now - metadata.lastAccess > maxAge) {
        this.priorityCache.delete(key);
        cleaned++;
      }
    }

    if (cleaned > 0) {
      console.log(`Cleaned ${cleaned} expired priority cache entries`);
    }
  }

  /**
   * Log performance metrics for monitoring
   */
  private async logPerformanceMetrics(): Promise<void> {
    const stats = await this.getStats();

    console.log('Cache Performance Metrics:', {
      hitRate: Math.round(stats.hitRate * 100) / 100,
      l1HitRate: Math.round(stats.l1HitRate * 100) / 100,
      avgResponseTime: Math.round(stats.avgResponseTime * 100) / 100,
      totalRequests: stats.totalRequests,
      priorityCacheSize: stats.priorityCacheSize,
      memoryUsage: stats.memoryUsage
    });
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

  async setMany(entries: Record<string, any>, options: { contentType?: string; priority?: number; compress?: boolean; tags?: string[] } = {}): Promise<void> {
    const promises = Object.entries(entries).map(([key, value]) =>
      this.set(key, value, options)
    );

    await Promise.all(promises);
  }

  async deleteMany(keys: string[]): Promise<void> {
    const promises = keys.map((key: any) => this.invalidate(key));
    await Promise.all(promises);
  }
}

// Enhanced type definitions
export interface EnhancedCacheStats {
  l1Hits: number;
  l2Hits: number;
  totalHits: number;
  misses: number;
  totalRequests: number;
  hitRate: number;
  l1HitRate: number;
  l2HitRate: number;
  avgResponseTime: number;
  requestsPerHour: number;
  invalidations: number;
  priorityCacheSize: number;
  warmupQueueSize: number;
  uptime: number;
  memoryUsage: number;
}

// Legacy interface for backward compatibility
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