/**
 * Context Cache
 * High-performance caching for business context data
 */

import type { KVNamespace } from '@cloudflare/workers-types';
import {
  BusinessContextData,
  ContextCacheEntry,
  CONTEXT_CONSTANTS
} from './types';
import { Logger } from '../../shared/logger';

export class ContextCache {
  private logger: Logger;
  private kv: KVNamespace;
  private memoryCache = new Map<string, ContextCacheEntry>();
  private accessStats = new Map<string, { hits: number; misses: number; lastAccess: number }>();

  constructor(kv: KVNamespace) {
    this.logger = new Logger();
    this.kv = kv;

    // Cleanup memory cache every 5 minutes
    setInterval(() => this.cleanupMemoryCache(), 300000);
  }

  /**
   * Get context data from cache
   */
  async get(key: string): Promise<BusinessContextData | null> {
    const startTime = Date.now();

    try {
      // Try memory cache first
      const memoryEntry = this.memoryCache.get(key);
      if (memoryEntry && memoryEntry.metadata.expiresAt > Date.now()) {
        this.updateAccessStats(key, true);
        memoryEntry.metadata.accessCount++;
        memoryEntry.metadata.lastAccessed = Date.now();

        this.logger.debug('Context cache hit (memory)', {
          key,
          accessTime: Date.now() - startTime,
          accessCount: memoryEntry.metadata.accessCount,
        });

        return memoryEntry.data;
      }

      // Try KV store
      const kvData = await this.kv.get(`context:${key}`, 'json');
      if (kvData) {
        const entry = kvData as ContextCacheEntry;
        if (entry.metadata.expiresAt > Date.now()) {
          // Store in memory cache for faster access
          this.memoryCache.set(key, entry);
          this.updateAccessStats(key, true);

          this.logger.debug('Context cache hit (KV)', {
            key,
            accessTime: Date.now() - startTime,
            accessCount: entry.metadata.accessCount,
          });

          return entry.data;
        } else {
          // Expired entry, remove it
          await this.kv.delete(`context:${key}`);
        }
      }

      this.updateAccessStats(key, false);
      this.logger.debug('Context cache miss', {
        key,
        accessTime: Date.now() - startTime,
      });

      return null;

    } catch (error: any) {
      this.logger.error('Failed to get from context cache', error, { key });
      this.updateAccessStats(key, false);
      return null;
    }
  }

  /**
   * Store context data in cache
   */
  async set(key: string, data: BusinessContextData, ttlSeconds: number): Promise<void> {
    const startTime = Date.now();

    try {
      const now = Date.now();
      const expiresAt = now + (ttlSeconds * 1000);

      const entry: ContextCacheEntry = {
        key,
        data,
        metadata: {
          createdAt: now,
          expiresAt,
          accessCount: 0,
          lastAccessed: now,
          version: data.metadata.version,
        },
      };

      // Store in memory cache
      this.memoryCache.set(key, entry);

      // Store in KV with TTL
      await this.kv.put(
        `context:${key}`,
        JSON.stringify(entry),
        { expirationTtl: ttlSeconds }
      );

      this.logger.debug('Context cached successfully', {
        key,
        ttlSeconds,
        dataSize: JSON.stringify(data).length,
        storeTime: Date.now() - startTime,
      });

      // Cleanup if memory cache is too large
      if (this.memoryCache.size > CONTEXT_CONSTANTS.MAX_CACHE_SIZE) {
        this.cleanupMemoryCache();
      }

    } catch (error: any) {
      this.logger.error('Failed to store in context cache', error, { key, ttlSeconds });
    }
  }

  /**
   * Invalidate cache entry
   */
  async invalidate(key: string): Promise<void> {
    try {
      this.memoryCache.delete(key);
      await this.kv.delete(`context:${key}`);

      this.logger.debug('Context cache invalidated', { key });

    } catch (error: any) {
      this.logger.error('Failed to invalidate context cache', error, { key });
    }
  }

  /**
   * Invalidate cache entries by pattern
   */
  async invalidateByPattern(pattern: string): Promise<void> {
    try {
      // Memory cache cleanup
      const keysToDelete: string[] = [];
      for (const key of this.memoryCache.keys()) {
        if (this.matchesPattern(key, pattern)) {
          keysToDelete.push(key);
        }
      }

      for (const key of keysToDelete) {
        this.memoryCache.delete(key);
      }

      // KV cleanup is more complex - we'll rely on TTL for now
      // In production, consider using KV list operations if available

      this.logger.debug('Context cache invalidated by pattern', {
        pattern,
        memoryKeysDeleted: keysToDelete.length,
      });

    } catch (error: any) {
      this.logger.error('Failed to invalidate context cache by pattern', error, { pattern });
    }
  }

  /**
   * Get cache statistics
   */
  getStatistics(): any {
    const totalHits = Array.from(this.accessStats.values())
      .reduce((sum, stats) => sum + stats.hits, 0);
    const totalMisses = Array.from(this.accessStats.values())
      .reduce((sum, stats) => sum + stats.misses, 0);
    const totalRequests = totalHits + totalMisses;
    const hitRate = totalRequests > 0 ? (totalHits / totalRequests) * 100 : 0;

    return {
      memoryCache: {
        size: this.memoryCache.size,
        maxSize: CONTEXT_CONSTANTS.MAX_CACHE_SIZE,
      },
      performance: {
        totalRequests,
        totalHits,
        totalMisses,
        hitRate: Math.round(hitRate * 100) / 100,
      },
      entries: Array.from(this.accessStats.entries()).map(([key, stats]) => ({
        key,
        hits: stats.hits,
        misses: stats.misses,
        hitRate: stats.hits + stats.misses > 0
          ? Math.round((stats.hits / (stats.hits + stats.misses)) * 10000) / 100
          : 0,
        lastAccess: stats.lastAccess,
      })).sort((a, b) => b.lastAccess - a.lastAccess).slice(0, 20), // Top 20 most recently accessed
    };
  }

  /**
   * Cleanup expired entries
   */
  async cleanup(): Promise<void> {
    try {
      const now = Date.now();
      const expiredKeys: string[] = [];

      // Cleanup memory cache
      for (const [key, entry] of this.memoryCache.entries()) {
        if (entry.metadata.expiresAt <= now) {
          expiredKeys.push(key);
        }
      }

      for (const key of expiredKeys) {
        this.memoryCache.delete(key);
      }

      // Cleanup old access stats (older than 24 hours)
      const oldStatsThreshold = now - (24 * 60 * 60 * 1000);
      for (const [key, stats] of this.accessStats.entries()) {
        if (stats.lastAccess < oldStatsThreshold) {
          this.accessStats.delete(key);
        }
      }

      this.logger.debug('Context cache cleanup completed', {
        expiredEntries: expiredKeys.length,
        remainingMemoryEntries: this.memoryCache.size,
        remainingStats: this.accessStats.size,
      });

    } catch (error: any) {
      this.logger.error('Failed to cleanup context cache', error);
    }
  }

  /**
   * Private methods
   */

  private updateAccessStats(key: string, hit: boolean): void {
    const stats = this.accessStats.get(key) || { hits: 0, misses: 0, lastAccess: 0 };

    if (hit) {
      stats.hits++;
    } else {
      stats.misses++;
    }

    stats.lastAccess = Date.now();
    this.accessStats.set(key, stats);
  }

  private matchesPattern(key: string, pattern: string): boolean {
    // Simple pattern matching with wildcards
    const regex = new RegExp(pattern.replace(/\*/g, '.*'));
    return regex.test(key);
  }

  private cleanupMemoryCache(): void {
    if (this.memoryCache.size <= CONTEXT_CONSTANTS.MAX_CACHE_SIZE) {
      return;
    }

    const now = Date.now();
    const entries = Array.from(this.memoryCache.entries())
      .map(([key, entry]) => ({
        key,
        entry,
        score: this.calculateEvictionScore(entry, now),
      }))
      .sort((a, b) => a.score - b.score); // Lower score = more likely to evict

    // Remove the least valuable entries
    const toRemove = entries.slice(0, entries.length - CONTEXT_CONSTANTS.MAX_CACHE_SIZE + 100);
    for (const { key } of toRemove) {
      this.memoryCache.delete(key);
    }

    this.logger.debug('Memory cache cleaned up', {
      removedEntries: toRemove.length,
      remainingEntries: this.memoryCache.size,
    });
  }

  private calculateEvictionScore(entry: ContextCacheEntry, now: number): number {
    const age = now - entry.metadata.createdAt;
    const timeSinceAccess = now - entry.metadata.lastAccessed;
    const accessFrequency = entry.metadata.accessCount;

    // Higher score = more valuable (less likely to evict)
    // Factors: recent access, high access count, low age
    return (accessFrequency * 1000) - (timeSinceAccess / 1000) - (age / 10000);
  }
}