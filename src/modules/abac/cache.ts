/**
 * ABAC Cache Module
 * High-performance caching system for Attribute-Based Access Control
 */
import { Logger } from '../../shared/logger';

interface CacheEntry<T> {
  value: T;
  expiresAt: number;
  createdAt: number;
  accessCount: number;
  lastAccessed: number;
}

interface CacheStats {
  hits: number;
  misses: number;
  evictions: number;
  size: number;
  hitRate: number;
  memoryUsage: number;
}

interface CacheConfig {
  maxSize: number;
  defaultTTL: number; // Time to live in milliseconds
  cleanupInterval: number; // Cleanup interval in milliseconds
  maxMemoryUsage: number; // Max memory usage in bytes
}

export class ABACCache<T = any> {
  private cache: Map<string, CacheEntry<T>> = new Map();
  private stats: CacheStats = {
    hits: 0,
    misses: 0,
    evictions: 0,
    size: 0,
    hitRate: 0,
    memoryUsage: 0
  };
  private config: CacheConfig;
  private logger: Logger;
  private cleanupTimer?: NodeJS.Timeout;

  constructor(config?: Partial<CacheConfig>) {
    this.config = {
      maxSize: 10000,
      defaultTTL: 5 * 60 * 1000, // 5 minutes
      cleanupInterval: 60 * 1000, // 1 minute
      maxMemoryUsage: 100 * 1024 * 1024, // 100MB
      ...config
    };
    this.logger = new Logger({ component: 'abac-cache' });
    this.startCleanupTimer();
  }

  set(key: string, value: T, ttl?: number): void {
    try {
      const now = Date.now();
      const expiresAt = now + (ttl || this.config.defaultTTL);

      // Check if we need to evict entries
      if (this.cache.size >= this.config.maxSize) {
        this.evictLRU();
      }

      // Check memory usage
      if (this.getMemoryUsage() > this.config.maxMemoryUsage) {
        this.evictOldest();
      }

      const entry: CacheEntry<T> = {
        value,
        expiresAt,
        createdAt: now,
        accessCount: 0,
        lastAccessed: now
      };

      this.cache.set(key, entry);
      this.updateStats();

      this.logger.debug('Cache entry set', { key, ttl: ttl || this.config.defaultTTL });

    } catch (error) {
      this.logger.error('Error setting cache entry', { key, error: error instanceof Error ? error.message : String(error) });
    }
  }

  get(key: string): T | null {
    try {
      const entry = this.cache.get(key);
      
      if (!entry) {
        this.stats.misses++;
        this.updateStats();
        return null;
      }

      const now = Date.now();
      
      // Check if entry has expired
      if (now > entry.expiresAt) {
        this.cache.delete(key);
        this.stats.misses++;
        this.updateStats();
        return null;
      }

      // Update access statistics
      entry.accessCount++;
      entry.lastAccessed = now;
      
      this.stats.hits++;
      this.updateStats();

      this.logger.debug('Cache hit', { key, accessCount: entry.accessCount });
      
      return entry.value;

    } catch (error) {
      this.logger.error('Error getting cache entry', { key, error: error instanceof Error ? error.message : String(error) });
      return null;
    }
  }

  has(key: string): boolean {
    const entry = this.cache.get(key);
    
    if (!entry) {
      return false;
    }

    const now = Date.now();
    
    if (now > entry.expiresAt) {
      this.cache.delete(key);
      return false;
    }

    return true;
  }

  delete(key: string): boolean {
    const deleted = this.cache.delete(key);
    this.updateStats();
    
    if (deleted) {
      this.logger.debug('Cache entry deleted', { key });
    }
    
    return deleted;
  }

  clear(): void {
    const size = this.cache.size;
    this.cache.clear();
    this.updateStats();
    
    this.logger.info('Cache cleared', { entriesRemoved: size });
  }

  keys(): string[] {
    return Array.from(this.cache.keys());
  }

  values(): T[] {
    return Array.from(this.cache.values()).map(entry => entry.value);
  }

  entries(): Array<[string, T]> {
    return Array.from(this.cache.entries()).map(([key, entry]) => [key, entry.value]);
  }

  size(): number {
    return this.cache.size;
  }

  getStats(): CacheStats {
    return { ...this.stats };
  }

  getConfig(): CacheConfig {
    return { ...this.config };
  }

  updateConfig(newConfig: Partial<CacheConfig>): void {
    this.config = { ...this.config, ...newConfig };
    this.logger.info('Cache config updated', { newConfig });
  }

  private evictLRU(): void {
    let oldestKey: string | null = null;
    let oldestTime = Date.now();

    for (const [key, entry] of this.cache.entries()) {
      if (entry.lastAccessed < oldestTime) {
        oldestTime = entry.lastAccessed;
        oldestKey = key;
      }
    }

    if (oldestKey) {
      this.cache.delete(oldestKey);
      this.stats.evictions++;
      this.logger.debug('LRU eviction', { key: oldestKey });
    }
  }

  private evictOldest(): void {
    let oldestKey: string | null = null;
    let oldestTime = Date.now();

    for (const [key, entry] of this.cache.entries()) {
      if (entry.createdAt < oldestTime) {
        oldestTime = entry.createdAt;
        oldestKey = key;
      }
    }

    if (oldestKey) {
      this.cache.delete(oldestKey);
      this.stats.evictions++;
      this.logger.debug('Oldest eviction', { key: oldestKey });
    }
  }

  private updateStats(): void {
    this.stats.size = this.cache.size;
    this.stats.memoryUsage = this.getMemoryUsage();
    
    const total = this.stats.hits + this.stats.misses;
    this.stats.hitRate = total > 0 ? this.stats.hits / total : 0;
  }

  private getMemoryUsage(): number {
    // Rough estimation of memory usage
    let usage = 0;
    
    for (const [key, entry] of this.cache.entries()) {
      usage += key.length * 2; // String length * 2 bytes per character
      usage += JSON.stringify(entry).length * 2; // JSON string length * 2 bytes
    }
    
    return usage;
  }

  private startCleanupTimer(): void {
    this.cleanupTimer = setInterval(() => {
      this.cleanup();
    }, this.config.cleanupInterval);
  }

  private cleanup(): void {
    const now = Date.now();
    let cleaned = 0;

    for (const [key, entry] of this.cache.entries()) {
      if (now > entry.expiresAt) {
        this.cache.delete(key);
        cleaned++;
      }
    }

    if (cleaned > 0) {
      this.logger.debug('Cache cleanup completed', { entriesRemoved: cleaned });
      this.updateStats();
    }
  }

  destroy(): void {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = undefined;
    }
    
    this.clear();
    this.logger.info('Cache destroyed');
  }

  // Specialized methods for ABAC
  setPolicy(policyId: string, policy: any, ttl?: number): void {
    this.set(`policy:${policyId}`, policy, ttl);
  }

  getPolicy(policyId: string): any | null {
    return this.get(`policy:${policyId}`);
  }

  setDecision(decisionKey: string, decision: any, ttl?: number): void {
    this.set(`decision:${decisionKey}`, decision, ttl);
  }

  getDecision(decisionKey: string): any | null {
    return this.get(`decision:${decisionKey}`);
  }

  setUserPermissions(userId: string, permissions: any, ttl?: number): void {
    this.set(`user_permissions:${userId}`, permissions, ttl);
  }

  getUserPermissions(userId: string): any | null {
    return this.get(`user_permissions:${userId}`);
  }

  setResourceAttributes(resourceId: string, attributes: any, ttl?: number): void {
    this.set(`resource_attributes:${resourceId}`, attributes, ttl);
  }

  getResourceAttributes(resourceId: string): any | null {
    return this.get(`resource_attributes:${resourceId}`);
  }

  // Batch operations
  setMultiple(entries: Array<{ key: string; value: T; ttl?: number }>): void {
    for (const entry of entries) {
      this.set(entry.key, entry.value, entry.ttl);
    }
  }

  getMultiple(keys: string[]): Map<string, T | null> {
    const result = new Map<string, T | null>();
    
    for (const key of keys) {
      result.set(key, this.get(key));
    }
    
    return result;
  }

  deleteMultiple(keys: string[]): number {
    let deleted = 0;
    
    for (const key of keys) {
      if (this.delete(key)) {
        deleted++;
      }
    }
    
    return deleted;
  }

  // Cache warming
  warmCache(entries: Array<{ key: string; value: T; ttl?: number }>): void {
    this.logger.info('Warming cache', { entryCount: entries.length });
    
    for (const entry of entries) {
      this.set(entry.key, entry.value, entry.ttl);
    }
    
    this.logger.info('Cache warming completed', { 
      entryCount: entries.length,
      cacheSize: this.size()
    });
  }

  // Health check
  isHealthy(): boolean {
    const stats = this.getStats();
    const memoryUsage = this.getMemoryUsage();
    
    return stats.hitRate > 0.5 && // At least 50% hit rate
           memoryUsage < this.config.maxMemoryUsage && // Within memory limits
           this.size() < this.config.maxSize; // Within size limits
  }

  // Export/Import
  export(): { entries: Array<{ key: string; value: T; ttl: number }>; stats: CacheStats } {
    const entries: Array<{ key: string; value: T; ttl: number }> = [];
    
    for (const [key, entry] of this.cache.entries()) {
      const ttl = entry.expiresAt - Date.now();
      if (ttl > 0) {
        entries.push({
          key,
          value: entry.value,
          ttl
        });
      }
    }
    
    return {
      entries,
      stats: this.getStats()
    };
  }

  import(data: { entries: Array<{ key: string; value: T; ttl: number }> }): void {
    this.clear();
    
    for (const entry of data.entries) {
      this.set(entry.key, entry.value, entry.ttl);
    }
    
    this.logger.info('Cache imported', { entryCount: data.entries.length });
  }
}

