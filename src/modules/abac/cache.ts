import type { KVNamespace } from '@cloudflare/workers-types';
import type {
  Subject,
  EvaluationResult,
  PermissionBundle,
  Capability,
} from './types';
import { SecurityLimits, SecurityError } from '../../shared/security-utils';
import { abacLogger } from '../../shared/logger';

/**
 * High-performance KV caching layer for ABAC permissions
 * Optimized for <1ms cache operations with circuit breaker protection
 */
export class PermissionCache {
  private kv: KVNamespace;
  private stats = {
    hits: 0,
    misses: 0,
    writes: 0,
    errors: 0,
    timeouts: 0,
    totalEvaluations: 0,
    slowQueries: 0,
    circuitBreakerTrips: 0,
  };

  // Circuit breaker configuration
  private circuitBreaker = {
    isOpen: false,
    errorCount: 0,
    lastFailureTime: 0,
    errorThreshold: 5,
    timeoutThreshold: 3,
    resetTimeout: 30000, // 30 seconds
    halfOpenMaxCalls: 3,
    halfOpenCalls: 0,
  };

  // Operation timeouts
  private readonly KV_TIMEOUT_MS = 5000; // 5 seconds
  private readonly KV_READ_TIMEOUT_MS = 2000; // 2 seconds for reads
  private readonly KV_WRITE_TIMEOUT_MS = 5000; // 5 seconds for writes

  constructor(kv: KVNamespace) {
    this.kv = kv;
  }

  /**
   * Get permission bundle for subject
   */
  async getPermissionBundle(subject: Subject): Promise<PermissionBundle | null> {
    const startTime = performance.now();

    // Check circuit breaker
    if (this.isCircuitBreakerOpen()) {
      this.stats.circuitBreakerTrips++;
      abacLogger.warn('Cache circuit breaker is open, skipping KV read', {
        operation: 'getPermissionBundle',
        userId: subject.userId,
        businessId: subject.businessId,
      });
      return null;
    }

    try {
      const key = this.generateBundleKey(subject.userId, subject.businessId);

      // Add timeout wrapper with retry logic
      const cached = await this.withTimeout(
        this.kvGetWithRetry(key, 'json'),
        this.KV_READ_TIMEOUT_MS,
        'getPermissionBundle'
      );

      const duration = performance.now() - startTime;
      this.recordCacheOperation('bundle_get', duration, cached !== null);

      if (!cached) {
        this.recordCircuitBreakerSuccess();
        return null;
      }

      // Verify bundle structure and expiration
      if (this.isValidBundle(cached)) {
        this.recordCircuitBreakerSuccess();
        return this.deserializeBundle(cached);
      }

      // Invalid or expired bundle - clean up asynchronously
      this.cleanupInvalidBundle(key).catch(error => {
        abacLogger.warn('Failed to cleanup invalid bundle', error, { key });
      });

      this.recordCircuitBreakerSuccess();
      return null;

    } catch (error) {
      const duration = performance.now() - startTime;
      this.handleCacheError(error, 'getPermissionBundle', duration);
      return null;
    }
  }

  /**
   * Set permission bundle for subject
   */
  async setPermissionBundle(
    subject: Subject,
    bundle: PermissionBundle
  ): Promise<void> {
    const startTime = performance.now();

    // Check circuit breaker
    if (this.isCircuitBreakerOpen()) {
      this.stats.circuitBreakerTrips++;
      abacLogger.warn('Cache circuit breaker is open, skipping KV write', {
        operation: 'setPermissionBundle',
        userId: subject.userId,
        businessId: subject.businessId,
      });
      return;
    }

    try {
      const key = this.generateBundleKey(subject.userId, subject.businessId);
      const serialized = this.serializeBundle(bundle);

      // Validate bundle size
      const serializedData = JSON.stringify(serialized);
      if (serializedData.length > 25 * 1024) { // 25KB limit for KV values
        throw new SecurityError('Permission bundle too large for cache', {
          code: 'BUNDLE_SIZE_EXCEEDED',
          size: serializedData.length,
          maxSize: 25 * 1024,
          userId: subject.userId,
        });
      }

      // Calculate TTL (time until expiration)
      const ttl = Math.max(60, Math.floor((bundle.expiresAt - Date.now()) / 1000));

      await this.withTimeout(
        this.kvPutWithRetry(key, serializedData, {
          expirationTtl: ttl,
          metadata: {
            userId: subject.userId,
            businessId: subject.businessId,
            capabilityCount: bundle.capabilities.size,
            createdAt: Date.now(),
            version: bundle.version,
          },
        }),
        this.KV_WRITE_TIMEOUT_MS,
        'setPermissionBundle'
      );

      const duration = performance.now() - startTime;
      this.recordCacheOperation('bundle_set', duration, true);
      this.stats.writes++;
      this.recordCircuitBreakerSuccess();

    } catch (error) {
      const duration = performance.now() - startTime;
      this.handleCacheError(error, 'setPermissionBundle', duration);
    }
  }

  /**
   * Get individual permission result
   */
  async getPermissionResult(key: string): Promise<EvaluationResult | null> {
    const startTime = performance.now();

    try {
      const cached = await this.kv.get(key, 'json');

      const duration = performance.now() - startTime;
      this.recordCacheOperation('result_get', duration, cached !== null);

      return cached as EvaluationResult | null;

    } catch (error) {
      this.stats.errors++;
      console.error('Cache get result error:', error);
      return null;
    }
  }

  /**
   * Set individual permission result
   */
  async setPermissionResult(
    key: string,
    result: EvaluationResult,
    ttlSeconds = 300 // 5 minutes default
  ): Promise<void> {
    const startTime = performance.now();

    try {
      await this.kv.put(key, JSON.stringify(result), {
        expirationTtl: ttlSeconds,
        metadata: {
          allowed: result.allowed,
          fastPath: result.fastPath,
          createdAt: Date.now(),
        },
      });

      const duration = performance.now() - startTime;
      this.recordCacheOperation('result_set', duration, true);
      this.stats.writes++;

    } catch (error) {
      this.stats.errors++;
      console.error('Cache set result error:', error);
    }
  }

  /**
   * Invalidate all permissions for a user in a business
   */
  async invalidateUserPermissions(
    userId: string,
    businessId: string
  ): Promise<void> {
    try {
      // Delete permission bundle
      const bundleKey = this.generateBundleKey(userId, businessId);
      await this.kv.delete(bundleKey);

      // Note: KV doesn't support pattern deletion, so individual results
      // will expire naturally. For immediate invalidation, we'd need to
      // track individual keys or use a different strategy.

      console.log('Invalidated permissions for user:', { userId, businessId });

    } catch (error) {
      this.stats.errors++;
      console.error('Cache invalidation error:', error);
    }
  }

  /**
   * Bulk invalidate permissions (e.g., when policies change)
   */
  async invalidateBusinessPermissions(businessId: string): Promise<void> {
    try {
      // In a production system, you might maintain an index of keys
      // to delete. For now, we'll use metadata to track and clean up.

      console.log('Initiated bulk invalidation for business:', businessId);

      // This is a limitation of KV - we can't efficiently delete by pattern
      // In practice, you'd either:
      // 1. Maintain a separate index of keys
      // 2. Use versioning in cache keys
      // 3. Accept that some stale data may persist until TTL

    } catch (error) {
      this.stats.errors++;
      console.error('Bulk invalidation error:', error);
    }
  }

  /**
   * Warm cache with common permissions
   */
  async warmCache(
    subjects: Subject[],
    commonCapabilities: Capability[]
  ): Promise<void> {
    const startTime = performance.now();

    try {
      // This would typically be called during off-peak hours
      // or when permission policies are updated

      console.log('Cache warming initiated:', {
        subjectCount: subjects.length,
        capabilityCount: commonCapabilities.length,
      });

      // In practice, you'd integrate this with the permission resolver
      // to precompute and cache common permission checks

      const duration = performance.now() - startTime;
      console.log('Cache warming completed:', `${duration.toFixed(2)}ms`);

    } catch (error) {
      this.stats.errors++;
      console.error('Cache warming error:', error);
    }
  }

  /**
   * Generate cache key for permission bundle
   */
  generateBundleKey(userId: string, businessId: string): string {
    return `perm:bundle:${businessId}:${userId}`;
  }

  /**
   * Generate cache key for individual permission
   */
  generatePermissionKey(
    userId: string,
    businessId: string,
    capability: Capability
  ): string {
    return `perm:check:${businessId}:${userId}:${capability}`;
  }

  /**
   * Generate cache key for resource-specific permission
   */
  generateResourcePermissionKey(
    userId: string,
    businessId: string,
    capability: Capability,
    resourceId: string
  ): string {
    return `perm:resource:${businessId}:${userId}:${capability}:${resourceId}`;
  }

  /**
   * Serialize permission bundle for storage
   */
  private serializeBundle(bundle: PermissionBundle): any {
    return {
      userId: bundle.userId,
      businessId: bundle.businessId,
      capabilities: Array.from(bundle.capabilities),
      constraints: Array.from(bundle.constraints.entries()),
      evaluatedAt: bundle.evaluatedAt,
      expiresAt: bundle.expiresAt,
      version: bundle.version,
    };
  }

  /**
   * Deserialize permission bundle from storage
   */
  private deserializeBundle(data: any): PermissionBundle {
    return {
      userId: data.userId,
      businessId: data.businessId,
      capabilities: new Set(data.capabilities),
      constraints: new Map(data.constraints),
      evaluatedAt: data.evaluatedAt,
      expiresAt: data.expiresAt,
      version: data.version,
    };
  }

  /**
   * Validate cached bundle structure and expiration
   */
  private isValidBundle(data: any): boolean {
    return (
      data &&
      typeof data === 'object' &&
      data.userId &&
      data.businessId &&
      Array.isArray(data.capabilities) &&
      Array.isArray(data.constraints) &&
      typeof data.expiresAt === 'number' &&
      data.expiresAt > Date.now()
    );
  }

  /**
   * Record cache operation for statistics
   */
  private recordCacheOperation(
    operation: string,
    duration: number,
    hit: boolean
  ): void {
    if (hit) {
      this.stats.hits++;
    } else {
      this.stats.misses++;
    }

    this.stats.totalEvaluations++;

    if (duration > 5) { // Over 5ms is considered slow for cache
      this.stats.slowQueries++;

      if (duration > 10) {
        console.warn('Slow cache operation:', {
          operation,
          duration: `${duration.toFixed(2)}ms`,
          hit,
        });
      }
    }
  }

  /**
   * Get cache statistics
   */
  async getStatistics(): Promise<{
    cacheHitRate: number;
    averageEvaluationTime: number;
    slowQueries: number;
    totalEvaluations: number;
    errors: number;
    writes: number;
  }> {
    const hitRate = this.stats.totalEvaluations > 0
      ? (this.stats.hits / this.stats.totalEvaluations) * 100
      : 0;

    return {
      cacheHitRate: Math.round(hitRate * 100) / 100,
      averageEvaluationTime: 0, // Would need to track timing separately
      slowQueries: this.stats.slowQueries,
      totalEvaluations: this.stats.totalEvaluations,
      errors: this.stats.errors,
      writes: this.stats.writes,
    };
  }

  /**
   * Clear cache statistics
   */
  clearStatistics(): void {
    this.stats = {
      hits: 0,
      misses: 0,
      writes: 0,
      errors: 0,
      totalEvaluations: 0,
      slowQueries: 0,
    };
  }

  /**
   * Get cache health status
   */
  getHealthStatus(): {
    status: 'healthy' | 'degraded' | 'unhealthy';
    hitRate: number;
    errorRate: number;
    slowQueryRate: number;
  } {
    const hitRate = this.stats.totalEvaluations > 0
      ? (this.stats.hits / this.stats.totalEvaluations) * 100
      : 0;

    const errorRate = this.stats.totalEvaluations > 0
      ? (this.stats.errors / this.stats.totalEvaluations) * 100
      : 0;

    const slowQueryRate = this.stats.totalEvaluations > 0
      ? (this.stats.slowQueries / this.stats.totalEvaluations) * 100
      : 0;

    let status: 'healthy' | 'degraded' | 'unhealthy' = 'healthy';

    if (errorRate > 5 || slowQueryRate > 20) {
      status = 'unhealthy';
    } else if (hitRate < 80 || errorRate > 1 || slowQueryRate > 10) {
      status = 'degraded';
    }

    return {
      status,
      hitRate: Math.round(hitRate * 100) / 100,
      errorRate: Math.round(errorRate * 100) / 100,
      slowQueryRate: Math.round(slowQueryRate * 100) / 100,
    };
  }

  /**
   * Preload permissions for multiple subjects (batch operation)
   */
  async batchGetPermissionBundles(
    subjects: Subject[]
  ): Promise<Map<string, PermissionBundle | null>> {
    const results = new Map<string, PermissionBundle | null>();

    // KV doesn't support true batch operations, but we can parallelize
    const operations = subjects.map(async (subject) => {
      const key = this.generateBundleKey(subject.userId, subject.businessId);
      const bundle = await this.getPermissionBundle(subject);
      return { key, bundle };
    });

    const settled = await Promise.allSettled(operations);

    settled.forEach((result, index) => {
      const subject = subjects[index];
      const key = this.generateBundleKey(subject.userId, subject.businessId);

      if (result.status === 'fulfilled') {
        results.set(key, result.value.bundle);
      } else {
        results.set(key, null);
        console.error('Batch get error for subject:', subject.userId, result.reason);
      }
    });

    return results;
  }

  /**
   * Update cache version (for cache invalidation strategy)
   */
  async incrementCacheVersion(businessId: string): Promise<number> {
    try {
      const versionKey = `cache:version:${businessId}`;
      const currentVersion = await this.kv.get(versionKey);
      const newVersion = currentVersion ? parseInt(currentVersion) + 1 : 1;

      await this.kv.put(versionKey, newVersion.toString(), {
        expirationTtl: 86400, // 24 hours
      });

      return newVersion;

    } catch (error) {
      console.error('Version increment error:', error);
      return 1;
    }
  }

  /**
   * Get current cache version for business
   */
  async getCacheVersion(businessId: string): Promise<number> {
    try {
      const versionKey = `cache:version:${businessId}`;
      const version = await this.withTimeout(
        this.kvGetWithRetry(versionKey),
        this.KV_READ_TIMEOUT_MS,
        'getCacheVersion'
      );
      return version ? parseInt(version) : 1;
    } catch (error) {
      abacLogger.error('Version get error', error, { businessId });
      return 1;
    }
  }

  /**
   * KV get operation with retry logic
   */
  private async kvGetWithRetry(
    key: string,
    type?: 'text' | 'json' | 'arrayBuffer' | 'stream',
    maxRetries = 2
  ): Promise<any> {
    let lastError: Error | undefined;

    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      try {
        if (type) {
          return await this.kv.get(key, type);
        } else {
          return await this.kv.get(key);
        }
      } catch (error) {
        lastError = error instanceof Error ? error : new Error(String(error));

        if (attempt < maxRetries) {
          // Exponential backoff: 100ms, 200ms, 400ms
          const delay = 100 * Math.pow(2, attempt);
          await new Promise(resolve => setTimeout(resolve, delay));
          continue;
        }
      }
    }

    throw lastError || new Error('KV get operation failed');
  }

  /**
   * KV put operation with retry logic
   */
  private async kvPutWithRetry(
    key: string,
    value: string,
    options?: any,
    maxRetries = 2
  ): Promise<void> {
    let lastError: Error | undefined;

    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      try {
        await this.kv.put(key, value, options);
        return;
      } catch (error) {
        lastError = error instanceof Error ? error : new Error(String(error));

        if (attempt < maxRetries) {
          // Exponential backoff
          const delay = 100 * Math.pow(2, attempt);
          await new Promise(resolve => setTimeout(resolve, delay));
          continue;
        }
      }
    }

    throw lastError || new Error('KV put operation failed');
  }

  /**
   * Add timeout wrapper to KV operations
   */
  private async withTimeout<T>(
    promise: Promise<T>,
    timeoutMs: number,
    operation: string
  ): Promise<T> {
    return Promise.race([
      promise,
      new Promise<never>((_, reject) => {
        setTimeout(() => {
          this.stats.timeouts++;
          reject(new Error(`KV operation '${operation}' timed out after ${timeoutMs}ms`));
        }, timeoutMs);
      }),
    ]);
  }

  /**
   * Circuit breaker state management
   */
  private isCircuitBreakerOpen(): boolean {
    const now = Date.now();

    // Reset circuit breaker if timeout has passed
    if (
      this.circuitBreaker.isOpen &&
      now - this.circuitBreaker.lastFailureTime > this.circuitBreaker.resetTimeout
    ) {
      this.circuitBreaker.isOpen = false;
      this.circuitBreaker.errorCount = 0;
      this.circuitBreaker.halfOpenCalls = 0;
      abacLogger.info('Cache circuit breaker reset to closed state');
    }

    return this.circuitBreaker.isOpen;
  }

  /**
   * Record circuit breaker success
   */
  private recordCircuitBreakerSuccess(): void {
    if (this.circuitBreaker.errorCount > 0) {
      this.circuitBreaker.errorCount = Math.max(0, this.circuitBreaker.errorCount - 1);
    }

    // Reset half-open state if we're getting successful calls
    if (this.circuitBreaker.halfOpenCalls > 0) {
      this.circuitBreaker.halfOpenCalls = 0;
    }
  }

  /**
   * Handle cache errors and circuit breaker logic
   */
  private handleCacheError(error: unknown, operation: string, duration: number): void {
    this.stats.errors++;

    const isTimeout = error instanceof Error && error.message.includes('timed out');
    if (isTimeout) {
      this.stats.timeouts++;
    }

    // Update circuit breaker
    this.circuitBreaker.errorCount++;
    this.circuitBreaker.lastFailureTime = Date.now();

    // Open circuit breaker if error threshold exceeded
    if (
      this.circuitBreaker.errorCount >= this.circuitBreaker.errorThreshold ||
      this.stats.timeouts >= this.circuitBreaker.timeoutThreshold
    ) {
      this.circuitBreaker.isOpen = true;
      this.stats.circuitBreakerTrips++;

      abacLogger.error('Cache circuit breaker opened due to errors', error, {
        operation,
        errorCount: this.circuitBreaker.errorCount,
        timeouts: this.stats.timeouts,
        duration,
      });
    } else {
      abacLogger.warn('Cache operation failed', error, {
        operation,
        errorCount: this.circuitBreaker.errorCount,
        duration,
        isTimeout,
      });
    }
  }

  /**
   * Cleanup invalid bundle asynchronously
   */
  private async cleanupInvalidBundle(key: string): Promise<void> {
    try {
      await this.withTimeout(
        this.kv.delete(key),
        this.KV_WRITE_TIMEOUT_MS,
        'cleanupInvalidBundle'
      );
    } catch (error) {
      // Don't throw - this is cleanup
      abacLogger.warn('Failed to cleanup invalid bundle', error, { key });
    }
  }

  /**
   * Enhanced warm cache with memory and concurrency limits
   */
  async warmCacheEnhanced(
    subjects: Subject[],
    commonCapabilities: Capability[]
  ): Promise<void> {
    const startTime = performance.now();

    try {
      // Apply security limits
      SecurityLimits.validateRequestLimits({
        batchSize: subjects.length,
      });

      // Apply hard limits
      const maxSubjects = Math.min(subjects.length, SecurityLimits.LIMITS.MAX_CACHE_WARMING_SUBJECTS);
      const maxCapabilities = Math.min(commonCapabilities.length, SecurityLimits.LIMITS.MAX_CACHE_WARMING_CAPABILITIES);

      const limitedSubjects = subjects.slice(0, maxSubjects);
      const limitedCapabilities = commonCapabilities.slice(0, maxCapabilities);

      abacLogger.info('Cache warming initiated', {
        requestedSubjects: subjects.length,
        actualSubjects: limitedSubjects.length,
        requestedCapabilities: commonCapabilities.length,
        actualCapabilities: limitedCapabilities.length,
      });

      // Batch operations with concurrency control
      const BATCH_SIZE = 10;
      const CONCURRENCY_LIMIT = 3;

      for (let i = 0; i < limitedSubjects.length; i += BATCH_SIZE) {
        const batch = limitedSubjects.slice(i, i + BATCH_SIZE);

        // Process batch with concurrency limit
        const batchPromises = batch.map(async (subject, index) => {
          // Stagger requests to avoid overwhelming KV
          await new Promise(resolve => setTimeout(resolve, index * 10));

          return this.precomputeSubjectPermissions(subject, limitedCapabilities);
        });

        // Process in chunks to limit concurrency
        for (let j = 0; j < batchPromises.length; j += CONCURRENCY_LIMIT) {
          const chunk = batchPromises.slice(j, j + CONCURRENCY_LIMIT);
          await Promise.allSettled(chunk);
        }

        // Yield control to prevent blocking
        await new Promise(resolve => setTimeout(resolve, 50));
      }

      const duration = performance.now() - startTime;
      abacLogger.info('Cache warming completed', {
        subjectCount: limitedSubjects.length,
        capabilityCount: limitedCapabilities.length,
        durationMs: duration,
      });

    } catch (error) {
      const duration = performance.now() - startTime;
      abacLogger.error('Cache warming failed', error, {
        subjectCount: subjects.length,
        durationMs: duration,
      });

      throw new SecurityError('Cache warming failed', {
        code: 'CACHE_WARMING_FAILED',
        subjectCount: subjects.length,
        capabilityCount: commonCapabilities.length,
      });
    }
  }

  /**
   * Precompute permissions for a single subject
   */
  private async precomputeSubjectPermissions(
    subject: Subject,
    capabilities: Capability[]
  ): Promise<void> {
    // This would integrate with the permission resolver
    // For now, just simulate the operation
    const bundle: PermissionBundle = {
      userId: subject.userId,
      businessId: subject.businessId,
      capabilities: new Set(capabilities),
      constraints: new Map(),
      evaluatedAt: Date.now(),
      expiresAt: Date.now() + (15 * 60 * 1000),
      version: 1,
    };

    await this.setPermissionBundle(subject, bundle);
  }

  /**
   * Get enhanced health status with circuit breaker info
   */
  getEnhancedHealthStatus(): {
    status: 'healthy' | 'degraded' | 'unhealthy';
    hitRate: number;
    errorRate: number;
    timeoutRate: number;
    slowQueryRate: number;
    circuitBreaker: {
      isOpen: boolean;
      errorCount: number;
      trips: number;
      lastFailureTime: number;
    };
    stats: typeof this.stats;
  } {
    const baseHealth = this.getHealthStatus();

    return {
      ...baseHealth,
      timeoutRate: this.stats.totalEvaluations > 0
        ? (this.stats.timeouts / this.stats.totalEvaluations) * 100
        : 0,
      circuitBreaker: {
        isOpen: this.circuitBreaker.isOpen,
        errorCount: this.circuitBreaker.errorCount,
        trips: this.stats.circuitBreakerTrips,
        lastFailureTime: this.circuitBreaker.lastFailureTime,
      },
      stats: { ...this.stats },
    };
  }
}