/**
 * Idempotency Manager for CoreFlow360 V4
 * Prevents duplicate operations and ensures data consistency
 */

import crypto from 'crypto';
import { Logger } from './logger';
import { SecurityError } from './security-utils';
import type { Env } from '../types/env';

export interface IdempotencyKey {
  key: string;
  operation: string;
  businessId: string;
  userId?: string;
  expiresAt: number;
}

export interface IdempotencyResult<T = any> {
  key: string;
  isRetry: boolean;
  result?: T;
  status: 'processing' | 'completed' | 'failed';
  createdAt: number;
  completedAt?: number;
}

export interface IdempotencyOptions {
  key?: string; // Custom idempotency key
  ttlSeconds?: number; // Time to live in seconds (default: 24 hours)
  operation: string;
  businessId: string;
  userId?: string;
  allowRetry?: boolean; // Allow retry of failed operations
}

export // TODO: Consider splitting IdempotencyManager into smaller, focused classes
class IdempotencyManager {
  private logger: Logger;
  private env: Env;
  private defaultTtl: number = 24 * 60 * 60; // 24 hours in seconds

  constructor(env: Env) {
    this.env = env;
    this.logger = new Logger({ component: 'idempotency-manager' });
  }

  /**
   * Execute operation with idempotency protection
   */
  async withIdempotency<T>(
    operation: () => Promise<T>,
    options: IdempotencyOptions
  ): Promise<IdempotencyResult<T>> {
    const idempotencyKey = this.generateIdempotencyKey(options);
    const lockKey = `lock:${idempotencyKey}`;

    try {
      // Check if operation already exists
      const existingResult = await this.getExistingResult<T>(idempotencyKey);
      if (existingResult) {
        this.logger.info('Idempotent operation found', {
          idempotencyKey,
          operation: options.operation,
          status: existingResult.status,
          isRetry: true
        });

        // Return existing result if completed successfully
        if (existingResult.status === 'completed') {
          return {
            ...existingResult,
            isRetry: true
          };
        }

        // Handle failed operations
        if (existingResult.status === 'failed' && !options.allowRetry) {
          throw new SecurityError('Operation failed and retry not allowed', {
            code: 'IDEMPOTENCY_OPERATION_FAILED',
            idempotencyKey,
            operation: options.operation
          });
        }

        // Handle processing operations (possible duplicate request)
        if (existingResult.status === 'processing') {
          throw new SecurityError('Operation already in progress', {
            code: 'IDEMPOTENCY_OPERATION_IN_PROGRESS',
            idempotencyKey,
            operation: options.operation
          });
        }
      }

      // Acquire lock to prevent concurrent execution
      const lockAcquired = await this.acquireLock(lockKey, 300); // 5 minute lock
      if (!lockAcquired) {
        throw new SecurityError('Could not acquire idempotency lock', {
          code: 'IDEMPOTENCY_LOCK_FAILED',
          idempotencyKey,
          operation: options.operation
        });
      }

      const startTime = Date.now();

      try {
        // Mark operation as processing
        await this.markProcessing(idempotencyKey, options);

        this.logger.info('Starting idempotent operation', {
          idempotencyKey,
          operation: options.operation,
          businessId: options.businessId,
          userId: options.userId
        });

        // Execute the operation
        const result = await operation();

        // Mark as completed and store result
        const completedAt = Date.now();
        await this.markCompleted(idempotencyKey, result, completedAt);

        this.logger.info('Idempotent operation completed', {
          idempotencyKey,
          operation: options.operation,
          duration: completedAt - startTime
        });

        return {
          key: idempotencyKey,
          isRetry: false,
          result,
          status: 'completed',
          createdAt: startTime,
          completedAt
        };

      } catch (error) {
        // Mark as failed
        await this.markFailed(idempotencyKey, error);

        this.logger.error('Idempotent operation failed', error, {
          idempotencyKey,
          operation: options.operation,
          duration: Date.now() - startTime
        });

        throw error;
      } finally {
        // Release lock
        await this.releaseLock(lockKey);
      }

    } catch (error) {
      // If it's not an idempotency-related error, wrap it
      if (!(error instanceof SecurityError) || !error.code.startsWith('IDEMPOTENCY_')) {
        throw new SecurityError('Idempotent operation failed', {
          code: 'IDEMPOTENCY_OPERATION_ERROR',
          idempotencyKey,
          operation: options.operation,
          originalError: error instanceof Error ? error.message : String(error)
        });
      }
      throw error;
    }
  }

  /**
   * Generate idempotency key from options and request context
   */
  private generateIdempotencyKey(options: IdempotencyOptions): string {
    if (options.key) {
      // Use custom key but ensure it's scoped to business
      return `${options.businessId}:${options.key}`;
    }

    // Generate key from operation context
    const keyData = {
      operation: options.operation,
      businessId: options.businessId,
      userId: options.userId || 'system',
      timestamp: Math.floor(Date.now() / 1000) // Round to second for potential duplicates
    };

    const hash = crypto
      .createHash('sha256')
      .update(JSON.stringify(keyData))
      .digest('hex')
      .substring(0, 16);

    return `${options.businessId}:${options.operation}:${hash}`;
  }

  /**
   * Get existing operation result
   */
  private async getExistingResult<T>(idempotencyKey: string): Promise<IdempotencyResult<T> | null> {
    try {
      if (!this.env.KV_CACHE) {
        return null;
      }

      const stored = await this.env.KV_CACHE.get(`idempotency:${idempotencyKey}`);
      if (!stored) {
        return null;
      }

      const result = JSON.parse(stored) as IdempotencyResult<T>;

      // Check if expired
      if (result.createdAt && Date.now() - result.createdAt > this.defaultTtl * 1000) {
        await this.cleanup(idempotencyKey);
        return null;
      }

      return result;
    } catch (error) {
      this.logger.error('Failed to get existing idempotency result', error, {
        idempotencyKey
      });
      return null;
    }
  }

  /**
   * Mark operation as processing
   */
  private async markProcessing(idempotencyKey: string, options: IdempotencyOptions): Promise<void> {
    const result: IdempotencyResult = {
      key: idempotencyKey,
      isRetry: false,
      status: 'processing',
      createdAt: Date.now()
    };

    if (this.env.KV_CACHE) {
      await this.env.KV_CACHE.put(
        `idempotency:${idempotencyKey}`,
        JSON.stringify(result),
        { expirationTtl: options.ttlSeconds || this.defaultTtl }
      );
    }

    // Also store in database for persistence
    if (this.env.DB_ANALYTICS) {
      await this.env.DB_ANALYTICS
        .prepare(`
          INSERT OR REPLACE INTO idempotency_keys (
            key, operation, business_id, user_id, status,
            created_at, expires_at
          )
  VALUES (?, ?, ?, ?, ?, datetime('now'), datetime('now', '+${options.ttlSeconds || this.defaultTtl} seconds'))
        `)
        .bind(
          idempotencyKey,
          options.operation,
          options.businessId,
          options.userId || null,
          'processing'
        )
        .run();
    }
  }

  /**
   * Mark operation as completed
   */
  private async markCompleted<T>(idempotencyKey: string, result: T, completedAt: number): Promise<void> {
    const idempotencyResult: IdempotencyResult<T> = {
      key: idempotencyKey,
      isRetry: false,
      result,
      status: 'completed',
      createdAt: completedAt,
      completedAt
    };

    if (this.env.KV_CACHE) {
      await this.env.KV_CACHE.put(
        `idempotency:${idempotencyKey}`,
        JSON.stringify(idempotencyResult),
        { expirationTtl: this.defaultTtl }
      );
    }

    if (this.env.DB_ANALYTICS) {
      await this.env.DB_ANALYTICS
        .prepare(`
          UPDATE idempotency_keys
          SET status = 'completed', completed_at = datetime('now'), result = ?
          WHERE key = ?
        `)
        .bind(JSON.stringify(result), idempotencyKey)
        .run();
    }
  }

  /**
   * Mark operation as failed
   */
  private async markFailed(idempotencyKey: string, error: any): Promise<void> {
    const errorInfo = {
      message: error instanceof Error ? error.message : String(error),
      name: error instanceof Error ? error.name : 'UnknownError',
      code: error instanceof SecurityError ? error.code : 'UNKNOWN_ERROR'
    };

    const idempotencyResult: IdempotencyResult = {
      key: idempotencyKey,
      isRetry: false,
      status: 'failed',
      createdAt: Date.now()
    };

    if (this.env.KV_CACHE) {
      await this.env.KV_CACHE.put(
        `idempotency:${idempotencyKey}`,
        JSON.stringify(idempotencyResult),
        { expirationTtl: this.defaultTtl }
      );
    }

    if (this.env.DB_ANALYTICS) {
      await this.env.DB_ANALYTICS
        .prepare(`
          UPDATE idempotency_keys
          SET status = 'failed', completed_at = datetime('now'), error = ?
          WHERE key = ?
        `)
        .bind(JSON.stringify(errorInfo), idempotencyKey)
        .run();
    }
  }

  /**
   * Acquire distributed lock
   */
  private async acquireLock(lockKey: string, ttlSeconds: number): Promise<boolean> {
    if (!this.env.KV_CACHE) {
      return true; // No KV store, assume lock acquired
    }

    try {
      const lockValue = crypto.randomUUID();
      const existing = await this.env.KV_CACHE.get(lockKey);

      if (existing) {
        return false; // Lock already held
      }

      await this.env.KV_CACHE.put(lockKey, lockValue, { expirationTtl: ttlSeconds });

      // Verify we got the lock (race condition check)
      const verification = await this.env.KV_CACHE.get(lockKey);
      return verification === lockValue;
    } catch (error) {
      this.logger.error('Failed to acquire lock', error, { lockKey });
      return false;
    }
  }

  /**
   * Release distributed lock
   */
  private async releaseLock(lockKey: string): Promise<void> {
    if (this.env.KV_CACHE) {
      try {
        await this.env.KV_CACHE.delete(lockKey);
      } catch (error) {
        this.logger.error('Failed to release lock', error, { lockKey });
      }
    }
  }

  /**
   * Cleanup expired idempotency key
   */
  private async cleanup(idempotencyKey: string): Promise<void> {
    if (this.env.KV_CACHE) {
      await this.env.KV_CACHE.delete(`idempotency:${idempotencyKey}`);
    }

    if (this.env.DB_ANALYTICS) {
      await this.env.DB_ANALYTICS
        .prepare('DELETE FROM idempotency_keys WHERE key = ?')
        .bind(idempotencyKey)
        .run();
    }
  }

  /**
   * Get operation status
   */
  async getOperationStatus(idempotencyKey: string): Promise<IdempotencyResult | null> {
    return this.getExistingResult(idempotencyKey);
  }

  /**
   * Cleanup expired keys (should be called periodically)
   */
  async cleanupExpiredKeys(): Promise<number> {
    if (!this.env.DB_ANALYTICS) {
      return 0;
    }

    try {
      const result = await this.env.DB_ANALYTICS
        .prepare('DELETE FROM idempotency_keys WHERE expires_at < datetime("now")')
        .run();

      this.logger.info('Cleaned up expired idempotency keys', {
        deletedCount: (result as any).changes || 0
      });

      return (result as any).changes || 0;
    } catch (error) {
      this.logger.error('Failed to cleanup expired idempotency keys', error);
      return 0;
    }
  }
}

/**
 * Decorator for automatic idempotency handling
 */
export function withIdempotency(options: Omit<IdempotencyOptions, 'operation'>) {
  return function (target: any, propertyKey: string, descriptor: PropertyDescriptor) {
    const originalMethod = descriptor.value;

    descriptor.value = async function (...args: any[]) {
      const idempotencyManager = new IdempotencyManager(this.env || args[0]?.env);

      const result = await idempotencyManager.withIdempotency(
        () => originalMethod.apply(this, args),
        {
          ...options,
          operation: `${target.constructor.name}.${propertyKey}`
        }
      );

      return result.result;
    };

    return descriptor;
  };
}

/**
 * Generate idempotency key from request
 */
export function generateIdempotencyKeyFromRequest(
  request: {
    method: string;
    url: string;
    body?: any;
    headers?: Record<string, string>;
  },
  businessId: string
): string {
  // Check for explicit idempotency key in headers
  const explicitKey = request.headers?.['idempotency-key'] || request.headers?.['Idempotency-Key'];
  if (explicitKey) {
    return `${businessId}:${explicitKey}`;
  }

  // Generate key from request characteristics for POST/PUT/PATCH
  if (['POST', 'PUT', 'PATCH'].includes(request.method.toUpperCase())) {
    const keyData = {
      method: request.method,
      url: request.url,
     
  body: request.body ? crypto.createHash('sha256').update(JSON.stringify(request.body)).digest('hex').substring(0, 16) : null,
      businessId
    };

    const hash = crypto
      .createHash('sha256')
      .update(JSON.stringify(keyData))
      .digest('hex')
      .substring(0, 16);

    return `${businessId}:auto:${hash}`;
  }

  // For GET/DELETE, use URL-based key
  const urlHash = crypto
    .createHash('sha256')
    .update(`${request.method}:${request.url}`)
    .digest('hex')
    .substring(0, 16);

  return `${businessId}:${request.method.toLowerCase()}:${urlHash}`;
}