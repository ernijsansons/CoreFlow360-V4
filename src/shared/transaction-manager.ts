/**
 * Database Transaction Manager for CoreFlow360 V4
 * Provides comprehensive transaction handling with rollback capabilities
 */

import { Logger } from './logger';
import { SecurityError, createSecurityContext } from './security-utils';
import type { Env } from '../types/env';

export interface TransactionContext {
  id: string;
  businessId: string;
  userId?: string;
  operation: string;
  startTime: number;
  status: 'active' | 'committed' | 'rolled_back' | 'failed';
  savepoints: string[];
}

export interface TransactionOptions {
  timeout?: number; // milliseconds
  isolation?: 'READ_UNCOMMITTED' | 'READ_COMMITTED' | 'REPEATABLE_READ' | 'SERIALIZABLE';
  retries?: number;
  businessId: string;
  operation: string;
  userId?: string;
}

export interface TransactionResult<T> {
  success: boolean;
  data?: T;
  error?: string;
  transactionId?: string;
  duration?: number;
}

export // TODO: Consider splitting TransactionManager into smaller, focused classes
class TransactionManager {
  private logger: Logger;
  private activeTransactions: Map<string, TransactionContext> = new Map();
  private env: Env;

  constructor(env: Env) {
    this.env = env;
    this.logger = new Logger({ component: 'transaction-manager' });
  }

  /**
   * Execute a function within a database transaction
   */
  async withTransaction<T>(
    operation: (db: D1Database) => Promise<T>,
    options: TransactionOptions
  ): Promise<TransactionResult<T>> {
    const transactionId = this.generateTransactionId();
    const startTime = Date.now();

    const context: TransactionContext = {
      id: transactionId,
      businessId: options.businessId,
      userId: options.userId,
      operation: options.operation,
      startTime,
      status: 'active',
      savepoints: []
    };

    this.activeTransactions.set(transactionId, context);

    try {
      this.logger.info('Starting transaction', {
        transactionId,
        operation: options.operation,
        businessId: options.businessId,
        userId: options.userId
      });

      // Begin transaction
      await this.env.DB.prepare('BEGIN TRANSACTION').run();

      // Set isolation level if specified
      if (options.isolation) {
        const pragmaValue = options.isolation === 'READ_UNCOMMITTED' ? 'ON' : 'OFF';
        // Note: PRAGMA statements cannot be parameterized, but we validate the input
        if (!['ON', 'OFF'].includes(pragmaValue)) {
          throw new SecurityError('Invalid isolation level', { code: 'INVALID_ISOLATION_LEVEL' });
        }
        await this.env.DB.prepare(`PRAGMA read_uncommitted = ${pragmaValue}`).run();
      }

      // Set timeout if specified
      if (options.timeout) {
        setTimeout(async () => {
          if (this.activeTransactions.has(transactionId)) {
            await this.rollbackTransaction(transactionId, 'Transaction timeout');
          }
        }, options.timeout);
      }

      // Execute the operation
      const result = await operation(this.env.DB);

      // Commit transaction
      await this.env.DB.prepare('COMMIT').run();
      context.status = 'committed';

      const duration = Date.now() - startTime;

      this.logger.info('Transaction committed successfully', {
        transactionId,
        operation: options.operation,
        duration
      });

      this.activeTransactions.delete(transactionId);

      return {
        success: true,
        data: result,
        transactionId,
        duration
      };

    } catch (error: any) {
      const duration = Date.now() - startTime;
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';

      this.logger.error('Transaction failed', error, {
        transactionId,
        operation: options.operation,
        duration
      });

      // Attempt rollback
      await this.rollbackTransaction(transactionId, errorMessage);

      return {
        success: false,
        error: errorMessage,
        transactionId,
        duration
      };
    }
  }

  /**
   * Execute multiple operations in a transaction with automatic rollback
   */
  async withBatchTransaction<T>(
    operations: Array<(db: D1Database) => Promise<T>>,
    options: TransactionOptions
  ): Promise<TransactionResult<T[]>> {
    return this.withTransaction(async (db: any) => {
      const results: T[] = [];

      for (let i = 0; i < operations.length; i++) {
        try {
          const result = await operations[i](db);
          results.push(result);
        } catch (error: any) {
          throw new Error(`Batch
  operation ${i + 1} failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
      }

      return results;
    }, options);
  }

  /**
   * Create a savepoint within a transaction
   */
  async createSavepoint(transactionId: string, name?: string): Promise<string> {
    const context = this.activeTransactions.get(transactionId);
    if (!context) {
      throw new SecurityError('Transaction not found', {
        code: 'TRANSACTION_NOT_FOUND',
        transactionId
      });
    }

    const savepointName = name || `sp_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

    try {
      // Validate savepoint name to prevent injection
      if (!/^[a-zA-Z0-9_]+$/.test(savepointName)) {
        throw new SecurityError('Invalid savepoint name', {
          code: 'INVALID_SAVEPOINT_NAME',
          savepointName
        });
      }
      // SQLite savepoint names cannot be parameterized, but we've validated the input
      await this.env.DB.prepare(`SAVEPOINT ${savepointName}`).run();
      context.savepoints.push(savepointName);

      this.logger.debug('Savepoint created', {
        transactionId,
        savepointName
      });

      return savepointName;
    } catch (error: any) {
      this.logger.error('Failed to create savepoint', error, {
        transactionId,
        savepointName
      });
      throw error;
    }
  }

  /**
   * Rollback to a specific savepoint
   */
  async rollbackToSavepoint(transactionId: string, savepointName: string): Promise<void> {
    const context = this.activeTransactions.get(transactionId);
    if (!context) {
      throw new SecurityError('Transaction not found', {
        code: 'TRANSACTION_NOT_FOUND',
        transactionId
      });
    }

    if (!context.savepoints.includes(savepointName)) {
      throw new SecurityError('Savepoint not found', {
        code: 'SAVEPOINT_NOT_FOUND',
        transactionId,
        savepointName
      });
    }

    try {
      // Validate savepoint name to prevent injection
      if (!/^[a-zA-Z0-9_]+$/.test(savepointName)) {
        throw new SecurityError('Invalid savepoint name', {
          code: 'INVALID_SAVEPOINT_NAME',
          savepointName
        });
      }
      // SQLite savepoint names cannot be parameterized, but we've validated the input
      await this.env.DB.prepare(`ROLLBACK TO SAVEPOINT ${savepointName}`).run();

      // Remove savepoints created after this one
      const index = context.savepoints.indexOf(savepointName);
      context.savepoints = context.savepoints.slice(0, index + 1);

      this.logger.info('Rolled back to savepoint', {
        transactionId,
        savepointName
      });
    } catch (error: any) {
      this.logger.error('Failed to rollback to savepoint', error, {
        transactionId,
        savepointName
      });
      throw error;
    }
  }

  /**
   * Rollback entire transaction
   */
  private async rollbackTransaction(transactionId: string, reason: string): Promise<void> {
    const context = this.activeTransactions.get(transactionId);
    if (!context) {
      return; // Transaction already cleaned up
    }

    try {
      await this.env.DB.prepare('ROLLBACK').run();
      context.status = 'rolled_back';

      this.logger.warn('Transaction rolled back', {
        transactionId,
        reason,
        operation: context.operation,
        duration: Date.now() - context.startTime
      });
    } catch (error: any) {
      context.status = 'failed';
      this.logger.error('Failed to rollback transaction', error, {
        transactionId,
        reason
      });
    } finally {
      this.activeTransactions.delete(transactionId);
    }
  }

  /**
   * Get active transaction status
   */
  getTransactionStatus(transactionId: string): TransactionContext | undefined {
    return this.activeTransactions.get(transactionId);
  }

  /**
   * Get all active transactions (for monitoring)
   */
  getActiveTransactions(): TransactionContext[] {
    return Array.from(this.activeTransactions.values());
  }

  /**
   * Force rollback of a transaction (emergency use)
   */
  async forceRollback(transactionId: string, reason: string = 'Force rollback'): Promise<void> {
    const context = this.activeTransactions.get(transactionId);
    if (!context) {
      throw new SecurityError('Transaction not found', {
        code: 'TRANSACTION_NOT_FOUND',
        transactionId
      });
    }

    this.logger.warn('Force rolling back transaction', {
      transactionId,
      reason,
      operation: context.operation
    });

    await this.rollbackTransaction(transactionId, reason);
  }

  /**
   * Clean up stale transactions (should be called periodically)
   */
  async cleanupStaleTransactions(maxAgeMs: number = 5 * 60 * 1000): Promise<void> {
    const now = Date.now();
    const staleTransactions: string[] = [];

    for (const [id, context] of this.activeTransactions.entries()) {
      if (now - context.startTime > maxAgeMs) {
        staleTransactions.push(id);
      }
    }

    if (staleTransactions.length > 0) {
      this.logger.warn('Cleaning up stale transactions', {
        count: staleTransactions.length,
        transactionIds: staleTransactions
      });

      for (const transactionId of staleTransactions) {
        await this.forceRollback(transactionId, 'Stale transaction cleanup');
      }
    }
  }

  /**
   * Execute with retry logic and transaction rollback
   */
  async withRetryTransaction<T>(
    operation: (db: D1Database, attempt: number) => Promise<T>,
    options: TransactionOptions & { maxRetries?: number; retryDelay?: number }
  ): Promise<TransactionResult<T>> {
    const maxRetries = options.maxRetries || 3;
    const retryDelay = options.retryDelay || 1000;

    let lastError: Error | undefined;

    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      const result = await this.withTransaction(
        (db) => operation(db, attempt),
        options
      );

      if (result.success) {
        if (attempt > 1) {
          this.logger.info('Transaction succeeded after retry', {
            operation: options.operation,
            attempt,
            transactionId: result.transactionId
          });
        }
        return result;
      }

      lastError = new Error(result.error || 'Transaction failed');

      if (attempt < maxRetries) {
        this.logger.warn('Transaction failed, retrying', {
          operation: options.operation,
          attempt,
          error: result.error,
          nextRetryIn: retryDelay
        });

        // Wait before retry
        await new Promise(resolve => setTimeout(resolve, retryDelay * attempt));
      }
    }

    this.logger.error('Transaction failed after all retries', lastError, {
      operation: options.operation,
      maxRetries
    });

    return {
      success: false,
      error: lastError?.message || 'Transaction failed after all retries'
    };
  }

  /**
   * Generate unique transaction ID
   */
  private generateTransactionId(): string {
    const timestamp = Date.now().toString(36);
    const random = Math.random().toString(36).substr(2, 9);
    return `tx_${timestamp}_${random}`;
  }
}

/**
 * Transaction decorator for automatic transaction management
 */
export function withTransaction(options: Omit<TransactionOptions, 'operation'>) {
  return function (target: any, propertyKey: string, descriptor: PropertyDescriptor) {
    const originalMethod = descriptor.value;

    descriptor.value = async function (...args: any[]) {
      const transactionManager = new TransactionManager((this as any).env || args[0]?.env);

      return transactionManager.withTransaction(
        async (db: any) => {
          // Replace database instance in arguments
          const modifiedArgs = args.map((arg: any) =>
            arg && typeof arg === 'object' && 'DB' in arg
              ? { ...arg, DB: db }
              : arg
          );

          return originalMethod.apply(this, modifiedArgs);
        },
        {
          ...options,
          operation: `${target.constructor.name}.${propertyKey}`
        }
      );
    };

    return descriptor;
  };
}

/**
 * Compensation pattern for complex transaction rollback
 */
export // TODO: Consider splitting CompensationManager into smaller, focused classes
class CompensationManager {
  private compensations: Map<string, Array<() => Promise<void>>> = new Map();
  private logger: Logger;

  constructor() {
    this.logger = new Logger({ component: 'compensation-manager' });
  }

  /**
   * Register a compensation action for a transaction
   */
  addCompensation(transactionId: string, compensation: () => Promise<void>): void {
    if (!this.compensations.has(transactionId)) {
      this.compensations.set(transactionId, []);
    }
    this.compensations.get(transactionId)!.push(compensation);
  }

  /**
   * Execute all compensations for a transaction (in reverse order)
   */
  async executeCompensations(transactionId: string): Promise<void> {
    const compensations = this.compensations.get(transactionId);
    if (!compensations || compensations.length === 0) {
      return;
    }

    this.logger.info('Executing compensations', {
      transactionId,
      count: compensations.length
    });

    // Execute in reverse order (LIFO)
    for (let i = compensations.length - 1; i >= 0; i--) {
      try {
        await compensations[i]();
      } catch (error: any) {
        this.logger.error('Compensation failed', error, {
          transactionId,
          compensationIndex: i
        });
        // Continue with other compensations even if one fails
      }
    }

    this.compensations.delete(transactionId);
  }

  /**
   * Clear compensations for a successful transaction
   */
  clearCompensations(transactionId: string): void {
    this.compensations.delete(transactionId);
  }
}