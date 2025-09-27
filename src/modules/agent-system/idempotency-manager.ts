/**
 * Idempotency Manager
 * Prevents duplicate task execution and provides result caching
 */

import type { KVNamespace } from '@cloudflare/workers-types';
import { Logger } from '../../shared/logger';
import { AgentTask, OrchestratorResult } from './types';
import {
  generateSecureToken,
  hashSensitiveData,
  sanitizeBusinessId
} from './security-utils';

export interface IdempotencyRecord {
  key: string;
  taskId: string;
  businessId: string;
  result?: OrchestratorResult;
  status: 'pending' | 'completed' | 'failed';
  createdAt: number;
  updatedAt: number;
  expiresAt: number;
  executionCount: number;
  metadata?: Record<string, any>;
}

export interface IdempotencyConfig {
  ttlSeconds: number;
  maxRetries: number;
  enableCaching: boolean;
  cacheOnlySuccess: boolean;
}

export // TODO: Consider splitting IdempotencyManager into smaller, focused classes
class IdempotencyManager {
  private logger: Logger;
  private kv: KVNamespace;
  private config: IdempotencyConfig;
  private pendingExecutions = new Map<string, Promise<OrchestratorResult>>();

  constructor(kv: KVNamespace, config?: Partial<IdempotencyConfig>) {
    this.logger = new Logger();
    this.kv = kv;
    this.config = {
      ttlSeconds: 300, // 5 minutes default
      maxRetries: 3,
      enableCaching: true,
      cacheOnlySuccess: true,
      ...config
    };
  }

  /**
   * Generate idempotency key from task
   */
  async generateKey(task: AgentTask): Promise<string> {
    // Create deterministic key from task properties
    const keyComponents = {
      businessId: task.context.businessId,
      capability: task.capability,
      input: JSON.stringify(task.input),
      department: task.context.department,
      // Include critical constraints in key
      constraints: task.constraints ? {
        maxCost: task.constraints.maxCost,
        maxLatency: task.constraints.maxLatency
      } : null
    };

    // Hash the components for a consistent key
    const hash = await hashSensitiveData(JSON.stringify(keyComponents));
    return `idempotent:${hash}`;
  }

  /**
   * Check if task has been executed recently
   */
  async checkExisting(task: AgentTask): Promise<{
    exists: boolean;
    result?: OrchestratorResult;
    record?: IdempotencyRecord;
  }> {
    try {
      const key = await this.generateKey(task);

      // Check if there's a pending execution
      const pending = this.pendingExecutions.get(key);
      if (pending) {
        this.logger.info('Found pending execution for idempotent task', {
          taskId: task.id,
          key
        });

        // Wait for the pending execution to complete
        try {
          const result = await pending;
          return {
            exists: true,
            result
          };
        } catch (error: any) {
          // If pending execution failed, allow retry
          this.logger.warn('Pending execution failed, allowing retry', {
            taskId: task.id,
            error: error instanceof Error ? error.message : 'Unknown error'
          });
          return { exists: false };
        }
      }

      // Check KV for cached result
      const cached = await this.kv.get(key, 'json') as IdempotencyRecord | null;

      if (!cached) {
        return { exists: false };
      }

      // Check if record is expired
      const now = Date.now();
      if (cached.expiresAt < now) {
        // Clean up expired record
        await this.kv.delete(key);
        return { exists: false };
      }

      // Check status
      if (cached.status === 'completed' && cached.result) {
        this.logger.info('Found cached result for idempotent task', {
          taskId: task.id,
          originalTaskId: cached.taskId,
          age: now - cached.createdAt
        });

        // Update access metadata
        cached.updatedAt = now;
        cached.executionCount++;
        await this.kv.put(key, JSON.stringify(cached), {
          expirationTtl: this.config.ttlSeconds
        });

        return {
          exists: true,
          result: cached.result,
          record: cached
        };
      }

      // If status is 'failed', check if we should retry
      if (cached.status === 'failed' && cached.executionCount >= this.config.maxRetries) {
        this.logger.warn('Max retries exceeded for idempotent task', {
          taskId: task.id,
          executionCount: cached.executionCount
        });

        return {
          exists: true,
          result: cached.result,
          record: cached
        };
      }

      // Allow retry for failed tasks
      return { exists: false, record: cached };

    } catch (error: any) {
      this.logger.error('Failed to check idempotency', error, {
        taskId: task.id
      });
      // On error, allow execution to proceed
      return { exists: false };
    }
  }

  /**
   * Register task execution start
   */
  async registerExecution(
    task: AgentTask,
    executionPromise: Promise<OrchestratorResult>
  ): Promise<void> {
    try {
      const key = await this.generateKey(task);
      const safeBusinessId = sanitizeBusinessId(task.context.businessId);

      // Store in pending map
      this.pendingExecutions.set(key, executionPromise);

      // Create or update record in KV
      const existingData = await this.kv.get(key, 'json') as IdempotencyRecord | null;

      const record: IdempotencyRecord = existingData || {
        key,
        taskId: task.id,
        businessId: safeBusinessId,
        status: 'pending',
        createdAt: Date.now(),
        updatedAt: Date.now(),
        expiresAt: Date.now() + (this.config.ttlSeconds * 1000),
        executionCount: (existingData?.executionCount || 0) + 1,
        metadata: {
          capability: task.capability,
          department: task.context.department,
          priority: task.priority
        }
      };

      // Update status to pending
      record.status = 'pending';
      record.updatedAt = Date.now();

      await this.kv.put(key, JSON.stringify(record), {
        expirationTtl: this.config.ttlSeconds
      });

      // Clean up pending map when execution completes
      executionPromise
        .finally(() => {
          this.pendingExecutions.delete(key);
        })
        .catch(() => {
          // Ignore errors here, they're handled elsewhere
        });

      this.logger.debug('Registered idempotent execution', {
        taskId: task.id,
        key,
        executionCount: record.executionCount
      });

    } catch (error: any) {
      this.logger.error('Failed to register execution', error, {
        taskId: task.id
      });
    }
  }

  /**
   * Store execution result
   */
  async storeResult(
    task: AgentTask,
    result: OrchestratorResult
  ): Promise<void> {
    try {
      // Only cache successful results if configured
      if (this.config.cacheOnlySuccess && !result.success) {
        this.logger.debug('Skipping cache for failed result', {
          taskId: task.id,
          success: result.success
        });
        return;
      }

      const key = await this.generateKey(task);
      const safeBusinessId = sanitizeBusinessId(task.context.businessId);

      // Get existing record
      const existingData = await this.kv.get(key, 'json') as IdempotencyRecord | null;

      const record: IdempotencyRecord = {
        key,
        taskId: task.id,
        businessId: safeBusinessId,
        result,
        status: result.success ? 'completed' : 'failed',
        createdAt: existingData?.createdAt || Date.now(),
        updatedAt: Date.now(),
        expiresAt: Date.now() + (this.config.ttlSeconds * 1000),
        executionCount: existingData?.executionCount || 1,
        metadata: {
          capability: task.capability,
          department: task.context.department,
          priority: task.priority,
          totalCost: result.totalCost,
          totalLatency: result.totalLatency,
          selectedAgent: result.selectedAgent
        }
      };

      await this.kv.put(key, JSON.stringify(record), {
        expirationTtl: this.config.ttlSeconds
      });

      this.logger.info('Stored idempotent result', {
        taskId: task.id,
        key,
        success: result.success,
        ttl: this.config.ttlSeconds
      });

    } catch (error: any) {
      this.logger.error('Failed to store result', error, {
        taskId: task.id
      });
    }
  }

  /**
   * Invalidate cached result
   */
  async invalidate(task: AgentTask): Promise<boolean> {
    try {
      const key = await this.generateKey(task);

      // Remove from pending executions
      this.pendingExecutions.delete(key);

      // Delete from KV
      await this.kv.delete(key);

      this.logger.info('Invalidated idempotent cache', {
        taskId: task.id,
        key
      });

      return true;

    } catch (error: any) {
      this.logger.error('Failed to invalidate cache', error, {
        taskId: task.id
      });
      return false;
    }
  }

  /**
   * Clean up expired records
   */
  async cleanupExpired(): Promise<number> {
    try {
      const prefix = 'idempotent:';
      const { keys } = await this.kv.list({ prefix });
      const now = Date.now();
      let cleaned = 0;

      for (const key of keys) {
        const data = await this.kv.get(key.name, 'json') as IdempotencyRecord | null;
        if (data && data.expiresAt < now) {
          await this.kv.delete(key.name);
          cleaned++;
        }
      }

      if (cleaned > 0) {
        this.logger.info('Cleaned up expired idempotency records', {
          count: cleaned
        });
      }

      return cleaned;

    } catch (error: any) {
      this.logger.error('Failed to cleanup expired records', error);
      return 0;
    }
  }

  /**
   * Get statistics
   */
  async getStatistics(): Promise<{
    totalRecords: number;
    pendingExecutions: number;
    completedCount: number;
    failedCount: number;
    averageExecutionCount: number;
  }> {
    try {
      const prefix = 'idempotent:';
      const { keys } = await this.kv.list({ prefix });

      let completed = 0;
      let failed = 0;
      let totalExecutionCount = 0;

      for (const key of keys) {
        const data = await this.kv.get(key.name, 'json') as IdempotencyRecord | null;
        if (data) {
          if (data.status === 'completed') completed++;
          if (data.status === 'failed') failed++;
          totalExecutionCount += data.executionCount;
        }
      }

      return {
        totalRecords: keys.length,
        pendingExecutions: this.pendingExecutions.size,
        completedCount: completed,
        failedCount: failed,
        averageExecutionCount: keys.length > 0 ? totalExecutionCount / keys.length : 0
      };

    } catch (error: any) {
      this.logger.error('Failed to get statistics', error);
      return {
        totalRecords: 0,
        pendingExecutions: this.pendingExecutions.size,
        completedCount: 0,
        failedCount: 0,
        averageExecutionCount: 0
      };
    }
  }

  /**
   * Update configuration
   */
  updateConfig(config: Partial<IdempotencyConfig>): void {
    this.config = {
      ...this.config,
      ...config
    };

    this.logger.info('Updated idempotency configuration', this.config);
  }
}