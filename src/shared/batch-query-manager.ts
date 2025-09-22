/**
 * Batch Query Manager
 * Optimizes database performance by batching multiple queries into single operations
 */

import type { D1Database, D1PreparedStatement } from '@cloudflare/workers-types';
import { Logger } from './logger';

export interface BatchOperation {
  id: string;
  query: string;
  params: any[];
  type: 'select' | 'insert' | 'update' | 'delete';
  businessId?: string;
}

export interface BatchResult<T = any> {
  id: string;
  success: boolean;
  data?: T;
  error?: string;
  rowsAffected?: number;
}

export interface BatchQueryOptions {
  maxBatchSize?: number;
  timeoutMs?: number;
  parallel?: boolean;
  validateBusinessId?: boolean;
}

export // TODO: Consider splitting BatchQueryManager into smaller, focused classes
class BatchQueryManager {
  private logger: Logger;
  private db: D1Database;
  private pendingBatches: Map<string, BatchOperation[]> = new Map();
  private batchTimers: Map<string, NodeJS.Timeout> = new Map();

  constructor(db: D1Database) {
    this.logger = new Logger();
    this.db = db;
  }

  /**
   * Execute multiple SELECT queries in a batch with optimized performance
   */
  async executeBatch<T = any>(
    operations: BatchOperation[],
    options: BatchQueryOptions = {}
  ): Promise<BatchResult<T>[]> {
    const {
      maxBatchSize = 50,
      timeoutMs = 5000,
      parallel = true,
      validateBusinessId = true
    } = options;

    if (operations.length === 0) {
      return [];
    }

    const startTime = performance.now();
    const results: BatchResult<T>[] = [];

    try {
      // Validate business ID isolation if required
      if (validateBusinessId) {
        this.validateBusinessIdIsolation(operations);
      }

      // Split into manageable batches
      const batches = this.splitIntoBatches(operations, maxBatchSize);

      if (parallel && batches.length > 1) {
        // Execute batches in parallel
        const batchPromises = batches.map(batch => this.executeSingleBatch<T>(batch, timeoutMs));
        const batchResults = await Promise.allSettled(batchPromises);

        for (const result of batchResults) {
          if (result.status === 'fulfilled') {
            results.push(...result.value);
          } else {
            this.logger.error('Batch execution failed', result.reason);
            // Add error results for failed batch
            results.push({
              id: 'batch_error',
              success: false,
              error: result.reason.message || 'Batch execution failed'
            });
          }
        }
      } else {
        // Execute batches sequentially
        for (const batch of batches) {
          const batchResults = await this.executeSingleBatch<T>(batch, timeoutMs);
          results.push(...batchResults);
        }
      }

      const executionTime = performance.now() - startTime;
      this.logger.debug('Batch query execution completed', {
        operationCount: operations.length,
        batchCount: batches.length,
        executionTimeMs: executionTime,
        parallel
      });

      return results;

    } catch (error) {
      this.logger.error('Batch query execution failed', error);
      throw error;
    }
  }

  /**
   * Create a batched INSERT operation for multiple records
   */
  async batchInsert<T = any>(
    tableName: string,
    records: Record<string, any>[],
    businessId: string,
    options: { chunkSize?: number; onConflict?: string } = {}
  ): Promise<BatchResult<T>[]> {
    const { chunkSize = 100, onConflict = '' } = options;

    if (records.length === 0) {
      return [];
    }

    const results: BatchResult<T>[] = [];
    const chunks = this.chunkArray(records, chunkSize);

    for (let i = 0; i < chunks.length; i++) {
      const chunk = chunks[i];

      try {
        // Build batch INSERT statement
        const { query, params } = this.buildBatchInsertQuery(tableName, chunk, businessId, onConflict);

        const result = await this.db.prepare(query).bind(...params).run();

        results.push({
          id: `batch_insert_${i}`,
          success: result.success,
          rowsAffected: result.changes,
          data: result.meta as T
        });

        this.logger.debug('Batch insert completed', {
          table: tableName,
          chunk: i + 1,
          totalChunks: chunks.length,
          recordsInChunk: chunk.length,
          success: result.success
        });

      } catch (error) {
        this.logger.error('Batch insert failed', error, {
          table: tableName,
          chunk: i + 1,
          recordsInChunk: chunk.length
        });

        results.push({
          id: `batch_insert_${i}`,
          success: false,
          error: error instanceof Error ? error.message : String(error)
        });
      }
    }

    return results;
  }

  /**
   * Create a batched UPDATE operation for multiple records
   */
  async batchUpdate<T = any>(
    tableName: string,
    updates: Array<{ id: string; data: Record<string, any> }>,
    businessId: string,
    options: { chunkSize?: number } = {}
  ): Promise<BatchResult<T>[]> {
    const { chunkSize = 50 } = options;

    if (updates.length === 0) {
      return [];
    }

    const results: BatchResult<T>[] = [];
    const chunks = this.chunkArray(updates, chunkSize);

    for (let i = 0; i < chunks.length; i++) {
      const chunk = chunks[i];

      try {
        // Use D1 batch API for updates
        const statements: D1PreparedStatement[] = [];

        for (const update of chunk) {
          const { query, params } = this.buildUpdateQuery(tableName, update.id, update.data, businessId);
          statements.push(this.db.prepare(query).bind(...params));
        }

        const batchResults = await this.db.batch(statements);

        for (let j = 0; j < batchResults.length; j++) {
          const result = batchResults[j];
          results.push({
            id: chunk[j].id,
            success: result.success,
            rowsAffected: result.changes,
            data: result.meta as T
          });
        }

        this.logger.debug('Batch update completed', {
          table: tableName,
          chunk: i + 1,
          totalChunks: chunks.length,
          recordsInChunk: chunk.length
        });

      } catch (error) {
        this.logger.error('Batch update failed', error, {
          table: tableName,
          chunk: i + 1,
          recordsInChunk: chunk.length
        });

        // Add error results for all records in failed chunk
        for (const update of chunk) {
          results.push({
            id: update.id,
            success: false,
            error: error instanceof Error ? error.message : String(error)
          });
        }
      }
    }

    return results;
  }

  /**
   * Queue operations for delayed batch execution
   */
  queueOperation(batchKey: string, operation: BatchOperation, delayMs: number = 100): void {
    if (!this.pendingBatches.has(batchKey)) {
      this.pendingBatches.set(batchKey, []);
    }

    this.pendingBatches.get(batchKey)!.push(operation);

    // Clear existing timer and set new one
    if (this.batchTimers.has(batchKey)) {
      clearTimeout(this.batchTimers.get(batchKey)!);
    }

    const timer = setTimeout(() => {
      this.executePendingBatch(batchKey);
    }, delayMs);

    this.batchTimers.set(batchKey, timer);
  }

  /**
   * Execute a single batch of operations
   */
  private async executeSingleBatch<T>(
    operations: BatchOperation[],
    timeoutMs: number
  ): Promise<BatchResult<T>[]> {
    const results: BatchResult<T>[] = [];

    // Separate read and write operations
    const readOps = operations.filter(op => op.type === 'select');
    const writeOps = operations.filter(op => op.type !== 'select');

    // Execute read operations in parallel
    if (readOps.length > 0) {
      const readPromises = readOps.map(async (op) => {
        try {
          const result = await Promise.race([
            this.db.prepare(op.query).bind(...op.params).all(),
            new Promise((_, reject) =>
              setTimeout(() => reject(new Error('Query timeout')), timeoutMs)
            )
          ]) as any;

          return {
            id: op.id,
            success: true,
            data: result.results || result
          };
        } catch (error) {
          return {
            id: op.id,
            success: false,
            error: error instanceof Error ? error.message : String(error)
          };
        }
      });

      const readResults = await Promise.allSettled(readPromises);
      for (const result of readResults) {
        if (result.status === 'fulfilled') {
          results.push(result.value);
        }
      }
    }

    // Execute write operations using D1 batch API
    if (writeOps.length > 0) {
      try {
        const statements = writeOps.map(op =>
          this.db.prepare(op.query).bind(...op.params)
        );

        const batchResults = await this.db.batch(statements);

        for (let i = 0; i < writeOps.length; i++) {
          const op = writeOps[i];
          const result = batchResults[i];

          results.push({
            id: op.id,
            success: result.success,
            rowsAffected: result.changes,
            data: result.meta as T
          });
        }
      } catch (error) {
        // Add error results for all write operations
        for (const op of writeOps) {
          results.push({
            id: op.id,
            success: false,
            error: error instanceof Error ? error.message : String(error)
          });
        }
      }
    }

    return results;
  }

  /**
   * Execute pending batch operations
   */
  private async executePendingBatch(batchKey: string): Promise<void> {
    const operations = this.pendingBatches.get(batchKey);
    if (!operations || operations.length === 0) {
      return;
    }

    try {
      await this.executeBatch(operations);
      this.logger.debug('Pending batch executed', {
        batchKey,
        operationCount: operations.length
      });
    } catch (error) {
      this.logger.error('Pending batch execution failed', error, { batchKey });
    } finally {
      // Clean up
      this.pendingBatches.delete(batchKey);
      this.batchTimers.delete(batchKey);
    }
  }

  /**
   * Validate business ID isolation across operations
   */
  private validateBusinessIdIsolation(operations: BatchOperation[]): void {
    const businessIds = new Set<string>();

    for (const op of operations) {
      if (op.businessId) {
        businessIds.add(op.businessId);
      }
    }

    if (businessIds.size > 1) {
      throw new Error('Batch operations must be within a single business context');
    }
  }

  /**
   * Split operations into smaller batches
   */
  private splitIntoBatches<T>(items: T[], batchSize: number): T[][] {
    const batches: T[][] = [];
    for (let i = 0; i < items.length; i += batchSize) {
      batches.push(items.slice(i, i + batchSize));
    }
    return batches;
  }

  /**
   * Split array into chunks
   */
  private chunkArray<T>(array: T[], chunkSize: number): T[][] {
    return this.splitIntoBatches(array, chunkSize);
  }

  /**
   * Build batch INSERT query
   */
  private buildBatchInsertQuery(
    tableName: string,
    records: Record<string, any>[],
    businessId: string,
    onConflict: string
  ): { query: string; params: any[] } {
    if (records.length === 0) {
      throw new Error('No records provided for batch insert');
    }

    // Ensure all records have business_id
    const enrichedRecords = records.map(record => ({
      ...record,
      business_id: businessId
    }));

    const columns = Object.keys(enrichedRecords[0]);
    const placeholders = columns.map(() => '?').join(', ');
    const valuesClause = enrichedRecords.map(() => `(${placeholders})`).join(', ');

    const query = `
      INSERT INTO ${tableName} (${columns.join(', ')})
      VALUES ${valuesClause}
      ${onConflict}
    `;

    const params = enrichedRecords.flatMap(record =>
      columns.map(col => record[col])
    );

    return { query, params };
  }

  /**
   * Build UPDATE query
   */
  private buildUpdateQuery(
    tableName: string,
    id: string,
    data: Record<string, any>,
    businessId: string
  ): { query: string; params: any[] } {
    const columns = Object.keys(data);
    const setClause = columns.map(col => `${col} = ?`).join(', ');

    const query = `
      UPDATE ${tableName}
      SET ${setClause}, updated_at = datetime('now')
      WHERE id = ? AND business_id = ?
    `;

    const params = [...Object.values(data), id, businessId];

    return { query, params };
  }

  /**
   * Get batch statistics
   */
  getStatistics(): {
    pendingBatches: number;
    totalPendingOperations: number;
  } {
    let totalOps = 0;
    for (const ops of this.pendingBatches.values()) {
      totalOps += ops.length;
    }

    return {
      pendingBatches: this.pendingBatches.size,
      totalPendingOperations: totalOps
    };
  }

  /**
   * Clear all pending batches
   */
  clearPendingBatches(): void {
    for (const timer of this.batchTimers.values()) {
      clearTimeout(timer);
    }

    this.pendingBatches.clear();
    this.batchTimers.clear();
  }
}