/**
 * Transaction Manager with Rollback Support
 * Provides atomic operations with compensation logic
 */

import type { D1Database } from '@cloudflare/workers-types';
import { Logger } from '../../shared/logger';
import { generateSecureToken } from './security-utils';

export interface Transaction {
  id: string;
  businessId: string;
  userId: string;
  operations: TransactionOperation[];
  status: 'pending' | 'committed' | 'rolled_back' | 'failed';
  startTime: number;
  endTime?: number;
  error?: string;
}

export interface TransactionOperation {
  id: string;
  type: 'cost' | 'knowledge' | 'metric' | 'conversation' | 'custom';
  action: 'insert' | 'update' | 'delete';
  table?: string;
  data: Record<string, any>;
  compensationData?: Record<string, any>;
  executed: boolean;
  compensated: boolean;
}

export interface TransactionResult {
  success: boolean;
  transactionId: string;
  operations: number;
  rollback?: boolean;
  error?: string;
}

export // TODO: Consider splitting TransactionManager into smaller, focused classes
class TransactionManager {
  private logger: Logger;
  private db: D1Database;
  private activeTransactions = new Map<string, Transaction>();
  private savepoints = new Map<string, string>();

  constructor(db: D1Database) {
    this.logger = new Logger();
    this.db = db;
  }

  /**
   * Begin a new transaction
   */
  async beginTransaction(
    businessId: string,
    userId: string
  ): Promise<string> {
    const transactionId = generateSecureToken(16);

    const transaction: Transaction = {
      id: transactionId,
      businessId,
      userId,
      operations: [],
      status: 'pending',
      startTime: Date.now()
    };

    this.activeTransactions.set(transactionId, transaction);

    // Create savepoint for rollback
    const savepointName = `sp_${transactionId.replace(/-/g, '_')}`;
    try {
      await this.db.prepare(`SAVEPOINT ${savepointName}`).run();
      this.savepoints.set(transactionId, savepointName);
    } catch (error: any) {
      this.logger.warn('Failed to create savepoint (D1 limitation)', { transactionId });
    }

    this.logger.info('Transaction started', {
      transactionId,
      businessId,
      userId
    });

    return transactionId;
  }

  /**
   * Add operation to transaction
   */
  async addOperation(
    transactionId: string,
    operation: Omit<TransactionOperation, 'id' | 'executed' | 'compensated'>
  ): Promise<void> {
    const transaction = this.activeTransactions.get(transactionId);
    if (!transaction) {
      throw new Error(`Transaction ${transactionId} not found`);
    }

    if (transaction.status !== 'pending') {
      throw new Error(`Transaction ${transactionId} is not pending`);
    }

    const op: TransactionOperation = {
      ...operation,
      id: generateSecureToken(8),
      executed: false,
      compensated: false
    };

    transaction.operations.push(op);

    this.logger.debug('Operation added to transaction', {
      transactionId,
      operationId: op.id,
      type: op.type,
      action: op.action
    });
  }

  /**
   * Execute operation with compensation tracking
   */
  private async executeOperation(
    operation: TransactionOperation,
    businessId: string
  ): Promise<void> {
    try {
      switch (operation.type) {
        case 'cost':
          await this.executeCostOperation(operation, businessId);
          break;
        case 'knowledge':
          await this.executeKnowledgeOperation(operation, businessId);
          break;
        case 'metric':
          await this.executeMetricOperation(operation, businessId);
          break;
        case 'conversation':
          await this.executeConversationOperation(operation, businessId);
          break;
        case 'custom':
          if (operation.table) {
            await this.executeCustomOperation(operation, businessId);
          }
          break;
      }
      operation.executed = true;
    } catch (error: any) {
      throw new Error(`Failed to execute operation ${operation.id}: ${error}`);
    }
  }

  /**
   * Execute cost operation
   */
  private async executeCostOperation(
    operation: TransactionOperation,
    businessId: string
  ): Promise<void> {
    switch (operation.action) {
      case 'insert':
        // Use INSERT OR IGNORE for idempotency - task_id should be unique
        await this.db.prepare(`
          INSERT OR IGNORE INTO agent_costs (
            task_id, business_id, user_id, agent_id, capability,
            department, cost, latency, success, timestamp
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).bind(
          operation.data.task_id,
          businessId,
          operation.data.user_id,
          operation.data.agent_id,
          operation.data.capability,
          operation.data.department,
          operation.data.cost,
          operation.data.latency,
          operation.data.success ? 1 : 0,
          operation.data.timestamp || Date.now()
        ).run();

        // Store compensation data for potential rollback
        operation.compensationData = {
          task_id: operation.data.task_id
        };
        break;

      case 'update':
        const result = await this.db.prepare(`
          SELECT * FROM agent_costs WHERE task_id = ? AND business_id = ?
        `).bind(operation.data.task_id, businessId).first();

        operation.compensationData = result as Record<string, any>;

        await this.db.prepare(`
          UPDATE agent_costs
          SET cost = ?, success = ?, updated_at = ?
          WHERE task_id = ? AND business_id = ?
        `).bind(
          operation.data.cost,
          operation.data.success ? 1 : 0,
          Date.now(),
          operation.data.task_id,
          businessId
        ).run();
        break;

      case 'delete':
        const deleteResult = await this.db.prepare(`
          SELECT * FROM agent_costs WHERE task_id = ? AND business_id = ?
        `).bind(operation.data.task_id, businessId).first();

        operation.compensationData = deleteResult as Record<string, any>;

        await this.db.prepare(`
          DELETE FROM agent_costs WHERE task_id = ? AND business_id = ?
        `).bind(operation.data.task_id, businessId).run();
        break;
    }
  }

  /**
   * Execute knowledge operation
   */
  private async executeKnowledgeOperation(
    operation: TransactionOperation,
    businessId: string
  ): Promise<void> {
    switch (operation.action) {
      case 'insert':
        await this.db.prepare(`
          INSERT INTO agent_knowledge (
            id, business_id, agent_id, topic, content,
            embedding, relevance, confidence, source, status,
            created_at, accessed_at, expires_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).bind(
          operation.data.id || generateSecureToken(16),
          businessId,
          operation.data.agent_id,
          operation.data.topic,
          operation.data.content,
          JSON.stringify(operation.data.embedding || []),
          operation.data.relevance || 0.5,
          operation.data.confidence || 0.5,
          operation.data.source,
          operation.data.status || 'active',
          Date.now(),
          Date.now(),
          operation.data.expires_at || (Date.now() + 86400000)
        ).run();

        operation.compensationData = {
          id: operation.data.id
        };
        break;

      case 'update':
        const knowledge = await this.db.prepare(`
          SELECT * FROM agent_knowledge WHERE id = ? AND business_id = ?
        `).bind(operation.data.id, businessId).first();

        operation.compensationData = knowledge as Record<string, any>;

        await this.db.prepare(`
          UPDATE agent_knowledge
          SET content = ?, relevance = ?, confidence = ?, accessed_at = ?
          WHERE id = ? AND business_id = ?
        `).bind(
          operation.data.content,
          operation.data.relevance,
          operation.data.confidence,
          Date.now(),
          operation.data.id,
          businessId
        ).run();
        break;

      case 'delete':
        const deleteKnowledge = await this.db.prepare(`
          SELECT * FROM agent_knowledge WHERE id = ? AND business_id = ?
        `).bind(operation.data.id, businessId).first();

        operation.compensationData = deleteKnowledge as Record<string, any>;

        await this.db.prepare(`
          DELETE FROM agent_knowledge WHERE id = ? AND business_id = ?
        `).bind(operation.data.id, businessId).run();
        break;
    }
  }

  /**
   * Execute metric operation
   */
  private async executeMetricOperation(
    operation: TransactionOperation,
    businessId: string
  ): Promise<void> {
    switch (operation.action) {
      case 'insert':
        await this.db.prepare(`
          INSERT INTO agent_metrics (
            agent_id, business_id, period_type, period_start, period_end,
            total_tasks, successful_tasks, failed_tasks, total_cost,
            avg_latency, p95_latency, error_rate
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).bind(
          operation.data.agent_id,
          businessId,
          operation.data.period_type,
          operation.data.period_start,
          operation.data.period_end,
          operation.data.total_tasks || 0,
          operation.data.successful_tasks || 0,
          operation.data.failed_tasks || 0,
          operation.data.total_cost || 0,
          operation.data.avg_latency || 0,
          operation.data.p95_latency || 0,
          operation.data.error_rate || 0
        ).run();
        break;

      case 'update':
        await this.db.prepare(`
          UPDATE agent_metrics
          SET total_tasks = total_tasks + ?,
              successful_tasks = successful_tasks + ?,
              failed_tasks = failed_tasks + ?,
              total_cost = total_cost + ?
          WHERE agent_id = ? AND business_id = ? AND period_type = ? AND period_start = ?
        `).bind(
          operation.data.task_increment || 0,
          operation.data.success_increment || 0,
          operation.data.failure_increment || 0,
          operation.data.cost_increment || 0,
          operation.data.agent_id,
          businessId,
          operation.data.period_type,
          operation.data.period_start
        ).run();
        break;
    }
  }

  /**
   * Execute conversation operation
   */
  private async executeConversationOperation(
    operation: TransactionOperation,
    businessId: string
  ): Promise<void> {
    if (operation.action === 'insert') {
      await this.db.prepare(`
        INSERT INTO agent_conversations (
          id, business_id, user_id, session_id, agent_id,
          capability, input, output, success, cost, latency, timestamp
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(
        operation.data.id || generateSecureToken(16),
        businessId,
        operation.data.user_id,
        operation.data.session_id,
        operation.data.agent_id,
        operation.data.capability,
        operation.data.input,
        operation.data.output,
        operation.data.success ? 1 : 0,
        operation.data.cost,
        operation.data.latency,
        operation.data.timestamp || Date.now()
      ).run();

      operation.compensationData = {
        id: operation.data.id
      };
    }
  }

  /**
   * Execute custom operation
   */
  private async executeCustomOperation(
    operation: TransactionOperation,
    businessId: string
  ): Promise<void> {
    if (!operation.table) return;

    // Build dynamic SQL based on operation
    // Note: In production, use proper query builders
    const columns = Object.keys(operation.data);
    const placeholders = columns.map(() => '?').join(', ');
    const values = Object.values(operation.data);

    if (operation.action === 'insert') {
      const sql = `INSERT INTO ${operation.table} (${columns.join(', ')}) VALUES (${placeholders})`;
      await this.db.prepare(sql).bind(...values).run();
    }
  }

  /**
   * Compensate (rollback) operation
   */
  private async compensateOperation(
    operation: TransactionOperation,
    businessId: string
  ): Promise<void> {
    if (!operation.executed || operation.compensated) {
      return;
    }

    try {
      switch (operation.action) {
        case 'insert':
          // Delete the inserted record
          if (operation.compensationData?.task_id) {
            await this.db.prepare(`
              DELETE FROM ${this.getTableName(operation.type)}
              WHERE ${this.getIdColumn(operation.type)} = ? AND business_id = ?
            `).bind(operation.compensationData.task_id, businessId).run();
          }
          break;

        case 'update':
          // Restore original values
          if (operation.compensationData) {
            await this.restoreOriginalValues(
              operation.type,
              operation.compensationData,
              businessId
            );
          }
          break;

        case 'delete':
          // Re-insert deleted record
          if (operation.compensationData) {
            await this.reinsertDeletedRecord(
              operation.type,
              operation.compensationData,
              businessId
            );
          }
          break;
      }

      operation.compensated = true;

    } catch (error: any) {
      this.logger.error('Failed to compensate operation', error, {
        operationId: operation.id,
        type: operation.type,
        action: operation.action
      });
      throw error;
    }
  }

  /**
   * Commit transaction
   */
  async commitTransaction(transactionId: string): Promise<TransactionResult> {
    const transaction = this.activeTransactions.get(transactionId);
    if (!transaction) {
      throw new Error(`Transaction ${transactionId} not found`);
    }

    if (transaction.status !== 'pending') {
      throw new Error(`Transaction ${transactionId} is not pending`);
    }

    try {
      // Execute all operations
      for (const operation of transaction.operations) {
        await this.executeOperation(operation, transaction.businessId);
      }

      // Release savepoint if exists
      const savepointName = this.savepoints.get(transactionId);
      if (savepointName) {
        try {
          await this.db.prepare(`RELEASE SAVEPOINT ${savepointName}`).run();
        } catch (error: any) {
          // Ignore if savepoints not supported
        }
        this.savepoints.delete(transactionId);
      }

      transaction.status = 'committed';
      transaction.endTime = Date.now();

      this.logger.info('Transaction committed', {
        transactionId,
        operations: transaction.operations.length,
        duration: transaction.endTime - transaction.startTime
      });

      // Clean up
      this.activeTransactions.delete(transactionId);

      return {
        success: true,
        transactionId,
        operations: transaction.operations.length
      };

    } catch (error: any) {
      // Rollback on error
      return await this.rollbackTransaction(
        transactionId,
        error instanceof Error ? error.message : 'Unknown error'
      );
    }
  }

  /**
   * Rollback transaction
   */
  async rollbackTransaction(
    transactionId: string,
    reason: string
  ): Promise<TransactionResult> {
    const transaction = this.activeTransactions.get(transactionId);
    if (!transaction) {
      throw new Error(`Transaction ${transactionId} not found`);
    }

    try {
      // Try database rollback first
      const savepointName = this.savepoints.get(transactionId);
      if (savepointName) {
        try {
          await this.db.prepare(`ROLLBACK TO SAVEPOINT ${savepointName}`).run();
          this.savepoints.delete(transactionId);

          transaction.status = 'rolled_back';
          transaction.endTime = Date.now();
          transaction.error = reason;

          this.logger.info('Transaction rolled back via savepoint', {
            transactionId,
            reason
          });

          return {
            success: false,
            transactionId,
            operations: transaction.operations.length,
            rollback: true,
            error: reason
          };
        } catch (error: any) {
          // Savepoint rollback failed, use compensation
          this.logger.warn('Savepoint rollback failed, using compensation', {
            transactionId,
            error: error instanceof Error ? error.message : 'Unknown'
          });
        }
      }

      // Compensate executed operations in reverse order
      const executedOps = transaction.operations.filter((op: any) => op.executed);
      for (let i = executedOps.length - 1; i >= 0; i--) {
        await this.compensateOperation(executedOps[i], transaction.businessId);
      }

      transaction.status = 'rolled_back';
      transaction.endTime = Date.now();
      transaction.error = reason;

      this.logger.info('Transaction rolled back via compensation', {
        transactionId,
        compensatedOperations: executedOps.length,
        reason
      });

      // Clean up
      this.activeTransactions.delete(transactionId);

      return {
        success: false,
        transactionId,
        operations: transaction.operations.length,
        rollback: true,
        error: reason
      };

    } catch (error: any) {
      transaction.status = 'failed';
      transaction.endTime = Date.now();
      transaction.error = `Rollback failed: ${error}`;

      this.logger.error('Transaction rollback failed', error, {
        transactionId,
        originalReason: reason
      });

      return {
        success: false,
        transactionId,
        operations: transaction.operations.length,
        rollback: false,
        error: transaction.error
      };
    }
  }

  /**
   * Helper methods
   */
  private getTableName(type: TransactionOperation['type']): string {
    const tableMap = {
      cost: 'agent_costs',
      knowledge: 'agent_knowledge',
      metric: 'agent_metrics',
      conversation: 'agent_conversations',
      custom: ''
    };
    return tableMap[type];
  }

  private getIdColumn(type: TransactionOperation['type']): string {
    const columnMap = {
      cost: 'task_id',
      knowledge: 'id',
      metric: 'agent_id',
      conversation: 'id',
      custom: 'id'
    };
    return columnMap[type];
  }

  private async restoreOriginalValues(
    type: TransactionOperation['type'],
    originalData: Record<string, any>,
    businessId: string
  ): Promise<void> {
    const table = this.getTableName(type);
    const idColumn = this.getIdColumn(type);

    if (table && originalData[idColumn]) {
      // Build update statement from original data
      const updates = Object.keys(originalData)
        .filter((k: any) => k !== idColumn && k !== 'business_id')
        .map((k: any) => `${k} = ?`)
        .join(', ');

      const values = Object.keys(originalData)
        .filter((k: any) => k !== idColumn && k !== 'business_id')
        .map((k: any) => originalData[k]);

      await this.db.prepare(`
        UPDATE ${table}
        SET ${updates}
        WHERE ${idColumn} = ? AND business_id = ?
      `).bind(...values, originalData[idColumn], businessId).run();
    }
  }

  private async reinsertDeletedRecord(
    type: TransactionOperation['type'],
    deletedData: Record<string, any>,
    businessId: string
  ): Promise<void> {
    const table = this.getTableName(type);

    if (table && deletedData) {
      const columns = Object.keys(deletedData);
      const placeholders = columns.map(() => '?').join(', ');
      const values = columns.map((k: any) => deletedData[k]);

      await this.db.prepare(`
        INSERT INTO ${table} (${columns.join(', ')})
        VALUES (${placeholders})
      `).bind(...values).run();
    }
  }

  /**
   * Get active transaction count
   */
  getActiveTransactionCount(): number {
    return this.activeTransactions.size;
  }

  /**
   * Cleanup stale transactions
   */
  async cleanupStaleTransactions(maxAgeMs: number = 300000): Promise<number> {
    const now = Date.now();
    let cleaned = 0;

    for (const [id, transaction] of this.activeTransactions) {
      if (transaction.status === 'pending' &&
          (now - transaction.startTime) > maxAgeMs) {
        try {
          await this.rollbackTransaction(id, 'Transaction timeout');
          cleaned++;
        } catch (error: any) {
          this.logger.error('Failed to cleanup stale transaction', error, {
            transactionId: id
          });
        }
      }
    }

    if (cleaned > 0) {
      this.logger.info('Cleaned up stale transactions', { count: cleaned });
    }

    return cleaned;
  }
}