/**
 * Database Connection Manager - Single Responsibility Principle Compliant
 * Focused solely on managing database connections and query execution
 */

import type { D1Database } from '@cloudflare/workers-types';
import { IConnectionManager } from '../repositories/interfaces';
import { Logger } from '../../shared/logger';
import { circuitBreakerRegistry, CircuitBreakerConfigs } from '../../shared/circuit-breaker';

export class DatabaseConnectionManager implements IConnectionManager {
  private readonly logger: Logger;
  private readonly connectionPool: Set<D1Database>;
  private readonly maxPoolSize: number = 10;
  private performanceMetrics = {
    totalQueries: 0,
    totalExecutionTime: 0,
    failedQueries: 0,
    connectionErrors: 0
  };

  constructor(private env: { DB_MAIN: D1Database }) {
    this.logger = new Logger();
    this.connectionPool = new Set();
    this.initializePool();
    this.initializeCircuitBreaker();
    this.startMonitoring();
  }

  async execute<T>(
    query: string,
    params: any[] = [],
    operation: 'first' | 'all' | 'run' = 'all'
  ): Promise<T> {
    const startTime = performance.now();
    const queryId = this.generateQueryId();

    // Circuit breaker protection
    const circuitBreaker = circuitBreakerRegistry.getOrCreate('database', {
      failureThreshold: 5,
      resetTimeout: 30000,
      monitoringPeriod: 60000,
      timeout: 10000
    });

    try {
      return await circuitBreaker.execute(async () => {
        return this.executeQuery<T>(query, params, operation, queryId);
      });
    } catch (error: any) {
      const executionTime = performance.now() - startTime;
      this.trackFailedQuery(query, executionTime, error);
      throw error;
    }
  }

  async batch(statements: any[]): Promise<any[]> {
    const startTime = performance.now();
    const batchId = this.generateQueryId();

    this.logger.debug('Executing batch queries', {
      batchId,
      statementCount: statements.length
    });

    try {
      const db = this.getConnection();
      const results = await db.batch(statements);

      const executionTime = performance.now() - startTime;
      this.trackSuccessfulQuery(`BATCH(${statements.length})`, executionTime);

      this.logger.debug('Batch execution completed', {
        batchId,
        executionTime: Math.round(executionTime),
        results: results.length
      });

      return results;

    } catch (error: any) {
      const executionTime = performance.now() - startTime;
      this.trackFailedQuery(`BATCH(${statements.length})`, executionTime, error);

      this.logger.error('Batch execution failed', error, {
        batchId,
        statementCount: statements.length,
        executionTime: Math.round(executionTime)
      });

      throw error;
    }
  }

  // Health check for the connection pool
  async healthCheck(): Promise<{
    status: 'healthy' | 'degraded' | 'unhealthy';
    connectionCount: number;
    metrics: {
      totalQueries: number;
      successfulQueries: number;
      failedQueries: number;
      averageQueryTime: number;
      currentConnections: number;
    };
    lastError?: string;
  }> {
    try {
      // Test connection with a simple query
      await this.execute('SELECT 1', [], 'first');

      const avgExecutionTime = this.performanceMetrics.totalQueries > 0
        ? this.performanceMetrics.totalExecutionTime / this.performanceMetrics.totalQueries
        : 0;

      const errorRate = this.performanceMetrics.totalQueries > 0
        ? this.performanceMetrics.failedQueries / this.performanceMetrics.totalQueries
        : 0;

      let status: 'healthy' | 'degraded' | 'unhealthy' = 'healthy';

      if (errorRate > 0.1 || avgExecutionTime > 1000) { // 10% error rate or > 1s avg
        status = 'degraded';
      }
      if (errorRate > 0.5 || avgExecutionTime > 5000) { // 50% error rate or > 5s avg
        status = 'unhealthy';
      }

      return {
        status,
        connectionCount: this.connectionPool.size,
        metrics: {
          totalQueries: this.performanceMetrics.totalQueries,
          successfulQueries: this.performanceMetrics.totalQueries - this.performanceMetrics.failedQueries,
          failedQueries: this.performanceMetrics.failedQueries,
          averageQueryTime: this.performanceMetrics.totalQueries > 0 ?
            this.performanceMetrics.totalExecutionTime / this.performanceMetrics.totalQueries : 0,
          currentConnections: this.connectionPool.size
        }
      };

    } catch (error: any) {
      return {
        status: 'unhealthy',
        connectionCount: this.connectionPool.size,
        metrics: {
          totalQueries: this.performanceMetrics.totalQueries,
          successfulQueries: this.performanceMetrics.totalQueries - this.performanceMetrics.failedQueries,
          failedQueries: this.performanceMetrics.failedQueries,
          averageQueryTime: this.performanceMetrics.totalQueries > 0 ?
            this.performanceMetrics.totalExecutionTime / this.performanceMetrics.totalQueries : 0,
          currentConnections: this.connectionPool.size
        },
        lastError: error.message
      };
    }
  }

  // Get performance statistics
  getPerformanceStats(): {
    totalQueries: number;
    avgExecutionTime: number;
    errorRate: number;
    queriesPerSecond: number;
    connectionPoolSize: number;
  } {
    const avgExecutionTime = this.performanceMetrics.totalQueries > 0
      ? this.performanceMetrics.totalExecutionTime / this.performanceMetrics.totalQueries
      : 0;

    const errorRate = this.performanceMetrics.totalQueries > 0
      ? (this.performanceMetrics.failedQueries / this.performanceMetrics.totalQueries) * 100
      : 0;

    // Estimate queries per second based on recent activity
    const queriesPerSecond = this.performanceMetrics.totalQueries / 60; // Rough estimate

    return {
      totalQueries: this.performanceMetrics.totalQueries,
      avgExecutionTime: Math.round(avgExecutionTime),
      errorRate: Math.round(errorRate * 100) / 100,
      queriesPerSecond: Math.round(queriesPerSecond * 100) / 100,
      connectionPoolSize: this.connectionPool.size
    };
  }

  // Reset performance metrics
  resetMetrics(): void {
    this.performanceMetrics = {
      totalQueries: 0,
      totalExecutionTime: 0,
      failedQueries: 0,
      connectionErrors: 0
    };
    this.logger.info('Database connection manager metrics reset');
  }

  // Private methods
  private initializePool(): void {
    // D1 doesn't support traditional connection pooling, but we simulate it
    for (let i = 0; i < this.maxPoolSize; i++) {
      this.connectionPool.add(this.env.DB_MAIN);
    }
    this.logger.info('Database connection pool initialized', {
      poolSize: this.maxPoolSize
    });
  }

  private initializeCircuitBreaker(): void {
    circuitBreakerRegistry.getOrCreate('database', {
      ...CircuitBreakerConfigs.database,
      onStateChange: (state, name) => {
        this.logger.warn('Database circuit breaker state changed', {
          circuitName: name,
          newState: state
        });
      },
      onFailure: (error, name) => {
        this.logger.error('Database circuit breaker recorded failure', {
          circuitName: name,
          error: error.message
        });
      }
    });
  }

  private async executeQuery<T>(
    query: string,
    params: any[],
    operation: 'first' | 'all' | 'run',
    queryId: string
  ): Promise<T> {
    const startTime = performance.now();

    this.logger.debug('Executing database query', {
      queryId,
      operation,
      query: query.substring(0, 100) + (query.length > 100 ? '...' : ''),
      paramCount: params.length
    });

    try {
      const db = this.getConnection();
      const statement = db.prepare(query);
      const boundStatement = params.length > 0 ? statement.bind(...params) : statement;

      let result: any;
      switch (operation) {
        case 'first':
          result = await boundStatement.first();
          break;
        case 'all':
          result = await boundStatement.all();
          break;
        case 'run':
          result = await boundStatement.run();
          break;
      }

      const executionTime = performance.now() - startTime;
      this.trackSuccessfulQuery(query, executionTime);

      this.logger.debug('Query execution completed', {
        queryId,
        operation,
        executionTime: Math.round(executionTime),
        hasResult: !!result
      });

      return result;

    } catch (error: any) {
      const executionTime = performance.now() - startTime;
      this.trackFailedQuery(query, executionTime, error);

      this.logger.error('Database query failed', error, {
        queryId,
        operation,
        query: query.substring(0, 100) + '...',
        executionTime: Math.round(executionTime)
      });

      throw error;
    }
  }

  private getConnection(): D1Database {
    // Simple round-robin connection selection
    // In a real pool, this would be more sophisticated
    return Array.from(this.connectionPool)[0];
  }

  private trackSuccessfulQuery(query: string, executionTime: number): void {
    this.performanceMetrics.totalQueries++;
    this.performanceMetrics.totalExecutionTime += executionTime;

    // Log slow queries
    if (executionTime > 100) {
      this.logger.warn('Slow query detected', {
        query: query.substring(0, 100) + '...',
        executionTime: Math.round(executionTime)
      });
    }
  }

  private trackFailedQuery(query: string, executionTime: number, error: any): void {
    this.performanceMetrics.totalQueries++;
    this.performanceMetrics.totalExecutionTime += executionTime;
    this.performanceMetrics.failedQueries++;

    if (error.message?.includes('connection')) {
      this.performanceMetrics.connectionErrors++;
    }
  }

  private generateQueryId(): string {
    return `query_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  private startMonitoring(): void {
    // Log performance metrics every 5 minutes
    setInterval(() => {
      const stats = this.getPerformanceStats();

      if (stats.totalQueries > 0) {
        this.logger.info('Database connection manager stats', stats);
      }

      // Reset metrics if they get too large (every hour)
      if (this.performanceMetrics.totalQueries > 10000) {
        this.resetMetrics();
      }
    }, 300000); // 5 minutes
  }

  // Transaction simulation (D1 doesn't support traditional transactions)
  async simulateTransaction<T>(
    operations: (() => Promise<any>)[]
  ): Promise<{ success: boolean; results?: T[]; error?: string }> {
    const results: T[] = [];
    const startTime = performance.now();

    try {
      // Execute all operations
      for (const operation of operations) {
        const result = await operation();
        results.push(result);
      }

      const executionTime = performance.now() - startTime;
      this.logger.info('Simulated transaction completed', {
        operationCount: operations.length,
        executionTime: Math.round(executionTime)
      });

      return { success: true, results };

    } catch (error: any) {
      const executionTime = performance.now() - startTime;
      this.logger.error('Simulated transaction failed', error, {
        operationCount: operations.length,
        completedOperations: results.length,
        executionTime: Math.round(executionTime)
      });

      // In a real transaction, we would rollback here
      // For D1, we need to handle this at the application level
      return {
        success: false,
        error: error.message
      };
    }
  }
}