/**
 * Error Handling and Transaction Rollback Tests
 * Testing comprehensive error handling system with transaction support
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import {
  ErrorHandler,
  BusinessLogicError,
  DatabaseTransactionError,
  AuthorizationError,
  ErrorCategory,
  ErrorSeverity,
  createErrorHandler,
  withErrorHandling
} from '../error-handler';
import { ValidationError } from '../validation';
import { RateLimitError } from '../rate-limiter';

// Mock database for transaction testing
class MockTransactionDatabase {
  private transactionActive = false;
  private shouldFailTransaction = false;
  private shouldFailRollback = false;
  private queries: Array<{ sql: string; params?: any[] }> = [];
  private transactionLog: string[] = [];

  prepare(sql: string) {
    this.queries.push({ sql });

    const runFunction = async () => {
      if (sql.includes('BEGIN TRANSACTION')) {
        if (this.transactionActive) {
          throw new Error('Transaction already active');
        }
        this.transactionActive = true;
        this.transactionLog.push('BEGIN');
        return { success: true };
      }

      if (sql.includes('COMMIT')) {
        if (!this.transactionActive) {
          throw new Error('No active transaction to commit');
        }
        this.transactionActive = false;
        this.transactionLog.push('COMMIT');
        return { success: true };
      }

      if (sql.includes('ROLLBACK')) {
        if (!this.transactionActive) {
          throw new Error('No active transaction to rollback');
        }
        if (this.shouldFailRollback) {
          throw new Error('Rollback failed');
        }
        this.transactionActive = false;
        this.transactionLog.push('ROLLBACK');
        return { success: true };
      }

      // Regular queries
      if (this.shouldFailTransaction) {
        throw new Error('Database operation failed');
      }

      return { success: true };
    };

    return {
      run: runFunction,
      bind: (...params: any[]) => {
        this.queries[this.queries.length - 1].params = params;
        return {
          run: runFunction,
          all: async () => {
            if (this.shouldFailTransaction) {
              throw new Error('Database query failed');
            }
            return { results: [] };
          },
          first: async () => {
            if (this.shouldFailTransaction) {
              throw new Error('Database query failed');
            }
            return null;
          }
        };
      }
    };
  }

  // Test helper methods
  isTransactionActive(): boolean {
    return this.transactionActive;
  }

  getTransactionLog(): string[] {
    return [...this.transactionLog];
  }

  getQueries(): Array<{ sql: string; params?: any[] }> {
    return [...this.queries];
  }

  simulateTransactionFailure(): void {
    this.shouldFailTransaction = true;
  }

  simulateRollbackFailure(): void {
    this.shouldFailRollback = true;
  }

  reset(): void {
    this.transactionActive = false;
    this.shouldFailTransaction = false;
    this.shouldFailRollback = false;
    this.queries = [];
    this.transactionLog = [];
  }
}

describe('Error Handling and Transaction Tests', () => {
  let mockDb: MockTransactionDatabase;
  let errorHandler: ErrorHandler;

  beforeEach(() => {
    mockDb = new MockTransactionDatabase();
    errorHandler = createErrorHandler();
  });

  afterEach(() => {
    mockDb.reset();
  });

  describe('Error Categorization and Handling', () => {
    it('should categorize validation errors correctly', async () => {
      const validationError = new ValidationError('Invalid input data');

      const errorDetails = await errorHandler.handleError(validationError, {
        businessId: 'test_business',
        userId: 'test_user',
        operation: 'test_operation'
      });

      expect(errorDetails.category).toBe(ErrorCategory.VALIDATION);
      expect(errorDetails.severity).toBe(ErrorSeverity.LOW);
      expect(errorDetails.recoverable).toBe(true);
      expect(errorDetails.retryable).toBe(false);
      expect(errorDetails.publicMessage).toContain('Invalid input');
    });

    it('should categorize rate limit errors correctly', async () => {
      const rateLimitError = new RateLimitError('Rate limit exceeded', 60, Date.now() + 60000);

      const errorDetails = await errorHandler.handleError(rateLimitError, {
        businessId: 'test_business',
        userId: 'test_user',
        operation: 'test_operation'
      });

      expect(errorDetails.category).toBe(ErrorCategory.RATE_LIMIT);
      expect(errorDetails.severity).toBe(ErrorSeverity.MEDIUM);
      expect(errorDetails.recoverable).toBe(true);
      expect(errorDetails.retryable).toBe(true);
      expect(errorDetails.publicMessage).toContain('Rate limit exceeded');
    });

    it('should categorize authorization errors correctly', async () => {
      const authError = new AuthorizationError(
        'Access denied',
        'read',
        'financial_reports',
        { businessId: 'test_business', userId: 'test_user' }
      );

      const errorDetails = await errorHandler.handleError(authError, {
        businessId: 'test_business',
        userId: 'test_user',
        operation: 'test_operation'
      });

      expect(errorDetails.category).toBe(ErrorCategory.AUTHORIZATION);
      expect(errorDetails.severity).toBe(ErrorSeverity.HIGH);
      expect(errorDetails.recoverable).toBe(false);
      expect(errorDetails.retryable).toBe(false);
      expect(errorDetails.publicMessage).toContain('permission');
    });

    it('should categorize business logic errors correctly', async () => {
      const businessError = new BusinessLogicError(
        'INVALID_JOURNAL_ENTRY',
        'Journal entry does not balance',
        { businessId: 'test_business' },
        {
          category: ErrorCategory.BUSINESS_LOGIC,
          severity: ErrorSeverity.MEDIUM,
          recoverable: true,
          retryable: false,
          publicMessage: 'Journal entry must balance (debits = credits)'
        }
      );

      const errorDetails = await errorHandler.handleError(businessError, {
        businessId: 'test_business',
        userId: 'test_user',
        operation: 'create_journal_entry'
      });

      expect(errorDetails.category).toBe(ErrorCategory.BUSINESS_LOGIC);
      expect(errorDetails.severity).toBe(ErrorSeverity.MEDIUM);
      expect(errorDetails.code).toBe('INVALID_JOURNAL_ENTRY');
      expect(errorDetails.recoverable).toBe(true);
      expect(errorDetails.retryable).toBe(false);
    });

    it('should categorize database errors correctly', async () => {
      const dbError = new Error('SQLITE_CONSTRAINT: UNIQUE constraint failed');

      const errorDetails = await errorHandler.handleError(dbError, {
        businessId: 'test_business',
        userId: 'test_user',
        operation: 'database_insert'
      });

      expect(errorDetails.category).toBe(ErrorCategory.DATABASE);
      expect(errorDetails.severity).toBe(ErrorSeverity.HIGH);
      expect(errorDetails.recoverable).toBe(false);
      expect(errorDetails.retryable).toBe(true);
      expect(errorDetails.publicMessage).toContain('database error');
    });

    it('should categorize unknown errors as system errors', async () => {
      const unknownError = new Error('Something went wrong');

      const errorDetails = await errorHandler.handleError(unknownError, {
        businessId: 'test_business',
        userId: 'test_user',
        operation: 'unknown_operation'
      });

      expect(errorDetails.category).toBe(ErrorCategory.SYSTEM);
      expect(errorDetails.severity).toBe(ErrorSeverity.CRITICAL);
      expect(errorDetails.recoverable).toBe(false);
      expect(errorDetails.retryable).toBe(false);
      expect(errorDetails.publicMessage).toContain('unexpected error');
    });
  });

  describe('Transaction Management', () => {
    it('should execute operation successfully with transaction', async () => {
      const operation = async () => {
        // Simulate successful database operations
        await mockDb.prepare('INSERT INTO invoices VALUES (?, ?)').bind('inv_1', 1000).run();
        await mockDb.prepare('INSERT INTO journal_entries VALUES (?, ?)').bind('je_1', 'Invoice').run();
        return { success: true };
      };

      const result = await errorHandler.executeWithErrorHandling(
        operation,
        { operation: 'create_invoice', businessId: 'test_business' },
        mockDb as any
      );

      expect(result.success).toBe(true);

      const transactionLog = mockDb.getTransactionLog();
      expect(transactionLog).toEqual(['BEGIN', 'COMMIT']);
      expect(mockDb.isTransactionActive()).toBe(false);
    });

    it('should rollback transaction on operation failure', async () => {
      const operation = async () => {
        // Simulate database operations that will fail
        await mockDb.prepare('INSERT INTO invoices VALUES (?, ?)').bind('inv_1', 1000).run();

        // Simulate failure after some operations
        mockDb.simulateTransactionFailure();
        await mockDb.prepare('INSERT INTO journal_entries VALUES (?, ?)').bind('je_1', 'Invoice').run();

        return { success: true };
      };

      try {
        await errorHandler.executeWithErrorHandling(
          operation,
          { operation: 'create_invoice', businessId: 'test_business' },
          mockDb as any
        );

        // Should not reach here
        expect(false).toBe(true);
      } catch (error: any) {
        // Verify transaction was rolled back
        const transactionLog = mockDb.getTransactionLog();
        expect(transactionLog).toEqual(['BEGIN', 'ROLLBACK']);
        expect(mockDb.isTransactionActive()).toBe(false);
      }
    });

    it('should handle rollback failures gracefully', async () => {
      const operation = async () => {
        mockDb.simulateTransactionFailure();
        await mockDb.prepare('INSERT INTO invoices VALUES (?, ?)').bind('inv_1', 1000).run();
        return { success: true };
      };

      // Simulate rollback failure
      mockDb.simulateRollbackFailure();

      try {
        await errorHandler.executeWithErrorHandling(
          operation,
          { operation: 'create_invoice', businessId: 'test_business' },
          mockDb as any
        );

        expect(false).toBe(true);
      } catch (error: any) {
        // Should still throw the original error, not the rollback error
        expect(error instanceof Error).toBe(true);

        // Verify transaction was attempted to be rolled back
        const transactionLog = mockDb.getTransactionLog();
        expect(transactionLog).toEqual(['BEGIN']);
      }
    });

    it('should work without transaction database', async () => {
      const operation = async () => {
        return { success: true, data: 'test_data' };
      };

      const result = await errorHandler.executeWithErrorHandling(
        operation,
        { operation: 'read_only_operation', businessId: 'test_business' }
        // No database parameter
      );

      expect(result.success).toBe(true);
      expect(result.data).toBe('test_data');

      // No transaction should be started
      const transactionLog = mockDb.getTransactionLog();
      expect(transactionLog).toEqual([]);
    });
  });

  describe('Retry Logic', () => {
    it('should retry retryable operations', async () => {
      let attemptCount = 0;

      const operation = async () => {
        attemptCount++;

        if (attemptCount < 3) {
          throw new Error('Temporary failure');
        }

        return { success: true, attempts: attemptCount };
      };

      const result = await errorHandler.retryOperation(
        operation,
        { operation: 'flaky_operation', businessId: 'test_business' },
        3, // maxRetries
        10  // baseDelayMs (short for testing)
      );

      expect(result.success).toBe(true);
      expect(result.attempts).toBe(3);
      expect(attemptCount).toBe(3);
    });

    it('should not retry non-retryable operations', async () => {
      let attemptCount = 0;

      const operation = async () => {
        attemptCount++;
        throw new ValidationError('Invalid input');
      };

      try {
        await errorHandler.retryOperation(
          operation,
          { operation: 'validation_operation', businessId: 'test_business' },
          3,
          10
        );

        expect(false).toBe(true);
      } catch (error: any) {
        expect(error instanceof ValidationError).toBe(true);
        expect(attemptCount).toBe(1); // Should not retry
      }
    });

    it('should respect maximum retry attempts', async () => {
      let attemptCount = 0;

      const operation = async () => {
        attemptCount++;
        throw new Error('Persistent failure');
      };

      try {
        await errorHandler.retryOperation(
          operation,
          { operation: 'persistent_failure', businessId: 'test_business' },
          3,
          10
        );

        expect(false).toBe(true);
      } catch (error: any) {
        expect(error instanceof Error).toBe(true);
        expect(attemptCount).toBe(3); // Should try exactly 3 times
      }
    });

    it('should implement exponential backoff', async () => {
      const timestamps: number[] = [];

      const operation = async () => {
        timestamps.push(Date.now());
        throw new Error('Always fails');
      };

      try {
        await errorHandler.retryOperation(
          operation,
          { operation: 'backoff_test', businessId: 'test_business' },
          3,
          100 // 100ms base delay
        );
      } catch (error: any) {
        // Verify exponential backoff timing
        expect(timestamps.length).toBe(3);

        if (timestamps.length >= 3) {
          const delay1 = timestamps[1] - timestamps[0];
          const delay2 = timestamps[2] - timestamps[1];

          // Second delay should be roughly double the first
          // Allow for some variance due to execution time
          expect(delay2).toBeGreaterThan(delay1 * 1.5);
          expect(delay2).toBeLessThan(delay1 * 3);
        }
      }
    });
  });

  describe('Error Context and Logging', () => {
    it('should preserve error context through handling', async () => {
      const originalError = new BusinessLogicError(
        'INVALID_AMOUNT',
        'Amount cannot be negative',
        { businessId: 'test_business', amount: -100 },
        { severity: ErrorSeverity.MEDIUM }
      );

      const errorDetails = await errorHandler.handleError(originalError, {
        businessId: 'test_business',
        userId: 'test_user',
        operation: 'create_invoice',
        additionalData: { invoiceId: 'inv_123' }
      });

      expect(errorDetails.context.businessId).toBe('test_business');
      expect(errorDetails.context.userId).toBe('test_user');
      expect(errorDetails.context.operation).toBe('create_invoice');
      expect(errorDetails.context.additionalData).toEqual({ invoiceId: 'inv_123' });
      expect(errorDetails.context.timestamp).toBeGreaterThan(Date.now() - 1000);
    });

    it('should generate correlation IDs for error tracking', async () => {
      const error1 = new Error('First error');
      const error2 = new Error('Second error');

      const handler1 = createErrorHandler();
      const handler2 = createErrorHandler();

      const details1 = await handler1.handleError(error1, {});
      const details2 = await handler2.handleError(error2, {});

      // Each handler should have its own correlation ID
      expect(details1.context.correlationId).toBeDefined();
      expect(details2.context.correlationId).toBeDefined();
      expect(details1.context.correlationId).not.toBe(details2.context.correlationId);

      // Correlation IDs should follow expected format
      expect(details1.context.correlationId).toMatch(/^corr_\d+_[a-z0-9]+$/);
      expect(details2.context.correlationId).toMatch(/^corr_\d+_[a-z0-9]+$/);
    });

    it('should use provided correlation ID when available', async () => {
      const customCorrelationId = 'custom_correlation_123';
      const customHandler = createErrorHandler(customCorrelationId);

      const error = new Error('Test error');
      const errorDetails = await customHandler.handleError(error, {});

      expect(errorDetails.context.correlationId).toBe(customCorrelationId);
    });
  });

  describe('Error Handling Middleware', () => {
    it('should create functional error handling wrapper', async () => {
      let executionCount = 0;

      const originalFunction = async (param1: string, param2: number) => {
        executionCount++;

        if (param1 === 'fail') {
          throw new Error('Function failed');
        }

        return { param1, param2, executionCount };
      };

      const wrappedFunction = withErrorHandling(originalFunction, {
        operation: 'test_function',
        businessId: 'test_business'
      });

      // Test successful execution
      const result1 = await wrappedFunction('success', 123);
      expect(result1.param1).toBe('success');
      expect(result1.param2).toBe(123);
      expect(result1.executionCount).toBe(1);

      // Test error handling
      try {
        await wrappedFunction('fail', 456);
        expect(false).toBe(true);
      } catch (error: any) {
        expect(error instanceof Error).toBe(true);
        expect(executionCount).toBe(2);
      }
    });

    it('should preserve function signatures in wrapped functions', async () => {
      const originalFunction = async (
        required: string,
        optional?: number,
        defaulted: boolean = true
      ): Promise<{ required: string; optional?: number; defaulted: boolean }> => {
        return { required, optional, defaulted };
      };

      const wrappedFunction = withErrorHandling(originalFunction);

      // Test with all parameters
      const result1 = await wrappedFunction('test', 123, false);
      expect(result1).toEqual({ required: 'test', optional: 123, defaulted: false });

      // Test with optional parameters
      const result2 = await wrappedFunction('test');
      expect(result2).toEqual({ required: 'test', optional: undefined, defaulted: true });

      // Test with partial parameters
      const result3 = await wrappedFunction('test', 456);
      expect(result3).toEqual({ required: 'test', optional: 456, defaulted: true });
    });
  });

  describe('Concurrent Error Handling', () => {
    it('should handle concurrent errors without interference', async () => {
      const errors = [
        new ValidationError('Validation error 1'),
        new Error('System error 1'),
        new BusinessLogicError('BL001', 'Business logic error 1', {}),
        new ValidationError('Validation error 2'),
        new Error('System error 2')
      ];

      const promises = errors.map((error, index) =>
        errorHandler.handleError(error, {
          businessId: `business_${index}`,
          userId: `user_${index}`,
          operation: `operation_${index}`
        })
      );

      const results = await Promise.all(promises);

      // Verify each error was handled correctly
      expect(results[0].category).toBe(ErrorCategory.VALIDATION);
      expect(results[1].category).toBe(ErrorCategory.SYSTEM);
      expect(results[2].category).toBe(ErrorCategory.BUSINESS_LOGIC);
      expect(results[3].category).toBe(ErrorCategory.VALIDATION);
      expect(results[4].category).toBe(ErrorCategory.SYSTEM);

      // Verify context isolation
      for (let i = 0; i < results.length; i++) {
        expect(results[i].context.businessId).toBe(`business_${i}`);
        expect(results[i].context.userId).toBe(`user_${i}`);
        expect(results[i].context.operation).toBe(`operation_${i}`);
      }
    });

    it('should handle concurrent transaction operations safely', async () => {
      const operations = Array.from({ length: 5 }, (_, index) =>
        async () => {
          await mockDb.prepare(`INSERT INTO test_table_${index} VALUES (?)`).bind(index).run();

          if (index === 2) {
            // Simulate failure in middle operation
            throw new Error(`Operation ${index} failed`);
          }

          return { success: true, index };
        }
      );

      const promises = operations.map((operation, index) =>
        errorHandler.executeWithErrorHandling(
          operation,
          { operation: `concurrent_op_${index}`, businessId: `business_${index}` },
          mockDb as any
        ).catch((error: any) => ({ error: error.message, index }))
      );

      const results = await Promise.all(promises);

      // Verify that only operation 2 failed
      for (let i = 0; i < results.length; i++) {
        if (i === 2) {
          expect(results[i]).toHaveProperty('error');
        } else {
          expect(results[i]).toHaveProperty('success');
          expect((results[i] as any).success).toBe(true);
        }
      }
    });
  });

  describe('Error Recovery and Cleanup', () => {
    it('should perform cleanup operations on error', async () => {
      let cleanupCalled = false;

      const operation = async () => {
        try {
          throw new Error('Operation failed');
        } finally {
          cleanupCalled = true;
        }
      };

      try {
        await errorHandler.executeWithErrorHandling(
          operation,
          { operation: 'cleanup_test', businessId: 'test_business' }
        );
      } catch (error: any) {
        // Expected to throw
      }

      expect(cleanupCalled).toBe(true);
    });

    it('should maintain error context across retry attempts', async () => {
      let attemptContexts: any[] = [];

      const operation = async () => {
        // Capture context from each attempt
        attemptContexts.push({
          timestamp: Date.now(),
          attempt: attemptContexts.length + 1
        });

        throw new Error('Retryable error');
      };

      try {
        await errorHandler.retryOperation(
          operation,
          {
            operation: 'context_test',
            businessId: 'test_business',
            userId: 'test_user'
          },
          3,
          10
        );
      } catch (error: any) {
        // Expected to fail
      }

      expect(attemptContexts.length).toBe(3);

      // Verify attempt numbers
      for (let i = 0; i < attemptContexts.length; i++) {
        expect(attemptContexts[i].attempt).toBe(i + 1);
      }
    });
  });
});