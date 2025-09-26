/**
 * Comprehensive Error Handling for Finance Module
 * Centralized error management with transaction rollback and recovery
 */

import { Logger } from '../../shared/logger';
import { ValidationError } from './validation';
import { RateLimitError } from './rate-limiter';

export enum ErrorCategory {
  VALIDATION = 'VALIDATION',
  DATABASE = 'DATABASE',
  BUSINESS_LOGIC = 'BUSINESS_LOGIC',
  RATE_LIMIT = 'RATE_LIMIT',
  AUTHORIZATION = 'AUTHORIZATION',
  EXTERNAL_SERVICE = 'EXTERNAL_SERVICE',
  SYSTEM = 'SYSTEM',
  AUDIT = 'AUDIT'
}

export enum ErrorSeverity {
  LOW = 'LOW',
  MEDIUM = 'MEDIUM',
  HIGH = 'HIGH',
  CRITICAL = 'CRITICAL'
}

export interface ErrorContext {
  businessId?: string;
  userId?: string;
  operation?: string;
  correlationId?: string;
  timestamp?: number;
  additionalData?: Record<string, any>;
}

export interface ErrorDetails {
  code: string;
  message: string;
  category: ErrorCategory;
  severity: ErrorSeverity;
  context: ErrorContext;
  recoverable: boolean;
  retryable: boolean;
  publicMessage?: string; // Safe message for end users
}

/**
 * Custom business logic error
 */
export class BusinessLogicError extends Error {
  public readonly code: string;
  public readonly category: ErrorCategory;
  public readonly severity: ErrorSeverity;
  public readonly context: ErrorContext;
  public readonly recoverable: boolean;
  public readonly retryable: boolean;
  public readonly publicMessage?: string;

  constructor(
    code: string,
    message: string,
    context: ErrorContext = {},
    options: {
      category?: ErrorCategory;
      severity?: ErrorSeverity;
      recoverable?: boolean;
      retryable?: boolean;
      publicMessage?: string;
    } = {}
  ) {
    super(message);
    this.name = 'BusinessLogicError';
    this.code = code;
    this.category = options.category || ErrorCategory.BUSINESS_LOGIC;
    this.severity = options.severity || ErrorSeverity.MEDIUM;
    this.context = { ...context, timestamp: Date.now() };
    this.recoverable = options.recoverable || false;
    this.retryable = options.retryable || false;
    this.publicMessage = options.publicMessage;
  }
}

/**
 * Database transaction error with rollback support
 */
export class DatabaseTransactionError extends Error {
  public readonly operation: string;
  public readonly context: ErrorContext;
  public readonly rollbackRequired: boolean;

  constructor(
    message: string,
    operation: string,
    context: ErrorContext = {},
    rollbackRequired: boolean = true
  ) {
    super(message);
    this.name = 'DatabaseTransactionError';
    this.operation = operation;
    this.context = { ...context, timestamp: Date.now() };
    this.rollbackRequired = rollbackRequired;
  }
}

/**
 * Authorization error
 */
export class AuthorizationError extends Error {
  public readonly context: ErrorContext;
  public readonly action: string;
  public readonly resource: string;

  constructor(
    message: string,
    action: string,
    resource: string,
    context: ErrorContext = {}
  ) {
    super(message);
    this.name = 'AuthorizationError';
    this.action = action;
    this.resource = resource;
    this.context = { ...context, timestamp: Date.now() };
  }
}

/**
 * Comprehensive error handler
 */
export class ErrorHandler {
  private logger: Logger;
  private correlationId: string;

  constructor(correlationId?: string) {
    this.logger = new Logger();
    this.correlationId = correlationId || this.generateCorrelationId();
  }

  /**
   * Handle and categorize errors
   */
  async handleError(
    error: Error,
    context: ErrorContext = {}
  ): Promise<ErrorDetails> {
    const enhancedContext = {
      ...context,
      correlationId: this.correlationId,
      timestamp: Date.now()
    };

    let errorDetails: ErrorDetails;

    // Categorize error based on type
    if (error instanceof ValidationError) {
      errorDetails = {
        code: 'VALIDATION_FAILED',
        message: error.message,
        category: ErrorCategory.VALIDATION,
        severity: ErrorSeverity.LOW,
        context: enhancedContext,
        recoverable: true,
        retryable: false,
        publicMessage: 'Invalid input provided. Please check your data and try again.'
      };
    } else if (error instanceof RateLimitError) {
      errorDetails = {
        code: 'RATE_LIMIT_EXCEEDED',
        message: error.message,
        category: ErrorCategory.RATE_LIMIT,
        severity: ErrorSeverity.MEDIUM,
        context: enhancedContext,
        recoverable: true,
        retryable: true,
        publicMessage: `Rate limit exceeded. Please try again in ${error.retryAfter} seconds.`
      };
    } else if (error instanceof AuthorizationError) {
      errorDetails = {
        code: 'AUTHORIZATION_FAILED',
        message: error.message,
        category: ErrorCategory.AUTHORIZATION,
        severity: ErrorSeverity.HIGH,
        context: { ...enhancedContext, action: error.action, resource: error.resource },
        recoverable: false,
        retryable: false,
        publicMessage: 'You do not have permission to perform this action.'
      };
    } else if (error instanceof BusinessLogicError) {
      errorDetails = {
        code: error.code,
        message: error.message,
        category: error.category,
        severity: error.severity,
        context: { ...enhancedContext, ...error.context },
        recoverable: error.recoverable,
        retryable: error.retryable,
        publicMessage: error.publicMessage || 'A business logic error occurred.'
      };
    } else if (error instanceof DatabaseTransactionError) {
      errorDetails = {
        code: 'DATABASE_TRANSACTION_FAILED',
        message: error.message,
        category: ErrorCategory.DATABASE,
        severity: ErrorSeverity.HIGH,
        context: { ...enhancedContext, operation: error.operation },
        recoverable: false,
        retryable: true,
        publicMessage: 'A database error occurred. Please try again.'
      };
    } else if (this.isDatabaseError(error)) {
      errorDetails = {
        code: 'DATABASE_ERROR',
        message: error.message,
        category: ErrorCategory.DATABASE,
        severity: ErrorSeverity.HIGH,
        context: enhancedContext,
        recoverable: false,
        retryable: true,
        publicMessage: 'A database error occurred. Please try again.'
      };
    } else {
      // Unknown/system error - check if it's temporary or permanent
      const isTemporary = this.isTemporaryError(error);
      const isPermanent = this.isPermanentError(error);

      // For severity: unknown errors are CRITICAL, temporary are MEDIUM
      // For retryability: unknown errors are retryable unless explicitly permanent
      const severity = isTemporary ? ErrorSeverity.MEDIUM : ErrorSeverity.CRITICAL;
      const retryable = !isPermanent; // Generic errors are retryable unless permanent

      errorDetails = {
        code: isTemporary ? 'TEMPORARY_ERROR' : 'SYSTEM_ERROR',
        message: error.message,
        category: ErrorCategory.SYSTEM,
        severity,
        context: enhancedContext,
        recoverable: retryable,
        retryable,
        publicMessage: isTemporary
          ? 'A temporary error occurred. Please try again.'
          : 'An unexpected error occurred. Please try again.'
      };
    }

    // Log error with appropriate level
    await this.logError(errorDetails, error);

    return errorDetails;
  }

  /**
   * Execute operation with comprehensive error handling and transaction rollback
   */
  async executeWithErrorHandling<T>(
    operation: () => Promise<T>,
    context: ErrorContext,
    transactionDb?: D1Database
  ): Promise<T> {
    let transactionStarted = false;

    try {
      // Start transaction if database provided
      if (transactionDb) {
        await transactionDb.prepare('BEGIN TRANSACTION').run();
        transactionStarted = true;
      }

      // Execute operation
      const result = await operation();

      // Commit transaction if started
      if (transactionStarted && transactionDb) {
        await transactionDb.prepare('COMMIT').run();
      }

      return result;

    } catch (error) {
      // Rollback transaction if started
      if (transactionStarted && transactionDb) {
        try {
          await transactionDb.prepare('ROLLBACK').run();
          this.logger.info('Transaction rolled back successfully', {
            correlationId: this.correlationId,
            operation: context.operation
          });
        } catch (rollbackError) {
          this.logger.error('Transaction rollback failed', rollbackError, {
            correlationId: this.correlationId,
            operation: context.operation
          });
        }
      }

      // Handle and re-throw error
      const errorDetails = await this.handleError(error as Error, context);

      // Create appropriate error to throw
      if (errorDetails.category === ErrorCategory.VALIDATION) {
        throw new ValidationError(errorDetails.publicMessage || errorDetails.message);
      } else if (errorDetails.category === ErrorCategory.RATE_LIMIT) {
        const rateLimitError = error as RateLimitError;
        throw new RateLimitError(
          errorDetails.publicMessage || errorDetails.message,
          rateLimitError.retryAfter,
          rateLimitError.resetTime
        );
      } else if (errorDetails.category === ErrorCategory.AUTHORIZATION) {
        const authError = error as AuthorizationError;
        throw new AuthorizationError(
          errorDetails.publicMessage || errorDetails.message,
          authError.action,
          authError.resource,
          context
        );
      } else {
        throw new BusinessLogicError(
          errorDetails.code,
          errorDetails.message,
          context,
          {
            category: errorDetails.category,
            severity: errorDetails.severity,
            recoverable: errorDetails.recoverable,
            retryable: errorDetails.retryable,
            publicMessage: errorDetails.publicMessage
          }
        );
      }
    }
  }

  /**
   * Retry operation with exponential backoff
   */
  async retryOperation<T>(
    operation: () => Promise<T>,
    context: ErrorContext,
    maxRetries: number = 3,
    baseDelayMs: number = 1000
  ): Promise<T> {
    let lastError: Error;

    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        return await operation();
      } catch (error) {
        lastError = error as Error;

        const errorDetails = await this.handleError(lastError, {
          ...context,
          attempt
        });

        // Don't retry if not retryable
        if (!errorDetails.retryable) {
          throw error;
        }

        // Don't retry on last attempt
        if (attempt === maxRetries) {
          break;
        }

        // Calculate delay with exponential backoff
        const delay = baseDelayMs * Math.pow(2, attempt - 1);

        this.logger.warn(`Operation failed, retrying in ${delay}ms`, {
          correlationId: this.correlationId,
          attempt,
          maxRetries,
          error: errorDetails.code
        });

        // Wait before retry
        await this.sleep(delay);
      }
    }

    throw lastError!;
  }

  /**
   * Log error with appropriate level and context
   */
  private async logError(errorDetails: ErrorDetails, originalError: Error): Promise<void> {
    const logData = {
      correlationId: this.correlationId,
      errorCode: errorDetails.code,
      category: errorDetails.category,
      severity: errorDetails.severity,
      context: errorDetails.context,
      stack: originalError.stack
    };

    switch (errorDetails.severity) {
      case ErrorSeverity.CRITICAL:
        this.logger.error('CRITICAL ERROR', originalError, logData);
        break;
      case ErrorSeverity.HIGH:
        this.logger.error('High severity error', originalError, logData);
        break;
      case ErrorSeverity.MEDIUM:
        this.logger.warn('Medium severity error', logData);
        break;
      case ErrorSeverity.LOW:
        this.logger.info('Low severity error', logData);
        break;
    }
  }

  /**
   * Check if error is database-related
   */
  private isDatabaseError(error: Error): boolean {
    const dbErrorMessages = [
      'SQLITE_',
      'database',
      'constraint',
      'foreign key',
      'unique constraint',
      'not null constraint',
      'check constraint'
    ];

    return dbErrorMessages.some(msg =>
      error.message.toLowerCase().includes(msg.toLowerCase())
    );
  }

  /**
   * Check if error is temporary/retryable
   */
  private isTemporaryError(error: Error): boolean {
    const temporaryErrorMessages = [
      'temporary',
      'timeout',
      'unavailable',
      'connection reset',
      'connection refused',
      'network error',
      'too many requests',
      'service unavailable',
      '503',
      '504',
      'gateway timeout'
    ];

    return temporaryErrorMessages.some(msg =>
      error.message.toLowerCase().includes(msg.toLowerCase())
    );
  }

  /**
   * Check if error is permanent (non-retryable)
   */
  private isPermanentError(error: Error): boolean {
    const permanentErrorMessages = [
      'invalid',
      'not found',
      'forbidden',
      'unauthorized',
      'bad request',
      'malformed',
      'corrupt',
      'fatal'
    ];

    return permanentErrorMessages.some(msg =>
      error.message.toLowerCase().includes(msg.toLowerCase())
    );
  }

  /**
   * Generate correlation ID for request tracking
   */
  private generateCorrelationId(): string {
    return `corr_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;
  }

  /**
   * Sleep utility for retry delays
   */
  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

/**
 * Global error handler instance factory
 */
export function createErrorHandler(correlationId?: string): ErrorHandler {
  return new ErrorHandler(correlationId);
}

/**
 * Error handler middleware for consistent error processing
 */
export function withErrorHandling<T extends any[], R>(
  fn: (...args: T) => Promise<R>,
  context: ErrorContext = {}
): (...args: T) => Promise<R> {
  return async (...args: T): Promise<R> => {
    const errorHandler = createErrorHandler();
    return errorHandler.executeWithErrorHandling(
      () => fn(...args),
      context
    );
  };
}

/**
 * Decorator for automatic error handling
 */
export function HandleErrors(context: ErrorContext = {}) {
  return function (
    target: any,
    propertyName: string,
    descriptor: PropertyDescriptor
  ) {
    const method = descriptor.value;

    descriptor.value = async function (...args: any[]) {
      const errorHandler = createErrorHandler();
      return errorHandler.executeWithErrorHandling(
        () => method.apply(this, args),
        {
          ...context,
          operation: `${target.constructor.name}.${propertyName}`,
          businessId: args[args.length - 1], // Assume last arg is businessId
          userId: args[args.length - 2] // Assume second to last is userId
        }
      );
    };

    return descriptor;
  };
}