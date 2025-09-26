/**
 * Comprehensive Error Handling System
 * Provides structured error handling, retry logic, and error categorization
 */

import { Logger } from './logger';

export enum ErrorCategory {
  VALIDATION = 'validation',
  AUTHENTICATION = 'authentication',
  AUTHORIZATION = 'authorization',
  NOT_FOUND = 'not_found',
  BUSINESS_LOGIC = 'business_logic',
  EXTERNAL_SERVICE = 'external_service',
  DATABASE = 'database',
  NETWORK = 'network',
  RATE_LIMIT = 'rate_limit',
  TIMEOUT = 'timeout',
  SYSTEM = 'system',
  UNKNOWN = 'unknown'
}

export enum ErrorSeverity {
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  CRITICAL = 'critical'
}

export interface ErrorContext {
  businessId?: string;
  userId?: string;
  correlationId?: string;
  operation?: string;
  resource?: string;
  service?: string;
  metadata?: Record<string, any>;
}

export interface ErrorDetails {
  category: ErrorCategory;
  severity: ErrorSeverity;
  code: string;
  message: string;
  context?: ErrorContext;
  originalError?: Error;
  timestamp: Date;
  retryable: boolean;
  userMessage?: string;
}

export class ApplicationError extends Error {
  public readonly category: ErrorCategory;
  public readonly severity: ErrorSeverity;
  public readonly code: string;
  public readonly context?: ErrorContext;
  public readonly originalError?: Error;
  public readonly timestamp: Date;
  public readonly retryable: boolean;
  public readonly userMessage?: string;

  constructor(details: Omit<ErrorDetails, 'timestamp'>) {
    super(details.message);
    this.name = 'ApplicationError';
    this.category = details.category;
    this.severity = details.severity;
    this.code = details.code;
    this.context = details.context;
    this.originalError = details.originalError;
    this.timestamp = new Date();
    this.retryable = details.retryable;
    this.userMessage = details.userMessage;

    // Maintain stack trace
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, ApplicationError);
    }
  }

  toJSON(): Record<string, any> {
    return {
      name: this.name,
      message: this.message,
      category: this.category,
      severity: this.severity,
      code: this.code,
      context: this.context,
      timestamp: this.timestamp.toISOString(),
      retryable: this.retryable,
      userMessage: this.userMessage,
      stack: this.stack
    };
  }
}

export interface RetryOptions {
  maxAttempts: number;
  baseDelay: number;
  maxDelay: number;
  exponentialBase: number;
  jitter: boolean;
  retryCondition?: (error: Error) => boolean;
}

export class ErrorHandler {
  private logger: Logger;

  constructor() {
    this.logger = new Logger();
  }

  /**
   * Create a standardized application error
   */
  createError(
    category: ErrorCategory,
    code: string,
    message: string,
    options: {
      severity?: ErrorSeverity;
      context?: ErrorContext;
      originalError?: Error;
      retryable?: boolean;
      userMessage?: string;
    } = {}
  ): ApplicationError {
    const {
      severity = ErrorSeverity.MEDIUM,
      context,
      originalError,
      retryable = false,
      userMessage
    } = options;

    return new ApplicationError({
      category,
      severity,
      code,
      message,
      context,
      originalError,
      retryable,
      userMessage
    });
  }

  /**
   * Wrap an unknown error into a standardized format
   */
  wrapError(error: unknown, context?: ErrorContext): ApplicationError {
    if (error instanceof ApplicationError) {
      return error;
    }

    let category = ErrorCategory.UNKNOWN;
    let code = 'UNKNOWN_ERROR';
    let message = 'An unknown error occurred';
    let retryable = false;

    if (error instanceof Error) {
      message = error.message;

      // Categorize based on error message/type
      category = this.categorizeError(error);
      code = this.generateErrorCode(category, error);
      retryable = this.isRetryable(error);
    }

    return new ApplicationError({
      category,
      severity: ErrorSeverity.MEDIUM,
      code,
      message,
      context,
      originalError: error instanceof Error ? error : undefined,
      retryable
    });
  }

  /**
   * Execute operation with retry logic
   */
  async withRetry<T>(
    operation: () => Promise<T>,
    options: Partial<RetryOptions> = {}
  ): Promise<T> {
    const config: RetryOptions = {
      maxAttempts: 3,
      baseDelay: 1000,
      maxDelay: 30000,
      exponentialBase: 2,
      jitter: true,
      retryCondition: (error) => this.isRetryable(error),
      ...options
    };

    let lastError: Error;

    for (let attempt = 1; attempt <= config.maxAttempts; attempt++) {
      try {
        return await operation();
      } catch (error) {
        lastError = error as Error;

        // Check if we should retry
        if (attempt === config.maxAttempts || !config.retryCondition!(lastError)) {
          break;
        }

        // Calculate delay with exponential backoff
        const baseDelay = config.baseDelay * Math.pow(config.exponentialBase, attempt - 1);
        let delay = Math.min(baseDelay, config.maxDelay);

        // Add jitter to prevent thundering herd
        if (config.jitter) {
          delay = delay * (0.5 + Math.random() * 0.5);
        }

        this.logger.debug('Retrying operation after failure', {
          attempt,
          maxAttempts: config.maxAttempts,
          delay,
          error: lastError.message
        });

        await new Promise(resolve => setTimeout(resolve, delay));
      }
    }

    throw this.wrapError(lastError!);
  }

  /**
   * Execute operation with error boundary
   */
  async withErrorBoundary<T>(
    operation: () => Promise<T>,
    context?: ErrorContext,
    fallback?: () => Promise<T>
  ): Promise<T> {
    try {
      return await operation();
    } catch (error) {
      const wrappedError = this.wrapError(error, context);

      this.logger.error('Operation failed in error boundary', wrappedError.toJSON());

      if (fallback) {
        try {
          this.logger.debug('Executing fallback operation');
          return await fallback();
        } catch (fallbackError) {
          this.logger.error('Fallback operation also failed', {
            originalError: wrappedError.toJSON(),
            fallbackError: this.wrapError(fallbackError, context).toJSON()
          });
          throw wrappedError; // Throw original error
        }
      }

      throw wrappedError;
    }
  }

  /**
   * Log error with appropriate level
   */
  logError(error: ApplicationError | Error, additionalContext?: Record<string, any>): void {
    const errorData = error instanceof ApplicationError
      ? { ...error.toJSON(), ...additionalContext }
      : {
          message: error.message,
          stack: error.stack,
          ...additionalContext
        };

    if (error instanceof ApplicationError) {
      switch (error.severity) {
        case ErrorSeverity.CRITICAL:
          this.logger.error('CRITICAL ERROR', errorData);
          break;
        case ErrorSeverity.HIGH:
          this.logger.error('High severity error', errorData);
          break;
        case ErrorSeverity.MEDIUM:
          this.logger.warn('Medium severity error', errorData);
          break;
        case ErrorSeverity.LOW:
          this.logger.debug('Low severity error', errorData);
          break;
      }
    } else {
      this.logger.error('Unhandled error', errorData);
    }
  }

  /**
   * Create HTTP response from error
   */
  createErrorResponse(error: ApplicationError | Error): {
    status: number;
    body: Record<string, any>;
  } {
    if (error instanceof ApplicationError) {
      const statusCode = this.getHttpStatusCode(error.category);

      return {
        status: statusCode,
        body: {
          success: false,
          error: {
            code: error.code,
            message: error.userMessage || error.message,
            category: error.category,
            retryable: error.retryable,
            timestamp: error.timestamp.toISOString()
          }
        }
      };
    }

    return {
      status: 500,
      body: {
        success: false,
        error: {
          code: 'INTERNAL_ERROR',
          message: 'An internal error occurred',
          category: ErrorCategory.SYSTEM,
          retryable: false,
          timestamp: new Date().toISOString()
        }
      }
    };
  }

  private categorizeError(error: Error): ErrorCategory {
    const message = error.message.toLowerCase();

    if (message.includes('validation') || message.includes('invalid')) {
      return ErrorCategory.VALIDATION;
    }
    if (message.includes('unauthorized') || message.includes('authentication')) {
      return ErrorCategory.AUTHENTICATION;
    }
    if (message.includes('forbidden') || message.includes('permission')) {
      return ErrorCategory.AUTHORIZATION;
    }
    if (message.includes('not found') || message.includes('404')) {
      return ErrorCategory.NOT_FOUND;
    }
    if (message.includes('timeout') || message.includes('timed out')) {
      return ErrorCategory.TIMEOUT;
    }
    if (message.includes('rate limit') || message.includes('too many requests')) {
      return ErrorCategory.RATE_LIMIT;
    }
    if (message.includes('network') || message.includes('connection')) {
      return ErrorCategory.NETWORK;
    }
    if (message.includes('database') || message.includes('sql')) {
      return ErrorCategory.DATABASE;
    }
    if (message.includes('external') || message.includes('api')) {
      return ErrorCategory.EXTERNAL_SERVICE;
    }

    return ErrorCategory.UNKNOWN;
  }

  private generateErrorCode(category: ErrorCategory, error: Error): string {
    const prefix = category.toUpperCase();

    // Generate a simple hash of the error message for consistency
    let hash = 0;
    for (let i = 0; i < error.message.length; i++) {
      const char = error.message.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32-bit integer
    }

    const suffix = Math.abs(hash).toString(16).slice(0, 4).toUpperCase();
    return `${prefix}_${suffix}`;
  }

  private isRetryable(error: Error): boolean {
    const message = error.message.toLowerCase();

    // Network and timeout errors are typically retryable
    if (message.includes('timeout') ||
        message.includes('network') ||
        message.includes('connection') ||
        message.includes('econnreset') ||
        message.includes('enotfound')) {
      return true;
    }

    // Rate limiting might be retryable after delay
    if (message.includes('rate limit') || message.includes('429')) {
      return true;
    }

    // Server errors (5xx) are often retryable
    if (message.includes('500') ||
        message.includes('502') ||
        message.includes('503') ||
        message.includes('504')) {
      return true;
    }

    return false;
  }

  private getHttpStatusCode(category: ErrorCategory): number {
    switch (category) {
      case ErrorCategory.VALIDATION:
        return 400;
      case ErrorCategory.AUTHENTICATION:
        return 401;
      case ErrorCategory.AUTHORIZATION:
        return 403;
      case ErrorCategory.NOT_FOUND:
        return 404;
      case ErrorCategory.RATE_LIMIT:
        return 429;
      case ErrorCategory.BUSINESS_LOGIC:
        return 422;
      case ErrorCategory.EXTERNAL_SERVICE:
      case ErrorCategory.DATABASE:
      case ErrorCategory.SYSTEM:
        return 500;
      case ErrorCategory.NETWORK:
      case ErrorCategory.TIMEOUT:
        return 503;
      default:
        return 500;
    }
  }
}

// Global error handler instance
export const errorHandler = new ErrorHandler();

// Pre-configured error factories
export const ErrorFactories = {
  validation: (message: string, context?: ErrorContext) =>
    errorHandler.createError(ErrorCategory.VALIDATION, 'VALIDATION_FAILED', message, {
      severity: ErrorSeverity.LOW,
      context,
      userMessage: 'Please check your input and try again'
    }),

  unauthorized: (message: string, context?: ErrorContext) =>
    errorHandler.createError(ErrorCategory.AUTHENTICATION, 'UNAUTHORIZED', message, {
      severity: ErrorSeverity.MEDIUM,
      context,
      userMessage: 'Authentication required'
    }),

  forbidden: (message: string, context?: ErrorContext) =>
    errorHandler.createError(ErrorCategory.AUTHORIZATION, 'FORBIDDEN', message, {
      severity: ErrorSeverity.MEDIUM,
      context,
      userMessage: 'You do not have permission to perform this action'
    }),

  notFound: (resource: string, context?: ErrorContext) =>
    errorHandler.createError(ErrorCategory.NOT_FOUND, 'NOT_FOUND', `${resource} not found`, {
      severity: ErrorSeverity.LOW,
      context: { ...context, resource },
      userMessage: `The requested ${resource.toLowerCase()} was not found`
    }),

  businessLogic: (message: string, context?: ErrorContext) =>
    errorHandler.createError(ErrorCategory.BUSINESS_LOGIC, 'BUSINESS_RULE_VIOLATION', message, {
      severity: ErrorSeverity.MEDIUM,
      context,
      userMessage: message
    }),

  externalService: (service: string, message: string, context?: ErrorContext) =>
    errorHandler.createError(ErrorCategory.EXTERNAL_SERVICE, 'EXTERNAL_SERVICE_ERROR', message, {
      severity: ErrorSeverity.HIGH,
      context: { ...context, service },
      retryable: true,
      userMessage: 'A temporary service issue occurred. Please try again later'
    }),

  database: (message: string, context?: ErrorContext) =>
    errorHandler.createError(ErrorCategory.DATABASE, 'DATABASE_ERROR', message, {
      severity: ErrorSeverity.HIGH,
      context,
      retryable: true,
      userMessage: 'A database error occurred. Please try again'
    }),

  rateLimit: (context?: ErrorContext) =>
    errorHandler.createError(ErrorCategory.RATE_LIMIT, 'RATE_LIMIT_EXCEEDED', 'Rate limit exceeded', {
      severity: ErrorSeverity.MEDIUM,
      context,
      retryable: true,
      userMessage: 'Too many requests. Please wait and try again'
    })
};