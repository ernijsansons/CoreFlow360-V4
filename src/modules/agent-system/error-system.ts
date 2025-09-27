/**
 * Enhanced Error System
 * Provides error classification, recovery strategies, and context enrichment
 */

import { Logger } from '../../shared/logger';
import type { D1Database } from '@cloudflare/workers-types';

export enum ErrorCategory {
  VALIDATION = 'VALIDATION',
  AUTHENTICATION = 'AUTHENTICATION',
  AUTHORIZATION = 'AUTHORIZATION',
  RATE_LIMIT = 'RATE_LIMIT',
  RESOURCE_NOT_FOUND = 'RESOURCE_NOT_FOUND',
  CONFLICT = 'CONFLICT',
  BUSINESS_LOGIC = 'BUSINESS_LOGIC',
  EXTERNAL_SERVICE = 'EXTERNAL_SERVICE',
  DATABASE = 'DATABASE',
  NETWORK = 'NETWORK',
  TIMEOUT = 'TIMEOUT',
  INTERNAL = 'INTERNAL',
  CONFIGURATION = 'CONFIGURATION'
}

export enum ErrorSeverity {
  LOW = 'LOW',
  MEDIUM = 'MEDIUM',
  HIGH = 'HIGH',
  CRITICAL = 'CRITICAL'
}

export enum RecoveryStrategy {
  NONE = 'NONE',
  RETRY = 'RETRY',
  RETRY_WITH_BACKOFF = 'RETRY_WITH_BACKOFF',
  FALLBACK = 'FALLBACK',
  CIRCUIT_BREAK = 'CIRCUIT_BREAK',
  COMPENSATE = 'COMPENSATE',
  IGNORE = 'IGNORE',
  ESCALATE = 'ESCALATE'
}

export interface ErrorContext {
  businessId?: string;
  userId?: string;
  taskId?: string;
  agentId?: string;
  capability?: string;
  department?: string;
  traceId?: string;
  spanId?: string;
  timestamp: number;
  environment?: string;
  version?: string;
  metadata?: Record<string, any>;
}

export interface ErrorRecoveryOptions {
  strategy: RecoveryStrategy;
  maxRetries?: number;
  retryDelay?: number;
  fallbackValue?: any;
  compensationAction?: () => Promise<void>;
  escalationTarget?: string;
}

export interface EnhancedError {
  id: string;
  code: string;
  message: string;
  category: ErrorCategory;
  severity: ErrorSeverity;
  context: ErrorContext;
  recovery: ErrorRecoveryOptions;
  originalError?: Error;
  stack?: string;
  cause?: EnhancedError;
  isRetryable: boolean;
  isUserFacing: boolean;
  userMessage?: string;
  documentation?: string;
}

export interface ErrorMetrics {
  totalErrors: number;
  errorsByCategory: Record<ErrorCategory, number>;
  errorsBySeverity: Record<ErrorSeverity, number>;
  errorRate: number;
  recoverySuccessRate: number;
}

export class ErrorSystem {
  private logger: Logger;
  private db?: D1Database;
  private errorHandlers = new Map<ErrorCategory, ErrorHandler>();
  private errorMetrics: ErrorMetrics = this.initializeMetrics();
  private errorBuffer: EnhancedError[] = [];
  private metricsInterval?: NodeJS.Timeout;

  constructor(db?: D1Database) {
    this.logger = new Logger();
    this.db = db;
    this.registerDefaultHandlers();
    this.startMetricsCollection();
  }

  /**
   * Create an enhanced error
   */
  createError(
    code: string,
    message: string,
    category: ErrorCategory,
    options: {
      severity?: ErrorSeverity;
      context?: Partial<ErrorContext>;
      recovery?: ErrorRecoveryOptions;
      originalError?: Error;
      cause?: EnhancedError;
      isRetryable?: boolean;
      isUserFacing?: boolean;
      userMessage?: string;
      documentation?: string;
    } = {}
  ): EnhancedError {
    const error: EnhancedError = {
      id: this.generateErrorId(),
      code,
      message,
      category,
      severity: options.severity || this.determineSeverity(category),
      context: {
        timestamp: Date.now(),
        ...options.context
      },
      recovery: options.recovery || this.getDefaultRecovery(category),
      originalError: options.originalError,
      stack: options.originalError?.stack || new Error().stack,
      cause: options.cause,
      isRetryable: options.isRetryable ?? this.isRetryableCategory(category),
      isUserFacing: options.isUserFacing ?? false,
      userMessage: options.userMessage || this.generateUserMessage(category, code),
      documentation: options.documentation || this.getErrorDocumentation(code)
    };

    this.recordError(error);
    return error;
  }

  /**
   * Handle an error with recovery
   */
  async handleError<T>(
    error: Error | EnhancedError,
    fallback?: T
  ): Promise<T | undefined> {
    const enhancedError = this.isEnhancedError(error)
      ? error
      : this.classifyError(error);

    this.logger.error('Handling error', enhancedError);

    const handler = this.errorHandlers.get(enhancedError.category);
    if (handler) {
      return await handler.handle(enhancedError, fallback);
    }

    return this.executeRecovery(enhancedError, fallback);
  }

  /**
   * Classify a standard error
   */
  classifyError(error: Error): EnhancedError {
    // Analyze error message and type
    const category = this.detectErrorCategory(error);
    const code = this.generateErrorCode(category, error);

    return this.createError(code, error.message, category, {
      originalError: error,
      severity: this.detectErrorSeverity(error),
      isRetryable: this.detectRetryability(error),
      isUserFacing: false
    });
  }

  /**
   * Execute recovery strategy
   */
  private async executeRecovery<T>(
    error: EnhancedError,
    fallback?: T
  ): Promise<T | undefined> {
    const { recovery } = error;

    switch (recovery.strategy) {
      case RecoveryStrategy.RETRY:
        if (error.isRetryable) {
          return await this.retryOperation(error, recovery);
        }
        break;

      case RecoveryStrategy.RETRY_WITH_BACKOFF:
        if (error.isRetryable) {
          return await this.retryWithBackoff(error, recovery);
        }
        break;

      case RecoveryStrategy.FALLBACK:
        return recovery.fallbackValue ?? fallback;

      case RecoveryStrategy.COMPENSATE:
        if (recovery.compensationAction) {
          await recovery.compensationAction();
        }
        break;

      case RecoveryStrategy.CIRCUIT_BREAK:
        this.activateCircuitBreaker(error);
        break;

      case RecoveryStrategy.ESCALATE:
        await this.escalateError(error, recovery.escalationTarget);
        break;

      case RecoveryStrategy.IGNORE:
        this.logger.warn('Ignoring error', { errorId: error.id });
        return fallback;
    }

    throw error;
  }

  /**
   * Retry operation
   */
  private async retryOperation<T>(
    error: EnhancedError,
    recovery: ErrorRecoveryOptions
  ): Promise<T | undefined> {
    const maxRetries = recovery.maxRetries || 3;
    const delay = recovery.retryDelay || 1000;

    for (let i = 0; i < maxRetries; i++) {
      this.logger.info(`Retrying operation (attempt ${i + 1}/${maxRetries})`, {
        errorId: error.id
      });

      await new Promise(resolve => setTimeout(resolve, delay));

      // In a real implementation, you would retry the original operation
      // For now, we'll throw to indicate retry failed
    }

    throw error;
  }

  /**
   * Retry with exponential backoff
   */
  private async retryWithBackoff<T>(
    error: EnhancedError,
    recovery: ErrorRecoveryOptions
  ): Promise<T | undefined> {
    const maxRetries = recovery.maxRetries || 3;
    const baseDelay = recovery.retryDelay || 1000;

    for (let i = 0; i < maxRetries; i++) {
      const delay = baseDelay * Math.pow(2, i);

      this.logger.info(`Retrying with backoff (attempt ${i + 1}/${maxRetries}, delay: ${delay}ms)`, {
        errorId: error.id
      });

      await new Promise(resolve => setTimeout(resolve, delay));

      // In a real implementation, you would retry the original operation
    }

    throw error;
  }

  /**
   * Activate circuit breaker
   */
  private activateCircuitBreaker(error: EnhancedError): void {
    this.logger.warn('Circuit breaker activated', {
      errorId: error.id,
      category: error.category
    });

    // In a real implementation, you would track circuit breaker state
  }

  /**
   * Escalate error
   */
  private async escalateError(error: EnhancedError, target?: string): Promise<void> {
    this.logger.error('Escalating error', {
      errorId: error.id,
      target: target || 'operations'
    });

    // In a real implementation, you would send notifications
    if (this.db) {
      await this.db.prepare(`
        INSERT INTO error_escalations (
          error_id, error_code, category, severity,
          message, context, escalated_to, escalated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(
        error.id,
        error.code,
        error.category,
        error.severity,
        error.message,
        JSON.stringify(error.context),
        target || 'operations',
        Date.now()
      ).run();
    }
  }

  /**
   * Detect error category from error
   */
  private detectErrorCategory(error: Error): ErrorCategory {
    const message = error.message.toLowerCase();

    if (message.includes('validation') || message.includes('invalid')) {
      return ErrorCategory.VALIDATION;
    }
    if (message.includes('unauthorized') || message.includes('auth')) {
      return ErrorCategory.AUTHENTICATION;
    }
    if (message.includes('forbidden') || message.includes('permission')) {
      return ErrorCategory.AUTHORIZATION;
    }
    if (message.includes('rate') || message.includes('limit')) {
      return ErrorCategory.RATE_LIMIT;
    }
    if (message.includes('not found') || message.includes('404')) {
      return ErrorCategory.RESOURCE_NOT_FOUND;
    }
    if (message.includes('conflict') || message.includes('duplicate')) {
      return ErrorCategory.CONFLICT;
    }
    if (message.includes('timeout')) {
      return ErrorCategory.TIMEOUT;
    }
    if (message.includes('network') || message.includes('connection')) {
      return ErrorCategory.NETWORK;
    }
    if (message.includes('database') || message.includes('sql')) {
      return ErrorCategory.DATABASE;
    }

    return ErrorCategory.INTERNAL;
  }

  /**
   * Detect error severity
   */
  private detectErrorSeverity(error: Error): ErrorSeverity {
    const message = error.message.toLowerCase();

    if (message.includes('critical') || message.includes('fatal')) {
      return ErrorSeverity.CRITICAL;
    }
    if (message.includes('error') || message.includes('failed')) {
      return ErrorSeverity.HIGH;
    }
    if (message.includes('warning') || message.includes('retry')) {
      return ErrorSeverity.MEDIUM;
    }

    return ErrorSeverity.LOW;
  }

  /**
   * Detect if error is retryable
   */
  private detectRetryability(error: Error): boolean {
    const message = error.message.toLowerCase();
    const retryablePatterns = [
      'timeout',
      'network',
      'connection',
      'rate limit',
      'temporary',
      'try again'
    ];

    return retryablePatterns.some(pattern => message.includes(pattern));
  }

  /**
   * Determine severity by category
   */
  private determineSeverity(category: ErrorCategory): ErrorSeverity {
    const severityMap: Record<ErrorCategory, ErrorSeverity> = {
      [ErrorCategory.VALIDATION]: ErrorSeverity.LOW,
      [ErrorCategory.AUTHENTICATION]: ErrorSeverity.HIGH,
      [ErrorCategory.AUTHORIZATION]: ErrorSeverity.MEDIUM,
      [ErrorCategory.RATE_LIMIT]: ErrorSeverity.LOW,
      [ErrorCategory.RESOURCE_NOT_FOUND]: ErrorSeverity.LOW,
      [ErrorCategory.CONFLICT]: ErrorSeverity.MEDIUM,
      [ErrorCategory.BUSINESS_LOGIC]: ErrorSeverity.MEDIUM,
      [ErrorCategory.EXTERNAL_SERVICE]: ErrorSeverity.MEDIUM,
      [ErrorCategory.DATABASE]: ErrorSeverity.HIGH,
      [ErrorCategory.NETWORK]: ErrorSeverity.MEDIUM,
      [ErrorCategory.TIMEOUT]: ErrorSeverity.MEDIUM,
      [ErrorCategory.INTERNAL]: ErrorSeverity.CRITICAL,
      [ErrorCategory.CONFIGURATION]: ErrorSeverity.HIGH
    };

    return severityMap[category] || ErrorSeverity.MEDIUM;
  }

  /**
   * Get default recovery strategy
   */
  private getDefaultRecovery(category: ErrorCategory): ErrorRecoveryOptions {
    const recoveryMap: Record<ErrorCategory, ErrorRecoveryOptions> = {
      [ErrorCategory.VALIDATION]: { strategy: RecoveryStrategy.NONE },
      [ErrorCategory.AUTHENTICATION]: { strategy: RecoveryStrategy.NONE },
      [ErrorCategory.AUTHORIZATION]: { strategy: RecoveryStrategy.NONE },
      [ErrorCategory.RATE_LIMIT]: {
        strategy: RecoveryStrategy.RETRY_WITH_BACKOFF,
        maxRetries: 3,
        retryDelay: 5000
      },
      [ErrorCategory.RESOURCE_NOT_FOUND]: { strategy: RecoveryStrategy.NONE },
      [ErrorCategory.CONFLICT]: { strategy: RecoveryStrategy.RETRY, maxRetries: 2 },
      [ErrorCategory.BUSINESS_LOGIC]: { strategy: RecoveryStrategy.NONE },
      [ErrorCategory.EXTERNAL_SERVICE]: {
        strategy: RecoveryStrategy.CIRCUIT_BREAK,
        maxRetries: 3
      },
      [ErrorCategory.DATABASE]: { strategy: RecoveryStrategy.RETRY, maxRetries: 2 },
      [ErrorCategory.NETWORK]: {
        strategy: RecoveryStrategy.RETRY_WITH_BACKOFF,
        maxRetries: 3
      },
      [ErrorCategory.TIMEOUT]: { strategy: RecoveryStrategy.RETRY, maxRetries: 1 },
      [ErrorCategory.INTERNAL]: { strategy: RecoveryStrategy.ESCALATE },
      [ErrorCategory.CONFIGURATION]: { strategy: RecoveryStrategy.ESCALATE }
    };

    return recoveryMap[category] || { strategy: RecoveryStrategy.NONE };
  }

  /**
   * Check if category is retryable
   */
  private isRetryableCategory(category: ErrorCategory): boolean {
    const retryableCategories = [
      ErrorCategory.RATE_LIMIT,
      ErrorCategory.CONFLICT,
      ErrorCategory.EXTERNAL_SERVICE,
      ErrorCategory.DATABASE,
      ErrorCategory.NETWORK,
      ErrorCategory.TIMEOUT
    ];

    return retryableCategories.includes(category);
  }

  /**
   * Generate user-friendly message
   */
  private generateUserMessage(category: ErrorCategory, code: string): string {
    const messageMap: Record<ErrorCategory, string> = {
      [ErrorCategory.VALIDATION]: 'Please check your input and try again.',
      [ErrorCategory.AUTHENTICATION]: 'Please sign in to continue.',
      [ErrorCategory.AUTHORIZATION]: 'You do not have permission to perform this action.',
      [ErrorCategory.RATE_LIMIT]: 'Too many requests. Please try again later.',
      [ErrorCategory.RESOURCE_NOT_FOUND]: 'The requested resource was not found.',
      [ErrorCategory.CONFLICT]: 'A conflict occurred. Please refresh and try again.',
      [ErrorCategory.BUSINESS_LOGIC]: 'Unable to process your request.',
      [ErrorCategory.EXTERNAL_SERVICE]: 'An external service is temporarily unavailable.',
      [ErrorCategory.DATABASE]: 'A database error occurred. Please try again.',
      [ErrorCategory.NETWORK]: 'Network connection error. Please check your connection.',
      [ErrorCategory.TIMEOUT]: 'The request timed out. Please try again.',
      [ErrorCategory.INTERNAL]: 'An unexpected error occurred. Please contact support.',
      [ErrorCategory.CONFIGURATION]: 'System configuration error. Please contact support.'
    };

    return messageMap[category] || 'An error occurred. Please try again.';
  }

  /**
   * Get error documentation link
   */
  private getErrorDocumentation(code: string): string {
    return `https://docs.coreflow360.com/errors/${code}`;
  }

  /**
   * Generate error code
   */
  private generateErrorCode(category: ErrorCategory, error: Error): string {
    const categoryPrefix = category.substring(0, 3).toUpperCase();
    const hash = this.hashCode(error.message);
    return `${categoryPrefix}-${Math.abs(hash).toString().substring(0, 6)}`;
  }

  /**
   * Generate error ID
   */
  private generateErrorId(): string {
    return `err_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;
  }

  /**
   * Hash code for string
   */
  private hashCode(str: string): number {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash;
    }
    return hash;
  }

  /**
   * Check if error is enhanced
   */
  private isEnhancedError(error: any): error is EnhancedError {
    return error && typeof error === 'object' && 'category' in error && 'recovery' in error;
  }

  /**
   * Record error for metrics
   */
  private recordError(error: EnhancedError): void {
    this.errorMetrics.totalErrors++;
    this.errorMetrics.errorsByCategory[error.category]++;
    this.errorMetrics.errorsBySeverity[error.severity]++;

    this.errorBuffer.push(error);

    if (this.errorBuffer.length >= 100) {
      this.flushErrorBuffer().catch(err => {
        this.logger.error('Failed to flush error buffer', err);
      });
    }
  }

  /**
   * Flush error buffer to database
   */
  private async flushErrorBuffer(): Promise<void> {
    if (!this.db || this.errorBuffer.length === 0) return;

    const errors = [...this.errorBuffer];
    this.errorBuffer = [];

    try {
      const batch = this.db.batch([]);

      for (const error of errors) {
        batch.push(
          this.db.prepare(`
            INSERT INTO error_logs (
              error_id, code, message, category, severity,
              context, stack, timestamp
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
          `).bind(
            error.id,
            error.code,
            error.message,
            error.category,
            error.severity,
            JSON.stringify(error.context),
            error.stack || '',
            error.context.timestamp
          )
        );
      }

      await this.db.batch(batch);

    } catch (error: any) {
      this.logger.error('Failed to persist errors', error);
      // Re-add to buffer
      this.errorBuffer.push(...errors);
    }
  }

  /**
   * Register error handler
   */
  registerHandler(category: ErrorCategory, handler: ErrorHandler): void {
    this.errorHandlers.set(category, handler);
  }

  /**
   * Register default handlers
   */
  private registerDefaultHandlers(): void {
    // Rate limit handler
    this.registerHandler(ErrorCategory.RATE_LIMIT, {
      handle: async (error, fallback) => {
        await new Promise(resolve => setTimeout(resolve, 5000));
        return fallback;
      }
    });

    // Network error handler
    this.registerHandler(ErrorCategory.NETWORK, {
      handle: async (error, fallback) => {
        this.logger.warn('Network error, using fallback', { errorId: error.id });
        return fallback;
      }
    });
  }

  /**
   * Initialize metrics
   */
  private initializeMetrics(): ErrorMetrics {
    const metrics: ErrorMetrics = {
      totalErrors: 0,
      errorsByCategory: {} as Record<ErrorCategory, number>,
      errorsBySeverity: {} as Record<ErrorSeverity, number>,
      errorRate: 0,
      recoverySuccessRate: 0
    };

    // Initialize category counts
    for (const category of Object.values(ErrorCategory)) {
      metrics.errorsByCategory[category as ErrorCategory] = 0;
    }

    // Initialize severity counts
    for (const severity of Object.values(ErrorSeverity)) {
      metrics.errorsBySeverity[severity as ErrorSeverity] = 0;
    }

    return metrics;
  }

  /**
   * Start metrics collection
   */
  private startMetricsCollection(): void {
    this.metricsInterval = setInterval(() => {
      this.calculateErrorRate();
    }, 60000) as any; // Calculate every minute
  }

  /**
   * Calculate error rate
   */
  private calculateErrorRate(): void {
    // Simple rate calculation - in production, use sliding window
    this.errorMetrics.errorRate = this.errorMetrics.totalErrors / 60; // Per minute
  }

  /**
   * Get error metrics
   */
  getMetrics(): ErrorMetrics {
    return { ...this.errorMetrics };
  }

  /**
   * Shutdown error system
   */
  async shutdown(): Promise<void> {
    if (this.metricsInterval) {
      clearInterval(this.metricsInterval);
    }

    await this.flushErrorBuffer();

    this.logger.info('Error system shutdown');
  }
}

/**
 * Error handler interface
 */
interface ErrorHandler {
  handle<T>(error: EnhancedError, fallback?: T): Promise<T | undefined>;
}

/**
 * Error builder for fluent API
 */
export class ErrorBuilder {
  private code: string = '';
  private message: string = '';
  private category: ErrorCategory = ErrorCategory.INTERNAL;
  private options: any = {};

  withCode(code: string): this {
    this.code = code;
    return this;
  }

  withMessage(message: string): this {
    this.message = message;
    return this;
  }

  withCategory(category: ErrorCategory): this {
    this.category = category;
    return this;
  }

  withSeverity(severity: ErrorSeverity): this {
    this.options.severity = severity;
    return this;
  }

  withContext(context: Partial<ErrorContext>): this {
    this.options.context = context;
    return this;
  }

  withRecovery(recovery: ErrorRecoveryOptions): this {
    this.options.recovery = recovery;
    return this;
  }

  withCause(cause: Error | EnhancedError): this {
    if (cause instanceof Error && !(cause as any).category) {
      this.options.originalError = cause;
    } else {
      this.options.cause = cause;
    }
    return this;
  }

  isRetryable(retryable: boolean = true): this {
    this.options.isRetryable = retryable;
    return this;
  }

  isUserFacing(userFacing: boolean = true): this {
    this.options.isUserFacing = userFacing;
    return this;
  }

  withUserMessage(message: string): this {
    this.options.userMessage = message;
    return this;
  }

  build(system: ErrorSystem): EnhancedError {
    return system.createError(this.code, this.message, this.category, this.options);
  }
}