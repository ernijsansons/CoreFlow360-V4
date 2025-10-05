/**
 * Global Error Handling Middleware
 * SECURITY: Prevents information leakage through error messages
 * Implements structured error responses and logging
 */

import type { AppContext, Next } from '../types/hono-context';

export interface ErrorResponse {
  error: {
    code: string;
    message: string;
    timestamp: string;
    requestId: string;
    details?: Record<string, any>;
  };
}

export interface ErrorContext {
  userId?: string;
  businessId?: string;
  ipAddress?: string;
  userAgent?: string;
  method?: string;
  path?: string;
  statusCode?: number;
  stack?: string;
  metadata?: Record<string, any>;
}

export class AppError extends Error {
  public readonly statusCode: number;
  public readonly code: string;
  public readonly isOperational: boolean;
  public readonly details?: Record<string, any>;

  constructor(
    message: string,
    statusCode: number = 500,
    code: string = 'INTERNAL_ERROR',
    isOperational: boolean = true,
    details?: Record<string, any>
  ) {
    super(message);
    this.statusCode = statusCode;
    this.code = code;
    this.isOperational = isOperational;
    this.details = details;

    Error.captureStackTrace(this, this.constructor);
  }
}

// Common error types
export class ValidationError extends AppError {
  constructor(message: string, details?: Record<string, any>) {
    super(message, 400, 'VALIDATION_ERROR', true, details);
  }
}

export class AuthenticationError extends AppError {
  constructor(message: string = 'Authentication failed') {
    super(message, 401, 'AUTHENTICATION_ERROR', true);
  }
}

export class AuthorizationError extends AppError {
  constructor(message: string = 'Insufficient permissions') {
    super(message, 403, 'AUTHORIZATION_ERROR', true);
  }
}

export class NotFoundError extends AppError {
  constructor(resource: string = 'Resource') {
    super(`${resource} not found`, 404, 'NOT_FOUND', true);
  }
}

export class RateLimitError extends AppError {
  constructor(retryAfter?: number) {
    super('Rate limit exceeded', 429, 'RATE_LIMIT_EXCEEDED', true, { retryAfter });
  }
}

export class ConflictError extends AppError {
  constructor(message: string = 'Resource conflict') {
    super(message, 409, 'CONFLICT', true);
  }
}

export class DatabaseError extends AppError {
  constructor(message: string = 'Database operation failed') {
    super(message, 500, 'DATABASE_ERROR', false);
  }
}

export interface ErrorHandlerConfig {
  logErrors: boolean;
  includeStack: boolean;
  sanitizeErrors: boolean;
  defaultMessage: string;
  env: 'development' | 'staging' | 'production';
}

export class ErrorHandler {
  private readonly config: ErrorHandlerConfig;
  private readonly kv?: KVNamespace;
  private readonly errorPrefix = 'error:log:';

  constructor(config: Partial<ErrorHandlerConfig> = {}, kv?: KVNamespace) {
    this.config = {
      logErrors: config.logErrors ?? true,
      includeStack: config.includeStack ?? (config.env === 'development'),
      sanitizeErrors: config.sanitizeErrors ?? true,
      defaultMessage: config.defaultMessage ?? 'An error occurred',
      env: config.env ?? 'production'
    };
    this.kv = kv;
  }

  /**
   * Main error handling middleware
   */
  middleware() {
    return async (c: AppContext, next: Next) => {
      try {
        await next();
      } catch (error: any) {
        await this.handleError(error, c);
      }
    };
  }

  /**
   * Handle error and generate response
   */
  private async handleError(error: any, c: AppContext): Promise<Response | void> {
    const requestId = c.get('requestId') || crypto.randomUUID();
    const timestamp = new Date().toISOString();

    // Determine if error is operational
    const isOperational = error instanceof AppError ? error.isOperational : false;

    // Get status code
    const statusCode = error.statusCode || error.status || 500;

    // Build error context
    const errorContext: ErrorContext = {
      userId: c.get('userId'),
      businessId: c.get('businessId'),
      ipAddress: c.req.header('CF-Connecting-IP') || c.req.header('X-Forwarded-For'),
      userAgent: c.req.header('User-Agent'),
      method: c.req.method,
      path: c.req.path,
      statusCode,
      stack: this.config.includeStack ? error.stack : undefined,
      metadata: {
        errorType: error.constructor.name,
        errorCode: error.code,
        isOperational
      }
    };

    // Log error
    if (this.config.logErrors) {
      await this.logError(error, errorContext, requestId);
    }

    // Prepare error response
    const errorResponse = this.prepareErrorResponse(error, requestId, timestamp);

    // Set security headers
    c.header('X-Content-Type-Options', 'nosniff');
    c.header('X-Frame-Options', 'DENY');

    // Set rate limit headers if applicable
    if (error instanceof RateLimitError && error.details?.retryAfter) {
      c.header('Retry-After', error.details.retryAfter.toString());
      c.header('X-RateLimit-Limit', '100');
      c.header('X-RateLimit-Remaining', '0');
      c.header('X-RateLimit-Reset', (Date.now() + error.details.retryAfter * 1000).toString());
    }

    // Send response
    c.status(statusCode);
    return c.json(errorResponse);
  }

  /**
   * Prepare sanitized error response
   */
  private prepareErrorResponse(error: any, requestId: string, timestamp: string): ErrorResponse {
    let message = error.message || this.config.defaultMessage;
    let code = 'INTERNAL_ERROR';
    let details: Record<string, any> | undefined;

    if (error instanceof AppError) {
      code = error.code;
      details = error.details;

      // Sanitize message in production
      if (this.config.sanitizeErrors && this.config.env === 'production') {
        if (!error.isOperational) {
          message = this.config.defaultMessage;
          details = undefined;
        }
      }
    } else if (this.config.sanitizeErrors && this.config.env === 'production') {
      // Don't expose internal errors in production
      message = this.config.defaultMessage;
      details = undefined;
    }

    // Remove sensitive information from details
    if (details) {
      details = this.sanitizeDetails(details);
    }

    return {
      error: {
        code,
        message,
        timestamp,
        requestId,
        ...(details && { details })
      }
    };
  }

  /**
   * Sanitize error details to remove sensitive information
   */
  private sanitizeDetails(details: Record<string, any>): Record<string, any> {
    const sanitized: Record<string, any> = {};
    const sensitiveKeys = ['password', 'token', 'secret', 'apiKey', 'authorization', 'cookie', 'session'];

    for (const [key, value] of Object.entries(details)) {
      const lowerKey = key.toLowerCase();

      // Check if key contains sensitive information
      if (sensitiveKeys.some(sensitive => lowerKey.includes(sensitive))) {
        sanitized[key] = '[REDACTED]';
      } else if (typeof value === 'object' && value !== null) {
        // Recursively sanitize nested objects
        sanitized[key] = this.sanitizeDetails(value);
      } else {
        sanitized[key] = value;
      }
    }

    return sanitized;
  }

  /**
   * Log error with context
   */
  private async logError(error: any, context: ErrorContext, requestId: string): Promise<void> {
    const logEntry = {
      requestId,
      timestamp: new Date().toISOString(),
      message: error.message,
      code: error.code || 'UNKNOWN',
      statusCode: context.statusCode,
      ...context,
      stack: context.stack?.split('\n').slice(0, 10) // Limit stack trace lines
    };

    // Console log for immediate visibility
    if (context.statusCode >= 500 || !error.isOperational) {
      console.error('[ERROR]', JSON.stringify(logEntry, null, 2));
    } else {
      console.warn('[WARNING]', JSON.stringify(logEntry, null, 2));
    }

    // Store in KV if available
    if (this.kv) {
      try {
        await this.kv.put(
          `${this.errorPrefix}${Date.now()}_${requestId}`,
          JSON.stringify(logEntry),
          { expirationTtl: 7 * 24 * 60 * 60 } // 7 days retention
        );
      } catch (kvError) {
        console.error('Failed to log error to KV:', kvError);
      }
    }
  }

  /**
   * Handle error for Hono's onError hook
   */
  async handle(error: any, c: AppContext): Promise<Response> {
    await this.handleError(error, c);
    return c.res;
  }

  /**
   * Handle unexpected errors outside the middleware chain
   */
  handleUnexpected(error: Error, request: Request): Response {
    const requestId = crypto.randomUUID();
    const timestamp = new Date().toISOString();

    // Log error
    console.error('[UNEXPECTED ERROR]', {
      requestId,
      timestamp,
      message: error.message,
      stack: error.stack,
      url: request.url,
      method: request.method
    });

    // Prepare error response
    const errorResponse: ErrorResponse = {
      error: {
        code: 'INTERNAL_ERROR',
        message: this.config.sanitizeErrors ? this.config.defaultMessage : error.message,
        timestamp,
        requestId
      }
    };

    return new Response(JSON.stringify(errorResponse), {
      status: 500,
      headers: {
        'Content-Type': 'application/json',
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY'
      }
    });
  }

  /**
   * Create async error wrapper for route handlers
   */
  static asyncWrapper(fn: Function) {
    return async (c: AppContext, next: Next) => {
      try {
        return await fn(c, next);
      } catch (error) {
        throw error; // Let the middleware handle it
      }
    };
  }

  /**
   * Validate and throw appropriate errors
   */
  static validate(condition: boolean, message: string, statusCode = 400): void {
    if (!condition) {
      throw new ValidationError(message);
    }
  }

  /**
   * Assert condition or throw error
   */
  static assert(condition: boolean, error: AppError): void {
    if (!condition) {
      throw error;
    }
  }
}

/**
 * Default error handler middleware factory
 */
export function createErrorHandler(config?: Partial<ErrorHandlerConfig>, kv?: KVNamespace) {
  const handler = new ErrorHandler(config, kv);
  return handler.middleware();
}

/**
 * Error recovery middleware - attempts to recover from errors
 */
export async function errorRecoveryMiddleware(c: AppContext, next: Next) {
  const maxRetries = 3;
  let lastError: any;

  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      await next();
      return; // Success, exit
    } catch (error: any) {
      lastError = error;

      // Don't retry client errors
      if (error.statusCode && error.statusCode < 500) {
        throw error;
      }

      // Don't retry non-operational errors
      if (error instanceof AppError && !error.isOperational) {
        throw error;
      }

      // Log retry attempt
      console.warn(`Retry attempt ${attempt}/${maxRetries} for request ${c.req.path}`);

      // Wait before retry (exponential backoff)
      if (attempt < maxRetries) {
        await new Promise(resolve => setTimeout(resolve, Math.pow(2, attempt) * 100));
      }
    }
  }

  // All retries failed
  throw lastError;
}

/**
 * Circuit breaker pattern for external service calls
 */
export class CircuitBreaker {
  private failures = 0;
  private lastFailTime = 0;
  private state: 'closed' | 'open' | 'half-open' = 'closed';

  constructor(
    private readonly threshold = 5,
    private readonly timeout = 60000 // 1 minute
  ) {}

  async execute<T>(fn: () => Promise<T>): Promise<T> {
    if (this.state === 'open') {
      if (Date.now() - this.lastFailTime > this.timeout) {
        this.state = 'half-open';
      } else {
        throw new AppError('Service temporarily unavailable', 503, 'CIRCUIT_BREAKER_OPEN');
      }
    }

    try {
      const result = await fn();

      if (this.state === 'half-open') {
        this.state = 'closed';
        this.failures = 0;
      }

      return result;
    } catch (error) {
      this.failures++;
      this.lastFailTime = Date.now();

      if (this.failures >= this.threshold) {
        this.state = 'open';
        console.error(`Circuit breaker opened after ${this.failures} failures`);
      }

      throw error;
    }
  }

  reset(): void {
    this.failures = 0;
    this.state = 'closed';
  }
}