/**
 * Comprehensive Error Handling and Monitoring Middleware
 * Provides security, observability, and recovery capabilities
 */

import type { Context, Next } from 'hono';
import type { Env } from '../types/env';
import { z } from 'zod';

// =====================================================
// ERROR TYPES AND INTERFACES
// =====================================================

export enum ErrorSeverity {
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  CRITICAL = 'critical'
}

export interface ErrorContext {
  traceId: string;
  businessId?: string;
  userId?: string;
  operation?: string;
  path?: string;
  method?: string;
  ip?: string;
  userAgent?: string;
  timestamp: string;
}

export class AppError extends Error {
  constructor(
    message: string,
    public code: string,
    public statusCode: number = 500,
    public severity: ErrorSeverity = ErrorSeverity.MEDIUM,
    public isOperational: boolean = true,
    public context?: any
  ) {
    super(message);
    this.name = 'AppError';
    Object.setPrototypeOf(this, AppError.prototype);
  }
}

export class ValidationError extends AppError {
  constructor(message: string, public issues: any[]) {
    super(message, 'VALIDATION_ERROR', 400, ErrorSeverity.LOW);
    this.name = 'ValidationError';
  }
}

export class AuthenticationError extends AppError {
  constructor(message: string = 'Authentication required') {
    super(message, 'AUTH_ERROR', 401, ErrorSeverity.MEDIUM);
    this.name = 'AuthenticationError';
  }
}

export class AuthorizationError extends AppError {
  constructor(message: string = 'Insufficient permissions') {
    super(message, 'AUTHZ_ERROR', 403, ErrorSeverity.MEDIUM);
    this.name = 'AuthorizationError';
  }
}

export class NotFoundError extends AppError {
  constructor(resource: string) {
    super(`${resource} not found`, 'NOT_FOUND', 404, ErrorSeverity.LOW);
    this.name = 'NotFoundError';
  }
}

export class RateLimitError extends AppError {
  constructor(retryAfter: number) {
    super('Rate limit exceeded', 'RATE_LIMIT', 429, ErrorSeverity.LOW);
    this.name = 'RateLimitError';
    this.context = { retryAfter };
  }
}

export class BusinessLogicError extends AppError {
  constructor(message: string, code: string) {
    super(message, code, 422, ErrorSeverity.HIGH);
    this.name = 'BusinessLogicError';
  }
}

// =====================================================
// SAFE LOGGER
// =====================================================

export class SafeLogger {
  private piiPatterns = [
    /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, // Email
    /\b\d{3}[-.]?\d{3}[-.]?\d{4}\b/g, // Phone
    /\b\d{3}-\d{2}-\d{4}\b/g, // SSN
    /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g, // Credit card
    /sk-[a-zA-Z0-9]{48}/g, // API keys
    /Bearer\s+[A-Za-z0-9\-._~+\/]+=*/g // Auth tokens
  ];

  log(level: 'info' | 'warn' | 'error' | 'debug', message: string, data?: any): void {
    const sanitized = this.sanitize(data);
    const timestamp = new Date().toISOString();

    const logEntry = {
      timestamp,
      level,
      message,
      ...sanitized
    };

    console[level](JSON.stringify(logEntry));
  }

  private sanitize(data: any): any {
    if (!data) return {};

    const str = JSON.stringify(data);
    let sanitized = str;

    // Replace PII patterns
    for (const pattern of this.piiPatterns) {
      sanitized = sanitized.replace(pattern, '[REDACTED]');
    }

    try {
      return JSON.parse(sanitized);
    } catch {
      return { raw: '[SANITIZATION_ERROR]' };
    }
  }

  info(message: string, data?: any): void {
    this.log('info', message, data);
  }

  warn(message: string, data?: any): void {
    this.log('warn', message, data);
  }

  error(message: string, data?: any): void {
    this.log('error', message, data);
  }

  debug(message: string, data?: any): void {
    if (process.env.NODE_ENV === 'development') {
      this.log('debug', message, data);
    }
  }
}

const logger = new SafeLogger();

// =====================================================
// TRACE ID MIDDLEWARE
// =====================================================

export async function traceIdMiddleware(c: Context<{ Bindings: Env }>, next: Next) {
  // Generate or extract trace ID
  const traceId = c.req.header('X-Trace-Id') ||
                   c.req.header('X-Request-Id') ||
                   crypto.randomUUID();

  // Set trace ID in context
  c.set('traceId', traceId);
  c.header('X-Trace-Id', traceId);

  // Log request
  logger.info('Request received', {
    traceId,
    method: c.req.method,
    path: c.req.path,
    query: c.req.query(),
    headers: {
      'user-agent': c.req.header('user-agent'),
      'content-type': c.req.header('content-type')
    }
  });

  // Time the request
  const start = Date.now();

  try {
    await next();
  } finally {
    const duration = Date.now() - start;

    // Log response
    logger.info('Request completed', {
      traceId,
      duration,
      status: c.res.status
    });

    // Track slow requests
    if (duration > 1000) { // Over 1 second
      await logSlowQuery(c.env, {
        traceId,
        path: c.req.path,
        duration,
        method: c.req.method
      });
    }
  }
}

// =====================================================
// BUSINESS CONTEXT MIDDLEWARE
// =====================================================

export async function businessContextMiddleware(c: Context<{ Bindings: Env }>, next: Next) {
  const businessId = c.req.header('X-Business-Id') || c.req.query('businessId');
  const userId = c.req.header('X-User-Id') || c.req.query('userId');

  if (businessId) {
    // Validate business ID format
    if (!/^biz_[a-zA-Z0-9_-]+$/.test(businessId)) {
      throw new ValidationError('Invalid business ID format', [
        { field: 'businessId', message: 'Must match pattern: biz_*' }
      ]);
    }
    c.set('businessId', businessId);
  }

  if (userId) {
    // Validate user ID format
    if (!/^[a-zA-Z0-9_-]+$/.test(userId)) {
      throw new ValidationError('Invalid user ID format', [
        { field: 'userId', message: 'Contains invalid characters' }
      ]);
    }
    c.set('userId', userId);
  }

  await next();
}

// =====================================================
// ERROR HANDLER MIDDLEWARE
// =====================================================

export async function errorHandlerMiddleware(c: Context<{ Bindings: Env }>, next: Next) {
  try {
    await next();
  } catch (error) {
    const traceId = c.get('traceId') || 'unknown';
    const context: ErrorContext = {
      traceId,
      businessId: c.get('businessId'),
      userId: c.get('userId'),
      path: c.req.path,
      method: c.req.method,
      ip: c.req.header('CF-Connecting-IP') || c.req.header('X-Forwarded-For'),
      userAgent: c.req.header('User-Agent'),
      timestamp: new Date().toISOString()
    };

    // Handle different error types
    if (error instanceof AppError) {
      return handleAppError(c, error, context);
    }

    if (error instanceof z.ZodError) {
      return handleValidationError(c, error, context);
    }

    // Unknown errors
    return handleUnknownError(c, error as Error, context);
  }
}

async function handleAppError(
  c: Context<{ Bindings: Env }>,
  error: AppError,
  context: ErrorContext
) {
  // Log based on severity
  if (error.severity === ErrorSeverity.CRITICAL) {
    await alertOncall(c.env, error, context);
  }

  logger.error('Application error', {
    ...context,
    code: error.code,
    severity: error.severity,
    message: error.message,
    stack: error.stack
  });

  // Track error metrics
  await trackErrorMetric(c.env, error, context);

  return c.json({
    error: {
      code: error.code,
      message: error.message,
      traceId: context.traceId
    }
  }, error.statusCode);
}

async function handleValidationError(
  c: Context<{ Bindings: Env }>,
  error: z.ZodError,
  context: ErrorContext
) {
  const issues = error.issues.map(issue => ({
    field: issue.path.join('.'),
    message: issue.message
  }));

  logger.warn('Validation error', {
    ...context,
    issues
  });

  return c.json({
    error: {
      code: 'VALIDATION_ERROR',
      message: 'Validation failed',
      issues,
      traceId: context.traceId
    }
  }, 400);
}

async function handleUnknownError(
  c: Context<{ Bindings: Env }>,
  error: Error,
  context: ErrorContext
) {
  logger.error('Unknown error', {
    ...context,
    name: error.name,
    message: error.message,
    stack: error.stack
  });

  // Alert for unknown errors
  await alertOncall(c.env, error, context);

  // Don't expose internal errors to clients
  return c.json({
    error: {
      code: 'INTERNAL_ERROR',
      message: 'An unexpected error occurred',
      traceId: context.traceId
    }
  }, 500);
}

// =====================================================
// MONITORING AND ALERTING
// =====================================================

async function trackErrorMetric(env: Env, error: AppError, context: ErrorContext) {
  try {
    if (env.DB_ANALYTICS) {
      await env.DB_ANALYTICS.prepare(`
        INSERT INTO error_metrics (
          trace_id, error_code, severity, business_id,
          user_id, path, method, timestamp
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(
        context.traceId,
        error.code,
        error.severity,
        context.businessId || null,
        context.userId || null,
        context.path,
        context.method,
        context.timestamp
      ).run();
    }
  } catch (err) {
    // Don't fail the request if metrics fail
  }
}

async function logSlowQuery(env: Env, data: any) {
  try {
    if (env.DB_ANALYTICS) {
      await env.DB_ANALYTICS.prepare(`
        INSERT INTO slow_query_log (
          trace_id, query, execution_time_ms, business_id,
          user_id, created_at
        ) VALUES (?, ?, ?, ?, ?, ?)
      `).bind(
        data.traceId,
        data.path,
        data.duration,
        data.businessId || null,
        data.userId || null,
        new Date().toISOString()
      ).run();
    }
  } catch (err) {
  }
}

async function alertOncall(env: Env, error: Error | AppError, context: ErrorContext) {
  try {
    // In production, this would send to PagerDuty, Slack, etc.
    const alert = {
      severity: error instanceof AppError ? error.severity : ErrorSeverity.HIGH,
      error: {
        name: error.name,
        message: error.message,
        code: error instanceof AppError ? error.code : 'UNKNOWN'
      },
      context,
      timestamp: new Date().toISOString()
    };

    // Store critical alerts
    if (env.KV_ALERTS) {
      await env.KV_ALERTS.put(
        `alert:${context.traceId}`,
        JSON.stringify(alert),
        { expirationTtl: 86400 } // 24 hours
      );
    }

    logger.error('CRITICAL ALERT', alert);
  } catch (err) {
  }
}

// =====================================================
// RETRY AND CIRCUIT BREAKER
// =====================================================

export class CircuitBreaker {
  private failures = 0;
  private lastFailureTime = 0;
  private state: 'CLOSED' | 'OPEN' | 'HALF_OPEN' = 'CLOSED';

  constructor(
    private threshold: number = 5,
    private timeout: number = 60000, // 1 minute
    private resetTimeout: number = 30000 // 30 seconds
  ) {}

  async execute<T>(fn: () => Promise<T>): Promise<T> {
    if (this.state === 'OPEN') {
      if (Date.now() - this.lastFailureTime > this.timeout) {
        this.state = 'HALF_OPEN';
      } else {
        throw new AppError(
          'Service temporarily unavailable',
          'CIRCUIT_OPEN',
          503,
          ErrorSeverity.HIGH
        );
      }
    }

    try {
      const result = await fn();
      this.onSuccess();
      return result;
    } catch (error) {
      this.onFailure();
      throw error;
    }
  }

  private onSuccess() {
    this.failures = 0;
    this.state = 'CLOSED';
  }

  private onFailure() {
    this.failures++;
    this.lastFailureTime = Date.now();

    if (this.failures >= this.threshold) {
      this.state = 'OPEN';
      logger.warn('Circuit breaker opened', {
        failures: this.failures,
        threshold: this.threshold
      });
    }
  }
}

export async function withRetry<T>(
  fn: () => Promise<T>,
  maxRetries: number = 3,
  backoff: number = 1000
): Promise<T> {
  let lastError: Error;

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error as Error;

      if (attempt < maxRetries) {
        const delay = backoff * Math.pow(2, attempt); // Exponential backoff
        logger.warn(`Retry attempt ${attempt + 1}/${maxRetries}`, {
          error: lastError.message,
          delay
        });
        await new Promise(resolve => setTimeout(resolve, delay));
      }
    }
  }

  throw lastError!;
}

// =====================================================
// RECOVERY STRATEGIES
// =====================================================

export class RecoveryStrategy {
  static async handleDatabaseError(error: Error, context: any): Promise<any> {
    // Try to use cache if database is down
    if (context.cacheKey && context.env?.KV_CACHE) {
      const cached = await context.env.KV_CACHE.get(context.cacheKey, 'json');
      if (cached) {
        logger.info('Using cached data due to database error', { cacheKey: context.cacheKey });
        return cached;
      }
    }

    throw new AppError(
      'Database temporarily unavailable',
      'DB_ERROR',
      503,
      ErrorSeverity.HIGH,
      true,
      { originalError: error.message }
    );
  }

  static async handleExternalAPIError(error: Error, context: any): Promise<any> {
    // Try fallback service
    if (context.fallbackService) {
      logger.info('Using fallback service', { service: context.fallbackService });
      return await context.fallbackService();
    }

    // Return degraded response
    return {
      degraded: true,
      message: 'Service operating in degraded mode',
      data: context.defaultData || null
    };
  }
}

// =====================================================
// EXPORT MIDDLEWARE CHAIN
// =====================================================

export function setupErrorHandling(app: any) {
  // Order matters!
  app.use('*', traceIdMiddleware);
  app.use('*', businessContextMiddleware);
  app.use('*', errorHandlerMiddleware);

  // Not found handler
  app.notFound((c: Context) => {
    const traceId = c.get('traceId');
    return c.json({
      error: {
        code: 'NOT_FOUND',
        message: 'The requested resource was not found',
        path: c.req.path,
        traceId
      }
    }, 404);
  });

  // Global error boundary
  app.onError((err: Error, c: Context) => {
    logger.error('Unhandled error in app boundary', {
      error: err.message,
      stack: err.stack
    });

    return c.json({
      error: {
        code: 'INTERNAL_ERROR',
        message: 'An unexpected error occurred',
        traceId: c.get('traceId')
      }
    }, 500);
  });
}