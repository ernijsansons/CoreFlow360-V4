import { Context } from 'hono';
import { z } from 'zod';
import { ERROR_CODES, HTTP_STATUS } from './constants';

export interface ErrorContext {
  requestId?: string;
  businessId?: string;
  userId?: string;
  path?: string;
  method?: string;
}

export class AppError extends Error {
  constructor(
    public code: string,
    message: string,
    public statusCode: number = 500,
    public details?: any
  ) {
    super(message);
    this.name = 'AppError';
  }
}

export class ValidationError extends AppError {
  constructor(message: string, details?: any) {
    super(ERROR_CODES.VALIDATION_ERROR, message, HTTP_STATUS.BAD_REQUEST, details);
    this.name = 'ValidationError';
  }
}

export class AuthenticationError extends AppError {
  constructor(message: string = 'Authentication required') {
    super(ERROR_CODES.AUTHENTICATION_REQUIRED, message, HTTP_STATUS.UNAUTHORIZED);
    this.name = 'AuthenticationError';
  }
}

export class AuthorizationError extends AppError {
  constructor(message: string = 'Permission denied') {
    super(ERROR_CODES.PERMISSION_DENIED, message, HTTP_STATUS.FORBIDDEN);
    this.name = 'AuthorizationError';
  }
}

export class NotFoundError extends AppError {
  constructor(resource: string, id?: string) {
    const message = id ? `${resource} with id ${id} not found` : `${resource} not found`;
    super(ERROR_CODES.RESOURCE_NOT_FOUND, message, HTTP_STATUS.NOT_FOUND);
    this.name = 'NotFoundError';
  }
}

export class SecurityError extends AppError {
  constructor(message: string = 'Security violation detected') {
    super(ERROR_CODES.SECURITY_VIOLATION, message, HTTP_STATUS.FORBIDDEN);
    this.name = 'SecurityError';
  }
}

export class ConflictError extends AppError {
  constructor(message: string, details?: any) {
    super(ERROR_CODES.RESOURCE_EXISTS, message, HTTP_STATUS.CONFLICT, details);
    this.name = 'ConflictError';
  }
}

export class RateLimitError extends AppError {
  constructor(retryAfter?: number) {
    super(
      ERROR_CODES.RATE_LIMIT_EXCEEDED,
      'Rate limit exceeded',
      HTTP_STATUS.TOO_MANY_REQUESTS,
      { retryAfter }
    );
    this.name = 'RateLimitError';
  }
}

export class BusinessLogicError extends AppError {
  constructor(message: string, details?: any) {
    super(ERROR_CODES.INVALID_REQUEST, message, HTTP_STATUS.UNPROCESSABLE_ENTITY, details);
    this.name = 'BusinessLogicError';
  }
}

/**
 * Global error handler for Hono apps
 */
export async function errorHandler(err: Error, c: Context): Promise<Response> {
  const requestId = c.get('requestId') || crypto.randomUUID();
  const startTime = c.get('startTime') || Date.now();

  // Log error to audit
  try {
    await logError(c, err, requestId);
  } catch (logError) {
  }

  // Handle Zod validation errors
  if (err instanceof z.ZodError) {
    return c.json({
      success: false,
      error: {
        code: ERROR_CODES.VALIDATION_ERROR,
        message: 'Validation failed',
        details: err.errors,
      },
      metadata: {
        requestId,
        timestamp: new Date().toISOString(),
        duration: Date.now() - startTime,
      },
    }, HTTP_STATUS.BAD_REQUEST);
  }

  // Handle custom app errors
  if (err instanceof AppError) {
    return c.json({
      success: false,
      error: {
        code: err.code,
        message: err.message,
        details: err.details,
      },
      metadata: {
        requestId,
        timestamp: new Date().toISOString(),
        duration: Date.now() - startTime,
      },
    }, err.statusCode);
  }

  // Handle unexpected errors
  const isDevelopment = c.env?.ENVIRONMENT === 'development';

  return c.json({
    success: false,
    error: {
      code: ERROR_CODES.INTERNAL_ERROR,
      message: isDevelopment ? err.message : 'An unexpected error occurred',
      details: isDevelopment ? { stack: err.stack } : undefined,
    },
    metadata: {
      requestId,
      timestamp: new Date().toISOString(),
      duration: Date.now() - startTime,
    },
  }, HTTP_STATUS.INTERNAL_SERVER_ERROR);
}

/**
 * Async error wrapper for route handlers
 */
export function asyncHandler<T = any>(
  fn: (c: Context) => Promise<T>
): (c: Context) => Promise<T> {
  return async (c: Context) => {
    try {
      return await fn(c);
    } catch (error) {
      throw error; // Will be caught by global error handler
    }
  };
}

/**
 * Log error to audit logs
 */
async function logError(c: Context, error: Error, requestId: string) {
  const env = c.env as any;
  const businessId = c.get('businessId') || 'SYSTEM';
  const userId = c.get('userId');

  const errorDetails = {
    name: error.name,
    message: error.message,
    stack: error.stack,
    code: error instanceof AppError ? error.code : 'UNKNOWN',
  };

  try {
    await env.DB_MAIN?.prepare(`
      INSERT INTO audit_logs (
        id, business_id, event_type, event_name, event_description,
        resource_type, resource_id, user_id,
        ip_address, user_agent, request_method, request_path,
        status, error_code, error_message,
        created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
    `).bind(
      crypto.randomUUID(),
      businessId,
      'error',
      'application_error',
      `Error in ${c.req.method} ${c.req.path}`,
      'request',
      requestId,
      userId,
      c.req.header('CF-Connecting-IP') || 'unknown',
      c.req.header('User-Agent') || 'unknown',
      c.req.method,
      c.req.path,
      'failure',
      errorDetails.code,
      errorDetails.message
    ).run();
  } catch (logError) {
  }
}

/**
 * Retry wrapper with exponential backoff
 */
export async function withRetry<T>(
  fn: () => Promise<T>,
  maxAttempts: number = 3,
  baseDelay: number = 1000
): Promise<T> {
  let lastError: Error | undefined;

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error as Error;

      if (attempt < maxAttempts) {
        const delay = baseDelay * Math.pow(2, attempt - 1);
        await new Promise(resolve => setTimeout(resolve, delay));
      }
    }
  }

  throw lastError;
}

/**
 * Timeout wrapper
 */
export async function withTimeout<T>(
  fn: () => Promise<T>,
  timeoutMs: number
): Promise<T> {
  const timeoutPromise = new Promise<never>((_, reject) => {
    setTimeout(() => reject(new Error('Operation timed out')), timeoutMs);
  });

  return Promise.race([fn(), timeoutPromise]);
}