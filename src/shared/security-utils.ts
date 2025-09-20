/**
 * Security utilities for CoreFlow360 V4
 * Provides validation, sanitization, and security controls
 */

import { z } from 'zod';

/**
 * Business isolation validation
 */
export class BusinessIsolation {
  /**
   * Validate that a user has access to a specific business
   */
  static validateBusinessAccess(
    userBusinessId: string | undefined,
    targetBusinessId: string,
    operation: string
  ): void {
    if (!userBusinessId) {
      throw new SecurityError('Missing user business context', {
        operation,
        targetBusinessId,
        code: 'MISSING_BUSINESS_CONTEXT',
      });
    }

    if (userBusinessId !== targetBusinessId) {
      throw new SecurityError('Cross-business access denied', {
        operation,
        userBusinessId: this.redactBusinessId(userBusinessId),
        targetBusinessId: this.redactBusinessId(targetBusinessId),
        code: 'CROSS_BUSINESS_ACCESS_DENIED',
      });
    }
  }

  /**
   * Extract business ID from resource and validate access
   */
  static validateResourceAccess(
    userBusinessId: string | undefined,
    resource: { businessId?: string; id?: string; type?: string },
    operation: string
  ): void {
    if (!resource.businessId) {
      throw new SecurityError('Resource missing business context', {
        operation,
        resourceType: resource.type,
        resourceId: this.redactResourceId(resource.id),
        code: 'RESOURCE_MISSING_BUSINESS_CONTEXT',
      });
    }

    this.validateBusinessAccess(userBusinessId, resource.businessId, operation);
  }

  /**
   * Redact business ID for logging (keep first 8 chars + hash)
   */
  static redactBusinessId(businessId?: string): string {
    if (!businessId) return '[missing]';
    const prefix = businessId.slice(0, 8);
    const hash = this.simpleHash(businessId).slice(0, 8);
    return `${prefix}...${hash}`;
  }

  /**
   * Redact resource ID for logging
   */
  static redactResourceId(resourceId?: string): string {
    if (!resourceId) return '[missing]';
    const prefix = resourceId.slice(0, 6);
    const hash = this.simpleHash(resourceId).slice(0, 6);
    return `${prefix}...${hash}`;
  }

  /**
   * Simple hash for redaction (not cryptographically secure)
   */
  private static simpleHash(str: string): string {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32bit integer
    }
    return Math.abs(hash).toString(16);
  }
}

/**
 * Input validation and sanitization
 */
export class InputValidator {
  /**
   * Resource ID validation schema
   */
  static readonly RESOURCE_ID_SCHEMA = z.string()
    .min(1, 'Resource ID cannot be empty')
    .max(255, 'Resource ID too long')
    .regex(
      /^[a-zA-Z0-9_-]+$/,
      'Resource ID can only contain alphanumeric characters, hyphens, and underscores'
    );

  /**
   * Business ID validation schema
   */
  static readonly BUSINESS_ID_SCHEMA = z.string()
    .min(1, 'Business ID cannot be empty')
    .max(255, 'Business ID too long')
    .regex(
      /^[a-zA-Z0-9_-]+$/,
      'Business ID can only contain alphanumeric characters, hyphens, and underscores'
    );

  /**
   * User ID validation schema
   */
  static readonly USER_ID_SCHEMA = z.string()
    .min(1, 'User ID cannot be empty')
    .max(255, 'User ID too long')
    .regex(
      /^[a-zA-Z0-9_-]+$/,
      'User ID can only contain alphanumeric characters, hyphens, and underscores'
    );

  /**
   * Capability validation schema
   */
  static readonly CAPABILITY_SCHEMA = z.string()
    .min(1, 'Capability cannot be empty')
    .max(255, 'Capability too long')
    .regex(
      /^[a-z_]+\.[a-z_]+\.(create|read|update|delete|approve|reject|export|share|archive|restore|\*)$/,
      'Invalid capability format. Expected: module.resource.action'
    );

  /**
   * Correlation ID validation schema
   */
  static readonly CORRELATION_ID_SCHEMA = z.string()
    .min(1, 'Correlation ID cannot be empty')
    .max(128, 'Correlation ID too long')
    .regex(
      /^[a-zA-Z0-9_-]+$/,
      'Correlation ID can only contain alphanumeric characters, hyphens, and underscores'
    );

  /**
   * Validate and sanitize resource ID
   */
  static validateResourceId(resourceId: unknown): string {
    try {
      return this.RESOURCE_ID_SCHEMA.parse(resourceId);
    } catch (error) {
      throw new SecurityError('Invalid resource ID format', {
        resourceId: typeof resourceId === 'string' ? resourceId.slice(0, 10) + '...' : typeof resourceId,
        code: 'INVALID_RESOURCE_ID',
        validationErrors: error instanceof z.ZodError ? error.errors : undefined,
      });
    }
  }

  /**
   * Validate and sanitize business ID
   */
  static validateBusinessId(businessId: unknown): string {
    try {
      return this.BUSINESS_ID_SCHEMA.parse(businessId);
    } catch (error) {
      throw new SecurityError('Invalid business ID format', {
        businessId: typeof businessId === 'string' ? businessId.slice(0, 10) + '...' : typeof businessId,
        code: 'INVALID_BUSINESS_ID',
        validationErrors: error instanceof z.ZodError ? error.errors : undefined,
      });
    }
  }

  /**
   * Validate and sanitize user ID
   */
  static validateUserId(userId: unknown): string {
    try {
      return this.USER_ID_SCHEMA.parse(userId);
    } catch (error) {
      throw new SecurityError('Invalid user ID format', {
        userId: typeof userId === 'string' ? userId.slice(0, 10) + '...' : typeof userId,
        code: 'INVALID_USER_ID',
        validationErrors: error instanceof z.ZodError ? error.errors : undefined,
      });
    }
  }

  /**
   * Validate capability format
   */
  static validateCapability(capability: unknown): string {
    try {
      return this.CAPABILITY_SCHEMA.parse(capability);
    } catch (error) {
      throw new SecurityError('Invalid capability format', {
        capability: typeof capability === 'string' ? capability : typeof capability,
        code: 'INVALID_CAPABILITY',
        validationErrors: error instanceof z.ZodError ? error.errors : undefined,
      });
    }
  }

  /**
   * Validate correlation ID
   */
  static validateCorrelationId(correlationId: unknown): string {
    try {
      return this.CORRELATION_ID_SCHEMA.parse(correlationId);
    } catch (error) {
      throw new SecurityError('Invalid correlation ID format', {
        correlationId: typeof correlationId === 'string' ? correlationId.slice(0, 10) + '...' : typeof correlationId,
        code: 'INVALID_CORRELATION_ID',
        validationErrors: error instanceof z.ZodError ? error.errors : undefined,
      });
    }
  }

  /**
   * Sanitize string input for logging (remove potential XSS/injection)
   */
  static sanitizeForLogging(input: unknown): string {
    if (typeof input !== 'string') {
      return String(input);
    }

    return input
      .replace(/[<>\"'&]/g, '') // Remove HTML/XML chars
      .replace(/[\x00-\x1f\x7f]/g, '') // Remove control chars
      .slice(0, 1000); // Limit length
  }

  /**
   * Extract safe user agent string
   */
  static sanitizeUserAgent(userAgent: unknown): string {
    if (typeof userAgent !== 'string') {
      return 'unknown';
    }

    return userAgent
      .replace(/[<>\"'&]/g, '')
      .slice(0, 500);
  }

  /**
   * Extract safe IP address
   */
  static sanitizeIpAddress(ipAddress: unknown): string {
    if (typeof ipAddress !== 'string') {
      return 'unknown';
    }

    // Basic IP validation (IPv4 and IPv6)
    const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
    const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;

    if (ipv4Regex.test(ipAddress) || ipv6Regex.test(ipAddress)) {
      return ipAddress;
    }

    // If not valid IP, sanitize as string
    return this.sanitizeForLogging(ipAddress);
  }
}

/**
 * PII redaction utilities
 */
export class PIIRedactor {
  /**
   * Redact user ID for logging (keep first 4 chars + hash)
   */
  static redactUserId(userId?: string): string {
    if (!userId) return '[missing]';
    const prefix = userId.slice(0, 4);
    const hash = this.simpleHash(userId).slice(0, 6);
    return `${prefix}...${hash}`;
  }

  /**
   * Redact email for logging (keep domain)
   */
  static redactEmail(email?: string): string {
    if (!email) return '[missing]';
    const [local, domain] = email.split('@');
    if (!domain) return '[invalid-email]';

    const redactedLocal = local.slice(0, 2) + '***';
    return `${redactedLocal}@${domain}`;
  }

  /**
   * Redact session ID (keep first 8 chars)
   */
  static redactSessionId(sessionId?: string): string {
    if (!sessionId) return '[missing]';
    return sessionId.slice(0, 8) + '...';
  }

  /**
   * Redact sensitive object properties
   */
  static redactSensitiveData(data: Record<string, unknown>): Record<string, unknown> {
    const redacted = { ...data };
    const sensitiveFields = [
      'password',
      'token',
      'secret',
      'key',
      'hash',
      'email',
      'phone',
      'ssn',
      'credit_card',
      'api_key',
      'session_id',
      'user_id',
      'business_id',
    ];

    for (const field of sensitiveFields) {
      if (field in redacted) {
        if (field === 'email') {
          redacted[field] = this.redactEmail(String(redacted[field]));
        } else if (field === 'user_id') {
          redacted[field] = this.redactUserId(String(redacted[field]));
        } else if (field === 'business_id') {
          redacted[field] = BusinessIsolation.redactBusinessId(String(redacted[field]));
        } else if (field === 'session_id') {
          redacted[field] = this.redactSessionId(String(redacted[field]));
        } else {
          redacted[field] = '[REDACTED]';
        }
      }
    }

    return redacted;
  }

  /**
   * Simple hash for redaction (not cryptographically secure)
   */
  private static simpleHash(str: string): string {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32bit integer
    }
    return Math.abs(hash).toString(16);
  }
}

/**
 * Correlation ID utilities
 */
export class CorrelationId {
  private static counter = 0;

  /**
   * Generate a new correlation ID
   */
  static generate(): string {
    const timestamp = Date.now().toString(36);
    const random = Math.random().toString(36).substr(2, 5);
    const counter = (++this.counter).toString(36);
    return `cflow_${timestamp}_${random}_${counter}`;
  }

  /**
   * Extract correlation ID from headers or generate new one
   */
  static extractOrGenerate(headers: Record<string, string | undefined>): string {
    const headerNames = [
      'x-correlation-id',
      'x-trace-id',
      'x-request-id',
      'correlation-id',
      'trace-id',
      'request-id',
    ];

    for (const headerName of headerNames) {
      const value = headers[headerName];
      if (value) {
        try {
          return InputValidator.validateCorrelationId(value);
        } catch {
          // Invalid format, continue to next header
        }
      }
    }

    return this.generate();
  }

  /**
   * Validate correlation ID format
   */
  static isValid(correlationId: string): boolean {
    try {
      InputValidator.validateCorrelationId(correlationId);
      return true;
    } catch {
      return false;
    }
  }
}

/**
 * Security-specific error class
 */
export class SecurityError extends Error {
  public readonly code: string;
  public readonly context: Record<string, unknown>;
  public readonly timestamp: string;

  constructor(
    message: string,
    context: Record<string, unknown> & { code: string }
  ) {
    super(message);
    this.name = 'SecurityError';
    this.code = context.code;
    this.context = PIIRedactor.redactSensitiveData(context);
    this.timestamp = new Date().toISOString();

    // Maintain stack trace
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, SecurityError);
    }
  }

  /**
   * Convert to JSON for logging
   */
  toJSON(): Record<string, unknown> {
    return {
      name: this.name,
      message: this.message,
      code: this.code,
      context: this.context,
      timestamp: this.timestamp,
      stack: this.stack,
    };
  }

  /**
   * Convert to safe JSON for client responses (no stack trace)
   */
  toSafeJSON(): Record<string, unknown> {
    return {
      error: this.message,
      code: this.code,
      timestamp: this.timestamp,
      // Don't include context or stack in client responses
    };
  }
}

/**
 * Rate limiting utilities
 */
export class SecurityLimits {
  /**
   * Default security limits
   */
  static readonly LIMITS = {
    MAX_PERMISSION_CHECKS_PER_MINUTE: 1000,
    MAX_POLICY_EVALUATIONS_PER_REQUEST: 100,
    MAX_CACHE_WARMING_SUBJECTS: 1000,
    MAX_CACHE_WARMING_CAPABILITIES: 100,
    MAX_BATCH_PERMISSION_CHECKS: 50,
    MAX_CORRELATION_ID_LENGTH: 128,
    MAX_RESOURCE_ID_LENGTH: 255,
    MAX_USER_CONTEXT_SIZE: 10000, // bytes
  } as const;

  /**
   * Validate request doesn't exceed security limits
   */
  static validateRequestLimits(params: {
    batchSize?: number;
    correlationId?: string;
    userContextSize?: number;
  }): void {
    if (params.batchSize && params.batchSize > this.LIMITS.MAX_BATCH_PERMISSION_CHECKS) {
      throw new SecurityError('Batch size exceeds security limit', {
        code: 'BATCH_SIZE_LIMIT_EXCEEDED',
        requestedSize: params.batchSize,
        maxSize: this.LIMITS.MAX_BATCH_PERMISSION_CHECKS,
      });
    }

    if (params.correlationId && params.correlationId.length > this.LIMITS.MAX_CORRELATION_ID_LENGTH) {
      throw new SecurityError('Correlation ID exceeds length limit', {
        code: 'CORRELATION_ID_TOO_LONG',
        length: params.correlationId.length,
        maxLength: this.LIMITS.MAX_CORRELATION_ID_LENGTH,
      });
    }

    if (params.userContextSize && params.userContextSize > this.LIMITS.MAX_USER_CONTEXT_SIZE) {
      throw new SecurityError('User context size exceeds limit', {
        code: 'USER_CONTEXT_TOO_LARGE',
        size: params.userContextSize,
        maxSize: this.LIMITS.MAX_USER_CONTEXT_SIZE,
      });
    }
  }
}

/**
 * Security context for request tracking
 */
export interface SecurityContext {
  correlationId: string;
  userId: string;
  businessId: string;
  ipAddress: string;
  userAgent: string;
  sessionId: string;
  timestamp: number;
  operation: string;
}

/**
 * Create security context from request data
 */
export function createSecurityContext(params: {
  correlationId?: string;
  userId: unknown;
  businessId: unknown;
  ipAddress: unknown;
  userAgent: unknown;
  sessionId: unknown;
  operation: string;
  headers?: Record<string, string | undefined>;
}): SecurityContext {
  return {
    correlationId: params.correlationId || CorrelationId.extractOrGenerate(params.headers || {}),
    userId: InputValidator.validateUserId(params.userId),
    businessId: InputValidator.validateBusinessId(params.businessId),
    ipAddress: InputValidator.sanitizeIpAddress(params.ipAddress),
    userAgent: InputValidator.sanitizeUserAgent(params.userAgent),
    sessionId: InputValidator.sanitizeForLogging(params.sessionId),
    timestamp: Date.now(),
    operation: InputValidator.sanitizeForLogging(params.operation),
  };
}