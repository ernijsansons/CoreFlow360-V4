/**
 * AppError Class Tests
 *
 * Comprehensive test suite for AppError and related error classes
 * following TDD principles with 95%+ coverage target.
 */

import { describe, it, expect } from 'vitest';
import {
  AppError,
  ValidationError,
  AuthenticationError,
  AuthorizationError,
  NotFoundError,
  ConflictError,
  SecurityError,
  RateLimitError,
  InternalError,
  isAppError,
  formatErrorResponse,
} from '../app-error';

describe('AppError', () => {
  describe('constructor', () => {
    it('should create error with message and default status code', () => {
      const error = new AppError('Test error');

      expect(error.message).toBe('Test error');
      expect(error.statusCode).toBe(500);
      expect(error.isOperational).toBe(true);
      expect(error.errorCode).toBeUndefined();
      expect(error.context).toBeUndefined();
    });

    it('should create error with message and custom status code', () => {
      const error = new AppError('Not found', 404);

      expect(error.message).toBe('Not found');
      expect(error.statusCode).toBe(404);
      expect(error.isOperational).toBe(true);
    });

    it('should create error with message, status code, and error code', () => {
      const error = new AppError('Invalid table', 403, 'INVALID_TABLE');

      expect(error.message).toBe('Invalid table');
      expect(error.statusCode).toBe(403);
      expect(error.errorCode).toBe('INVALID_TABLE');
      expect(error.isOperational).toBe(true);
    });

    it('should create error with all parameters', () => {
      const context = { table: 'users', field: 'password' };
      const error = new AppError('Access denied', 403, 'SENSITIVE_FIELD', false, context);

      expect(error.message).toBe('Access denied');
      expect(error.statusCode).toBe(403);
      expect(error.errorCode).toBe('SENSITIVE_FIELD');
      expect(error.isOperational).toBe(false);
      expect(error.context).toEqual(context);
    });

    it('should create error with context but default isOperational', () => {
      const context = { userId: '123' };
      const error = new AppError('Error', 500, undefined, undefined, context);

      expect(error.context).toEqual(context);
      expect(error.isOperational).toBe(true);
    });

    it('should set error name to AppError', () => {
      const error = new AppError('Test');
      expect(error.name).toBe('AppError');
    });

    it('should be instance of Error', () => {
      const error = new AppError('Test');
      expect(error).toBeInstanceOf(Error);
    });

    it('should capture stack trace', () => {
      const error = new AppError('Test');
      expect(error.stack).toBeDefined();
      expect(error.stack).toContain('AppError');
    });
  });

  describe('security error codes', () => {
    it('should support INVALID_TABLE error code', () => {
      const error = new AppError('Invalid table', 403, 'INVALID_TABLE');
      expect(error.errorCode).toBe('INVALID_TABLE');
    });

    it('should support SENSITIVE_FIELD error code', () => {
      const error = new AppError('Sensitive field', 403, 'SENSITIVE_FIELD');
      expect(error.errorCode).toBe('SENSITIVE_FIELD');
    });

    it('should support SQL_KEYWORD_IN_FIELD error code', () => {
      const error = new AppError('SQL keyword', 403, 'SQL_KEYWORD_IN_FIELD');
      expect(error.errorCode).toBe('SQL_KEYWORD_IN_FIELD');
    });

    it('should support PARAM_LIMIT_EXCEEDED error code', () => {
      const error = new AppError('Too many params', 400, 'PARAM_LIMIT_EXCEEDED');
      expect(error.errorCode).toBe('PARAM_LIMIT_EXCEEDED');
    });

    it('should support PARAM_TOO_LONG error code', () => {
      const error = new AppError('Param too long', 400, 'PARAM_TOO_LONG');
      expect(error.errorCode).toBe('PARAM_TOO_LONG');
    });

    it('should support SQL_INJECTION error code', () => {
      const error = new AppError('SQL injection', 403, 'SQL_INJECTION');
      expect(error.errorCode).toBe('SQL_INJECTION');
    });

    it('should support CROSS_TENANT_VIOLATION error code', () => {
      const error = new AppError('Cross tenant', 403, 'CROSS_TENANT_VIOLATION');
      expect(error.errorCode).toBe('CROSS_TENANT_VIOLATION');
    });

    it('should support BUSINESS_ID_IMMUTABLE error code', () => {
      const error = new AppError('Immutable field', 403, 'BUSINESS_ID_IMMUTABLE');
      expect(error.errorCode).toBe('BUSINESS_ID_IMMUTABLE');
    });

    it('should support UNSAFE_DELETE error code', () => {
      const error = new AppError('Unsafe delete', 403, 'UNSAFE_DELETE');
      expect(error.errorCode).toBe('UNSAFE_DELETE');
    });

    it('should support INSUFFICIENT_PERMISSIONS error code', () => {
      const error = new AppError('No permission', 403, 'INSUFFICIENT_PERMISSIONS');
      expect(error.errorCode).toBe('INSUFFICIENT_PERMISSIONS');
    });

    it('should support QUERY_TOO_LONG error code', () => {
      const error = new AppError('Query too long', 400, 'QUERY_TOO_LONG');
      expect(error.errorCode).toBe('QUERY_TOO_LONG');
    });

    it('should support DANGEROUS_OPERATION error code', () => {
      const error = new AppError('Dangerous op', 403, 'DANGEROUS_OPERATION');
      expect(error.errorCode).toBe('DANGEROUS_OPERATION');
    });
  });
});

describe('ValidationError', () => {
  it('should create validation error with default status 400', () => {
    const error = new ValidationError('Invalid input');

    expect(error.message).toBe('Invalid input');
    expect(error.statusCode).toBe(400);
    expect(error.isOperational).toBe(true);
    expect(error.name).toBe('ValidationError');
  });

  it('should support context parameter', () => {
    const context = { field: 'email', value: 'invalid' };
    const error = new ValidationError('Invalid email', context);

    expect(error.context).toEqual(context);
  });
});

describe('AuthenticationError', () => {
  it('should create auth error with default status 401', () => {
    const error = new AuthenticationError('Not authenticated');

    expect(error.message).toBe('Not authenticated');
    expect(error.statusCode).toBe(401);
    expect(error.isOperational).toBe(true);
    expect(error.name).toBe('AuthenticationError');
  });

  it('should support context parameter', () => {
    const context = { token: 'expired' };
    const error = new AuthenticationError('Token expired', context);

    expect(error.context).toEqual(context);
  });
});

describe('AuthorizationError', () => {
  it('should create authorization error with default status 403', () => {
    const error = new AuthorizationError('Access denied');

    expect(error.message).toBe('Access denied');
    expect(error.statusCode).toBe(403);
    expect(error.isOperational).toBe(true);
    expect(error.name).toBe('AuthorizationError');
  });

  it('should support context parameter', () => {
    const context = { resource: 'admin', action: 'delete' };
    const error = new AuthorizationError('Cannot delete', context);

    expect(error.context).toEqual(context);
  });
});

describe('NotFoundError', () => {
  it('should create not found error with default status 404', () => {
    const error = new NotFoundError('Resource not found');

    expect(error.message).toBe('Resource not found');
    expect(error.statusCode).toBe(404);
    expect(error.isOperational).toBe(true);
    expect(error.name).toBe('NotFoundError');
  });

  it('should support context parameter', () => {
    const context = { resourceType: 'user', id: '123' };
    const error = new NotFoundError('User not found', context);

    expect(error.context).toEqual(context);
  });
});

describe('ConflictError', () => {
  it('should create conflict error with default status 409', () => {
    const error = new ConflictError('Resource already exists');

    expect(error.message).toBe('Resource already exists');
    expect(error.statusCode).toBe(409);
    expect(error.isOperational).toBe(true);
    expect(error.name).toBe('ConflictError');
  });

  it('should support context parameter', () => {
    const context = { field: 'email', value: 'test@test.com' };
    const error = new ConflictError('Email exists', context);

    expect(error.context).toEqual(context);
  });
});

describe('SecurityError', () => {
  it('should create security error with default status 403', () => {
    const error = new SecurityError('Security violation');

    expect(error.message).toBe('Security violation');
    expect(error.statusCode).toBe(403);
    expect(error.isOperational).toBe(true);
    expect(error.name).toBe('SecurityError');
  });

  it('should support context parameter', () => {
    const context = { violation: 'SQL_INJECTION', ip: '1.2.3.4' };
    const error = new SecurityError('Injection detected', context);

    expect(error.context).toEqual(context);
  });
});

describe('RateLimitError', () => {
  it('should create rate limit error with default status 429', () => {
    const error = new RateLimitError('Too many requests');

    expect(error.message).toBe('Too many requests');
    expect(error.statusCode).toBe(429);
    expect(error.isOperational).toBe(true);
    expect(error.name).toBe('RateLimitError');
  });

  it('should support context parameter', () => {
    const context = { limit: 100, window: '1m' };
    const error = new RateLimitError('Rate limit exceeded', context);

    expect(error.context).toEqual(context);
  });
});

describe('InternalError', () => {
  it('should create internal error with default status 500 and non-operational', () => {
    const error = new InternalError('Internal server error');

    expect(error.message).toBe('Internal server error');
    expect(error.statusCode).toBe(500);
    expect(error.isOperational).toBe(false);
    expect(error.name).toBe('InternalError');
  });

  it('should support context parameter', () => {
    const context = { service: 'database', error: 'connection failed' };
    const error = new InternalError('DB connection error', context);

    expect(error.context).toEqual(context);
  });
});

describe('isAppError', () => {
  it('should return true for AppError instances', () => {
    const error = new AppError('Test');
    expect(isAppError(error)).toBe(true);
  });

  it('should return true for AppError subclasses', () => {
    expect(isAppError(new ValidationError('Test'))).toBe(true);
    expect(isAppError(new AuthenticationError('Test'))).toBe(true);
    expect(isAppError(new AuthorizationError('Test'))).toBe(true);
    expect(isAppError(new NotFoundError('Test'))).toBe(true);
    expect(isAppError(new ConflictError('Test'))).toBe(true);
    expect(isAppError(new SecurityError('Test'))).toBe(true);
    expect(isAppError(new RateLimitError('Test'))).toBe(true);
    expect(isAppError(new InternalError('Test'))).toBe(true);
  });

  it('should return false for standard Error', () => {
    const error = new Error('Test');
    expect(isAppError(error)).toBe(false);
  });

  it('should return false for non-error values', () => {
    expect(isAppError(null)).toBe(false);
    expect(isAppError(undefined)).toBe(false);
    expect(isAppError('error')).toBe(false);
    expect(isAppError(123)).toBe(false);
    expect(isAppError({})).toBe(false);
  });
});

describe('formatErrorResponse', () => {
  it('should format error response with all fields', () => {
    const error = new AppError('Test error', 404, 'NOT_FOUND', true, { id: '123' });
    const response = formatErrorResponse(error);

    expect(response).toEqual({
      error: {
        message: 'Test error',
        code: 'AppError',
        statusCode: 404,
        context: { id: '123' },
      },
    });
  });

  it('should not include context for non-operational errors', () => {
    const error = new InternalError('Internal error', { stack: 'sensitive' });
    const response = formatErrorResponse(error);

    expect(response).toEqual({
      error: {
        message: 'Internal error',
        code: 'InternalError',
        statusCode: 500,
        context: undefined,
      },
    });
  });

  it('should use constructor name as code', () => {
    const validationError = new ValidationError('Invalid');
    const response = formatErrorResponse(validationError);

    expect(response.error.code).toBe('ValidationError');
  });

  it('should handle errors without context', () => {
    const error = new AppError('Simple error');
    const response = formatErrorResponse(error);

    expect(response.error.context).toBeUndefined();
  });
});

describe('Edge Cases', () => {
  it('should handle empty error messages', () => {
    const error = new AppError('');
    expect(error.message).toBe('');
  });

  it('should handle very long error messages', () => {
    const longMessage = 'x'.repeat(10000);
    const error = new AppError(longMessage);
    expect(error.message).toBe(longMessage);
  });

  it('should handle special characters in messages', () => {
    const message = 'Error: <script>alert("xss")</script>';
    const error = new AppError(message);
    expect(error.message).toBe(message);
  });

  it('should handle complex context objects', () => {
    const context = {
      nested: { deeply: { value: 123 } },
      array: [1, 2, 3],
      nullValue: null,
      undefinedValue: undefined,
    };
    const error = new AppError('Test', 500, undefined, undefined, context);
    expect(error.context).toEqual(context);
  });

  it('should maintain prototype chain for inheritance', () => {
    const error = new ValidationError('Test');
    expect(error).toBeInstanceOf(ValidationError);
    expect(error).toBeInstanceOf(AppError);
    expect(error).toBeInstanceOf(Error);
  });
});

describe('Error Code Usage Patterns', () => {
  it('should support database security error codes', () => {
    const errors = [
      new AppError('Invalid table', 403, 'INVALID_TABLE'),
      new AppError('Sensitive field', 403, 'SENSITIVE_FIELD'),
      new AppError('SQL keyword', 403, 'SQL_KEYWORD_IN_FIELD'),
      new AppError('Param limit', 400, 'PARAM_LIMIT_EXCEEDED'),
      new AppError('Param too long', 400, 'PARAM_TOO_LONG'),
      new AppError('SQL injection', 403, 'SQL_INJECTION'),
      new AppError('Cross tenant', 403, 'CROSS_TENANT_VIOLATION'),
      new AppError('Immutable', 403, 'BUSINESS_ID_IMMUTABLE'),
      new AppError('Unsafe delete', 403, 'UNSAFE_DELETE'),
      new AppError('No permission', 403, 'INSUFFICIENT_PERMISSIONS'),
      new AppError('Query too long', 400, 'QUERY_TOO_LONG'),
      new AppError('Dangerous op', 403, 'DANGEROUS_OPERATION'),
    ];

    errors.forEach(error => {
      expect(error.errorCode).toBeDefined();
      expect(typeof error.errorCode).toBe('string');
      expect(error.errorCode!.length).toBeGreaterThan(0);
    });
  });
});
