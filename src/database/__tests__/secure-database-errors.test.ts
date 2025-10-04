/**
 * SecureDatabase Error Handling Tests
 *
 * Tests that AppError constructor changes work correctly with secure-database
 * security validations and error codes.
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { SecureDatabase } from '../secure-database';
import { AppError } from '../../shared/errors/app-error';

describe('SecureDatabase Error Handling', () => {
  let secureDb: SecureDatabase;
  let mockD1Database: any;

  beforeEach(() => {
    mockD1Database = {
      prepare: vi.fn().mockReturnValue({
        bind: vi.fn().mockReturnThis(),
        all: vi.fn().mockResolvedValue({ results: [] }),
        run: vi.fn().mockResolvedValue({ success: true }),
      }),
    };

    secureDb = new SecureDatabase(mockD1Database, {
      businessId: 'test-business-123',
      userId: 'test-user-456',
      role: 'admin',
    });
  });

  describe('Table Name Validation', () => {
    it('should throw AppError with INVALID_TABLE error code for invalid table', async () => {
      try {
        await (secureDb as any).sanitizeTableName('invalid_table_name');
        expect.fail('Should have thrown AppError');
      } catch (error) {
        expect(error).toBeInstanceOf(AppError);
        expect((error as AppError).errorCode).toBe('INVALID_TABLE');
        expect((error as AppError).statusCode).toBe(403);
        expect((error as AppError).message).toContain('Invalid table name');
      }
    });

    it('should throw AppError with correct properties', async () => {
      try {
        await (secureDb as any).sanitizeTableName('DROP TABLE users;');
        expect.fail('Should have thrown AppError');
      } catch (error) {
        expect(error).toBeInstanceOf(AppError);
        expect((error as AppError).errorCode).toBe('INVALID_TABLE');
        expect((error as AppError).statusCode).toBe(403);
        expect((error as AppError).isOperational).toBe(true);
      }
    });
  });

  describe('Field Name Validation', () => {
    it('should throw AppError with SENSITIVE_FIELD error code', async () => {
      try {
        await (secureDb as any).sanitizeFieldNames(['password']);
        expect.fail('Should have thrown AppError');
      } catch (error) {
        expect(error).toBeInstanceOf(AppError);
        expect((error as AppError).errorCode).toBe('SENSITIVE_FIELD');
        expect((error as AppError).statusCode).toBe(403);
        expect((error as AppError).message).toContain('sensitive field');
      }
    });

    it('should throw AppError with SQL_KEYWORD_IN_FIELD error code', async () => {
      try {
        await (secureDb as any).sanitizeFieldNames(['select']);
        expect.fail('Should have thrown AppError');
      } catch (error) {
        expect(error).toBeInstanceOf(AppError);
        expect((error as AppError).errorCode).toBe('SQL_KEYWORD_IN_FIELD');
        expect((error as AppError).statusCode).toBe(403);
        expect((error as AppError).message).toContain('Invalid field name');
      }
    });

    it('should throw AppError for multiple SQL keywords', async () => {
      const keywords = ['select', 'from', 'where', 'union', 'drop'];

      for (const keyword of keywords) {
        try {
          await (secureDb as any).sanitizeFieldNames([keyword]);
          expect.fail(`Should have thrown AppError for keyword: ${keyword}`);
        } catch (error) {
          expect(error).toBeInstanceOf(AppError);
          expect((error as AppError).errorCode).toBe('SQL_KEYWORD_IN_FIELD');
        }
      }
    });
  });

  describe('Parameter Validation', () => {
    it('should throw AppError with PARAM_LIMIT_EXCEEDED error code', async () => {
      const tooManyParams = new Array(1001).fill('test');

      try {
        await (secureDb as any).validateParams(tooManyParams);
        expect.fail('Should have thrown AppError');
      } catch (error) {
        expect(error).toBeInstanceOf(AppError);
        expect((error as AppError).errorCode).toBe('PARAM_LIMIT_EXCEEDED');
        expect((error as AppError).statusCode).toBe(400);
      }
    });

    it('should throw AppError with PARAM_TOO_LONG error code', async () => {
      const longParam = 'x'.repeat(100001);

      try {
        await (secureDb as any).validateParams([longParam]);
        expect.fail('Should have thrown AppError');
      } catch (error) {
        expect(error).toBeInstanceOf(AppError);
        expect((error as AppError).errorCode).toBe('PARAM_TOO_LONG');
        expect((error as AppError).statusCode).toBe(400);
      }
    });

    it('should throw AppError with SQL_INJECTION error code for malicious input', async () => {
      const maliciousParams = [
        "'; DROP TABLE users; --",
        '1 OR 1=1',
        'admin\' --',
      ];

      for (const param of maliciousParams) {
        try {
          await (secureDb as any).validateParams([param]);
          expect.fail(`Should have thrown AppError for param: ${param}`);
        } catch (error) {
          expect(error).toBeInstanceOf(AppError);
          expect((error as AppError).errorCode).toBe('SQL_INJECTION');
          expect((error as AppError).statusCode).toBe(403);
        }
      }
    });
  });

  describe('Cross-Tenant Validation', () => {
    it('should throw AppError with CROSS_TENANT_VIOLATION error code', async () => {
      try {
        await secureDb.insert('companies', {
          id: 'comp-123',
          business_id: 'different-business-456', // Different from context
          name: 'Test Company',
        });
        expect.fail('Should have thrown AppError');
      } catch (error) {
        expect(error).toBeInstanceOf(AppError);
        expect((error as AppError).errorCode).toBe('CROSS_TENANT_VIOLATION');
        expect((error as AppError).statusCode).toBe(403);
      }
    });
  });

  describe('Business ID Immutability', () => {
    it('should throw AppError with BUSINESS_ID_IMMUTABLE error code', async () => {
      try {
        await secureDb.update(
          'companies',
          { business_id: 'new-business-789' }, // Trying to update business_id
          { id: 'comp-123' }
        );
        expect.fail('Should have thrown AppError');
      } catch (error) {
        expect(error).toBeInstanceOf(AppError);
        expect((error as AppError).errorCode).toBe('BUSINESS_ID_IMMUTABLE');
        expect((error as AppError).statusCode).toBe(403);
      }
    });
  });

  describe('Delete Safety', () => {
    it('should throw AppError with UNSAFE_DELETE error code for delete without conditions', async () => {
      try {
        await secureDb.delete('companies', {});
        expect.fail('Should have thrown AppError');
      } catch (error) {
        expect(error).toBeInstanceOf(AppError);
        expect((error as AppError).errorCode).toBe('UNSAFE_DELETE');
        expect((error as AppError).statusCode).toBe(403);
      }
    });
  });

  describe('Raw Query Permissions', () => {
    it('should throw AppError with INSUFFICIENT_PERMISSIONS for non-owner', async () => {
      const viewerDb = new SecureDatabase(mockD1Database, {
        businessId: 'test-business-123',
        userId: 'test-user-456',
        role: 'viewer', // Not owner or admin
      });

      try {
        await viewerDb.rawQuery('SELECT * FROM companies');
        expect.fail('Should have thrown AppError');
      } catch (error) {
        expect(error).toBeInstanceOf(AppError);
        expect((error as AppError).errorCode).toBe('INSUFFICIENT_PERMISSIONS');
        expect((error as AppError).statusCode).toBe(403);
      }
    });

    it('should throw AppError with QUERY_TOO_LONG for overly long queries', async () => {
      const longQuery = 'SELECT ' + 'column, '.repeat(10000) + ' FROM companies';

      try {
        await secureDb.rawQuery(longQuery);
        expect.fail('Should have thrown AppError');
      } catch (error) {
        expect(error).toBeInstanceOf(AppError);
        expect((error as AppError).errorCode).toBe('QUERY_TOO_LONG');
        expect((error as AppError).statusCode).toBe(400);
      }
    });

    it('should throw AppError with DANGEROUS_OPERATION for DROP/TRUNCATE', async () => {
      const dangerousQueries = [
        'DROP TABLE companies',
        'TRUNCATE TABLE users',
        'ALTER TABLE companies DROP COLUMN name',
      ];

      for (const query of dangerousQueries) {
        try {
          await secureDb.rawQuery(query);
          expect.fail(`Should have thrown AppError for query: ${query}`);
        } catch (error) {
          expect(error).toBeInstanceOf(AppError);
          expect((error as AppError).errorCode).toBe('DANGEROUS_OPERATION');
          expect((error as AppError).statusCode).toBe(403);
        }
      }
    });
  });

  describe('Error Code Consistency', () => {
    it('should have errorCode property on all thrown AppErrors', async () => {
      const testCases = [
        { fn: () => (secureDb as any).sanitizeTableName('invalid'), expectedCode: 'INVALID_TABLE' },
        { fn: () => (secureDb as any).sanitizeFieldNames(['password']), expectedCode: 'SENSITIVE_FIELD' },
        { fn: () => (secureDb as any).sanitizeFieldNames(['select']), expectedCode: 'SQL_KEYWORD_IN_FIELD' },
      ];

      for (const testCase of testCases) {
        try {
          await testCase.fn();
          expect.fail('Should have thrown AppError');
        } catch (error) {
          expect(error).toBeInstanceOf(AppError);
          expect((error as AppError).errorCode).toBe(testCase.expectedCode);
          expect((error as AppError).errorCode).toBeDefined();
          expect(typeof (error as AppError).errorCode).toBe('string');
        }
      }
    });

    it('should have consistent statusCode for similar error types', async () => {
      const securityErrors = [
        () => (secureDb as any).sanitizeTableName('invalid'),
        () => (secureDb as any).sanitizeFieldNames(['password']),
        () => (secureDb as any).sanitizeFieldNames(['select']),
      ];

      for (const errorFn of securityErrors) {
        try {
          await errorFn();
          expect.fail('Should have thrown AppError');
        } catch (error) {
          expect((error as AppError).statusCode).toBe(403);
        }
      }
    });

    it('should have isOperational=true for all security errors', async () => {
      const testCases = [
        () => (secureDb as any).sanitizeTableName('invalid'),
        () => (secureDb as any).sanitizeFieldNames(['password']),
        () => (secureDb as any).validateParams(['x'.repeat(100001)]),
      ];

      for (const errorFn of testCases) {
        try {
          await errorFn();
          expect.fail('Should have thrown AppError');
        } catch (error) {
          expect((error as AppError).isOperational).toBe(true);
        }
      }
    });
  });
});
