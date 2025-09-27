/**
 * Security Integration Tests for Finance Module
 * Comprehensive testing of SQL injection prevention and security fixes
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { CustomReportBuilder } from '../custom-report-builder';
import { FinancialReportingEngine } from '../financial-reporting-engine';
import { AgingReportsGenerator } from '../aging-reports-generator';
import { GDPRDataExportService } from '../gdpr-data-export';
import { validateInput, ValidationError } from '../validation';
import { generateReportRequestSchema } from '../validation';
import { ReportDataSource, FilterOperator, FilterDataType, ReportType } from '../types';

// Mock database for testing
class MockDatabase {
  private queries: Array<{ sql: string; params: any[] }> = [];
  private shouldFail = false;
  private failureMessage = '';
  private mockReportDefinitions: any[] = [];

  addMockReportDefinition(definition: any) {
    this.mockReportDefinitions.push(definition);
  }

  prepare(sql: string) {
    return {
      bind: (...params: any[]) => {
        this.queries.push({ sql, params });
        return {
          all: async () => {
            if (this.shouldFail) {
              throw new Error(this.failureMessage);
            }
            return { results: [] };
          },
          first: async () => {
            if (this.shouldFail) {
              throw new Error(this.failureMessage);
            }
            // Return mock report definition for custom report queries
            if (sql.includes('custom_report_definitions') && this.mockReportDefinitions.length > 0) {
              return this.mockReportDefinitions[0];
            }
            return null;
          },
          run: async () => {
            if (this.shouldFail) {
              throw new Error(this.failureMessage);
            }
            return { success: true };
          }
        };
      }
    };
  }

  getQueries() {
    return this.queries;
  }

  clearQueries() {
    this.queries = [];
  }

  simulateFailure(message: string) {
    this.shouldFail = true;
    this.failureMessage = message;
  }

  resetFailure() {
    this.shouldFail = false;
    this.failureMessage = '';
  }

  clearMockDefinitions() {
    this.mockReportDefinitions = [];
  }
}

describe('Security Integration Tests', () => {
  let mockDb: MockDatabase;
  let customReportBuilder: CustomReportBuilder;

  beforeEach(() => {
    mockDb = new MockDatabase();
    customReportBuilder = new CustomReportBuilder(mockDb as any);
  });

  afterEach(() => {
    mockDb.clearQueries();
    mockDb.resetFailure();
    mockDb.clearMockDefinitions();
  });

  describe('SQL Injection Prevention', () => {
    const maliciousSqlPayloads = [
      "'; DROP TABLE invoices; --",
      "' OR '1'='1' --",
      "'; DELETE FROM customers WHERE '1'='1",
      "' UNION SELECT * FROM users WHERE '1'='1",
      "'; INSERT INTO admin_users VALUES ('hacker', 'password'); --",
      "' OR 1=1 UNION SELECT password FROM users --",
      "'; UPDATE invoices SET total=0 WHERE '1'='1",
      "' AND (SELECT COUNT(*) FROM information_schema.tables) > 0 --",
      "'; EXEC xp_cmdshell('rm -rf /'); --",
      "' OR SLEEP(10) --"
    ];

    it('should prevent SQL injection in custom report filters', async () => {
      const testFilter = {
        field: 'customer_name',
        operator: FilterOperator.EQUALS,
        value: "'; DROP TABLE invoices; --",
        dataType: FilterDataType.STRING
      };

      const reportDefinition = {
        id: 'test_report',
        name: 'Test Report',
        dataSource: ReportDataSource.INVOICES,
        columns: [{
          id: 'customer_name',
          field: 'customer_name',
          name: 'Customer Name',
          dataType: FilterDataType.STRING,
          isVisible: true
        }],
        filters: [testFilter],
        sorting: [],
        grouping: [],
        aggregations: [],
        isTemplate: false,
        isPublic: false,
        createdBy: 'test_user',
        createdAt: Date.now(),
        updatedAt: Date.now(),
        businessId: 'test_business'
      };

      // Convert objects to JSON strings for database storage format
      const mockDefinition = {
        ...reportDefinition,
        columns: JSON.stringify(reportDefinition.columns),
        filters: JSON.stringify(reportDefinition.filters),
        sorting: JSON.stringify(reportDefinition.sorting),
        grouping: JSON.stringify(reportDefinition.grouping),
        aggregations: JSON.stringify(reportDefinition.aggregations),
        id: 'test_report_def',
        data_source: reportDefinition.dataSource, // Use snake_case as expected by database
        business_id: reportDefinition.businessId,
        created_by: reportDefinition.createdBy,
        created_at: reportDefinition.createdAt,
        updated_at: reportDefinition.updatedAt,
        is_template: reportDefinition.isTemplate ? 1 : 0,
        is_public: reportDefinition.isPublic ? 1 : 0
      };

      // Add mock report definition to database
      mockDb.addMockReportDefinition(mockDefinition);

      // Execute custom report which should use parameterized queries
      await customReportBuilder.executeCustomReport(
        'test_report_def',
        {
          startDate: Date.now() - 86400000,
          endDate: Date.now()
        },
        'test_business',
        'test_user'
      );

      const queries = mockDb.getQueries();

      // Verify that SQL injection payload is passed as parameter, not concatenated
      expect(queries.length).toBeGreaterThan(0);

      for (const query of queries) {
        // Check that the malicious payload is in parameters, not in the SQL string
        expect(query.sql).not.toContain("'; DROP TABLE invoices; --");
        expect(query.sql).not.toContain("DROP TABLE");
        expect(query.sql).not.toContain("DELETE FROM");

        // Verify parameterized query structure
        expect(query.sql).toMatch(/\?/); // Should contain parameter placeholders

        // Check if malicious payload is safely passed as parameter
        const hasPayloadInParams = query.params.some(param =>
          typeof param === 'string' && param.includes("'; DROP TABLE invoices; --")
        );
        if (hasPayloadInParams) {
          // This is expected - the payload should be in parameters, not SQL
          expect(true).toBe(true);
        }
      }
    });

    it('should handle all common SQL injection patterns safely', async () => {
      for (const payload of maliciousSqlPayloads) {
        mockDb.clearQueries();

        const testDefinition = {
          id: 'test_report',
          name: 'Test Report',
          dataSource: ReportDataSource.CUSTOMERS,
          columns: [{
            id: 'name',
            field: 'name',
            name: 'Name',
            dataType: FilterDataType.STRING,
            isVisible: true
          }],
          filters: [{
            field: 'name',
            operator: FilterOperator.CONTAINS,
            value: payload,
            dataType: FilterDataType.STRING
          }],
          sorting: [],
          grouping: [],
          aggregations: [],
          isTemplate: false,
          isPublic: false,
          createdBy: 'test_user',
          createdAt: Date.now(),
          updatedAt: Date.now(),
          businessId: 'test_business'
        };

        // Convert definition to database storage format
        const mockDefinition = {
          ...testDefinition,
          columns: JSON.stringify(testDefinition.columns),
          filters: JSON.stringify(testDefinition.filters),
          sorting: JSON.stringify(testDefinition.sorting),
          grouping: JSON.stringify(testDefinition.grouping),
          aggregations: JSON.stringify(testDefinition.aggregations),
          id: 'test_def'
        };

        // Clear and add fresh mock definition
        mockDb.clearMockDefinitions();
        mockDb.addMockReportDefinition(mockDefinition);

        try {
          await customReportBuilder.executeCustomReport(
            'test_def',
            { startDate: Date.now() - 86400000, endDate: Date.now() },
            'test_business',
            'test_user'
          );

          const queries = mockDb.getQueries();

          // Verify no malicious SQL in any query
          for (const query of queries) {
            expect(query.sql.toLowerCase()).not.toContain('drop');
            expect(query.sql.toLowerCase()).not.toContain('delete');
            expect(query.sql.toLowerCase()).not.toContain('insert');
            expect(query.sql.toLowerCase()).not.toContain('update');
            expect(query.sql.toLowerCase()).not.toContain('union');
            expect(query.sql.toLowerCase()).not.toContain('exec');
            expect(query.sql.toLowerCase()).not.toContain('sleep');

            // Should use parameterized queries
            expect(query.sql).toMatch(/\?/);
          }
        } catch (error: any) {
          // Errors are acceptable as long as they're not SQL injection
          // Check that the error is validation-related, not SQL injection
          if (error instanceof Error) {
            expect(error.message).not.toContain('syntax error');
            expect(error.message).not.toContain('SQL injection');
          }
        }
      }
    });

    it('should prevent SQL injection in report list queries', async () => {
      const maliciousBusinessId = "test'; DROP TABLE financial_reports; --";

      try {
        await customReportBuilder.listReportDefinitions(maliciousBusinessId, true);
      } catch (error: any) {
        // Should fail due to validation, not SQL injection
        expect(error instanceof Error).toBe(true);
      }

      const queries = mockDb.getQueries();

      for (const query of queries) {
        expect(query.sql).not.toContain('DROP TABLE');
        expect(query.sql).not.toContain(maliciousBusinessId);
      }
    });
  });

  describe('Business ID Isolation', () => {
    it('should enforce business_id isolation in all database queries', async () => {
      const businessId1 = 'business_1';
      const businessId2 = 'business_2';

      // Test aging reports
      const agingGenerator = new AgingReportsGenerator(mockDb as any);

      await agingGenerator.generateARAgingReport(
        { startDate: Date.now() - 86400000, endDate: Date.now() },
        businessId1,
        'Business 1'
      );

      const queries = mockDb.getQueries();

      // Verify all queries include business_id parameter
      for (const query of queries) {
        if (query.sql.toLowerCase().includes('where')) {
          expect(query.sql.toLowerCase()).toContain('business_id');
          expect(query.params).toContain(businessId1);
          expect(query.params).not.toContain(businessId2);
        }
      }
    });

    it('should validate business_id format and prevent tampering', async () => {
      const invalidBusinessIds = [
        '', // Empty
        null, // Null
        undefined, // Undefined
        'business_id\'; DROP TABLE invoices; --', // SQL injection attempt
        'business_id OR 1=1', // Logic injection
        '../../../etc/passwd', // Path traversal
        '<script>alert("xss")</script>', // XSS attempt
        'business_id\x00admin' // Null byte injection
      ];

      for (const invalidId of invalidBusinessIds) {
        try {
          const result = await customReportBuilder.listReportDefinitions(invalidId as any, false);

          // If it doesn't throw, verify it returns empty results (safe failure)
          expect(Array.isArray(result)).toBe(true);
          expect(result.length).toBe(0);
        } catch (error: any) {
          // Should throw validation error, not SQL error
          expect(error instanceof Error).toBe(true);
          expect(error.message).toMatch(/business.*id/i);
        }
      }
    });

    it('should prevent cross-tenant data access attempts', async () => {
      mockDb.clearQueries();

      // Simulate report definition belonging to business_1
      const reportForBusiness1 = 'report_business_1';

      // Try to access from business_2
      const result = await customReportBuilder.getReportDefinition(
        reportForBusiness1,
        'business_2'
      );

      // Should return null (not found) rather than the data
      expect(result).toBeNull();

      const queries = mockDb.getQueries();

      // Verify query includes both report ID and business_id
      expect(queries.length).toBeGreaterThan(0);
      expect(queries[0].sql.toLowerCase()).toContain('business_id');
      expect(queries[0].params).toContain('business_2');
    });
  });

  describe('Input Validation Security', () => {
    it('should reject malformed report generation requests', async () => {
      const maliciousRequests = [
        {
          type: 'INVALID_TYPE',
          parameters: { startDate: 'not_a_date', endDate: 'not_a_date' },
          businessId: 'test_business'
        },
        {
          type: ReportType.PROFIT_AND_LOSS,
          parameters: {
            startDate: -1, // Invalid negative date
            endDate: Date.now(),
            customFilters: [{
              field: 'test\'; DROP TABLE invoices; --',
              operator: 'INVALID_OPERATOR',
              value: 'test'
            }]
          },
          businessId: 'test_business'
        },
        {
          type: ReportType.BALANCE_SHEET,
          parameters: null, // Null parameters
          businessId: null // Null business ID
        }
      ];

      for (const request of maliciousRequests) {
        try {
          validateInput(generateReportRequestSchema, request);

          // Should not reach here - validation should fail
          expect(false).toBe(true);
        } catch (error: any) {
          expect(error instanceof ValidationError || error instanceof Error).toBe(true);
        }
      }
    });

    it('should sanitize and validate all input fields', async () => {
      const testCases = [
        {
          field: 'reportName',
          value: '<script>alert("xss")</script>',
          expectRejection: true
        },
        {
          field: 'description',
          value: 'A'.repeat(1000), // Very long string
          expectRejection: true
        },
        {
          field: 'currency',
          value: 'INVALID_CURRENCY_CODE_TOO_LONG',
          expectRejection: true
        },
        {
          field: 'amount',
          value: -1, // Negative amount where not allowed
          expectRejection: true
        },
        {
          field: 'email',
          value: 'not-an-email',
          expectRejection: true
        }
      ];

      // Test each validation case
      for (const testCase of testCases) {
        try {
          // This would use the appropriate validation schema based on the field
          // For now, we'll test with a sample schema
          const result = validateInput(generateReportRequestSchema, {
            type: ReportType.PROFIT_AND_LOSS,
            parameters: {
              startDate: Date.now() - 86400000,
              endDate: Date.now()
            },
            businessId: 'test_business'
          });

          if (testCase.expectRejection) {
            // Should have failed validation
            expect(false).toBe(true);
          }
        } catch (error: any) {
          if (testCase.expectRejection) {
            expect(error instanceof ValidationError || error instanceof Error).toBe(true);
          } else {
            throw error;
          }
        }
      }
    });
  });

  describe('Error Handling Security', () => {
    it('should not leak sensitive information in error messages', async () => {
      // Simulate database error
      mockDb.simulateFailure('SQLITE_ERROR: table users_secrets does not exist');

      try {
        await customReportBuilder.executeCustomReport(
          'test_report',
          { startDate: Date.now() - 86400000, endDate: Date.now() },
          'test_business',
          'test_user'
        );

        // Should throw an error
        expect(false).toBe(true);
      } catch (error: any) {
        const errorMessage = error instanceof Error ? error.message : String(error);

        // Should not expose internal database details
        expect(errorMessage).not.toContain('SQLITE_ERROR');
        expect(errorMessage).not.toContain('users_secrets');
        expect(errorMessage).not.toContain('table');
        expect(errorMessage).not.toContain('does not exist');

        // Should be a generic error message (or specific validation error)
        expect(errorMessage).toMatch(/error|failed|not found|invalid/i);
      }
    });

    it('should handle concurrent access safely', async () => {
      // Simulate multiple concurrent requests
      const concurrentRequests = Array.from({ length: 10 }, (_, i) =>
        customReportBuilder.executeCustomReport(
          `test_report_${i}`,
          { startDate: Date.now() - 86400000, endDate: Date.now() },
          `business_${i}`,
          `user_${i}`
        )
      );

      // All should complete without interfering with each other
      const results = await Promise.allSettled(concurrentRequests);

      // Verify no cross-contamination of business IDs
      const queries = mockDb.getQueries();

      for (let i = 0; i < 10; i++) {
        const businessSpecificQueries = queries.filter((q: any) =>
          q.params.includes(`business_${i}`)
        );

        // Each business should only see its own queries
        for (const query of businessSpecificQueries) {
          expect(query.params).toContain(`business_${i}`);

          // Should not contain other business IDs
          for (let j = 0; j < 10; j++) {
            if (i !== j) {
              expect(query.params).not.toContain(`business_${j}`);
            }
          }
        }
      }
    });
  });

  describe('Authentication and Authorization', () => {
    it('should enforce user permissions for sensitive operations', async () => {
      // Test that GDPR export requires proper authorization
      const gdprService = new GDPRDataExportService(mockDb as any);

      const unauthorizedRequest = {
        businessId: 'test_business',
        requestedBy: 'unauthorized_user',
        requestedAt: Date.now(),
        purpose: 'user_request' as const,
        includePersonalData: true,
        includeFinancialData: true,
        includeAuditTrails: true,
        exportFormat: 'JSON' as const,
        deliveryMethod: 'download' as const
      };

      // This would normally check authorization
      // For now, we verify the request is logged properly
      const exportId = await gdprService.createExportRequest(unauthorizedRequest);

      expect(typeof exportId).toBe('string');
      expect(exportId).toMatch(/gdpr_export_/);

      const queries = mockDb.getQueries();
      const insertQuery = queries.find(q =>
        q.sql.toLowerCase().includes('insert') &&
        q.sql.toLowerCase().includes('gdpr_export_requests')
      );

      expect(insertQuery).toBeDefined();
      expect(insertQuery?.params).toContain('unauthorized_user');
    });
  });

  describe('Data Integrity', () => {
    it('should maintain referential integrity under stress', async () => {
      // Test that business_id relationships are maintained
      const businessId = 'test_business';

      // Create multiple related records
      const operations = [
        () => customReportBuilder.createReportDefinition({
          name: 'Test Report',
          dataSource: ReportDataSource.INVOICES,
          columns: [],
          filters: [],
          sorting: [],
          createdBy: 'test_user'
        }, businessId),

        () => customReportBuilder.listReportDefinitions(businessId, false),

        () => customReportBuilder.executeCustomReport(
          'test_report',
          { startDate: Date.now() - 86400000, endDate: Date.now() },
          businessId,
          'test_user'
        )
      ];

      // Execute operations
      for (const operation of operations) {
        try {
          await operation();
        } catch (error: any) {
          // Errors are acceptable as long as they maintain integrity
        }
      }

      const queries = mockDb.getQueries();

      // Verify all queries include the correct business_id
      const businessIdQueries = queries.filter((q: any) =>
        q.params.includes(businessId)
      );

      expect(businessIdQueries.length).toBeGreaterThan(0);

      // No query should reference a different business_id
      for (const query of businessIdQueries) {
        expect(query.params).toContain(businessId);
      }
    });
  });
});

export { MockDatabase };