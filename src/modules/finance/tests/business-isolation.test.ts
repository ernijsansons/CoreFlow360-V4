/**
 * Business ID Isolation Tests
 * Comprehensive testing to ensure strict multi-tenant data isolation
 */

import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { MockDatabase } from './security-integration.test';
import { FinancialReportingEngine } from '../financial-reporting-engine';
import { AgingReportsGenerator } from '../aging-reports-generator';
import { CustomReportBuilder } from '../custom-report-builder';
import { GDPRDataExportService } from '../gdpr-data-export';
import { FinanceAuditLogger } from '../audit-logger';
import { ReportType, ReportDataSource, FilterOperator, FilterDataType } from '../types';

describe('Business ID Isolation Tests', () => {
  let mockDb: MockDatabase;
  let reportingEngine: FinancialReportingEngine;
  let agingGenerator: AgingReportsGenerator;
  let customReportBuilder: CustomReportBuilder;
  let gdprService: GDPRDataExportService;
  let auditLogger: FinanceAuditLogger;

  const BUSINESS_A = 'business_a_12345';
  const BUSINESS_B = 'business_b_67890';
  const BUSINESS_C = 'business_c_54321';

  beforeEach(() => {
    mockDb = new MockDatabase();
    auditLogger = new FinanceAuditLogger(mockDb as any);
    reportingEngine = new FinancialReportingEngine(mockDb as any, auditLogger);
    agingGenerator = new AgingReportsGenerator(mockDb as any);
    customReportBuilder = new CustomReportBuilder(mockDb as any);
    gdprService = new GDPRDataExportService(mockDb as any);
  });

  afterEach(() => {
    mockDb.clearQueries();
    mockDb.resetFailure();
  });

  describe('Financial Reporting Engine Isolation', () => {
    it('should isolate report generation by business_id', async () => {
      const reportRequest = {
        type: ReportType.PROFIT_AND_LOSS,
        parameters: {
          startDate: Date.now() - 86400000 * 30,
          endDate: Date.now()
        }
      };

      try {
        // Generate reports for different businesses
        await reportingEngine.generateReport(reportRequest, 'user_a', BUSINESS_A);
        await reportingEngine.generateReport(reportRequest, 'user_b', BUSINESS_B);
      } catch (error) {
        // Errors are acceptable for testing
      }

      const queries = mockDb.getQueries();

      // Verify business isolation in all queries
      const businessAQueries = queries.filter(q => q.params.includes(BUSINESS_A));
      const businessBQueries = queries.filter(q => q.params.includes(BUSINESS_B));

      expect(businessAQueries.length).toBeGreaterThan(0);
      expect(businessBQueries.length).toBeGreaterThan(0);

      // Business A queries should not contain Business B ID and vice versa
      for (const query of businessAQueries) {
        expect(query.params).toContain(BUSINESS_A);
        expect(query.params).not.toContain(BUSINESS_B);
        expect(query.params).not.toContain(BUSINESS_C);
      }

      for (const query of businessBQueries) {
        expect(query.params).toContain(BUSINESS_B);
        expect(query.params).not.toContain(BUSINESS_A);
        expect(query.params).not.toContain(BUSINESS_C);
      }
    });

    it('should prevent cross-business report access', async () => {
      mockDb.clearQueries();

      // Try to get a report that belongs to Business A using Business B credentials
      const reportId = 'report_belonging_to_business_a';

      const result = await reportingEngine.getReport(reportId, BUSINESS_B);

      // Should return null (not found) rather than the actual report
      expect(result).toBeNull();

      const queries = mockDb.getQueries();
      expect(queries.length).toBeGreaterThan(0);

      // Verify the query includes Business B ID, not Business A
      const selectQuery = queries.find(q => q.sql.toLowerCase().includes('select'));
      expect(selectQuery).toBeDefined();
      expect(selectQuery?.params).toContain(BUSINESS_B);
      expect(selectQuery?.params).not.toContain(BUSINESS_A);
    });

    it('should isolate report lists by business', async () => {
      mockDb.clearQueries();

      // List reports for different businesses
      await reportingEngine.listReports(BUSINESS_A);
      await reportingEngine.listReports(BUSINESS_B);

      const queries = mockDb.getQueries();

      // Each list operation should only query its own business
      const businessAListQueries = queries.filter(q =>
        q.params.includes(BUSINESS_A) && q.sql.toLowerCase().includes('select')
      );
      const businessBListQueries = queries.filter(q =>
        q.params.includes(BUSINESS_B) && q.sql.toLowerCase().includes('select')
      );

      expect(businessAListQueries.length).toBeGreaterThan(0);
      expect(businessBListQueries.length).toBeGreaterThan(0);

      // Verify no cross-contamination
      for (const query of businessAListQueries) {
        expect(query.params).not.toContain(BUSINESS_B);
      }

      for (const query of businessBListQueries) {
        expect(query.params).not.toContain(BUSINESS_A);
      }
    });
  });

  describe('Aging Reports Isolation', () => {
    it('should generate AR aging reports with strict business isolation', async () => {
      mockDb.clearQueries();

      const reportParams = {
        startDate: Date.now() - 86400000 * 90,
        endDate: Date.now()
      };

      try {
        await agingGenerator.generateARAgingReport(reportParams, BUSINESS_A, 'Business A');
        await agingGenerator.generateARAgingReport(reportParams, BUSINESS_B, 'Business B');
      } catch (error) {
        // Errors acceptable for testing
      }

      const queries = mockDb.getQueries();

      // Find invoice queries (main data source for AR aging)
      const invoiceQueries = queries.filter(q =>
        q.sql.toLowerCase().includes('invoices') && q.sql.toLowerCase().includes('where')
      );

      expect(invoiceQueries.length).toBeGreaterThan(0);

      // Each invoice query should include business_id constraint
      for (const query of invoiceQueries) {
        expect(query.sql.toLowerCase()).toMatch(/business_id\s*=\s*\?/);

        // Should contain exactly one business ID
        const businessIds = [BUSINESS_A, BUSINESS_B, BUSINESS_C];
        const foundBusinessIds = businessIds.filter(id => query.params.includes(id));
        expect(foundBusinessIds.length).toBe(1);
      }
    });

    it('should prevent access to invoices from other businesses', async () => {
      mockDb.clearQueries();

      // Simulate scenario where user tries to access aging report with wrong business context
      try {
        await agingGenerator.generateARAgingReport(
          {
            startDate: Date.now() - 86400000 * 30,
            endDate: Date.now(),
            customerIds: ['customer_from_business_a'] // Customer from different business
          },
          BUSINESS_B, // But using Business B context
          'Business B'
        );
      } catch (error) {
        // Expected to fail or return empty results
      }

      const queries = mockDb.getQueries();

      // All queries should enforce Business B isolation
      const dataQueries = queries.filter(q =>
        q.sql.toLowerCase().includes('where') && q.sql.toLowerCase().includes('business_id')
      );

      for (const query of dataQueries) {
        expect(query.params).toContain(BUSINESS_B);
        expect(query.params).not.toContain(BUSINESS_A);
      }
    });
  });

  describe('Custom Report Builder Isolation', () => {
    it('should enforce business isolation in custom report execution', async () => {
      mockDb.clearQueries();

      const customReportParams = {
        startDate: Date.now() - 86400000 * 30,
        endDate: Date.now(),
        customFilters: [{
          field: 'customer_name',
          operator: FilterOperator.CONTAINS,
          value: 'test',
          dataType: FilterDataType.STRING
        }]
      };

      try {
        await customReportBuilder.executeCustomReport(
          'report_def_business_a',
          customReportParams,
          BUSINESS_A,
          'user_a'
        );

        await customReportBuilder.executeCustomReport(
          'report_def_business_b',
          customReportParams,
          BUSINESS_B,
          'user_b'
        );
      } catch (error) {
        // Acceptable for testing
      }

      const queries = mockDb.getQueries();

      // Verify business isolation in all generated queries
      const businessAQueries = queries.filter(q => q.params.includes(BUSINESS_A));
      const businessBQueries = queries.filter(q => q.params.includes(BUSINESS_B));

      expect(businessAQueries.length).toBeGreaterThan(0);
      expect(businessBQueries.length).toBeGreaterThan(0);

      // No cross-contamination
      for (const query of businessAQueries) {
        expect(query.params).not.toContain(BUSINESS_B);
      }

      for (const query of businessBQueries) {
        expect(query.params).not.toContain(BUSINESS_A);
      }
    });

    it('should prevent access to report definitions from other businesses', async () => {
      mockDb.clearQueries();

      // Try to get report definition that belongs to Business A using Business B context
      const result = await customReportBuilder.getReportDefinition(
        'report_def_business_a',
        BUSINESS_B
      );

      expect(result).toBeNull();

      const queries = mockDb.getQueries();
      const selectQuery = queries.find(q =>
        q.sql.toLowerCase().includes('custom_report_definitions')
      );

      expect(selectQuery).toBeDefined();
      expect(selectQuery?.params).toContain(BUSINESS_B);
      expect(selectQuery?.params).not.toContain(BUSINESS_A);
    });

    it('should isolate report definition lists by business', async () => {
      mockDb.clearQueries();

      // List report definitions for different businesses
      await customReportBuilder.listReportDefinitions(BUSINESS_A, false);
      await customReportBuilder.listReportDefinitions(BUSINESS_B, false);

      const queries = mockDb.getQueries();

      const listQueries = queries.filter(q =>
        q.sql.toLowerCase().includes('custom_report_definitions') &&
        q.sql.toLowerCase().includes('where')
      );

      expect(listQueries.length).toBeGreaterThan(0);

      // Each query should be isolated to its business
      const businessAListQueries = listQueries.filter(q => q.params.includes(BUSINESS_A));
      const businessBListQueries = listQueries.filter(q => q.params.includes(BUSINESS_B));

      expect(businessAListQueries.length).toBeGreaterThan(0);
      expect(businessBListQueries.length).toBeGreaterThan(0);

      // Verify isolation
      for (const query of businessAListQueries) {
        expect(query.params).not.toContain(BUSINESS_B);
      }

      for (const query of businessBListQueries) {
        expect(query.params).not.toContain(BUSINESS_A);
      }
    });
  });

  describe('GDPR Export Isolation', () => {
    it('should isolate GDPR exports by business', async () => {
      mockDb.clearQueries();

      const gdprRequest = {
        businessId: BUSINESS_A,
        requestedBy: 'user_a',
        requestedAt: Date.now(),
        purpose: 'user_request' as const,
        includePersonalData: true,
        includeFinancialData: true,
        includeAuditTrails: false,
        exportFormat: 'JSON' as const,
        deliveryMethod: 'download' as const
      };

      const exportId = await gdprService.createExportRequest(gdprRequest);

      expect(typeof exportId).toBe('string');

      const queries = mockDb.getQueries();

      // Verify the export request is stored with correct business isolation
      const insertQuery = queries.find(q =>
        q.sql.toLowerCase().includes('insert') &&
        q.sql.toLowerCase().includes('gdpr_export_requests')
      );

      expect(insertQuery).toBeDefined();
      expect(insertQuery?.params).toContain(BUSINESS_A);
      expect(insertQuery?.params).not.toContain(BUSINESS_B);
    });

    it('should prevent access to GDPR exports from other businesses', async () => {
      mockDb.clearQueries();

      // Try to get export status for Business A export using Business B context
      const result = await gdprService.getExportStatus(
        'export_belonging_to_business_a',
        BUSINESS_B
      );

      expect(result).toBeNull();

      const queries = mockDb.getQueries();
      const selectQuery = queries.find(q =>
        q.sql.toLowerCase().includes('gdpr_export_requests')
      );

      expect(selectQuery).toBeDefined();
      expect(selectQuery?.params).toContain(BUSINESS_B);
      expect(selectQuery?.params).not.toContain(BUSINESS_A);
    });

    it('should list only business-specific GDPR exports', async () => {
      mockDb.clearQueries();

      // List exports for different businesses
      await gdprService.listExportRequests(BUSINESS_A);
      await gdprService.listExportRequests(BUSINESS_B);

      const queries = mockDb.getQueries();

      const listQueries = queries.filter(q =>
        q.sql.toLowerCase().includes('gdpr_export_requests') &&
        q.sql.toLowerCase().includes('where')
      );

      expect(listQueries.length).toBeGreaterThan(0);

      // Verify each list query is isolated
      const businessAListQueries = listQueries.filter(q => q.params.includes(BUSINESS_A));
      const businessBListQueries = listQueries.filter(q => q.params.includes(BUSINESS_B));

      expect(businessAListQueries.length).toBeGreaterThan(0);
      expect(businessBListQueries.length).toBeGreaterThan(0);

      // No cross-contamination
      for (const query of businessAListQueries) {
        expect(query.params).not.toContain(BUSINESS_B);
      }

      for (const query of businessBListQueries) {
        expect(query.params).not.toContain(BUSINESS_A);
      }
    });
  });

  describe('Audit Logger Isolation', () => {
    it('should maintain audit trail isolation by business', async () => {
      mockDb.clearQueries();

      // Log activities for different businesses
      await auditLogger.logActivity(
        'invoice',
        'inv_123',
        'CREATE',
        { amount: 1000 },
        'user_a',
        BUSINESS_A
      );

      await auditLogger.logActivity(
        'invoice',
        'inv_456',
        'UPDATE',
        { amount: 2000 },
        'user_b',
        BUSINESS_B
      );

      const queries = mockDb.getQueries();

      const auditInserts = queries.filter(q =>
        q.sql.toLowerCase().includes('insert') &&
        q.sql.toLowerCase().includes('audit_logs')
      );

      expect(auditInserts.length).toBe(2);

      // Verify each audit entry is associated with correct business
      const businessAAudit = auditInserts.find(q => q.params.includes(BUSINESS_A));
      const businessBAudit = auditInserts.find(q => q.params.includes(BUSINESS_B));

      expect(businessAAudit).toBeDefined();
      expect(businessBAudit).toBeDefined();

      expect(businessAAudit?.params).not.toContain(BUSINESS_B);
      expect(businessBAudit?.params).not.toContain(BUSINESS_A);
    });

    it('should retrieve audit trails only for authorized business', async () => {
      mockDb.clearQueries();

      // Get audit trail for specific business
      await auditLogger.getAuditTrail('invoice', 'inv_123', BUSINESS_A);

      const queries = mockDb.getQueries();

      const selectQuery = queries.find(q =>
        q.sql.toLowerCase().includes('select') &&
        q.sql.toLowerCase().includes('audit_logs')
      );

      expect(selectQuery).toBeDefined();
      expect(selectQuery?.params).toContain(BUSINESS_A);
      expect(selectQuery?.params).not.toContain(BUSINESS_B);
      expect(selectQuery?.params).not.toContain(BUSINESS_C);
    });
  });

  describe('Edge Cases and Attack Scenarios', () => {
    it('should handle business_id manipulation attempts', async () => {
      const manipulationAttempts = [
        `${BUSINESS_A}' OR business_id='${BUSINESS_B}`, // SQL injection attempt
        `${BUSINESS_A}'; DROP TABLE invoices; --`, // Destructive attempt
        `${BUSINESS_A} UNION SELECT * FROM invoices WHERE business_id='${BUSINESS_B}'`, // Union attack
        `${BUSINESS_A}%' OR '1'='1`, // Wildcard injection
        `${BUSINESS_A}\x00${BUSINESS_B}` // Null byte injection
      ];

      for (const maliciousBusinessId of manipulationAttempts) {
        mockDb.clearQueries();

        try {
          await customReportBuilder.listReportDefinitions(maliciousBusinessId, false);
        } catch (error) {
          // Should fail due to validation, not execute malicious query
        }

        const queries = mockDb.getQueries();

        // If any queries were executed, they should not contain malicious SQL
        for (const query of queries) {
          expect(query.sql).not.toContain('DROP TABLE');
          expect(query.sql).not.toContain('UNION SELECT');
          expect(query.sql).not.toContain("OR '1'='1'");

          // Should use parameterized queries
          if (query.params.length > 0) {
            expect(query.sql).toMatch(/\?/);
          }
        }
      }
    });

    it('should prevent timing attacks for business existence', async () => {
      const startTime = Date.now();

      // Try to access non-existent business
      const result1 = await customReportBuilder.getReportDefinition(
        'non_existent_report',
        'non_existent_business'
      );

      const midTime = Date.now();

      // Try to access existing business but non-existent report
      const result2 = await customReportBuilder.getReportDefinition(
        'non_existent_report',
        BUSINESS_A
      );

      const endTime = Date.now();

      // Both should return null
      expect(result1).toBeNull();
      expect(result2).toBeNull();

      // Timing should be similar (no significant difference)
      const time1 = midTime - startTime;
      const time2 = endTime - midTime;

      // Allow for some variance but should be roughly similar
      const timeDifference = Math.abs(time1 - time2);
      expect(timeDifference).toBeLessThan(100); // 100ms tolerance
    });

    it('should handle concurrent access from different businesses', async () => {
      const concurrentOperations = [
        () => customReportBuilder.listReportDefinitions(BUSINESS_A, false),
        () => customReportBuilder.listReportDefinitions(BUSINESS_B, false),
        () => customReportBuilder.listReportDefinitions(BUSINESS_C, false),
        () => agingGenerator.generateARAgingReport(
          { startDate: Date.now() - 86400000, endDate: Date.now() },
          BUSINESS_A,
          'Business A'
        ),
        () => agingGenerator.generateARAgingReport(
          { startDate: Date.now() - 86400000, endDate: Date.now() },
          BUSINESS_B,
          'Business B'
        )
      ];

      // Execute all operations concurrently
      const results = await Promise.allSettled(concurrentOperations);

      const queries = mockDb.getQueries();

      // Verify no cross-contamination occurred
      const businessAQueries = queries.filter(q => q.params.includes(BUSINESS_A));
      const businessBQueries = queries.filter(q => q.params.includes(BUSINESS_B));
      const businessCQueries = queries.filter(q => q.params.includes(BUSINESS_C));

      // Each business should have its own isolated queries
      for (const query of businessAQueries) {
        expect(query.params).not.toContain(BUSINESS_B);
        expect(query.params).not.toContain(BUSINESS_C);
      }

      for (const query of businessBQueries) {
        expect(query.params).not.toContain(BUSINESS_A);
        expect(query.params).not.toContain(BUSINESS_C);
      }

      for (const query of businessCQueries) {
        expect(query.params).not.toContain(BUSINESS_A);
        expect(query.params).not.toContain(BUSINESS_B);
      }
    });
  });
});