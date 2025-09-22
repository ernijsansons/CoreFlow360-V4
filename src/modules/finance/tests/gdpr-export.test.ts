/**
 * GDPR Data Export Functionality Tests
 * Testing comprehensive data export capabilities with sample data
 */

import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import {
  GDPRDataExportService,
  GDPRExportRequest,
  PersonalDataRecord,
  FinancialDataRecord,
  AuditTrailRecord
} from '../gdpr-data-export';
import { MockDatabase } from './security-integration.test';

// Mock R2 Bucket for testing
class MockR2Bucket {
  private objects: Map<string, { content: string; metadata: any }> = new Map();

  async put(key: string, value: string | ArrayBuffer, options?: any): Promise<void> {
    const content = typeof value === 'string' ? value : new TextDecoder().decode(value);
    this.objects.set(key, {
      content,
      metadata: options?.httpMetadata || {}
    });
  }

  async get(key: string): Promise<{ body?: ReadableStream; httpMetadata?: any } | null> {
    const object = this.objects.get(key);
    if (!object) return null;

    return {
      body: new ReadableStream({
        start(controller) {
          controller.enqueue(new TextEncoder().encode(object.content));
          controller.close();
        }
      }),
      httpMetadata: object.metadata
    };
  }

  async delete(key: string): Promise<void> {
    this.objects.delete(key);
  }

  // Test helper methods
  getStoredObject(key: string): { content: string; metadata: any } | undefined {
    return this.objects.get(key);
  }

  getStoredKeys(): string[] {
    return Array.from(this.objects.keys());
  }

  clear(): void {
    this.objects.clear();
  }

  size(): number {
    return this.objects.size;
  }
}

describe('GDPR Data Export Tests', () => {
  let mockDb: MockDatabase;
  let mockR2: MockR2Bucket;
  let gdprService: GDPRDataExportService;

  // Sample test data
  const sampleCustomers = [
    {
      id: 'cust_001',
      name: 'John Smith',
      email: 'john.smith@example.com',
      phone: '+1-555-0123',
      address: '123 Main St, Anytown, ST 12345',
      tax_id: 'TAX123456',
      created_at: Date.now() - 86400000 * 365, // 1 year ago
      updated_at: Date.now() - 86400000 * 30,   // 30 days ago
      business_id: 'business_123'
    },
    {
      id: 'cust_002',
      name: 'Jane Doe',
      email: 'jane.doe@example.com',
      phone: '+1-555-0456',
      address: '456 Oak Ave, Another City, ST 67890',
      tax_id: 'TAX789012',
      created_at: Date.now() - 86400000 * 180, // 6 months ago
      updated_at: Date.now() - 86400000 * 7,    // 1 week ago
      business_id: 'business_123'
    }
  ];

  const sampleInvoices = [
    {
      id: 'inv_001',
      invoice_number: 'INV-2024-001',
      customer_id: 'cust_001',
      customer_name: 'John Smith',
      total: 1500.00,
      currency: 'USD',
      status: 'PAID',
      issue_date: Date.now() - 86400000 * 60,
      due_date: Date.now() - 86400000 * 30,
      created_at: Date.now() - 86400000 * 60,
      updated_at: Date.now() - 86400000 * 30,
      business_id: 'business_123'
    },
    {
      id: 'inv_002',
      invoice_number: 'INV-2024-002',
      customer_id: 'cust_002',
      customer_name: 'Jane Doe',
      total: 2750.50,
      currency: 'USD',
      status: 'SENT',
      issue_date: Date.now() - 86400000 * 15,
      due_date: Date.now() + 86400000 * 15,
      created_at: Date.now() - 86400000 * 15,
      updated_at: Date.now() - 86400000 * 10,
      business_id: 'business_123'
    }
  ];

  const sampleAuditLogs = [
    {
      id: 'audit_001',
      entity_type: 'invoice',
      entity_id: 'inv_001',
      action: 'CREATE',
      changes: JSON.stringify({ total: 1500.00, status: 'DRAFT' }),
      performed_by: 'user_123',
      performed_at: Date.now() - 86400000 * 60,
      ip_address: '192.168.1.100',
      user_agent: 'Mozilla/5.0...',
      business_id: 'business_123'
    },
    {
      id: 'audit_002',
      entity_type: 'invoice',
      entity_id: 'inv_001',
      action: 'UPDATE',
      changes: JSON.stringify({ status: { from: 'DRAFT', to: 'SENT' } }),
      performed_by: 'user_123',
      performed_at: Date.now() - 86400000 * 45,
      ip_address: '192.168.1.100',
      user_agent: 'Mozilla/5.0...',
      business_id: 'business_123'
    }
  ];

  beforeEach(() => {
    mockDb = new MockDatabase();
    mockR2 = new MockR2Bucket();
    gdprService = new GDPRDataExportService(mockDb as any, mockR2 as any);

    // Setup mock database responses
    setupMockDatabaseResponses();
  });

  afterEach(() => {
    mockDb.clearQueries();
    mockDb.resetFailure();
    mockR2.clear();
  });

  function setupMockDatabaseResponses() {
    // Mock the database to return sample data
    const originalPrepare = mockDb.prepare.bind(mockDb);
    mockDb.prepare = function(sql: string) {
      const prepared = originalPrepare(sql);
      const originalBind = prepared.bind.bind(prepared);

      prepared.bind = function(...params: any[]) {
        const bound = originalBind(...params);
        const originalAll = bound.all.bind(bound);
        const originalFirst = bound.first.bind(bound);

        // Override responses based on SQL queries
        bound.all = async function() {
          if (sql.includes('customers') && sql.includes('SELECT')) {
            return { results: sampleCustomers };
          }
          if (sql.includes('invoices') && sql.includes('SELECT')) {
            return { results: sampleInvoices };
          }
          if (sql.includes('audit_logs') && sql.includes('SELECT')) {
            return { results: sampleAuditLogs };
          }
          if (sql.includes('gdpr_export_requests') && sql.includes('SELECT')) {
            return { results: [] };
          }
          return originalAll();
        };

        bound.first = async function() {
          if (sql.includes('gdpr_export_requests') && sql.includes('SELECT')) {
            return null; // Simulate no existing export
          }
          return originalFirst();
        };

        return bound;
      };

      return prepared;
    };
  }

  describe('Export Request Creation', () => {
    it('should create GDPR export request successfully', async () => {
      const exportRequest: GDPRExportRequest = {
        businessId: 'business_123',
        requestedBy: 'user_123',
        requestedAt: Date.now(),
        purpose: 'user_request',
        includePersonalData: true,
        includeFinancialData: true,
        includeAuditTrails: true,
        exportFormat: 'JSON',
        deliveryMethod: 'download'
      };

      const exportId = await gdprService.createExportRequest(exportRequest);

      expect(typeof exportId).toBe('string');
      expect(exportId).toMatch(/^gdpr_export_\d+_[a-z0-9]+$/);

      const queries = mockDb.getQueries();
      const insertQuery = queries.find(q =>
        q.sql.includes('INSERT') && q.sql.includes('gdpr_export_requests')
      );

      expect(insertQuery).toBeDefined();
      expect(insertQuery?.params).toContain('business_123');
      expect(insertQuery?.params).toContain('user_123');
      expect(insertQuery?.params).toContain('user_request');
    });

    it('should validate business ID in export request', async () => {
      const invalidRequest: GDPRExportRequest = {
        businessId: '', // Invalid empty business ID
        requestedBy: 'user_123',
        requestedAt: Date.now(),
        purpose: 'user_request',
        includePersonalData: true,
        includeFinancialData: false,
        includeAuditTrails: false,
        exportFormat: 'JSON',
        deliveryMethod: 'download'
      };

      await expect(gdprService.createExportRequest(invalidRequest))
        .rejects.toThrow();
    });

    it('should handle different export purposes', async () => {
      const purposes: Array<'user_request' | 'legal_obligation' | 'compliance_audit'> = [
        'user_request',
        'legal_obligation',
        'compliance_audit'
      ];

      for (const purpose of purposes) {
        mockDb.clearQueries();

        const exportRequest: GDPRExportRequest = {
          businessId: 'business_123',
          requestedBy: 'user_123',
          requestedAt: Date.now(),
          purpose,
          includePersonalData: true,
          includeFinancialData: true,
          includeAuditTrails: true,
          exportFormat: 'JSON',
          deliveryMethod: 'download'
        };

        const exportId = await gdprService.createExportRequest(exportRequest);
        expect(exportId).toBeDefined();

        const queries = mockDb.getQueries();
        const insertQuery = queries.find(q => q.sql.includes('INSERT'));
        expect(insertQuery?.params).toContain(purpose);
      }
    });

    it('should handle different export formats', async () => {
      const formats: Array<'JSON' | 'CSV' | 'XML'> = ['JSON', 'CSV', 'XML'];

      for (const format of formats) {
        mockDb.clearQueries();

        const exportRequest: GDPRExportRequest = {
          businessId: 'business_123',
          requestedBy: 'user_123',
          requestedAt: Date.now(),
          purpose: 'user_request',
          includePersonalData: true,
          includeFinancialData: false,
          includeAuditTrails: false,
          exportFormat: format,
          deliveryMethod: 'download'
        };

        const exportId = await gdprService.createExportRequest(exportRequest);
        expect(exportId).toBeDefined();

        const queries = mockDb.getQueries();
        const insertQuery = queries.find(q => q.sql.includes('INSERT'));
        expect(insertQuery?.params).toContain(format);
      }
    });
  });

  describe('Data Collection and Processing', () => {
    it('should collect personal data correctly', async () => {
      const exportRequest: GDPRExportRequest = {
        businessId: 'business_123',
        requestedBy: 'user_123',
        requestedAt: Date.now(),
        purpose: 'user_request',
        includePersonalData: true,
        includeFinancialData: false,
        includeAuditTrails: false,
        exportFormat: 'JSON',
        deliveryMethod: 'download'
      };

      const exportId = await gdprService.createExportRequest(exportRequest);

      // Wait for processing to complete (in real implementation, this would be async)
      await new Promise(resolve => setTimeout(resolve, 100));

      const queries = mockDb.getQueries();
      const customerQuery = queries.find(q =>
        q.sql.includes('customers') && q.sql.includes('business_id')
      );

      expect(customerQuery).toBeDefined();
      expect(customerQuery?.params).toContain('business_123');
    });

    it('should collect financial data correctly', async () => {
      const exportRequest: GDPRExportRequest = {
        businessId: 'business_123',
        requestedBy: 'user_123',
        requestedAt: Date.now(),
        purpose: 'user_request',
        includePersonalData: false,
        includeFinancialData: true,
        includeAuditTrails: false,
        exportFormat: 'JSON',
        deliveryMethod: 'download'
      };

      const exportId = await gdprService.createExportRequest(exportRequest);

      // Wait for processing
      await new Promise(resolve => setTimeout(resolve, 100));

      const queries = mockDb.getQueries();
      const invoiceQuery = queries.find(q =>
        q.sql.includes('invoices') && q.sql.includes('business_id')
      );

      expect(invoiceQuery).toBeDefined();
      expect(invoiceQuery?.params).toContain('business_123');
    });

    it('should collect audit trails correctly', async () => {
      const exportRequest: GDPRExportRequest = {
        businessId: 'business_123',
        requestedBy: 'user_123',
        requestedAt: Date.now(),
        purpose: 'compliance_audit',
        includePersonalData: false,
        includeFinancialData: false,
        includeAuditTrails: true,
        exportFormat: 'JSON',
        deliveryMethod: 'download'
      };

      const exportId = await gdprService.createExportRequest(exportRequest);

      // Wait for processing
      await new Promise(resolve => setTimeout(resolve, 100));

      const queries = mockDb.getQueries();
      const auditQuery = queries.find(q =>
        q.sql.includes('audit_logs') && q.sql.includes('business_id')
      );

      expect(auditQuery).toBeDefined();
      expect(auditQuery?.params).toContain('business_123');
    });

    it('should respect date range filters', async () => {
      const startDate = Date.now() - 86400000 * 90; // 90 days ago
      const endDate = Date.now() - 86400000 * 30;   // 30 days ago

      const exportRequest: GDPRExportRequest = {
        businessId: 'business_123',
        requestedBy: 'user_123',
        requestedAt: Date.now(),
        purpose: 'user_request',
        includePersonalData: true,
        includeFinancialData: true,
        includeAuditTrails: true,
        dateRange: { startDate, endDate },
        exportFormat: 'JSON',
        deliveryMethod: 'download'
      };

      const exportId = await gdprService.createExportRequest(exportRequest);

      // Wait for processing
      await new Promise(resolve => setTimeout(resolve, 100));

      const queries = mockDb.getQueries();

      // Verify date range is applied in queries
      const queriesWithDateRange = queries.filter(q =>
        q.sql.includes('BETWEEN') && q.params && q.params.includes(startDate) && q.params.includes(endDate)
      );

      expect(queriesWithDateRange.length).toBeGreaterThan(0);
    });
  });

  describe('Export Format Generation', () => {
    it('should generate JSON export correctly', async () => {
      const exportRequest: GDPRExportRequest = {
        businessId: 'business_123',
        requestedBy: 'user_123',
        requestedAt: Date.now(),
        purpose: 'user_request',
        includePersonalData: true,
        includeFinancialData: true,
        includeAuditTrails: true,
        exportFormat: 'JSON',
        deliveryMethod: 'download'
      };

      const exportId = await gdprService.createExportRequest(exportRequest);

      // Wait for processing and file generation
      await new Promise(resolve => setTimeout(resolve, 200));

      // Check if file was uploaded to R2
      const storedFiles = mockR2.getStoredKeys();
      expect(storedFiles.length).toBeGreaterThan(0);

      const jsonFile = storedFiles.find(key => key.includes(exportId) && key.endsWith('.json'));
      expect(jsonFile).toBeDefined();

      if (jsonFile) {
        const storedObject = mockR2.getStoredObject(jsonFile);
        expect(storedObject).toBeDefined();

        // Parse and validate JSON structure
        const exportData = JSON.parse(storedObject!.content);

        expect(exportData).toHaveProperty('metadata');
        expect(exportData).toHaveProperty('personalData');
        expect(exportData).toHaveProperty('financialData');
        expect(exportData).toHaveProperty('auditTrails');

        expect(exportData.metadata.format).toBe('JSON');
        expect(exportData.metadata.version).toBe('1.0.0');

        // Verify data structure
        expect(Array.isArray(exportData.personalData)).toBe(true);
        expect(Array.isArray(exportData.financialData)).toBe(true);
        expect(Array.isArray(exportData.auditTrails)).toBe(true);
      }
    });

    it('should generate CSV export correctly', async () => {
      const exportRequest: GDPRExportRequest = {
        businessId: 'business_123',
        requestedBy: 'user_123',
        requestedAt: Date.now(),
        purpose: 'user_request',
        includePersonalData: true,
        includeFinancialData: true,
        includeAuditTrails: true,
        exportFormat: 'CSV',
        deliveryMethod: 'download'
      };

      const exportId = await gdprService.createExportRequest(exportRequest);

      // Wait for processing
      await new Promise(resolve => setTimeout(resolve, 200));

      const storedFiles = mockR2.getStoredKeys();
      const csvFile = storedFiles.find(key => key.includes(exportId) && key.endsWith('.csv'));
      expect(csvFile).toBeDefined();

      if (csvFile) {
        const storedObject = mockR2.getStoredObject(csvFile);
        expect(storedObject).toBeDefined();

        const csvContent = storedObject!.content;

        // Verify CSV structure
        expect(csvContent).toContain('PERSONAL DATA');
        expect(csvContent).toContain('FINANCIAL DATA');
        expect(csvContent).toContain('AUDIT TRAILS');

        // Verify CSV headers
        expect(csvContent).toContain('Entity Type,Entity ID,Name,Email,Phone');
        expect(csvContent).toContain('Record Type,Record ID,Customer Name,Amount,Currency');
        expect(csvContent).toContain('Action,Entity Type,Entity ID,Performed By,Performed At');

        // Verify data rows
        expect(csvContent).toContain('customer,cust_001,John Smith');
        expect(csvContent).toContain('invoice,inv_001,John Smith,1500');
        expect(csvContent).toContain('CREATE,invoice,inv_001,user_123');
      }
    });

    it('should generate XML export correctly', async () => {
      const exportRequest: GDPRExportRequest = {
        businessId: 'business_123',
        requestedBy: 'user_123',
        requestedAt: Date.now(),
        purpose: 'user_request',
        includePersonalData: true,
        includeFinancialData: false,
        includeAuditTrails: false,
        exportFormat: 'XML',
        deliveryMethod: 'download'
      };

      const exportId = await gdprService.createExportRequest(exportRequest);

      // Wait for processing
      await new Promise(resolve => setTimeout(resolve, 200));

      const storedFiles = mockR2.getStoredKeys();
      const xmlFile = storedFiles.find(key => key.includes(exportId) && key.endsWith('.xml'));
      expect(xmlFile).toBeDefined();

      if (xmlFile) {
        const storedObject = mockR2.getStoredObject(xmlFile);
        expect(storedObject).toBeDefined();

        const xmlContent = storedObject!.content;

        // Verify XML structure
        expect(xmlContent).toContain('<?xml version="1.0" encoding="UTF-8"?>');
        expect(xmlContent).toContain('<gdpr_export>');
        expect(xmlContent).toContain('<metadata>');
        expect(xmlContent).toContain('<personal_data>');
        expect(xmlContent).toContain('</gdpr_export>');

        // Verify XML is well-formed (basic check)
        expect(xmlContent.split('<gdpr_export>').length).toBe(2);
        expect(xmlContent.split('</gdpr_export>').length).toBe(2);
      }
    });
  });

  describe('Export Status and Management', () => {
    it('should track export status correctly', async () => {
      const exportRequest: GDPRExportRequest = {
        businessId: 'business_123',
        requestedBy: 'user_123',
        requestedAt: Date.now(),
        purpose: 'user_request',
        includePersonalData: true,
        includeFinancialData: false,
        includeAuditTrails: false,
        exportFormat: 'JSON',
        deliveryMethod: 'download'
      };

      const exportId = await gdprService.createExportRequest(exportRequest);

      // Mock the status retrieval
      mockDb.prepare = function(sql: string) {
        const prepared = { bind: (...params: any[]) => ({
          first: async () => {
            if (sql.includes('gdpr_export_requests') && sql.includes('SELECT')) {
              return {
                id: exportId,
                business_id: 'business_123',
                requested_by: 'user_123',
                requested_at: exportRequest.requestedAt,
                purpose: 'user_request',
                include_personal_data: 1,
                include_financial_data: 0,
                include_audit_trails: 0,
                export_format: 'JSON',
                delivery_method: 'download',
                retention_days: 30,
                status: 'completed',
                created_at: Date.now(),
                completed_at: Date.now(),
                download_url: `https://exports.example.com/gdpr_export_${exportId}.json`,
                file_size: 1024,
                expires_at: Date.now() + 30 * 24 * 60 * 60 * 1000,
                personal_data_count: 2,
                financial_data_count: 0,
                audit_trail_count: 0,
                error_message: null
              };
            }
            return null;
          }
        }) };
        return prepared;
      };

      const status = await gdprService.getExportStatus(exportId, 'business_123');

      expect(status).toBeDefined();
      expect(status?.exportId).toBe(exportId);
      expect(status?.status).toBe('completed');
      expect(status?.requestDetails.businessId).toBe('business_123');
      expect(status?.requestDetails.includePersonalData).toBe(true);
      expect(status?.requestDetails.includeFinancialData).toBe(false);
      expect(status?.recordCounts.personalData).toBe(2);
      expect(status?.downloadUrl).toContain(exportId);
    });

    it('should prevent cross-business export access', async () => {
      const exportId = 'export_belonging_to_other_business';

      const status = await gdprService.getExportStatus(exportId, 'business_456');

      expect(status).toBeNull();

      const queries = mockDb.getQueries();
      const selectQuery = queries.find(q => q.sql.includes('gdpr_export_requests'));

      expect(selectQuery).toBeDefined();
      expect(selectQuery?.params).toContain('business_456');
      expect(selectQuery?.params).not.toContain('business_123');
    });

    it('should list exports for business correctly', async () => {
      // Mock list response
      mockDb.prepare = function(sql: string) {
        const prepared = { bind: (...params: any[]) => ({
          all: async () => {
            if (sql.includes('gdpr_export_requests') && sql.includes('ORDER BY')) {
              return {
                results: [
                  {
                    id: 'export_1',
                    business_id: 'business_123',
                    requested_by: 'user_123',
                    status: 'completed',
                    created_at: Date.now() - 86400000,
                    export_format: 'JSON'
                  },
                  {
                    id: 'export_2',
                    business_id: 'business_123',
                    requested_by: 'user_456',
                    status: 'generating',
                    created_at: Date.now() - 3600000,
                    export_format: 'CSV'
                  }
                ]
              };
            }
            return { results: [] };
          }
        }) };
        return prepared;
      };

      const exports = await gdprService.listExportRequests('business_123', 10, 0);

      expect(exports.length).toBe(2);
      expect(exports[0].exportId).toBe('export_1');
      expect(exports[0].status).toBe('completed');
      expect(exports[1].exportId).toBe('export_2');
      expect(exports[1].status).toBe('generating');
    });
  });

  describe('Data Privacy and Security', () => {
    it('should enforce business isolation in data collection', async () => {
      const exportRequest: GDPRExportRequest = {
        businessId: 'business_123',
        requestedBy: 'user_123',
        requestedAt: Date.now(),
        purpose: 'user_request',
        includePersonalData: true,
        includeFinancialData: true,
        includeAuditTrails: true,
        exportFormat: 'JSON',
        deliveryMethod: 'download'
      };

      const exportId = await gdprService.createExportRequest(exportRequest);

      // Wait for processing
      await new Promise(resolve => setTimeout(resolve, 100));

      const queries = mockDb.getQueries();

      // Verify all data collection queries include business_id filter
      const dataQueries = queries.filter(q =>
        (q.sql.includes('customers') || q.sql.includes('invoices') || q.sql.includes('audit_logs')) &&
        q.sql.includes('SELECT')
      );

      expect(dataQueries.length).toBeGreaterThan(0);

      for (const query of dataQueries) {
        expect(query.sql.toLowerCase()).toContain('business_id');
        expect(query.params).toContain('business_123');
      }
    });

    it('should handle sensitive data appropriately', async () => {
      const exportRequest: GDPRExportRequest = {
        businessId: 'business_123',
        requestedBy: 'user_123',
        requestedAt: Date.now(),
        purpose: 'user_request',
        includePersonalData: true,
        includeFinancialData: false,
        includeAuditTrails: false,
        exportFormat: 'JSON',
        deliveryMethod: 'download'
      };

      const exportId = await gdprService.createExportRequest(exportRequest);

      // Wait for processing
      await new Promise(resolve => setTimeout(resolve, 200));

      const storedFiles = mockR2.getStoredKeys();
      const jsonFile = storedFiles.find(key => key.includes(exportId) && key.endsWith('.json'));

      if (jsonFile) {
        const storedObject = mockR2.getStoredObject(jsonFile);
        const exportData = JSON.parse(storedObject!.content);

        // Verify personal data is included with proper structure
        expect(exportData.personalData.length).toBeGreaterThan(0);

        for (const record of exportData.personalData) {
          expect(record).toHaveProperty('entityType');
          expect(record).toHaveProperty('entityId');
          expect(record).toHaveProperty('dataFields');
          expect(record).toHaveProperty('legalBasis');
          expect(record).toHaveProperty('processingPurpose');

          // Verify sensitive data fields are present
          if (record.dataFields.email) {
            expect(record.dataFields.email).toMatch(/\S+@\S+\.\S+/);
          }
        }
      }
    });

    it('should set appropriate file metadata for security', async () => {
      const exportRequest: GDPRExportRequest = {
        businessId: 'business_123',
        requestedBy: 'user_123',
        requestedAt: Date.now(),
        purpose: 'user_request',
        includePersonalData: true,
        includeFinancialData: false,
        includeAuditTrails: false,
        exportFormat: 'JSON',
        deliveryMethod: 'download'
      };

      const exportId = await gdprService.createExportRequest(exportRequest);

      // Wait for processing
      await new Promise(resolve => setTimeout(resolve, 200));

      const storedFiles = mockR2.getStoredKeys();
      const jsonFile = storedFiles.find(key => key.includes(exportId));

      if (jsonFile) {
        const storedObject = mockR2.getStoredObject(jsonFile);

        expect(storedObject?.metadata).toBeDefined();
        expect(storedObject?.metadata.contentType).toBe('application/json');
        expect(storedObject?.metadata.contentDisposition).toContain('attachment');
        expect(storedObject?.metadata.contentDisposition).toContain(jsonFile);
      }
    });
  });

  describe('Export Cleanup and Retention', () => {
    it('should handle export expiration correctly', async () => {
      // Mock expired export
      mockDb.prepare = function(sql: string) {
        const prepared = { bind: (...params: any[]) => ({
          all: async () => {
            if (sql.includes('expires_at') && sql.includes('<')) {
              return {
                results: [
                  {
                    id: 'expired_export_1',
                    download_url: 'https://exports.example.com/expired_export_1.json'
                  },
                  {
                    id: 'expired_export_2',
                    download_url: 'https://exports.example.com/expired_export_2.csv'
                  }
                ]
              };
            }
            return { results: [] };
          },
          run: async () => ({ success: true })
        }) };
        return prepared;
      };

      // Add files to mock R2 that should be deleted
      await mockR2.put('expired_export_1.json', '{"expired": true}');
      await mockR2.put('expired_export_2.csv', 'expired,data');

      expect(mockR2.size()).toBe(2);

      await gdprService.cleanupExpiredExports();

      // Files should be deleted from R2
      expect(mockR2.size()).toBe(0);

      const queries = mockDb.getQueries();

      // Should have queried for expired exports
      const selectQuery = queries.find(q =>
        q.sql.includes('expires_at') && q.sql.includes('<')
      );
      expect(selectQuery).toBeDefined();

      // Should have updated export status to expired
      const updateQueries = queries.filter(q =>
        q.sql.includes('UPDATE') && q.sql.includes('expired')
      );
      expect(updateQueries.length).toBeGreaterThan(0);
    });

    it('should handle different retention periods', async () => {
      const retentionDays = [7, 30, 90, 365];

      for (const days of retentionDays) {
        mockDb.clearQueries();

        const exportRequest: GDPRExportRequest = {
          businessId: 'business_123',
          requestedBy: 'user_123',
          requestedAt: Date.now(),
          purpose: 'user_request',
          includePersonalData: true,
          includeFinancialData: false,
          includeAuditTrails: false,
          exportFormat: 'JSON',
          deliveryMethod: 'download',
          retentionDays: days
        };

        const exportId = await gdprService.createExportRequest(exportRequest);

        const queries = mockDb.getQueries();
        const insertQuery = queries.find(q => q.sql.includes('INSERT'));

        expect(insertQuery?.params).toContain(days);
      }
    });
  });

  describe('Error Scenarios and Edge Cases', () => {
    it('should handle database failures during export generation', async () => {
      const exportRequest: GDPRExportRequest = {
        businessId: 'business_123',
        requestedBy: 'user_123',
        requestedAt: Date.now(),
        purpose: 'user_request',
        includePersonalData: true,
        includeFinancialData: false,
        includeAuditTrails: false,
        exportFormat: 'JSON',
        deliveryMethod: 'download'
      };

      // Simulate database failure after export creation
      setTimeout(() => {
        mockDb.simulateFailure('Database connection lost');
      }, 50);

      const exportId = await gdprService.createExportRequest(exportRequest);

      // Wait for processing to fail
      await new Promise(resolve => setTimeout(resolve, 200));

      // Export should be created but processing should fail gracefully
      expect(exportId).toBeDefined();

      // Check if error status would be updated (in real implementation)
      const queries = mockDb.getQueries();
      expect(queries.length).toBeGreaterThan(0);
    });

    it('should handle R2 storage failures', async () => {
      // Replace R2 with failing mock
      const failingR2 = {
        put: async () => { throw new Error('R2 storage unavailable'); },
        get: async () => { throw new Error('R2 storage unavailable'); },
        delete: async () => { throw new Error('R2 storage unavailable'); }
      };

      const failingGdprService = new GDPRDataExportService(mockDb as any, failingR2 as any);

      const exportRequest: GDPRExportRequest = {
        businessId: 'business_123',
        requestedBy: 'user_123',
        requestedAt: Date.now(),
        purpose: 'user_request',
        includePersonalData: true,
        includeFinancialData: false,
        includeAuditTrails: false,
        exportFormat: 'JSON',
        deliveryMethod: 'download'
      };

      const exportId = await failingGdprService.createExportRequest(exportRequest);

      // Should create request even if R2 fails
      expect(exportId).toBeDefined();
    });

    it('should handle empty data sets', async () => {
      // Mock empty responses
      mockDb.prepare = function(sql: string) {
        const prepared = { bind: (...params: any[]) => ({
          all: async () => ({ results: [] }),
          first: async () => null,
          run: async () => ({ success: true })
        }) };
        return prepared;
      };

      const exportRequest: GDPRExportRequest = {
        businessId: 'business_no_data',
        requestedBy: 'user_123',
        requestedAt: Date.now(),
        purpose: 'user_request',
        includePersonalData: true,
        includeFinancialData: true,
        includeAuditTrails: true,
        exportFormat: 'JSON',
        deliveryMethod: 'download'
      };

      const exportId = await gdprService.createExportRequest(exportRequest);

      // Wait for processing
      await new Promise(resolve => setTimeout(resolve, 200));

      // Should generate export even with empty data
      const storedFiles = mockR2.getStoredKeys();
      const jsonFile = storedFiles.find(key => key.includes(exportId));

      if (jsonFile) {
        const storedObject = mockR2.getStoredObject(jsonFile);
        const exportData = JSON.parse(storedObject!.content);

        expect(exportData.personalData).toEqual([]);
        expect(exportData.financialData).toEqual([]);
        expect(exportData.auditTrails).toEqual([]);
      }
    });

    it('should handle very large data sets efficiently', async () => {
      // Mock large data set
      const largeDataSet = Array.from({ length: 10000 }, (_, i) => ({
        id: `record_${i}`,
        name: `Record ${i}`,
        created_at: Date.now() - i * 1000,
        business_id: 'business_123'
      }));

      mockDb.prepare = function(sql: string) {
        const prepared = { bind: (...params: any[]) => ({
          all: async () => {
            if (sql.includes('customers')) {
              return { results: largeDataSet };
            }
            return { results: [] };
          },
          first: async () => null,
          run: async () => ({ success: true })
        }) };
        return prepared;
      };

      const exportRequest: GDPRExportRequest = {
        businessId: 'business_123',
        requestedBy: 'user_123',
        requestedAt: Date.now(),
        purpose: 'user_request',
        includePersonalData: true,
        includeFinancialData: false,
        includeAuditTrails: false,
        exportFormat: 'JSON',
        deliveryMethod: 'download'
      };

      const startTime = Date.now();
      const exportId = await gdprService.createExportRequest(exportRequest);

      // Wait for processing
      await new Promise(resolve => setTimeout(resolve, 500));

      const endTime = Date.now();
      const processingTime = endTime - startTime;

      // Should complete in reasonable time even with large data set
      expect(processingTime).toBeLessThan(2000); // 2 seconds max

      const storedFiles = mockR2.getStoredKeys();
      const jsonFile = storedFiles.find(key => key.includes(exportId));

      if (jsonFile) {
        const storedObject = mockR2.getStoredObject(jsonFile);
        const exportData = JSON.parse(storedObject!.content);

        expect(exportData.personalData.length).toBe(10000);
      }
    });
  });
});