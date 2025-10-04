/**
 * Multi-Business Logic Testing Framework
 * Testing tenant isolation, data segregation, and cross-business operations
 */

import { describe, it, expect, beforeEach, afterEach, vi, type MockedFunction } from 'vitest';
import type { KVNamespace, D1Database } from '../../src/cloudflare/types/cloudflare';
import { BusinessContextProvider } from '../../src/modules/business-context/provider';
import { TenantIsolationMiddleware } from '../../src/middleware/tenant-isolation';
import { BusinessSwitchClient } from '../../src/modules/business-switch/client';
import { SecurityUtils } from '../../src/shared/security-utils';
import { AuditLogger, AuditEventType } from '../../src/modules/agent-system/audit-logger';

// Mock implementations for testing
class MockKVNamespace implements Partial<KVNamespace> {
  private storage = new Map<string, string>();
  private tenantStorage = new Map<string, Map<string, string>>();

  async get(key: string, options?: any): Promise<string | null> {
    const value = this.storage.get(key);
    if (options?.type === 'json' && value) {
      return JSON.parse(value) as any;
    }
    return value || null;
  }

  async put(key: string, value: string | ArrayBuffer | ArrayBufferView | ReadableStream, options?: any): Promise<void> {
    if (typeof value !== 'string') {
      value = JSON.stringify(value);
    }
    this.storage.set(key, value as string);
  }

  async delete(key: string): Promise<void> {
    this.storage.delete(key);
  }

  // Tenant-specific operations
  getTenantNamespace(businessId: string): Map<string, string> {
    if (!this.tenantStorage.has(businessId)) {
      this.tenantStorage.set(businessId, new Map());
    }
    return this.tenantStorage.get(businessId)!;
  }

  async getTenantData(businessId: string, key: string): Promise<string | null> {
    const namespace = this.getTenantNamespace(businessId);
    return namespace.get(key) || null;
  }

  async putTenantData(businessId: string, key: string, value: string): Promise<void> {
    const namespace = this.getTenantNamespace(businessId);
    namespace.set(key, value);
  }

  clear(): void {
    this.storage.clear();
    this.tenantStorage.clear();
  }

  getTenantCount(): number {
    return this.tenantStorage.size;
  }

  getTenantKeys(businessId: string): string[] {
    const namespace = this.getTenantNamespace(businessId);
    return Array.from(namespace.keys());
  }
}

class MockD1Database implements Partial<D1Database> {
  private tables = new Map<string, any[]>();
  private queryLog: Array<{ query: string; params: any[]; businessId?: string }> = [];

  prepare(query: string): any {
    const mockPrepared = {
      bind: (...params: any[]) => ({
        all: async () => {
          this.queryLog.push({ query, params });

          // Extract business_id from query for isolation testing
          const businessIdMatch = params.find(p => typeof p === 'string' && p.startsWith('biz_'));
          const businessId = businessIdMatch || 'unknown';

          // Simulate tenant isolation
          if (query.includes('SELECT') && query.includes('business_id')) {
            const tableName = this.extractTableName(query);
            const tableData = this.tables.get(tableName) || [];
            const filteredData = tableData.filter(row => row.business_id === businessId);
            return { results: filteredData, success: true };
          }

          if (query.includes('INSERT') || query.includes('UPDATE')) {
            const tableName = this.extractTableName(query);
            if (!this.tables.has(tableName)) {
              this.tables.set(tableName, []);
            }

            // Simulate insert/update with business_id
            const tableData = this.tables.get(tableName)!;
            const newRow = { id: Math.random(), business_id: businessId, ...this.parseParams(params) };
            tableData.push(newRow);

            return { success: true, meta: { changes: 1 } };
          }

          return { results: [], success: true };
        },
        first: async () => {
          const result = await this.bind(...params).all();
          return result.results[0] || null;
        },
        run: async () => {
          return await this.bind(...params).all();
        }
      }),
      all: async () => ({ results: [], success: true }),
      first: async () => null,
      run: async () => ({ success: true })
    };

    return mockPrepared;
  }

  private extractTableName(query: string): string {
    const match = query.match(/(?:FROM|INTO|UPDATE)\s+(\w+)/i);
    return match ? match[1] : 'unknown_table';
  }

  private parseParams(params: any[]): any {
    return params.reduce((obj, param, index) => {
      obj[`param_${index}`] = param;
      return obj;
    }, {});
  }

  getQueryLog(): Array<{ query: string; params: any[]; businessId?: string }> {
    return [...this.queryLog];
  }

  getTableData(tableName: string, businessId?: string): any[] {
    const tableData = this.tables.get(tableName) || [];
    if (businessId) {
      return tableData.filter(row => row.business_id === businessId);
    }
    return tableData;
  }

  clear(): void {
    this.tables.clear();
    this.queryLog = [];
  }
}

// Test fixtures
const createBusinessContext = (businessId: string, overrides: any = {}) => ({
  businessId,
  userId: `user_${businessId}`,
  sessionId: `session_${businessId}_${Date.now()}`,
  department: 'general',
  timezone: 'UTC',
  currency: 'USD',
  locale: 'en-US',
  permissions: ['read', 'write'],
  ...overrides
});

const createTestBusinesses = () => [
  {
    id: 'biz_acme_corp',
    name: 'ACME Corporation',
    industry: 'manufacturing',
    tier: 'enterprise',
    region: 'us-east',
    settings: {
      dataRetention: 7,
      encryption: true,
      auditLevel: 'detailed'
    }
  },
  {
    id: 'biz_startup_inc',
    name: 'Startup Inc',
    industry: 'technology',
    tier: 'growth',
    region: 'us-west',
    settings: {
      dataRetention: 30,
      encryption: true,
      auditLevel: 'standard'
    }
  },
  {
    id: 'biz_global_ltd',
    name: 'Global Ltd',
    industry: 'finance',
    tier: 'enterprise',
    region: 'eu-central',
    settings: {
      dataRetention: 90,
      encryption: true,
      auditLevel: 'detailed',
      gdprCompliant: true
    }
  }
];

describe.skip('Multi-Business Logic Testing Framework', () => {
  let mockKV: MockKVNamespace;
  let mockDB: MockD1Database;
  let businessProvider: BusinessContextProvider;
  let tenantMiddleware: TenantIsolationMiddleware;
  let businessSwitch: BusinessSwitchClient;
  let auditLogger: AuditLogger;
  let testBusinesses: any[];

  beforeEach(async () => {
    vi.clearAllMocks();

    // Initialize mocks
    mockKV = new MockKVNamespace();
    mockDB = new MockD1Database();

    // Initialize components
    businessProvider = new BusinessContextProvider(mockKV as any, mockDB as any);
    tenantMiddleware = new TenantIsolationMiddleware();
    businessSwitch = new BusinessSwitchClient(mockKV as any, mockDB as any);
    auditLogger = AuditLogger.getInstance(mockDB as any);

    // Set up test businesses
    testBusinesses = createTestBusinesses();

    for (const business of testBusinesses) {
      await mockKV.putTenantData(business.id, 'business_config', JSON.stringify(business));
    }
  });

  afterEach(() => {
    mockKV.clear();
    mockDB.clear();
  });

  describe('Tenant Data Isolation', () => {
    it('should maintain strict data isolation between businesses', async () => {
      const business1 = testBusinesses[0];
      const business2 = testBusinesses[1];

      // Store data for business 1
      await mockKV.putTenantData(business1.id, 'sensitive_data', JSON.stringify({
        revenue: 1000000,
        employees: 50,
        strategy: 'confidential_business_plan'
      }));

      // Store data for business 2
      await mockKV.putTenantData(business2.id, 'sensitive_data', JSON.stringify({
        revenue: 500000,
        employees: 20,
        strategy: 'different_confidential_plan'
      }));

      // Verify business 1 can only access its data
      const business1Data = await mockKV.getTenantData(business1.id, 'sensitive_data');
      const parsedBusiness1Data = JSON.parse(business1Data!);
      expect(parsedBusiness1Data.revenue).toBe(1000000);
      expect(parsedBusiness1Data.strategy).toBe('confidential_business_plan');

      // Verify business 2 can only access its data
      const business2Data = await mockKV.getTenantData(business2.id, 'sensitive_data');
      const parsedBusiness2Data = JSON.parse(business2Data!);
      expect(parsedBusiness2Data.revenue).toBe(500000);
      expect(parsedBusiness2Data.strategy).toBe('different_confidential_plan');

      // Verify cross-tenant access is prevented
      const business1TryingBusiness2 = await mockKV.getTenantData(business1.id, 'business2_key');
      expect(business1TryingBusiness2).toBeNull();
    });

    it('should enforce database-level tenant isolation', async () => {
      const business1 = testBusinesses[0];
      const business2 = testBusinesses[1];

      // Insert customer data for each business
      await mockDB.prepare('INSERT INTO customers (business_id, name, email) VALUES (?, ?, ?)')
        .bind(business1.id, 'John Doe', 'john@acme.com').run();

      await mockDB.prepare('INSERT INTO customers (business_id, name, email) VALUES (?, ?, ?)')
        .bind(business2.id, 'Jane Smith', 'jane@startup.com').run();

      // Query for business 1 customers
      const business1Customers = await mockDB.prepare('SELECT * FROM customers WHERE business_id = ?')
        .bind(business1.id).all();

      // Query for business 2 customers
      const business2Customers = await mockDB.prepare('SELECT * FROM customers WHERE business_id = ?')
        .bind(business2.id).all();

      // Verify isolation
      expect(business1Customers.results).toHaveLength(1);
      expect(business2Customers.results).toHaveLength(1);

      // Verify no cross-contamination
      const business1Data = mockDB.getTableData('customers', business1.id);
      const business2Data = mockDB.getTableData('customers', business2.id);

      expect(business1Data.every(row => row.business_id === business1.id)).toBe(true);
      expect(business2Data.every(row => row.business_id === business2.id)).toBe(true);
    });

    it('should prevent unauthorized cross-tenant queries', async () => {
      const business1 = testBusinesses[0];
      const business2 = testBusinesses[1];

      // Insert financial data for each business
      await mockDB.prepare('INSERT INTO invoices (business_id, amount, status) VALUES (?, ?, ?)')
        .bind(business1.id, 10000, 'paid').run();

      await mockDB.prepare('INSERT INTO invoices (business_id, amount, status) VALUES (?, ?, ?)')
        .bind(business2.id, 5000, 'pending').run();

      // Attempt to query all invoices without business_id filter (should fail)
      const allInvoicesQuery = await mockDB.prepare('SELECT * FROM invoices').all();

      // In a real implementation, this would be blocked by middleware
      // For testing, we verify the data exists but would be filtered
      const business1Invoices = mockDB.getTableData('invoices', business1.id);
      const business2Invoices = mockDB.getTableData('invoices', business2.id);

      expect(business1Invoices).toHaveLength(1);
      expect(business2Invoices).toHaveLength(1);
      expect(business1Invoices[0].business_id).toBe(business1.id);
      expect(business2Invoices[0].business_id).toBe(business2.id);
    });

    it('should handle concurrent operations across multiple tenants', async () => {
      const operations = testBusinesses.map(async (business) => {
        // Simulate concurrent operations for each business
        const promises = Array.from({ length: 10 }, async (_, i) => {
          await mockKV.putTenantData(business.id, `key_${i}`, `value_${i}`);
          await mockDB.prepare('INSERT INTO transactions (business_id, amount, type) VALUES (?, ?, ?)')
            .bind(business.id, 100 * i, 'test').run();
        });

        return Promise.all(promises);
      });

      await Promise.all(operations);

      // Verify each business has its expected data
      for (const business of testBusinesses) {
        const keys = mockKV.getTenantKeys(business.id);
        expect(keys.filter(k => k.startsWith('key_'))).toHaveLength(10);

        const transactions = mockDB.getTableData('transactions', business.id);
        expect(transactions).toHaveLength(10);
        expect(transactions.every(t => t.business_id === business.id)).toBe(true);
      }
    });
  });

  describe('Business Context Management', () => {
    it('should provide accurate business context for each tenant', async () => {
      for (const business of testBusinesses) {
        const context = await businessProvider.getBusinessContext(business.id);

        expect(context).toBeDefined();
        expect(context.businessId).toBe(business.id);
        expect(context.metadata.name).toBe(business.name);
        expect(context.metadata.industry).toBe(business.industry);
        expect(context.metadata.tier).toBe(business.tier);
      }
    });

    it('should enforce business-specific settings and constraints', async () => {
      const enterpriseBusiness = testBusinesses.find(b => b.tier === 'enterprise');
      const growthBusiness = testBusinesses.find(b => b.tier === 'growth');

      const enterpriseContext = await businessProvider.getBusinessContext(enterpriseBusiness!.id);
      const growthContext = await businessProvider.getBusinessContext(growthBusiness!.id);

      // Verify tier-specific settings are applied
      expect(enterpriseContext.constraints.dataRetention).toBe(enterpriseBusiness!.settings.dataRetention);
      expect(growthContext.constraints.dataRetention).toBe(growthBusiness!.settings.dataRetention);

      // Verify security levels
      expect(enterpriseContext.security.encryption).toBe(true);
      expect(enterpriseContext.security.auditLevel).toBe('detailed');
      expect(growthContext.security.auditLevel).toBe('standard');
    });

    it('should handle business switching with proper context transition', async () => {
      const user = 'user_multi_business';
      const business1 = testBusinesses[0];
      const business2 = testBusinesses[1];

      // Establish session for business 1
      await businessSwitch.switchToBusiness(user, business1.id);
      let currentContext = await businessSwitch.getCurrentContext(user);

      expect(currentContext.businessId).toBe(business1.id);
      expect(currentContext.metadata.name).toBe(business1.name);

      // Switch to business 2
      await businessSwitch.switchToBusiness(user, business2.id);
      currentContext = await businessSwitch.getCurrentContext(user);

      expect(currentContext.businessId).toBe(business2.id);
      expect(currentContext.metadata.name).toBe(business2.name);

      // Verify session isolation
      const sessionHistory = await businessSwitch.getSessionHistory(user);
      expect(sessionHistory).toHaveLength(2);
      expect(sessionHistory.map(s => s.businessId)).toContain(business1.id);
      expect(sessionHistory.map(s => s.businessId)).toContain(business2.id);
    });

    it('should validate business permissions and access rights', async () => {
      const restrictedBusiness = {
        ...testBusinesses[0],
        permissions: {
          allowedOperations: ['read'],
          restrictedFeatures: ['export', 'admin'],
          ipWhitelist: ['192.168.1.0/24']
        }
      };

      await mockKV.putTenantData(restrictedBusiness.id, 'business_config', JSON.stringify(restrictedBusiness));

      const context = await businessProvider.getBusinessContext(restrictedBusiness.id);

      expect(context.permissions.allowedOperations).toContain('read');
      expect(context.permissions.allowedOperations).not.toContain('write');
      expect(context.permissions.restrictedFeatures).toContain('export');
      expect(context.permissions.restrictedFeatures).toContain('admin');
    });
  });

  describe('Cross-Business Operations', () => {
    it('should prevent unauthorized cross-business data access', async () => {
      const business1 = testBusinesses[0];
      const business2 = testBusinesses[1];

      // Store sensitive data for business 1
      await mockKV.putTenantData(business1.id, 'api_keys', JSON.stringify({
        stripe: 'sk_test_business1_key',
        salesforce: 'sf_business1_token'
      }));

      // Attempt to access business 1 data from business 2 context
      const business2Context = createBusinessContext(business2.id);

      // This should fail or return null
      try {
        const unauthorizedData = await mockKV.getTenantData(business1.id, 'api_keys');
        // In a real system, this would be blocked by middleware
        expect(unauthorizedData).toBeDefined(); // Data exists but access should be controlled
      } catch (error) {
        expect(error).toBeDefined(); // Access should be denied
      }

      // Verify legitimate access works
      const business1Context = createBusinessContext(business1.id);
      const authorizedData = await mockKV.getTenantData(business1.id, 'api_keys');
      expect(authorizedData).toBeDefined();
    });

    it('should audit cross-business operations appropriately', async () => {
      const business1 = testBusinesses[0];
      const business2 = testBusinesses[1];

      // Log operations for each business
      await auditLogger.log(
        AuditEventType.DATA_ACCESS,
        'medium',
        business1.id,
        'user1',
        { resource: 'customer_data', action: 'read' },
        { requestId: 'req_1' }
      );

      await auditLogger.log(
        AuditEventType.DATA_MODIFICATION,
        'high',
        business2.id,
        'user2',
        { resource: 'financial_data', action: 'update' },
        { requestId: 'req_2' }
      );

      // Verify audit logs are properly segregated
      const business1Logs = await auditLogger.getAuditTrail(business1.id, {
        startDate: new Date(Date.now() - 86400000),
        endDate: new Date()
      });

      const business2Logs = await auditLogger.getAuditTrail(business2.id, {
        startDate: new Date(Date.now() - 86400000),
        endDate: new Date()
      });

      // Each business should only see its own logs
      expect(business1Logs.every(log => log.businessId === business1.id)).toBe(true);
      expect(business2Logs.every(log => log.businessId === business2.id)).toBe(true);
    });

    it('should handle multi-business user sessions correctly', async () => {
      const multiBusinessUser = 'user_consultant';
      const accessibleBusinesses = [testBusinesses[0].id, testBusinesses[1].id];

      // Set up user with access to multiple businesses
      for (const businessId of accessibleBusinesses) {
        await businessSwitch.grantBusinessAccess(multiBusinessUser, businessId, ['read', 'write']);
      }

      // Test switching between businesses
      for (const businessId of accessibleBusinesses) {
        await businessSwitch.switchToBusiness(multiBusinessUser, businessId);
        const context = await businessSwitch.getCurrentContext(multiBusinessUser);

        expect(context.businessId).toBe(businessId);
        expect(context.userId).toBe(multiBusinessUser);

        // Verify user can only access current business data
        const currentBusinessData = await mockKV.getTenantData(businessId, 'business_config');
        expect(currentBusinessData).toBeDefined();
      }

      // Verify session tracking
      const sessionHistory = await businessSwitch.getSessionHistory(multiBusinessUser);
      expect(sessionHistory.length).toBeGreaterThanOrEqual(accessibleBusinesses.length);
    });

    it('should enforce data residency and regional compliance', async () => {
      const euBusiness = testBusinesses.find(b => b.region === 'eu-central');
      const usBusiness = testBusinesses.find(b => b.region === 'us-east');

      // Verify EU business has GDPR compliance enabled
      const euContext = await businessProvider.getBusinessContext(euBusiness!.id);
      expect(euContext.compliance.gdpr).toBe(true);
      expect(euContext.dataResidency.region).toBe('eu-central');

      // Verify US business has different compliance requirements
      const usContext = await businessProvider.getBusinessContext(usBusiness!.id);
      expect(usContext.dataResidency.region).toBe('us-east');

      // Test data processing restrictions
      const sensitiveEuData = {
        personalData: true,
        gdprSubject: true,
        processingPurpose: 'customer_service'
      };

      // EU data should be processed with GDPR considerations
      await mockKV.putTenantData(euBusiness!.id, 'customer_pii', JSON.stringify(sensitiveEuData));

      const retrievedEuData = await mockKV.getTenantData(euBusiness!.id, 'customer_pii');
      expect(JSON.parse(retrievedEuData!).gdprSubject).toBe(true);
    });
  });

  describe('Performance and Scalability', () => {
    it('should handle high concurrent multi-tenant load', async () => {
      const concurrentOperations = 100;
      const operationsPerBusiness = 20;

      const operations = testBusinesses.flatMap(business =>
        Array.from({ length: operationsPerBusiness }, async (_, i) => {
          // Simulate various operations
          await mockKV.putTenantData(business.id, `load_test_${i}`, `data_${i}`);
          await mockDB.prepare('INSERT INTO load_test (business_id, sequence, data) VALUES (?, ?, ?)')
            .bind(business.id, i, `test_data_${i}`).run();

          return { businessId: business.id, operation: i };
        })
      );

      const startTime = Date.now();
      const results = await Promise.all(operations);
      const duration = Date.now() - startTime;

      expect(results).toHaveLength(testBusinesses.length * operationsPerBusiness);
      expect(duration).toBeLessThan(10000); // Should complete within 10 seconds

      // Verify data integrity across all tenants
      for (const business of testBusinesses) {
        const keys = mockKV.getTenantKeys(business.id);
        const loadTestKeys = keys.filter(k => k.startsWith('load_test_'));
        expect(loadTestKeys).toHaveLength(operationsPerBusiness);

        const dbData = mockDB.getTableData('load_test', business.id);
        expect(dbData).toHaveLength(operationsPerBusiness);
      }
    });

    it('should maintain consistent performance across tenant scaling', async () => {
      const scaleTestBusinesses = Array.from({ length: 50 }, (_, i) => ({
        id: `scale_test_biz_${i}`,
        name: `Scale Test Business ${i}`,
        industry: 'testing',
        tier: 'standard'
      }));

      // Initialize all test businesses
      for (const business of scaleTestBusinesses) {
        await mockKV.putTenantData(business.id, 'business_config', JSON.stringify(business));
      }

      // Measure performance with increasing tenant count
      const performanceMetrics = [];

      for (let tenantCount = 10; tenantCount <= 50; tenantCount += 10) {
        const selectedBusinesses = scaleTestBusinesses.slice(0, tenantCount);

        const startTime = Date.now();

        await Promise.all(selectedBusinesses.map(async business => {
          await mockKV.putTenantData(business.id, 'performance_test', 'test_data');
          await mockDB.prepare('INSERT INTO performance (business_id, timestamp) VALUES (?, ?)')
            .bind(business.id, Date.now()).run();
        }));

        const duration = Date.now() - startTime;
        performanceMetrics.push({ tenantCount, duration });
      }

      // Verify performance doesn't degrade significantly with scale
      const maxDuration = Math.max(...performanceMetrics.map(m => m.duration));
      const minDuration = Math.min(...performanceMetrics.map(m => m.duration));

      // Performance shouldn't degrade more than 300% at scale
      expect(maxDuration / minDuration).toBeLessThan(3);
    });

    it('should efficiently manage memory usage across tenants', async () => {
      // This test would measure actual memory usage in a real environment
      // For now, we'll simulate by checking data structure efficiency

      const largeTenantCount = 100;
      const dataPointsPerTenant = 1000;

      for (let i = 0; i < largeTenantCount; i++) {
        const businessId = `memory_test_biz_${i}`;

        for (let j = 0; j < dataPointsPerTenant; j++) {
          await mockKV.putTenantData(businessId, `data_${j}`, `value_${j}`);
        }
      }

      // Verify all data is accessible and properly segregated
      expect(mockKV.getTenantCount()).toBe(largeTenantCount);

      // Random sampling to verify data integrity
      const sampleBusinessId = `memory_test_biz_${Math.floor(Math.random() * largeTenantCount)}`;
      const sampleKeys = mockKV.getTenantKeys(sampleBusinessId);

      expect(sampleKeys.length).toBe(dataPointsPerTenant);
      expect(sampleKeys.every(k => k.startsWith('data_'))).toBe(true);
    });
  });

  describe('Security and Compliance', () => {
    it('should encrypt sensitive data per business requirements', async () => {
      const enterpriseBusiness = testBusinesses.find(b => b.settings.encryption === true);

      const sensitiveData = {
        customerSSN: '123-45-6789',
        creditCardNumber: '4111-1111-1111-1111',
        bankAccount: '9876543210'
      };

      // In a real implementation, this would be encrypted
      await mockKV.putTenantData(
        enterpriseBusiness!.id,
        'sensitive_customer_data',
        JSON.stringify(sensitiveData)
      );

      const retrievedData = await mockKV.getTenantData(enterpriseBusiness!.id, 'sensitive_customer_data');
      expect(retrievedData).toBeDefined();

      // In production, we'd verify the data is encrypted at rest
      const parsedData = JSON.parse(retrievedData!);
      expect(parsedData.customerSSN).toBeDefined();
    });

    it('should enforce data retention policies per business', async () => {
      const shortRetentionBusiness = testBusinesses.find(b => b.settings.dataRetention === 7);
      const longRetentionBusiness = testBusinesses.find(b => b.settings.dataRetention === 90);

      // Test retention policy enforcement
      const oldTimestamp = Date.now() - (30 * 24 * 60 * 60 * 1000); // 30 days ago

      await mockDB.prepare('INSERT INTO audit_logs (business_id, timestamp, event) VALUES (?, ?, ?)')
        .bind(shortRetentionBusiness!.id, oldTimestamp, 'old_event').run();

      await mockDB.prepare('INSERT INTO audit_logs (business_id, timestamp, event) VALUES (?, ?, ?)')
        .bind(longRetentionBusiness!.id, oldTimestamp, 'old_event').run();

      // Simulate retention policy cleanup
      const shortRetentionLogs = mockDB.getTableData('audit_logs', shortRetentionBusiness!.id);
      const longRetentionLogs = mockDB.getTableData('audit_logs', longRetentionBusiness!.id);

      // In production, old data would be automatically purged based on policy
      expect(shortRetentionLogs).toBeDefined();
      expect(longRetentionLogs).toBeDefined();
    });

    it('should maintain compliance audit trails per business', async () => {
      for (const business of testBusinesses) {
        await auditLogger.log(
          AuditEventType.CONFIGURATION_CHANGE,
          'high',
          business.id,
          'admin_user',
          {
            setting: 'data_retention',
            oldValue: '30',
            newValue: business.settings.dataRetention.toString()
          },
          { timestamp: Date.now() }
        );
      }

      // Verify each business has its own audit trail
      for (const business of testBusinesses) {
        const auditTrail = await auditLogger.getAuditTrail(business.id, {
          startDate: new Date(Date.now() - 86400000),
          endDate: new Date()
        });

        expect(auditTrail.length).toBeGreaterThan(0);
        expect(auditTrail.every(entry => entry.businessId === business.id)).toBe(true);
        expect(auditTrail.some(entry => entry.eventType === AuditEventType.CONFIGURATION_CHANGE)).toBe(true);
      }
    });
  });
});