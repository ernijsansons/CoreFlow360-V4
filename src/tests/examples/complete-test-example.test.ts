/**
 * Complete Test Example
 * Demonstrates best practices for testing in CoreFlow360 V4
 *
 * This file showcases:
 * - Mock setup using centralized infrastructure
 * - Test data creation using fixtures
 * - Test utilities usage
 * - Proper assertions
 * - Test isolation and cleanup
 * - Type safety throughout
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import {
  createMockEnv,
  MockEnvManager,
  MockKVNamespace,
  MockD1Database,
} from '../mocks';
import {
  createTestUser,
  createTestBusiness,
  createTestSession,
  createTestRequest,
  createBatch,
} from '../fixtures';
import {
  waitFor,
  expectError,
  createSpy,
  mockConsole,
  random,
  assertResponse,
  TimeController,
  measurePerformance,
} from '../utils';

describe('Complete Test Example', () => {
  let envManager: MockEnvManager;
  let mockDB: MockD1Database;
  let mockKV: MockKVNamespace;

  // Setup before each test
  beforeEach(() => {
    // Create fresh mock environment for each test
    envManager = new MockEnvManager();
    mockDB = envManager.getDB();
    mockKV = envManager.getKVCache();
  });

  // Cleanup after each test
  afterEach(() => {
    envManager.clear();
  });

  describe('Basic Test Patterns', () => {
    it('should demonstrate mock environment setup', () => {
      // Get the complete mock environment
      const env = envManager.getEnv();

      // Assert environment has all required bindings
      expect(env.DB).toBeDefined();
      expect(env.KV_CACHE).toBeDefined();
      expect(env.JWT_SECRET).toBeDefined();
      expect(env.APP_NAME).toBe('CoreFlow360-Test');
    });

    it('should demonstrate fixture usage', () => {
      // Create test user with default values
      const user = createTestUser();

      expect(user.id).toBe('test-user-id');
      expect(user.email).toBe('test@example.com');
      expect(user.business_id).toBe('test-business-id');
      expect(user.created_at).toBeDefined();

      // Create test user with custom values
      const customUser = createTestUser({
        id: 'custom-user-id',
        email: 'custom@example.com',
        role: 'admin',
      });

      expect(customUser.id).toBe('custom-user-id');
      expect(customUser.email).toBe('custom@example.com');
      expect(customUser.role).toBe('admin');
    });

    it('should demonstrate batch fixture creation', () => {
      // Create 5 users with sequential IDs
      const users = createBatch(createTestUser, 5, (index) => ({
        id: `user-${index}`,
        email: `user${index}@example.com`,
      }));

      expect(users).toHaveLength(5);
      expect(users[0].id).toBe('user-0');
      expect(users[4].id).toBe('user-4');
    });
  });

  describe('Database Mock Patterns', () => {
    it('should demonstrate D1 mock setup and queries', async () => {
      // Setup mock database results
      const mockUsers = [
        createTestUser({ id: 'user-1' }),
        createTestUser({ id: 'user-2' }),
      ];

      mockDB.setMockResults('SELECT * FROM users', mockUsers);

      // Execute query
      const stmt = mockDB.prepare('SELECT * FROM users WHERE business_id = ?');
      const result = await stmt.bind('test-business-id').all();

      // Assert results
      expect(result.success).toBe(true);
      expect(result.results).toHaveLength(2);
      expect(result.results[0].id).toBe('user-1');
    });

    it('should demonstrate batch operations', async () => {
      // Setup multiple queries
      const statements = [
        mockDB.prepare('INSERT INTO users VALUES (?)').bind('user-1'),
        mockDB.prepare('INSERT INTO users VALUES (?)').bind('user-2'),
        mockDB.prepare('INSERT INTO users VALUES (?)').bind('user-3'),
      ];

      // Execute batch
      const results = await mockDB.batch(statements);

      expect(results).toHaveLength(3);
      results.forEach((result) => {
        expect(result.success).toBe(true);
      });
    });
  });

  describe('KV Mock Patterns', () => {
    it('should demonstrate KV operations', async () => {
      // Put value
      await mockKV.put('test-key', JSON.stringify({ foo: 'bar' }));

      // Get value as JSON
      const value = await mockKV.get('test-key', 'json');

      expect(value).toEqual({ foo: 'bar' });
    });

    it('should demonstrate KV list operations', async () => {
      // Put multiple values with prefix
      await mockKV.put('user:1', 'User 1');
      await mockKV.put('user:2', 'User 2');
      await mockKV.put('session:1', 'Session 1');

      // List with prefix
      const result = await mockKV.list({ prefix: 'user:' });

      expect(result.keys).toHaveLength(2);
      expect(result.list_complete).toBe(true);
    });

    it('should demonstrate KV metadata', async () => {
      // Put with metadata
      await mockKV.put('test-key', 'test-value', {
        metadata: { created_by: 'test-user' },
      });

      // Get with metadata
      const result = await mockKV.getWithMetadata('test-key', 'text');

      expect(result.value).toBe('test-value');
      expect(result.metadata).toEqual({ created_by: 'test-user' });
    });
  });

  describe('Test Utilities Patterns', () => {
    it('should demonstrate error assertions', async () => {
      // Function that throws error
      const throwError = async () => {
        throw new Error('Test error message');
      };

      // Assert error is thrown
      await expectError(throwError(), 'Test error message');
    });

    it('should demonstrate spy functions', () => {
      // Create spy
      const mockFn = createSpy((x: number) => x * 2);

      // Call function
      const result1 = mockFn(5);
      const result2 = mockFn(10);

      // Assert spy tracking
      expect(result1).toBe(10);
      expect(result2).toBe(20);
      expect(mockFn.callCount).toBe(2);
      expect(mockFn.calls[0].args).toEqual([5]);
      expect(mockFn.calls[1].args).toEqual([10]);
    });

    it('should demonstrate console mocking', () => {
      const consoleMock = mockConsole();

      console.log('Test log');
      console.warn('Test warning');
      console.error('Test error');

      expect(consoleMock.getLogs()).toContain('Test log');
      expect(consoleMock.getWarnings()).toContain('Test warning');
      expect(consoleMock.getErrors()).toContain('Test error');

      consoleMock.restore();
    });

    it('should demonstrate random data generation', () => {
      const str = random.string(10);
      const num = random.number(1, 100);
      const email = random.email();
      const uuid = random.uuid();
      const bool = random.boolean();

      expect(str).toHaveLength(10);
      expect(num).toBeGreaterThanOrEqual(1);
      expect(num).toBeLessThanOrEqual(100);
      expect(email).toMatch(/@example\.com$/);
      expect(uuid).toMatch(
        /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
      );
      expect(typeof bool).toBe('boolean');
    });

    it('should demonstrate time control', () => {
      const timeController = new TimeController(1000000);

      timeController.install();

      const time1 = Date.now();
      timeController.advance(5000);
      const time2 = Date.now();

      expect(time2 - time1).toBe(5000);

      timeController.restore();
    });

    it('should demonstrate performance measurement', async () => {
      const { result, duration } = await measurePerformance(async () => {
        // Simulate some work
        await new Promise((resolve) => setTimeout(resolve, 10));
        return 'done';
      });

      expect(result).toBe('done');
      expect(duration).toBeGreaterThan(0);
    });
  });

  describe('Request/Response Patterns', () => {
    it('should demonstrate request creation', () => {
      const request = createTestRequest({
        url: 'http://localhost:8787/api/users',
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          authorization: 'Bearer test-token',
        },
        body: { email: 'test@example.com' },
      });

      expect(request.method).toBe('POST');
      expect(request.url).toBe('http://localhost:8787/api/users');
      expect(request.headers.get('authorization')).toBe('Bearer test-token');
    });

    it('should demonstrate response assertions', async () => {
      const response = Response.json(
        { success: true, data: { id: 1 } },
        { status: 200 }
      );

      await assertResponse(response, {
        status: 200,
        json: { success: true, data: { id: 1 } },
      });
    });
  });

  describe('Integration Patterns', () => {
    it('should demonstrate complete workflow test', async () => {
      // 1. Setup test data
      const user = createTestUser({ id: 'workflow-user' });
      const business = createTestBusiness({ owner_id: user.id });

      // 2. Setup mock database
      mockDB.setMockResults('SELECT * FROM users WHERE id = ?', [user]);
      mockDB.setMockResults('SELECT * FROM businesses WHERE id = ?', [
        business,
      ]);

      // 3. Setup KV cache
      await mockKV.put(`user:${user.id}`, JSON.stringify(user));

      // 4. Execute workflow
      const dbUser = await mockDB
        .prepare('SELECT * FROM users WHERE id = ?')
        .bind(user.id)
        .first();

      const cachedUser = await mockKV.get(`user:${user.id}`, 'json');

      // 5. Assert results
      expect(dbUser).toEqual(user);
      expect(cachedUser).toEqual(user);
    });

    it('should demonstrate environment manager workflow', async () => {
      // Setup mock data using environment manager
      envManager.setupDBResults('SELECT * FROM users', [
        createTestUser({ id: 'user-1' }),
      ]);

      await envManager.setupCacheValue('test-key', { foo: 'bar' });
      await envManager.setupSession('session-123', {
        userId: 'user-1',
        expiresAt: Date.now() + 3600000,
      });

      // Get environment
      const env = envManager.getEnv();

      // Execute operations
      const dbResult = await env.DB.prepare('SELECT * FROM users').all();
      const cacheValue = await env.KV_CACHE.get('test-key', 'json');
      const sessionValue = await env.KV_SESSION.get('session-123', 'json');

      // Assert results
      expect(dbResult.results).toHaveLength(1);
      expect(dbResult.results[0].id).toBe('user-1');
      expect(cacheValue).toEqual({ foo: 'bar' });
      expect(sessionValue.userId).toBe('user-1');
    });
  });

  describe('Edge Cases and Error Handling', () => {
    it('should handle null values correctly', async () => {
      mockDB.setMockResults('SELECT * FROM users WHERE id = ?', []);

      const result = await mockDB
        .prepare('SELECT * FROM users WHERE id = ?')
        .bind('non-existent')
        .first();

      expect(result).toBeNull();
    });

    it('should handle empty results', async () => {
      mockDB.setMockResults('SELECT * FROM users', []);

      const result = await mockDB.prepare('SELECT * FROM users').all();

      expect(result.results).toEqual([]);
    });

    it('should handle missing KV keys', async () => {
      const value = await mockKV.get('non-existent-key', 'text');

      expect(value).toBeNull();
    });
  });

  describe('Performance Testing', () => {
    it('should meet performance requirements', async () => {
      // Setup large dataset
      const users = createBatch(createTestUser, 100, (i) => ({
        id: `user-${i}`,
      }));

      mockDB.setMockResults('SELECT * FROM users', users);

      // Measure query performance
      const { duration } = await measurePerformance(async () => {
        return await mockDB.prepare('SELECT * FROM users').all();
      });

      // Assert performance (should be very fast for mock)
      expect(duration).toBeLessThan(100); // 100ms
    });
  });

  describe('Cleanup and Isolation', () => {
    it('should isolate test data between tests', async () => {
      // Put data in first test
      await mockKV.put('test-1', 'value-1');

      // Verify isolation (cleanup happens in afterEach)
      const value = await mockKV.get('test-1', 'text');
      expect(value).toBe('value-1');
    });

    it('should not see data from previous test', async () => {
      // This test should not see data from previous test
      const value = await mockKV.get('test-1', 'text');
      expect(value).toBeNull();
    });
  });
});
