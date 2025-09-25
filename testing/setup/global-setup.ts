/**
 * Global Test Setup
 * Initializes test environment for all test suites
 */

import { beforeAll, afterAll, beforeEach, afterEach } from 'vitest';
import { Miniflare } from 'miniflare';
import { IntelligentMocker } from '../framework/intelligent-mocker';
import { Logger } from '../../src/shared/logger';

// Global test context
declare global {
  var miniflare: Miniflare;
  var testContext: TestContext;
  var mocks: any;
}

interface TestContext {
  correlationId: string;
  timestamp: number;
  env: any;
  database: any;
  kv: any;
  cache: any;
}

// Initialize Miniflare for Cloudflare Workers testing
beforeAll(async () => {
  globalThis.miniflare = new Miniflare({
    script: `
      export default {
        async fetch(request, env, ctx) {
          return new Response('Test Worker');
        }
      }
    `,
    bindings: {
      DB: 'test-database',
      KV: 'test-kv',
      CACHE: 'test-cache',
      QUEUE: 'test-queue',
      DO_NAMESPACE: 'test-durable-objects'
    },
    kvPersist: false,
    durableObjectsPersist: false,
    cachePersist: false
  });

  // Initialize test database
  await setupTestDatabase();

  // Create intelligent mocks
  const mocker = new IntelligentMocker();
  const mockSet = await mocker.createMocks([
    {
      name: 'database',
      type: 'database',
      methods: ['prepare', 'batch', 'dump']
    },
    {
      name: 'kv',
      type: 'service',
      methods: ['get', 'put', 'delete', 'list']
    },
    {
      name: 'cache',
      type: 'service',
      methods: ['match', 'put', 'delete']
    },
    {
      name: 'anthropic',
      type: 'external',
      endpoints: ['https://api.anthropic.com/*']
    }
  ]);

  mockSet.apply();
  globalThis.mocks = mockSet;
});

// Clean up after all tests
afterAll(async () => {
  await globalThis.miniflare?.dispose();
  await cleanupTestDatabase();
  globalThis.mocks?.reset();
});

// Setup before each test
beforeEach(async (context) => {
  // Create test context
  globalThis.testContext = {
    correlationId: crypto.randomUUID(),
    timestamp: Date.now(),
    env: await globalThis.miniflare.getBindings(),
    database: await getTestDatabase(),
    kv: await getTestKV(),
    cache: await getTestCache()
  };

  // Clear all mocks
  globalThis.mocks?.reset();

  // Setup test transaction
  await beginTestTransaction();
});

// Cleanup after each test
afterEach(async () => {
  // Rollback test transaction
  await rollbackTestTransaction();

  // Clear test data
  await clearTestData();

  // Check for memory leaks
  if (global.gc) {
    global.gc();
  }

  // Log test metrics
  logTestMetrics();
});

/**
 * Database Setup Functions
 */
async function setupTestDatabase() {
  const db = await globalThis.miniflare.getD1Database('DB');

  // Create test schema
  await db.exec(`
    CREATE TABLE IF NOT EXISTS test_users (
      id TEXT PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      created_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS test_transactions (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      amount REAL NOT NULL,
      status TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      FOREIGN KEY (user_id) REFERENCES test_users(id)
    );

    CREATE INDEX IF NOT EXISTS idx_test_transactions_user
    ON test_transactions(user_id);
  `);
}

async function cleanupTestDatabase() {
  const db = await globalThis.miniflare.getD1Database('DB');

  await db.exec(`
    DROP TABLE IF EXISTS test_transactions;
    DROP TABLE IF EXISTS test_users;
  `);
}

async function getTestDatabase() {
  return globalThis.miniflare.getD1Database('DB');
}

/**
 * KV Store Setup Functions
 */
async function getTestKV() {
  return globalThis.miniflare.getKVNamespace('KV');
}

/**
 * Cache Setup Functions
 */
async function getTestCache() {
  return globalThis.miniflare.getCaches();
}

/**
 * Transaction Management
 */
let transactionDepth = 0;
let savepoints: string[] = [];

async function beginTestTransaction() {
  const db = await getTestDatabase();

  if (transactionDepth === 0) {
    await db.exec('BEGIN TRANSACTION');
  } else {
    const savepoint = `sp_${Date.now()}_${Math.random()}`;
    await db.exec(`SAVEPOINT ${savepoint}`);
    savepoints.push(savepoint);
  }

  transactionDepth++;
}

async function rollbackTestTransaction() {
  const db = await getTestDatabase();

  transactionDepth--;

  if (transactionDepth === 0) {
    await db.exec('ROLLBACK');
  } else {
    const savepoint = savepoints.pop();
    if (savepoint) {
      await db.exec(`ROLLBACK TO SAVEPOINT ${savepoint}`);
    }
  }
}

/**
 * Test Data Management
 */
async function clearTestData() {
  const db = await getTestDatabase();
  const kv = await getTestKV();
  const cache = await getTestCache();

  // Clear database
  await db.exec('DELETE FROM test_transactions');
  await db.exec('DELETE FROM test_users');

  // Clear KV
  const kvList = await kv.list();
  for (const key of kvList.keys) {
    await kv.delete(key.name);
  }

  // Clear cache
  const cacheNames = await cache.default.keys();
  for (const request of cacheNames) {
    await cache.default.delete(request);
  }
}

/**
 * Test Metrics Logging
 */
function logTestMetrics() {
  if (process.env.CI) {
    const metrics = {
      duration: Date.now() - globalThis.testContext.timestamp,
      correlationId: globalThis.testContext.correlationId,
      memory: process.memoryUsage(),
      cpu: process.cpuUsage()
    };

    console.log('TEST_METRICS:', JSON.stringify(metrics));
  }
}

/**
 * Test Helpers
 */
export async function createTestUser(data?: Partial<{ email: string }>) {
  const db = await getTestDatabase();
  const id = crypto.randomUUID();
  const email = data?.email || `test-${id}@example.com`;

  await db.prepare(`
    INSERT INTO test_users (id, email, created_at)
    VALUES (?, ?, ?)
  `).bind(id, email, Date.now()).run();

  return { id, email };
}

export async function createTestTransaction(userId: string, amount: number) {
  const db = await getTestDatabase();
  const id = crypto.randomUUID();

  await db.prepare(`
    INSERT INTO test_transactions (id, user_id, amount, status, created_at)
    VALUES (?, ?, ?, ?, ?)
  `).bind(id, userId, amount, 'pending', Date.now()).run();

  return { id, userId, amount, status: 'pending' };
}

/**
 * Mock Helpers
 */
export function mockAPI(endpoint: string, response: any) {
  const mock = globalThis.mocks.get('anthropic');
  if (mock) {
    mock.scenarios.push({
      matches: (args: any[]) => args[0] === endpoint,
      response: () => response,
      latency: 10
    });
  }
}

export function mockDatabase(query: string, result: any) {
  const mock = globalThis.mocks.get('database');
  if (mock) {
    mock.scenarios.push({
      matches: (args: any[]) => args[0].includes(query),
      response: () => result,
      latency: 5
    });
  }
}

/**
 * Assertion Helpers
 */
export function assertBusinessIsolation(query: string, businessId: string) {
  if (!query.toLowerCase().includes('business_id')) {
    throw new Error(`Query missing business_id isolation: ${query}`);
  }
}

export function assertNoHardcodedSecrets(code: string) {
  const patterns = [
    /api[_-]?key\s*=\s*["'][^"']+["']/i,
    /password\s*=\s*["'][^"']+["']/i,
    /secret\s*=\s*["'][^"']+["']/i,
    /token\s*=\s*["'][^"']+["']/i
  ];

  for (const pattern of patterns) {
    if (pattern.test(code)) {
      throw new Error('Hardcoded secret detected in code');
    }
  }
}

export function assertPerformance(duration: number, threshold: number) {
  if (duration > threshold) {
    throw new Error(`Performance threshold exceeded: ${duration}ms > ${threshold}ms`);
  }
}

/**
 * Chaos Testing Helpers
 */
export async function simulateNetworkFailure() {
  globalThis.mocks.get('anthropic')?.scenarios.push({
    matches: () => true,
    response: () => { throw new Error('Network timeout'); },
    latency: 0
  });
}

export async function simulateDatabaseSlowdown(factor: number = 10) {
  const mock = globalThis.mocks.get('database');
  if (mock) {
    for (const scenario of mock.scenarios) {
      scenario.latency = (scenario.latency || 5) * factor;
    }
  }
}

export async function simulateHighLoad(requestsPerSecond: number) {
  const promises: Promise<any>[] = [];
  const duration = 1000; // 1 second
  const interval = duration / requestsPerSecond;

  for (let i = 0; i < requestsPerSecond; i++) {
    setTimeout(() => {
      promises.push(fetch('http://localhost:8787/test'));
    }, i * interval);
  }

  return Promise.all(promises);
}