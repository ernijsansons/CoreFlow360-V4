/**
 * Production-Quality Env Mock
 * Complete implementation of Cloudflare Env interface for testing
 *
 * Features:
 * - All required bindings (D1, KV, R2, etc.)
 * - Complete environment variables
 * - Type-safe implementation matching src/types/env.ts
 * - Helper methods for test setup
 *
 * @see src/types/env.ts for canonical Env type
 */

import type { Env } from '../../types/env';
import { MockD1Database } from './d1-database-mock';
import { MockKVNamespace } from './kv-namespace-mock';
import { MockR2Bucket } from './r2-bucket-mock';
import { MockAnalyticsEngine } from './analytics-mock';

/**
 * Create a complete mock Env object with all required bindings
 */
export function createMockEnv(overrides?: Partial<Env>): Env {
  // Create mock bindings
  const mockDB = new MockD1Database();
  const mockKVCache = new MockKVNamespace();
  const mockKVSession = new MockKVNamespace();
  const mockKVRateLimit = new MockKVNamespace();
  const mockKVAuth = new MockKVNamespace();
  const mockR2Documents = new MockR2Bucket();
  const mockR2Backups = new MockR2Bucket();
  const mockAnalytics = new MockAnalyticsEngine();

  const env: Env = {
    // ==========================================
    // D1 DATABASE BINDINGS
    // ==========================================
    DB: mockDB,
    DB_MAIN: mockDB,
    DB_ANALYTICS: new MockD1Database(),

    // ==========================================
    // KV NAMESPACE BINDINGS
    // ==========================================
    KV_CACHE: mockKVCache.asKVNamespace() as any,
    KV_SESSION: mockKVSession.asKVNamespace() as any,
    KV_RATE_LIMIT_METRICS: mockKVRateLimit.asKVNamespace() as any,
    KV_AUTH: mockKVAuth.asKVNamespace() as any,

    // Agent-specific KV namespaces (optional)
    AGENT_CACHE: new MockKVNamespace().asKVNamespace() as any,
    AGENT_MEMORY: new MockKVNamespace().asKVNamespace() as any,
    PATTERN_CACHE: new MockKVNamespace().asKVNamespace() as any,

    // ==========================================
    // R2 BUCKET BINDINGS
    // ==========================================
    R2_DOCUMENTS: mockR2Documents as any,
    R2_BACKUPS: mockR2Backups as any,

    // ==========================================
    // ANALYTICS
    // ==========================================
    ANALYTICS: mockAnalytics as any,

    // ==========================================
    // ENVIRONMENT VARIABLES
    // ==========================================
    APP_NAME: 'CoreFlow360-Test',
    API_VERSION: 'v4',
    LOG_LEVEL: 'debug',
    ENVIRONMENT: 'test',

    // Agent configuration
    AGENT_SYSTEM_ENABLED: 'true',
    MAX_AGENT_CONCURRENCY: '10',
    AGENT_TIMEOUT_MS: '5000',

    // ==========================================
    // SECRETS
    // ==========================================
    JWT_SECRET: 'test-jwt-secret-min-32-chars-long-for-hs256',
    AUTH_SECRET: 'test-auth-secret',
    ENCRYPTION_KEY: 'test-encryption-key-32-chars-min',

    // AI Services
    ANTHROPIC_API_KEY: 'test-anthropic-key',
    OPENAI_API_KEY: 'test-openai-key',

    // Payment processors
    STRIPE_SECRET_KEY: 'sk_test_mock',
    STRIPE_PUBLISHABLE_KEY: 'pk_test_mock',
    STRIPE_WEBHOOK_SECRET: 'whsec_test_mock',
    PAYPAL_CLIENT_ID: 'paypal-test-client',
    PAYPAL_CLIENT_SECRET: 'paypal-test-secret',

    // Communication services
    EMAIL_API_KEY: 'test-email-key',
    SMS_API_KEY: 'test-sms-key',
    TWILIO_ACCOUNT_SID: 'test-twilio-sid',
    TWILIO_AUTH_TOKEN: 'test-twilio-token',
    SENDGRID_API_KEY: 'test-sendgrid-key',

    // Data enrichment
    CLEARBIT_API_KEY: 'test-clearbit-key',
    APOLLO_API_KEY: 'test-apollo-key',
    HUNTER_API_KEY: 'test-hunter-key',

    // Monitoring & Analytics
    SENTRY_DSN: 'https://test@sentry.io/test',
    SENTRY_ENVIRONMENT: 'test',

    // Internal service tokens
    API_KEY: 'test-api-key',
    ADMIN_API_KEY: 'test-admin-key',
    WEBHOOK_SECRET: 'test-webhook-secret',

    // ==========================================
    // OPTIONAL CONFIGURATION
    // ==========================================
    API_BASE_URL: 'http://localhost:8787',
    ALLOWED_ORIGINS: 'http://localhost:3000',
    CDN_URL: 'http://localhost:8787',
    DASHBOARD_URL: 'http://localhost:3000',

    // Debug and feature flags
    DEBUG: 'true',
    ENABLE_MFA: 'true',
    ENABLE_AI: 'true',
    ENABLE_ANALYTICS: 'true',

    // Rate limiting configuration
    GLOBAL_RATE_LIMIT: '1000',
    USER_RATE_LIMIT: '100',
    IP_RATE_LIMIT: '100',

    // Security configuration
    MAX_REQUEST_SIZE: '10485760', // 10MB
    REQUEST_TIMEOUT: '30000',
    JWT_EXPIRY: '24h',

    // CORS
    CORS_ORIGINS: 'http://localhost:3000',

    // Legacy/deprecated bindings (optional)
    CACHE: mockKVCache.asKVNamespace() as any,
    KV_CONFIG: new MockKVNamespace().asKVNamespace() as any,
    KV_RATE_LIMIT: mockKVRateLimit.asKVNamespace() as any,

    // Apply overrides
    ...overrides,
  };

  return env;
}

/**
 * Create a minimal mock Env with only required fields
 */
export function createMinimalMockEnv(): Env {
  const mockDB = new MockD1Database();
  const mockKVCache = new MockKVNamespace();
  const mockKVSession = new MockKVNamespace();
  const mockKVAuth = new MockKVNamespace();

  return {
    DB: mockDB,
    DB_MAIN: mockDB,
    DB_ANALYTICS: new MockD1Database(),
    KV_CACHE: mockKVCache.asKVNamespace() as any,
    KV_SESSION: mockKVSession.asKVNamespace() as any,
    KV_RATE_LIMIT_METRICS: new MockKVNamespace().asKVNamespace() as any,
    KV_AUTH: mockKVAuth.asKVNamespace() as any,
    R2_DOCUMENTS: new MockR2Bucket() as any,
    R2_BACKUPS: new MockR2Bucket() as any,
    APP_NAME: 'CoreFlow360-Test',
    API_VERSION: 'v4',
    LOG_LEVEL: 'error',
    ENVIRONMENT: 'test',
    JWT_SECRET: 'test-jwt-secret-min-32-chars-long-for-hs256',
  };
}

/**
 * Helper class for managing mock Env in tests
 */
export class MockEnvManager {
  private env: Env;
  private mockDB: MockD1Database;
  private mockKVCache: MockKVNamespace;
  private mockKVSession: MockKVNamespace;
  private mockKVAuth: MockKVNamespace;
  private mockR2Documents: MockR2Bucket;
  private mockAnalytics: MockAnalyticsEngine;

  constructor(overrides?: Partial<Env>) {
    this.mockDB = new MockD1Database();
    this.mockKVCache = new MockKVNamespace();
    this.mockKVSession = new MockKVNamespace();
    this.mockKVAuth = new MockKVNamespace();
    this.mockR2Documents = new MockR2Bucket();
    this.mockAnalytics = new MockAnalyticsEngine();

    this.env = createMockEnv({
      DB: this.mockDB,
      DB_MAIN: this.mockDB,
      KV_CACHE: this.mockKVCache.asKVNamespace() as any,
      KV_SESSION: this.mockKVSession.asKVNamespace() as any,
      KV_AUTH: this.mockKVAuth.asKVNamespace() as any,
      R2_DOCUMENTS: this.mockR2Documents as any,
      ANALYTICS: this.mockAnalytics as any,
      ...overrides,
    });
  }

  /**
   * Get the mock Env object
   */
  getEnv(): Env {
    return this.env;
  }

  /**
   * Get direct access to mock bindings for test setup
   */
  getDB(): MockD1Database {
    return this.mockDB;
  }

  getKVCache(): MockKVNamespace {
    return this.mockKVCache;
  }

  getKVSession(): MockKVNamespace {
    return this.mockKVSession;
  }

  getKVAuth(): MockKVNamespace {
    return this.mockKVAuth;
  }

  getR2Documents(): MockR2Bucket {
    return this.mockR2Documents;
  }

  getAnalytics(): MockAnalyticsEngine {
    return this.mockAnalytics;
  }

  /**
   * Setup mock database results
   */
  setupDBResults(queryPattern: string, results: any[], meta?: any): void {
    this.mockDB.setMockResults(queryPattern, results, meta);
  }

  /**
   * Setup KV cache values
   */
  async setupCacheValue(key: string, value: any): Promise<void> {
    await this.mockKVCache.put(key, JSON.stringify(value));
  }

  /**
   * Setup session data
   */
  async setupSession(sessionId: string, data: any): Promise<void> {
    await this.mockKVSession.put(sessionId, JSON.stringify(data));
  }

  /**
   * Clear all mock data
   */
  clear(): void {
    this.mockDB.clear();
    this.mockKVCache.clear();
    this.mockKVSession.clear();
    this.mockKVAuth.clear();
    this.mockR2Documents.clear();
    this.mockAnalytics.clear();
  }

  /**
   * Reset to initial state
   */
  reset(): void {
    this.clear();
  }
}
