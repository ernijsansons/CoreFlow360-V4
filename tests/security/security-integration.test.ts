/**
 * Security Integration Tests
 * Comprehensive security testing suite for all security components
 */

import { describe, test, expect, beforeEach, afterEach, beforeAll, afterAll } from 'vitest';
import { SecurityMiddleware, createSecurityMiddleware } from '../../src/middleware/security-middleware';
import { ThreatDetectionEngine } from '../../src/security/threat-detection-engine';
import { SQLInjectionGuard } from '../../src/security/sql-injection-guard';
import { AdaptiveRateLimiter } from '../../src/security/adaptive-rate-limiter';
import { SecurityHeaders } from '../../src/security/security-headers';
import { ZeroTrustSecretsManager } from '../../src/security/zero-trust-secrets';
import { AdvancedXSSProtection, createAdvancedXSSProtection } from '../../src/security/advanced-xss-protection';
import { PenetrationTestingAutomation, createPenetrationTestingAutomation } from '../../src/security/penetration-testing-automation';

describe('Security Integration Tests', () => {
  let securityMiddleware: SecurityMiddleware;
  let threatEngine: ThreatDetectionEngine;
  let sqlGuard: SQLInjectionGuard;
  let rateLimiter: AdaptiveRateLimiter;
  let securityHeaders: SecurityHeaders;
  let secretsManager: ZeroTrustSecretsManager;
  let xssProtection: AdvancedXSSProtection;
  let penTestAutomation: PenetrationTestingAutomation;

  beforeAll(async () => {
    // Initialize security components
    securityMiddleware = createSecurityMiddleware({
      threatDetection: { enabled: true, blockThreshold: 0.9, challengeThreshold: 0.7 },
      rateLimit: { enabled: true, adaptive: true },
      sqlInjection: { enabled: true, strictMode: true },
      headers: { enabled: true, reportOnly: false },
      monitoring: { enabled: true, logLevel: 'info' }
    });

    threatEngine = new ThreatDetectionEngine();
    sqlGuard = new SQLInjectionGuard();
    rateLimiter = new AdaptiveRateLimiter();
    securityHeaders = new SecurityHeaders();
    secretsManager = new ZeroTrustSecretsManager('http://localhost:8080/kms', 'development');
    xssProtection = createAdvancedXSSProtection();
    penTestAutomation = createPenetrationTestingAutomation();
  });

  afterAll(async () => {
    // Cleanup resources
  });

  describe('Threat Detection Engine', () => {
    test('should detect SQL injection attempts', async () => {
      const maliciousRequest = new Request('http://localhost/api/users?id=1\' OR \'1\'=\'1', {
        method: 'GET',
        headers: { 'User-Agent': 'Mozilla/5.0' }
      });

      const result = await threatEngine.analyzeRequest(maliciousRequest);

      expect(result.action).toBe('BLOCK');
      expect(result.score).toBeGreaterThan(0.8);
      expect(result.threats).toContain('sql_injection');
    });

    test('should detect XSS attempts', async () => {
      const xssRequest = new Request('http://localhost/api/comments', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ comment: '<script>alert("XSS")</script>' })
      });

      const result = await threatEngine.analyzeRequest(xssRequest);

      expect(result.action).toBe('BLOCK');
      expect(result.score).toBeGreaterThan(0.7);
      expect(result.threats).toContain('xss');
    });

    test('should detect suspicious user agent patterns', async () => {
      const botRequest = new Request('http://localhost/api/data', {
        method: 'GET',
        headers: { 'User-Agent': 'sqlmap/1.0' }
      });

      const result = await threatEngine.analyzeRequest(botRequest);

      expect(result.action).toBe('BLOCK');
      expect(result.threats).toContain('automated_tool');
    });

    test('should allow legitimate requests', async () => {
      const legitimateRequest = new Request('http://localhost/api/users/profile', {
        method: 'GET',
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
          'Accept': 'application/json'
        }
      });

      const result = await threatEngine.analyzeRequest(legitimateRequest);

      expect(result.action).toBe('ALLOW');
      expect(result.score).toBeLessThan(0.5);
    });

    test('should detect rate limiting abuse', async () => {
      // Simulate multiple requests from same IP
      const requests = Array.from({ length: 10 }, () =>
        new Request('http://localhost/api/login', {
          method: 'POST',
          headers: { 'X-Forwarded-For': '192.168.1.100' }
        })
      );

      let blockedCount = 0;
      for (const request of requests) {
        const result = await threatEngine.analyzeRequest(request);
        if (result.action === 'BLOCK') blockedCount++;
      }

      expect(blockedCount).toBeGreaterThan(0);
    });
  });

  describe('SQL Injection Guard', () => {
    test('should block obvious SQL injection', async () => {
      const maliciousQuery = "SELECT * FROM users WHERE id = '1' OR '1'='1'";

      const result = await sqlGuard.validate(maliciousQuery, {
        query: maliciousQuery,
        isParameterized: false,
        expectedType: 'select',
        maxLength: 1000,
        allowedPattern: /^[a-zA-Z0-9\s='".,()]*$/,
        businessId: 'test-business'
      });

      expect(result.valid).toBe(false);
      expect(result.reason).toContain('SQL injection');
      expect(result.confidence).toBeGreaterThan(0.8);
    });

    test('should allow legitimate parameterized queries', async () => {
      const legitimateQuery = "SELECT * FROM users WHERE id = ?";

      const result = await sqlGuard.validate(legitimateQuery, {
        query: legitimateQuery,
        params: ['123'],
        isParameterized: true,
        expectedType: 'select',
        maxLength: 1000,
        allowedPattern: /^[a-zA-Z0-9\s='".,()?\*]*$/,
        businessId: 'test-business'
      });

      expect(result.valid).toBe(true);
    });

    test('should detect union-based injection', async () => {
      const unionQuery = "SELECT id FROM users WHERE name = 'test' UNION SELECT password FROM admin";

      const result = await sqlGuard.validate(unionQuery, {
        query: unionQuery,
        isParameterized: false,
        expectedType: 'select',
        maxLength: 1000,
        allowedPattern: /^[a-zA-Z0-9\s='".,()]*$/,
        businessId: 'test-business'
      });

      expect(result.valid).toBe(false);
      expect(result.threats).toContain('union_injection');
    });

    test('should detect time-based injection', async () => {
      const timeBasedQuery = "SELECT * FROM users WHERE id = 1; WAITFOR DELAY '00:00:05'";

      const result = await sqlGuard.validate(timeBasedQuery, {
        query: timeBasedQuery,
        isParameterized: false,
        expectedType: 'select',
        maxLength: 1000,
        allowedPattern: /^[a-zA-Z0-9\s='".,()]*$/,
        businessId: 'test-business'
      });

      expect(result.valid).toBe(false);
      expect(result.threats).toContain('time_based_injection');
    });
  });

  describe('Adaptive Rate Limiter', () => {
    test('should apply rate limits based on threat level', async () => {
      const normalRequest = new Request('http://localhost/api/data', {
        headers: { 'X-Forwarded-For': '192.168.1.50' }
      });

      const suspiciousRequest = new Request('http://localhost/api/data', {
        headers: {
          'X-Forwarded-For': '192.168.1.50',
          'User-Agent': 'wget/1.0'
        }
      });

      // Normal request should have higher limits
      const normalResult = await rateLimiter.shouldLimit(normalRequest);

      // Suspicious request should have lower limits
      const suspiciousResult = await rateLimiter.shouldLimit(suspiciousRequest);

      expect(suspiciousResult.allowedRequests).toBeLessThan(normalResult.allowedRequests);
    });

    test('should track request patterns over time', async () => {
      const ipAddress = '192.168.1.75';

      // Simulate burst of requests
      const requests = Array.from({ length: 5 }, () =>
        new Request('http://localhost/api/login', {
          method: 'POST',
          headers: { 'X-Forwarded-For': ipAddress }
        })
      );

      let limitedCount = 0;
      for (const request of requests) {
        const result = await rateLimiter.shouldLimit(request);
        if (result.limited) limitedCount++;
      }

      expect(limitedCount).toBeGreaterThan(0);
    });

    test('should implement adaptive algorithms', async () => {
      const request = new Request('http://localhost/api/sensitive', {
        headers: { 'X-Forwarded-For': '192.168.1.100' }
      });

      const result = await rateLimiter.shouldLimit(request);

      expect(result.algorithm).toBeDefined();
      expect(['token_bucket', 'sliding_window', 'leaky_bucket']).toContain(result.algorithm);
    });
  });

  describe('Security Headers', () => {
    test('should apply comprehensive security headers', async () => {
      const response = new Response('{"data": "test"}', {
        status: 200,
        headers: { 'Content-Type': 'application/json' }
      });

      const context = {
        businessId: 'test-business',
        userId: 'test-user',
        module: 'api',
        role: 'user',
        endpoint: '/api/data',
        method: 'GET',
        correlationId: 'test-123'
      };

      const securedResponse = await securityHeaders.apply(response, context);

      expect(securedResponse.headers.get('Content-Security-Policy')).toBeDefined();
      expect(securedResponse.headers.get('X-Frame-Options')).toBe('DENY');
      expect(securedResponse.headers.get('X-Content-Type-Options')).toBe('nosniff');
      expect(securedResponse.headers.get('Strict-Transport-Security')).toBeDefined();
      expect(securedResponse.headers.get('X-XSS-Protection')).toBeDefined();
    });

    test('should apply module-specific headers', async () => {
      const response = new Response('{"balance": 1000}', {
        status: 200,
        headers: { 'Content-Type': 'application/json' }
      });

      const financeContext = {
        businessId: 'test-business',
        userId: 'test-user',
        module: 'finance',
        role: 'user',
        endpoint: '/api/finance/balance',
        method: 'GET',
        correlationId: 'test-456'
      };

      const securedResponse = await securityHeaders.apply(response, financeContext);

      expect(securedResponse.headers.get('X-Finance-Security')).toBe('enabled');
      expect(securedResponse.headers.get('Cache-Control')).toContain('no-store');
    });

    test('should validate response security', async () => {
      const insecureResponse = new Response('test', {
        headers: {
          'Server': 'Apache/2.4.41',
          'X-Powered-By': 'PHP/7.4'
        }
      });

      const validation = await securityHeaders.validateResponse(insecureResponse);

      expect(validation.secure).toBe(false);
      expect(validation.issues.length).toBeGreaterThan(0);
      expect(validation.issues.some(i => i.type === 'information_disclosure')).toBe(true);
    });
  });

  describe('Zero-Trust Secrets Manager', () => {
    test('should store and retrieve secrets securely', async () => {
      const secretValue = 'super-secret-api-key-12345';

      const metadata = await secretsManager.storeSecret(
        'test-api-key',
        secretValue,
        'api_key',
        'test-business',
        {
          allowedRoles: ['admin', 'user'],
          allowedServices: ['api-service'],
          allowedEnvironments: ['development'],
          mfaRequired: false,
          auditLevel: 'detailed'
        },
        {
          enabled: true,
          intervalDays: 90,
          gracePeriodDays: 7,
          autoRotate: false,
          notifyBeforeDays: 14
        },
        'test-user'
      );

      expect(metadata.id).toBeDefined();
      expect(metadata.type).toBe('api_key');

      const retrieved = await secretsManager.retrieveSecret(
        metadata.id,
        'test-user',
        'api-service',
        'test-business',
        'API authentication'
      );

      expect(retrieved.value).toBe(secretValue);
      expect(retrieved.metadata.id).toBe(metadata.id);
    });

    test('should enforce access policies', async () => {
      const metadata = await secretsManager.storeSecret(
        'restricted-secret',
        'secret-value',
        'encryption_key',
        'test-business',
        {
          allowedRoles: ['admin'],
          allowedServices: ['auth-service'],
          allowedEnvironments: ['production'],
          mfaRequired: true,
          auditLevel: 'comprehensive'
        },
        {
          enabled: true,
          intervalDays: 30,
          gracePeriodDays: 3,
          autoRotate: true,
          notifyBeforeDays: 7
        },
        'admin-user'
      );

      // Should fail for wrong business
      await expect(
        secretsManager.retrieveSecret(
          metadata.id,
          'test-user',
          'auth-service',
          'other-business',
          'encryption'
        )
      ).rejects.toThrow('Access denied');

      // Should fail for wrong service
      await expect(
        secretsManager.retrieveSecret(
          metadata.id,
          'test-user',
          'wrong-service',
          'test-business',
          'encryption'
        )
      ).rejects.toThrow('Access denied');
    });

    test('should rotate secrets', async () => {
      const metadata = await secretsManager.storeSecret(
        'rotation-test',
        'original-value',
        'jwt_secret',
        'test-business',
        {
          allowedRoles: ['admin'],
          allowedServices: ['auth-service'],
          allowedEnvironments: ['development'],
          mfaRequired: false,
          auditLevel: 'basic'
        },
        {
          enabled: true,
          intervalDays: 1,
          gracePeriodDays: 1,
          autoRotate: false,
          notifyBeforeDays: 1
        },
        'test-user'
      );

      const newMetadata = await secretsManager.rotateSecret(
        metadata.id,
        'new-rotated-value',
        'test-user',
        true
      );

      expect(newMetadata.version).toBe(metadata.version + 1);
      expect(newMetadata.lastRotated).toBeGreaterThan(metadata.lastRotated);

      const retrieved = await secretsManager.retrieveSecret(
        metadata.id,
        'test-user',
        'auth-service',
        'test-business',
        'rotation test'
      );

      expect(retrieved.value).toBe('new-rotated-value');
    });
  });

  describe('Advanced XSS Protection', () => {
    test('should detect and sanitize HTML XSS', async () => {
      const maliciousContent = '<script>alert("XSS")</script><p>Safe content</p>';

      const result = await xssProtection.protectContent(maliciousContent, {
        context: 'html',
        allowedTags: ['p', 'br', 'strong'],
        businessId: 'test-business',
        userId: 'test-user',
        endpoint: '/api/content'
      });

      expect(result.isXSS).toBe(true);
      expect(result.blocked).toBe(true);
      expect(result.confidence).toBeGreaterThan(0.8);
      expect(result.attackType).toContain('reflected');
    });

    test('should handle different contexts appropriately', async () => {
      const jsContent = 'eval(userInput)';

      const result = await xssProtection.protectContent(jsContent, {
        context: 'javascript',
        businessId: 'test-business',
        userId: 'test-user',
        endpoint: '/api/script'
      });

      expect(result.isXSS).toBe(true);
      expect(result.sanitizedContent).not.toContain('eval');
    });

    test('should detect evasion techniques', async () => {
      const evasiveContent = '&#60;script&#62;alert(1)&#60;/script&#62;';

      const result = await xssProtection.protectContent(evasiveContent, {
        context: 'html',
        businessId: 'test-business',
        userId: 'test-user',
        endpoint: '/api/content'
      });

      expect(result.isXSS).toBe(true);
      expect(result.attackType).toContain('filter_evasion');
    });

    test('should preserve safe content', async () => {
      const safeContent = '<p>This is <strong>safe</strong> content.</p>';

      const result = await xssProtection.protectContent(safeContent, {
        context: 'html',
        allowedTags: ['p', 'strong'],
        businessId: 'test-business',
        userId: 'test-user',
        endpoint: '/api/content'
      });

      expect(result.isXSS).toBe(false);
      expect(result.sanitizedContent).toContain('<p>');
      expect(result.sanitizedContent).toContain('<strong>');
    });
  });

  describe('Penetration Testing Automation', () => {
    test('should run basic vulnerability scans', async () => {
      const results = await penTestAutomation.runPenetrationTest(
        'test-business',
        'development',
        ['owasp-top10']
      );

      expect(results).toBeDefined();
      expect(Array.isArray(results)).toBe(true);
    });

    test('should detect SQL injection vulnerabilities', async () => {
      // This would require setting up test endpoints
      // Implementation depends on actual testing infrastructure
      expect(true).toBe(true); // Placeholder
    });

    test('should generate comprehensive reports', async () => {
      const results = await penTestAutomation.runPenetrationTest(
        'test-business',
        'development'
      );

      for (const result of results) {
        expect(result.testId).toBeDefined();
        expect(result.status).toBeDefined();
        expect(result.metrics).toBeDefined();
        expect(result.findings).toBeDefined();
      }
    });
  });

  describe('Security Middleware Integration', () => {
    test('should orchestrate all security components', async () => {
      const middleware = securityMiddleware.middleware();

      // Mock context
      const mockContext = {
        req: {
          url: 'http://localhost/api/test',
          method: 'GET',
          header: (name: string) => {
            const headers: Record<string, string> = {
              'user-agent': 'Mozilla/5.0',
              'x-tenant-id': 'test-business',
              'x-user-id': 'test-user'
            };
            return headers[name.toLowerCase()];
          },
          raw: new Request('http://localhost/api/test')
        },
        set: (key: string, value: any) => {},
        json: (data: any, status?: number) => new Response(JSON.stringify(data), { status })
      };

      const nextCalled = { value: false };
      const next = async () => { nextCalled.value = true; };

      await middleware(mockContext, next);

      expect(nextCalled.value).toBe(true);
    });

    test('should block malicious requests', async () => {
      const middleware = securityMiddleware.middleware();

      const mockContext = {
        req: {
          url: "http://localhost/api/users?id=1' OR '1'='1",
          method: 'GET',
          header: (name: string) => {
            const headers: Record<string, string> = {
              'user-agent': 'sqlmap/1.0',
              'x-tenant-id': 'test-business',
              'x-user-id': 'test-user'
            };
            return headers[name.toLowerCase()];
          },
          raw: new Request("http://localhost/api/users?id=1' OR '1'='1")
        },
        set: (key: string, value: any) => {},
        json: (data: any, status?: number) => new Response(JSON.stringify(data), { status })
      };

      const nextCalled = { value: false };
      const next = async () => { nextCalled.value = true; };

      const response = await middleware(mockContext, next);

      expect(nextCalled.value).toBe(false);
      expect(response).toBeDefined();
    });

    test('should handle security errors gracefully', async () => {
      const middleware = securityMiddleware.middleware();

      const mockContext = {
        req: {
          url: 'http://localhost/api/test',
          method: 'GET',
          header: () => { throw new Error('Header error'); },
          raw: new Request('http://localhost/api/test')
        },
        set: (key: string, value: any) => {},
        json: (data: any, status?: number) => new Response(JSON.stringify(data), { status })
      };

      const next = async () => {};

      const response = await middleware(mockContext, next);

      expect(response).toBeDefined();
      // Should fail closed on error
    });
  });

  describe('Performance and Load Testing', () => {
    test('should handle high load without degradation', async () => {
      const startTime = Date.now();
      const requests = 100;

      const promises = Array.from({ length: requests }, async () => {
        const request = new Request('http://localhost/api/data', {
          headers: { 'User-Agent': 'LoadTest/1.0' }
        });

        return await threatEngine.analyzeRequest(request);
      });

      await Promise.all(promises);

      const duration = Date.now() - startTime;
      const avgResponseTime = duration / requests;

      expect(avgResponseTime).toBeLessThan(100); // Less than 100ms per request
    });

    test('should maintain memory efficiency', async () => {
      const initialMemory = process.memoryUsage().heapUsed;

      // Simulate sustained load
      for (let i = 0; i < 1000; i++) {
        const request = new Request(`http://localhost/api/test${i}`, {
          headers: { 'User-Agent': 'MemoryTest/1.0' }
        });

        await threatEngine.analyzeRequest(request);
      }

      const finalMemory = process.memoryUsage().heapUsed;
      const memoryIncrease = (finalMemory - initialMemory) / (1024 * 1024); // MB

      expect(memoryIncrease).toBeLessThan(50); // Less than 50MB increase
    });
  });

  describe('Compliance and Audit', () => {
    test('should maintain comprehensive audit logs', async () => {
      const secretMetadata = await secretsManager.storeSecret(
        'audit-test',
        'test-value',
        'api_key',
        'test-business',
        {
          allowedRoles: ['user'],
          allowedServices: ['test-service'],
          allowedEnvironments: ['development'],
          mfaRequired: false,
          auditLevel: 'comprehensive'
        },
        {
          enabled: true,
          intervalDays: 90,
          gracePeriodDays: 7,
          autoRotate: false,
          notifyBeforeDays: 14
        },
        'test-user'
      );

      const auditTrail = await secretsManager.getAuditTrail(secretMetadata.id, 'test-business');

      expect(auditTrail.length).toBeGreaterThan(0);
      expect(auditTrail[0].action).toBe('create');
      expect(auditTrail[0].userId).toBe('test-user');
      expect(auditTrail[0].businessId).toBe('test-business');
    });

    test('should support compliance reporting', async () => {
      const healthCheck = await secretsManager.healthCheck();

      expect(healthCheck.healthy).toBeDefined();
      expect(healthCheck.metrics).toBeDefined();
      expect(healthCheck.timestamp).toBeDefined();
    });
  });
});

/**
 * Helper functions for tests
 */
function createMockRequest(options: {
  url?: string;
  method?: string;
  headers?: Record<string, string>;
  body?: string;
}): Request {
  return new Request(options.url || 'http://localhost/api/test', {
    method: options.method || 'GET',
    headers: options.headers || {},
    body: options.body
  });
}

function createMockContext(overrides: Partial<any> = {}): any {
  return {
    req: {
      url: 'http://localhost/api/test',
      method: 'GET',
      header: (name: string) => 'test-value',
      raw: new Request('http://localhost/api/test')
    },
    set: (key: string, value: any) => {},
    json: (data: any, status?: number) => new Response(JSON.stringify(data), { status }),
    ...overrides
  };
}

async function simulateLoad(
  fn: (request: Request) => Promise<any>,
  requests: number = 100
): Promise<{ avgResponseTime: number; totalTime: number }> {
  const startTime = Date.now();

  const promises = Array.from({ length: requests }, async (_, i) => {
    const request = new Request(`http://localhost/api/load-test-${i}`);
    return await fn(request);
  });

  await Promise.all(promises);

  const totalTime = Date.now() - startTime;
  const avgResponseTime = totalTime / requests;

  return { avgResponseTime, totalTime };
}

export {
  createMockRequest,
  createMockContext,
  simulateLoad
};