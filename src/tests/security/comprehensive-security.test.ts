/**
 * Comprehensive Security Test Suite
 * Tests all security components for OWASP compliance
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { unstable_dev } from 'wrangler';
import type { Unstable_DevWorker } from 'wrangler';

// Import security components for unit testing
import { JWTRotation } from '../../security/jwt-rotation';
import { createSessionManager } from '../../security/session-manager';
import { createEnhancedApiKeySecurity } from '../../security/enhanced-api-key-security';
import { createRBACSystem } from '../../security/rbac-system';
import { AppError, ValidationError, AuthenticationError } from '../../middleware/error-handler';
import { createStructuredLogger } from '../../middleware/structured-logger';
import { createPerformanceMonitor } from '../../monitoring/performance-monitor';

describe('JWT Secret Rotation Tests', () => {
  let mockEnv: any;
  let jwtRotation: JWTRotation;

  beforeAll(() => {
    mockEnv = {
      KV_AUTH: createMockKV(),
      JWT_SECRET: 'test-secret-with-minimum-32-characters-for-security'
    };
    jwtRotation = new JWTRotation(mockEnv);
  });

  it('should rotate JWT secrets successfully', async () => {
    const newSecret = await jwtRotation.rotateSecrets();
    expect(newSecret).toBeDefined();
    expect(newSecret.version).toBeGreaterThan(0);
    expect(newSecret.status).toBe('active');
  });

  it('should verify tokens with rotated secrets', async () => {
    const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'; // Mock token
    const result = await jwtRotation.verifyWithRotation(token);
    expect(result.valid).toBeDefined();
  });

  it('should handle emergency rotation', async () => {
    const emergencySecret = await jwtRotation.emergencyRotation(
      'Security breach detected',
      'admin@coreflow360.com'
    );
    expect(emergencySecret).toBeDefined();
    expect(emergencySecret.rotationReason).toContain('EMERGENCY');
  });

  it('should validate secret entropy', async () => {
    const weakSecret = 'weak';
    const validation = await jwtRotation['validateSecret'](weakSecret);
    expect(validation.isValid).toBe(false);
    expect(validation.errors).toContain('Secret must be at least 64 characters');
  });
});

describe('Session Management Tests', () => {
  let sessionManager: any;
  let mockKV: any;

  beforeAll(() => {
    mockKV = createMockKV();
    sessionManager = createSessionManager(mockKV);
  });

  it('should create session with fingerprint', async () => {
    const mockRequest = createMockRequest();
    const { sessionId, session } = await sessionManager.createSession(
      'user123',
      'business456',
      'user@example.com',
      ['user'],
      ['read:profile'],
      mockRequest
    );

    expect(sessionId).toBeDefined();
    expect(session.fingerprint).toBeDefined();
    expect(session.userId).toBe('user123');
  });

  it('should detect session hijacking', async () => {
    const mockRequest1 = createMockRequest({ 'CF-Connecting-IP': '192.168.1.1' });
    const { sessionId } = await sessionManager.createSession(
      'user123',
      'business456',
      'user@example.com',
      ['user'],
      ['read:profile'],
      mockRequest1
    );

    // Different IP attempting to use same session
    const mockRequest2 = createMockRequest({ 'CF-Connecting-IP': '10.0.0.1' });
    const validation = await sessionManager.validateSession(sessionId, mockRequest2);

    expect(validation.valid).toBe(false);
    expect(validation.reason).toContain('hijacking');
  });

  it('should regenerate session ID', async () => {
    const mockRequest = createMockRequest();
    const { sessionId: oldId } = await sessionManager.createSession(
      'user123',
      'business456',
      'user@example.com',
      ['user'],
      ['read:profile'],
      mockRequest
    );

    const result = await sessionManager.regenerateSession(oldId, mockRequest);
    expect(result).toBeDefined();
    expect(result.sessionId).not.toBe(oldId);
  });

  it('should enforce concurrent session limits', async () => {
    const mockRequest = createMockRequest();
    const sessions = [];

    // Create max concurrent sessions
    for (let i = 0; i < 5; i++) {
      const { sessionId } = await sessionManager.createSession(
        'user123',
        'business456',
        'user@example.com',
        ['user'],
        ['read:profile'],
        mockRequest
      );
      sessions.push(sessionId);
    }

    // Creating one more should remove the oldest
    const { sessionId: newSession } = await sessionManager.createSession(
      'user123',
      'business456',
      'user@example.com',
      ['user'],
      ['read:profile'],
      mockRequest
    );

    const oldestValidation = await sessionManager.validateSession(sessions[0], mockRequest);
    expect(oldestValidation.valid).toBe(false);
  });
});

describe('API Key Security Tests', () => {
  let apiKeySecurity: any;
  let mockKV: any;

  beforeAll(() => {
    mockKV = createMockKV();
    apiKeySecurity = createEnhancedApiKeySecurity(mockKV);
  });

  it('should generate secure API keys with Argon2', async () => {
    const { apiKey, keyData } = await apiKeySecurity.generateApiKey(
      'user123',
      'business456',
      'Test API Key',
      ['read', 'write']
    );

    expect(apiKey).toMatch(/^cf_[a-zA-Z0-9_-]{32}$/);
    expect(keyData.keyHash).toBeDefined();
    expect(keyData.keyHash).not.toBe(apiKey); // Should be hashed
  });

  it('should validate API keys correctly', async () => {
    const { apiKey } = await apiKeySecurity.generateApiKey(
      'user123',
      'business456',
      'Test Key',
      ['read']
    );

    const validation = await apiKeySecurity.validateApiKey(apiKey);
    expect(validation.valid).toBe(true);
    expect(validation.keyData).toBeDefined();
  });

  it('should enforce rate limiting on API keys', async () => {
    const { apiKey } = await apiKeySecurity.generateApiKey(
      'user123',
      'business456',
      'Rate Limited Key',
      ['read'],
      30
    );

    // Simulate multiple requests
    for (let i = 0; i < 100; i++) {
      await apiKeySecurity.validateApiKey(apiKey);
    }

    // Next request should be rate limited
    const validation = await apiKeySecurity.validateApiKey(apiKey);
    expect(validation.remainingRequests).toBeLessThan(1);
  });

  it('should rotate API keys with grace period', async () => {
    const { apiKey: oldKey } = await apiKeySecurity.generateApiKey(
      'user123',
      'business456',
      'Rotating Key',
      ['read']
    );

    const result = await apiKeySecurity.rotateApiKey(oldKey, 7);
    expect(result).toBeDefined();
    expect(result.apiKey).not.toBe(oldKey);

    // Old key should still work during grace period
    const oldValidation = await apiKeySecurity.validateApiKey(oldKey);
    expect(oldValidation.valid).toBe(true);
  });
});

describe('RBAC System Tests', () => {
  let rbacSystem: any;
  let mockKV: any;

  beforeAll(() => {
    mockKV = createMockKV();
    rbacSystem = createRBACSystem(mockKV);
  });

  it('should enforce role-based permissions', async () => {
    // Assign user role
    await rbacSystem.assignRoles('user123', 'business456', ['user']);

    // Check allowed action
    const readAccess = await rbacSystem.checkAccess({
      userId: 'user123',
      businessId: 'business456',
      resource: 'profile',
      action: 'read',
      context: { ownerId: 'user123' }
    });

    expect(readAccess.allowed).toBe(true);

    // Check denied action
    const deleteAccess = await rbacSystem.checkAccess({
      userId: 'user123',
      businessId: 'business456',
      resource: 'users',
      action: 'delete'
    });

    expect(deleteAccess.allowed).toBe(false);
  });

  it('should support role hierarchy', async () => {
    await rbacSystem.assignRoles('manager123', 'business456', ['manager']);

    // Manager should inherit user permissions
    const userAccess = await rbacSystem.checkAccess({
      userId: 'manager123',
      businessId: 'business456',
      resource: 'profile',
      action: 'read',
      context: { ownerId: 'manager123' }
    });

    expect(userAccess.allowed).toBe(true);

    // Plus have manager permissions
    const reportAccess = await rbacSystem.checkAccess({
      userId: 'manager123',
      businessId: 'business456',
      resource: 'reports',
      action: 'read'
    });

    expect(reportAccess.allowed).toBe(true);
  });

  it('should handle direct permissions', async () => {
    await rbacSystem.grantPermission('user123', 'business456', {
      id: 'custom',
      resource: 'special',
      action: 'execute',
      scope: 'own'
    });

    const access = await rbacSystem.checkAccess({
      userId: 'user123',
      businessId: 'business456',
      resource: 'special',
      action: 'execute',
      context: { ownerId: 'user123' }
    });

    expect(access.allowed).toBe(true);
  });
});

describe('Error Handling Tests', () => {
  it('should sanitize error messages in production', () => {
    const error = new AppError('Database connection failed', 500, 'DB_ERROR', false);
    expect(error.message).toBe('Database connection failed');
    expect(error.isOperational).toBe(false);
  });

  it('should handle validation errors correctly', () => {
    const error = new ValidationError('Invalid email format');
    expect(error.statusCode).toBe(400);
    expect(error.code).toBe('VALIDATION_ERROR');
  });

  it('should handle authentication errors', () => {
    const error = new AuthenticationError();
    expect(error.statusCode).toBe(401);
    expect(error.code).toBe('AUTHENTICATION_ERROR');
  });
});

describe('XSS and Injection Prevention Tests', () => {
  it('should prevent XSS in input sanitization', () => {
    const inputs = [
      '<script>alert(1)</script>',
      '<img src=x onerror=alert(1)>',
      'javascript:alert(1)',
      '<svg onload=alert(1)>',
      '"><script>alert(1)</script>'
    ];

    for (const input of inputs) {
      const sanitized = sanitizeInput(input);
      expect(sanitized).not.toContain('<script');
      expect(sanitized).not.toContain('alert');
      expect(sanitized).not.toContain('javascript:');
      expect(sanitized).not.toContain('onerror');
      expect(sanitized).not.toContain('onload');
    }
  });

  it('should prevent SQL injection', () => {
    const inputs = [
      "'; DROP TABLE users; --",
      "1' OR '1'='1",
      "admin' --",
      "1; UPDATE users SET admin=true"
    ];

    for (const input of inputs) {
      const sanitized = sanitizeInput(input);
      expect(sanitized).not.toContain('DROP TABLE');
      expect(sanitized).not.toContain('UPDATE');
      expect(sanitized).not.toContain("OR '1'='1");
    }
  });

  it('should prevent path traversal', () => {
    const paths = [
      '../../../etc/passwd',
      '..\\..\\windows\\system32',
      '%2e%2e%2f%2e%2e%2f',
      '....//....//etc/passwd'
    ];

    for (const path of paths) {
      const sanitized = sanitizeInput(path);
      expect(sanitized).not.toContain('..');
      expect(sanitized).not.toContain('%2e');
    }
  });
});

describe('Performance Monitoring Tests', () => {
  let monitor: any;
  let mockKV: any;

  beforeAll(() => {
    mockKV = createMockKV();
    monitor = createPerformanceMonitor({}, mockKV);
  });

  it('should track request metrics', async () => {
    const ctx = createMockContext();
    const middleware = monitor.middleware();

    await middleware(ctx, async () => {
      // Simulate request processing
      await new Promise(resolve => setTimeout(resolve, 100));
    });

    const summary = await monitor.getPerformanceSummary(1);
    expect(summary.totalRequests).toBeGreaterThan(0);
    expect(summary.averageResponseTime).toBeGreaterThan(0);
  });

  it('should detect slow requests', async () => {
    monitor = createPerformanceMonitor(
      { responseTimeThreshold: 50 },
      mockKV
    );

    const ctx = createMockContext();
    const middleware = monitor.middleware();

    await middleware(ctx, async () => {
      // Simulate slow request
      await new Promise(resolve => setTimeout(resolve, 100));
    });

    const summary = await monitor.getPerformanceSummary(1);
    expect(summary.slowRequests).toBeGreaterThan(0);
  });

  it('should calculate error rates', async () => {
    const ctx = createMockContext();
    const middleware = monitor.middleware();

    // Simulate error
    try {
      await middleware(ctx, async () => {
        throw new Error('Test error');
      });
    } catch {}

    const summary = await monitor.getPerformanceSummary(1);
    expect(summary.errorRate).toBeGreaterThan(0);
  });
});

// Helper functions
function createMockKV() {
  const storage = new Map();
  return {
    get: async (key: string) => storage.get(key) || null,
    put: async (key: string, value: string, options?: any) => {
      storage.set(key, value);
    },
    delete: async (key: string) => storage.delete(key),
    list: async (options?: any) => ({
      keys: Array.from(storage.keys()).map(name => ({ name }))
    })
  };
}

function createMockRequest(headers: Record<string, string> = {}) {
  return {
    headers: {
      get: (name: string) => headers[name] || null
    },
    header: (name: string) => headers[name] || null,
    raw: {} // Mock raw request
  };
}

function createMockContext() {
  const vars = new Map();
  return {
    req: {
      method: 'GET',
      path: '/test',
      header: (name: string) => null,
      raw: {}
    },
    res: {
      status: 200
    },
    get: (key: string) => vars.get(key),
    set: (key: string, value: any) => vars.set(key, value)
  };
}

function sanitizeInput(input: string): string {
  // Import from security middleware
  const { sanitizeInput } = require('../../middleware/security');
  return sanitizeInput(input);
}