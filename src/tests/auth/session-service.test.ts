/**
 * Comprehensive Unit Tests for Session Service
 * Target: 95%+ Test Coverage
 *
 * Tests cover:
 * - Session creation with fingerprinting
 * - Session validation and security checks
 * - Session regeneration (anti-fixation)
 * - Session destruction and cleanup
 * - Anomaly detection
 * - Multi-session management
 * - Security violations handling
 */

import { describe, it, expect, beforeEach, afterEach, vi, Mock } from 'vitest';
import {
  SessionService,
  SessionData,
  SessionConfig,
  SessionValidationResult,
  createSessionService
} from '../../services/session-service';

// Mock KVNamespace for testing
class MockKVNamespace implements KVNamespace {
  private store = new Map<string, string>();

  async get(key: string): Promise<string | null> {
    return this.store.get(key) || null;
  }

  async put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void> {
    this.store.set(key, value);
  }

  async delete(key: string): Promise<void> {
    this.store.delete(key);
  }

  async list(options?: { prefix?: string; limit?: number }): Promise<{ keys: { name: string }[] }> {
    const keys = Array.from(this.store.keys())
      .filter(key => !options?.prefix || key.startsWith(options.prefix))
      .slice(0, options?.limit || 1000)
      .map(name => ({ name }));
    return { keys };
  }

  clear(): void {
    this.store.clear();
  }

  getAll(): Map<string, string> {
    return new Map(this.store);
  }

  // Additional KVNamespace methods
  async getWithMetadata(): Promise<any> { return null; }
  async getMetadata(): Promise<any> { return null; }
}

// Mock Request object
class MockRequest {
  public headers: Map<string, string>;
  public url: string;

  constructor(headers: Record<string, string> = {}, url: string = 'https://example.com') {
    this.headers = new Map(Object.entries(headers));
    this.url = url;
  }

  get(name: string): string | null {
    return this.headers.get(name.toLowerCase()) || null;
  }
}

// Create mock Request that matches Web API
function createMockRequest(headers: Record<string, string> = {}): Request {
  return {
    headers: {
      get: (name: string) => headers[name.toLowerCase()] || null,
      has: (name: string) => name.toLowerCase() in headers,
      forEach: () => {},
      entries: () => [][Symbol.iterator](),
      keys: () => [][Symbol.iterator](),
      values: () => [][Symbol.iterator](),
      [Symbol.iterator]: () => [][Symbol.iterator](),
      append: () => {},
      delete: () => {},
      set: () => {}
    },
    url: 'https://example.com/test',
    method: 'GET'
  } as any;
}

describe('SessionService', () => {
  let sessionService: SessionService;
  let mockKV: MockKVNamespace;
  let mockRequest: Request;
  let originalCrypto: any;

  const testConfig: Partial<SessionConfig> = {
    maxAge: 3600, // 1 hour for testing
    idleTimeout: 1800, // 30 minutes
    maxConcurrentSessions: 3,
    enableFingerprinting: true,
    enableAnomalyDetection: true
  };

  beforeEach(() => {
    mockKV = new MockKVNamespace();
    sessionService = createSessionService(mockKV as any, testConfig);

    mockRequest = createMockRequest({
      'cf-connecting-ip': '192.168.1.100',
      'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
      'accept-language': 'en-US,en;q=0.9',
      'accept-encoding': 'gzip, deflate, br'
    });

    // Mock crypto for consistent testing using vi.stubGlobal
    originalCrypto = global.crypto;
    vi.stubGlobal('crypto', {
      ...originalCrypto,
      getRandomValues: vi.fn((array: Uint8Array) => {
        for (let i = 0; i < array.length; i++) {
          array[i] = i % 256;
        }
        return array;
      }),
      subtle: {
        ...originalCrypto.subtle,
        digest: vi.fn().mockResolvedValue(new ArrayBuffer(32))
      }
    });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.clearAllMocks();
  });

  describe('Session Creation', () => {
    it('should create session with correct data structure', async () => {
      const session = await sessionService.createSession(
        'user123',
        'business123',
        'user@example.com',
        ['user'],
        ['read:profile'],
        mockRequest,
        'password',
        true
      );

      expect(session).toMatchObject({
        sessionId: expect.stringMatching(/^sess_/),
        userId: 'user123',
        businessId: 'business123',
        email: 'user@example.com',
        roles: ['user'],
        permissions: ['read:profile'],
        mfaVerified: true,
        createdAt: expect.any(Number),
        lastActivity: expect.any(Number),
        expiresAt: expect.any(Number),
        fingerprint: {
          ipAddress: '192.168.1.100',
          userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
          acceptLanguage: 'en-US,en;q=0.9',
          acceptEncoding: 'gzip, deflate, br'
        },
        metadata: {
          loginMethod: 'password',
          riskScore: expect.any(Number),
          anomalyFlags: expect.any(Array)
        }
      });
    });

    it('should generate unique session IDs', async () => {
      const session1 = await sessionService.createSession(
        'user123',
        'business123',
        'user@example.com',
        ['user'],
        ['read:profile'],
        mockRequest
      );

      const session2 = await sessionService.createSession(
        'user456',
        'business123',
        'user456@example.com',
        ['user'],
        ['read:profile'],
        mockRequest
      );

      expect(session1.sessionId).not.toBe(session2.sessionId);
    });

    it('should create comprehensive fingerprint', async () => {
      const session = await sessionService.createSession(
        'user123',
        'business123',
        'user@example.com',
        ['user'],
        ['read:profile'],
        mockRequest
      );

      expect(session.fingerprint).toMatchObject({
        ipAddress: expect.any(String),
        userAgent: expect.any(String),
        acceptLanguage: expect.any(String),
        acceptEncoding: expect.any(String)
      });
    });

    it('should handle missing headers gracefully', async () => {
      const requestWithMissingHeaders = createMockRequest({
        'cf-connecting-ip': '192.168.1.100'
        // Missing other headers
      });

      const session = await sessionService.createSession(
        'user123',
        'business123',
        'user@example.com',
        ['user'],
        ['read:profile'],
        requestWithMissingHeaders
      );

      expect(session.fingerprint.userAgent).toBe('unknown');
      expect(session.fingerprint.acceptLanguage).toBe('unknown');
    });

    it('should set correct expiration times', async () => {
      const beforeCreate = Date.now();

      const session = await sessionService.createSession(
        'user123',
        'business123',
        'user@example.com',
        ['user'],
        ['read:profile'],
        mockRequest
      );

      const afterCreate = Date.now();

      expect(session.createdAt).toBeGreaterThanOrEqual(beforeCreate);
      expect(session.createdAt).toBeLessThanOrEqual(afterCreate);
      expect(session.expiresAt).toBe(session.createdAt + (testConfig.maxAge! * 1000));
    });

    it('should perform anomaly detection during creation', async () => {
      const suspiciousRequest = createMockRequest({
        'cf-connecting-ip': '192.168.1.100',
        'user-agent': 'curl/7.68.0' // Suspicious user agent
      });

      const session = await sessionService.createSession(
        'user123',
        'business123',
        'user@example.com',
        ['user'],
        ['read:profile'],
        suspiciousRequest
      );

      expect(session.metadata.riskScore).toBeGreaterThan(0);
    });
  });

  describe('Session Validation', () => {
    let testSession: SessionData;

    beforeEach(async () => {
      testSession = await sessionService.createSession(
        'user123',
        'business123',
        'user@example.com',
        ['user'],
        ['read:profile'],
        mockRequest
      );
    });

    it('should validate active sessions', async () => {
      const validation = await sessionService.validateSession(
        testSession.sessionId,
        mockRequest
      );

      expect(validation).toMatchObject({
        valid: true,
        session: expect.objectContaining({
          sessionId: testSession.sessionId,
          userId: 'user123'
        })
      });
    });

    it('should reject non-existent sessions', async () => {
      const validation = await sessionService.validateSession(
        'nonexistent-session-id',
        mockRequest
      );

      expect(validation).toMatchObject({
        valid: false,
        error: 'Session not found'
      });
    });

    it('should reject expired sessions', async () => {
      // Manually expire the session
      testSession.expiresAt = Date.now() - 1000; // 1 second ago
      await mockKV.put(`session:${testSession.sessionId}`, JSON.stringify(testSession));

      const validation = await sessionService.validateSession(
        testSession.sessionId,
        mockRequest
      );

      expect(validation).toMatchObject({
        valid: false,
        error: 'Session expired'
      });
    });

    it('should reject idle sessions', async () => {
      // Set last activity to trigger idle timeout
      testSession.lastActivity = Date.now() - (testConfig.idleTimeout! * 1000) - 1000;
      await mockKV.put(`session:${testSession.sessionId}`, JSON.stringify(testSession));

      const validation = await sessionService.validateSession(
        testSession.sessionId,
        mockRequest
      );

      expect(validation).toMatchObject({
        valid: false,
        error: 'Session idle timeout'
      });
    });

    it('should detect fingerprint mismatches', async () => {
      const differentRequest = createMockRequest({
        'cf-connecting-ip': '192.168.1.200', // Different IP
        'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)'
      });

      const validation = await sessionService.validateSession(
        testSession.sessionId,
        differentRequest
      );

      expect(validation).toMatchObject({
        valid: false,
        error: 'Session security violation detected',
        securityViolation: true
      });
    });

    it('should allow minor fingerprint changes with warnings', async () => {
      const slightlyDifferentRequest = createMockRequest({
        'cf-connecting-ip': '192.168.1.100', // Same IP
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.37', // Slightly different UA
        'accept-language': 'en-US,en;q=0.9',
        'accept-encoding': 'gzip, deflate, br'
      });

      const validation = await sessionService.validateSession(
        testSession.sessionId,
        slightlyDifferentRequest
      );

      expect(validation.valid).toBe(true);
      expect(validation.warnings).toBeDefined();
      expect(validation.warnings?.length).toBeGreaterThan(0);
    });

    it('should update last activity on successful validation', async () => {
      const originalActivity = testSession.lastActivity;

      // Wait a bit to ensure timestamp difference
      await new Promise(resolve => setTimeout(resolve, 10));

      await sessionService.validateSession(testSession.sessionId, mockRequest);

      const updatedSession = await sessionService.getSession(testSession.sessionId);
      expect(updatedSession?.lastActivity).toBeGreaterThan(originalActivity);
    });

    it('should indicate when renewal is required', async () => {
      // Set session to be 80% of max age (should trigger renewal)
      const ageForRenewal = testConfig.maxAge! * 1000 * 0.8;
      testSession.createdAt = Date.now() - ageForRenewal;
      await mockKV.put(`session:${testSession.sessionId}`, JSON.stringify(testSession));

      const validation = await sessionService.validateSession(
        testSession.sessionId,
        mockRequest
      );

      expect(validation.valid).toBe(true);
      expect(validation.renewRequired).toBe(true);
    });

    it('should handle missing session ID', async () => {
      const validation = await sessionService.validateSession('', mockRequest);

      expect(validation).toMatchObject({
        valid: false,
        error: 'Session ID missing'
      });
    });
  });

  describe('Session Renewal', () => {
    let testSession: SessionData;

    beforeEach(async () => {
      testSession = await sessionService.createSession(
        'user123',
        'business123',
        'user@example.com',
        ['user'],
        ['read:profile'],
        mockRequest
      );
    });

    it('should renew session with new ID', async () => {
      const renewedSession = await sessionService.renewSession(
        testSession.sessionId,
        mockRequest
      );

      expect(renewedSession).toBeDefined();
      expect(renewedSession?.sessionId).not.toBe(testSession.sessionId);
      expect(renewedSession?.userId).toBe(testSession.userId);
      expect(renewedSession?.expiresAt).toBeGreaterThan(testSession.expiresAt);
    });

    it('should invalidate old session after renewal', async () => {
      const renewedSession = await sessionService.renewSession(
        testSession.sessionId,
        mockRequest
      );

      expect(renewedSession).toBeDefined();

      // Old session should not exist
      const oldSession = await sessionService.getSession(testSession.sessionId);
      expect(oldSession).toBeNull();

      // New session should exist
      const newSession = await sessionService.getSession(renewedSession!.sessionId);
      expect(newSession).toBeDefined();
    });

    it('should return null for non-existent session', async () => {
      const renewedSession = await sessionService.renewSession(
        'non-existent-session',
        mockRequest
      );

      expect(renewedSession).toBeNull();
    });

    it('should update fingerprint during renewal', async () => {
      const newRequest = createMockRequest({
        'cf-connecting-ip': '192.168.1.100',
        'user-agent': 'Updated User Agent',
        'accept-language': 'en-US,en;q=0.9',
        'accept-encoding': 'gzip, deflate, br'
      });

      const renewedSession = await sessionService.renewSession(
        testSession.sessionId,
        newRequest
      );

      expect(renewedSession?.fingerprint.userAgent).toBe('Updated User Agent');
    });
  });

  describe('Session Destruction', () => {
    let testSession: SessionData;

    beforeEach(async () => {
      testSession = await sessionService.createSession(
        'user123',
        'business123',
        'user@example.com',
        ['user'],
        ['read:profile'],
        mockRequest
      );
    });

    it('should destroy session completely', async () => {
      await sessionService.destroySession(testSession.sessionId);

      const session = await sessionService.getSession(testSession.sessionId);
      expect(session).toBeNull();
    });

    it('should handle destroying non-existent session', async () => {
      // Should not throw error
      await expect(
        sessionService.destroySession('non-existent-session')
      ).resolves.toBeUndefined();
    });

    it('should destroy all user sessions except specified one', async () => {
      // Create multiple sessions for the same user
      const session2 = await sessionService.createSession(
        'user123',
        'business123',
        'user@example.com',
        ['user'],
        ['read:profile'],
        mockRequest
      );

      const session3 = await sessionService.createSession(
        'user123',
        'business123',
        'user@example.com',
        ['user'],
        ['read:profile'],
        mockRequest
      );

      const destroyedCount = await sessionService.destroyAllUserSessions(
        'user123',
        testSession.sessionId
      );

      expect(destroyedCount).toBe(2);

      // Original session should still exist
      const remainingSession = await sessionService.getSession(testSession.sessionId);
      expect(remainingSession).toBeDefined();

      // Other sessions should be destroyed
      const destroyedSession2 = await sessionService.getSession(session2.sessionId);
      const destroyedSession3 = await sessionService.getSession(session3.sessionId);
      expect(destroyedSession2).toBeNull();
      expect(destroyedSession3).toBeNull();
    });

    it('should destroy all user sessions when no exception', async () => {
      const session2 = await sessionService.createSession(
        'user123',
        'business123',
        'user@example.com',
        ['user'],
        ['read:profile'],
        mockRequest
      );

      const destroyedCount = await sessionService.destroyAllUserSessions('user123');

      expect(destroyedCount).toBe(2);

      // All sessions should be destroyed
      const session1Check = await sessionService.getSession(testSession.sessionId);
      const session2Check = await sessionService.getSession(session2.sessionId);
      expect(session1Check).toBeNull();
      expect(session2Check).toBeNull();
    });
  });

  describe('Concurrent Session Management', () => {
    it('should enforce maximum concurrent sessions', async () => {
      const sessions: SessionData[] = [];

      // Create sessions up to the limit
      for (let i = 0; i < testConfig.maxConcurrentSessions!; i++) {
        const session = await sessionService.createSession(
          'user123',
          'business123',
          'user@example.com',
          ['user'],
          ['read:profile'],
          mockRequest
        );
        sessions.push(session);
      }

      // Create one more session - should evict the oldest
      const extraSession = await sessionService.createSession(
        'user123',
        'business123',
        'user@example.com',
        ['user'],
        ['read:profile'],
        mockRequest
      );

      // First session should be destroyed
      const firstSession = await sessionService.getSession(sessions[0].sessionId);
      expect(firstSession).toBeNull();

      // Latest session should exist
      const latestSession = await sessionService.getSession(extraSession.sessionId);
      expect(latestSession).toBeDefined();
    });

    it('should track sessions per user separately', async () => {
      // Create sessions for different users
      const user1Session = await sessionService.createSession(
        'user123',
        'business123',
        'user123@example.com',
        ['user'],
        ['read:profile'],
        mockRequest
      );

      const user2Session = await sessionService.createSession(
        'user456',
        'business123',
        'user456@example.com',
        ['user'],
        ['read:profile'],
        mockRequest
      );

      // Both sessions should exist independently
      const session1 = await sessionService.getSession(user1Session.sessionId);
      const session2 = await sessionService.getSession(user2Session.sessionId);

      expect(session1).toBeDefined();
      expect(session2).toBeDefined();
    });
  });

  describe('Anomaly Detection', () => {
    it('should detect suspicious user agents', async () => {
      const suspiciousRequest = createMockRequest({
        'cf-connecting-ip': '192.168.1.100',
        'user-agent': 'python-requests/2.28.0'
      });

      const session = await sessionService.createSession(
        'user123',
        'business123',
        'user@example.com',
        ['user'],
        ['read:profile'],
        suspiciousRequest
      );

      expect(session.metadata.riskScore).toBeGreaterThan(0.3);
      expect(session.metadata.anomalyFlags).toContain('suspicious_user_agent');
    });

    it('should detect automation tools', async () => {
      const botRequest = createMockRequest({
        'cf-connecting-ip': '192.168.1.100',
        'user-agent': 'Googlebot/2.1'
      });

      const session = await sessionService.createSession(
        'user123',
        'business123',
        'user@example.com',
        ['user'],
        ['read:profile'],
        botRequest
      );

      expect(session.metadata.riskScore).toBeGreaterThan(0.3);
      expect(session.metadata.anomalyFlags).toContain('automation_detected');
    });

    it('should detect rapid location changes in ongoing sessions', async () => {
      const session = await sessionService.createSession(
        'user123',
        'business123',
        'user@example.com',
        ['user'],
        ['read:profile'],
        mockRequest
      );

      // Mock different IP (simulating location change)
      const differentLocationRequest = createMockRequest({
        'cf-connecting-ip': '10.0.0.100', // Different IP
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
      });

      // This should trigger security violation due to IP change
      const validation = await sessionService.validateSession(
        session.sessionId,
        differentLocationRequest
      );

      expect(validation.valid).toBe(false);
      expect(validation.securityViolation).toBe(true);
    });
  });

  describe('Security Cookie Creation', () => {
    it('should create secure cookie with proper attributes', async () => {
      const sessionId = 'sess_test123';
      const cookie = sessionService.createSecureCookie(sessionId);

      expect(cookie).toContain('session=sess_test123');
      expect(cookie).toContain('HttpOnly');
      expect(cookie).toContain('Secure');
      expect(cookie).toContain('SameSite=strict');
      expect(cookie).toContain('Path=/');
      expect(cookie).toContain(`Max-Age=${testConfig.maxAge}`);
    });

    it('should handle custom cookie configuration', async () => {
      const customConfig: Partial<SessionConfig> = {
        ...testConfig,
        cookieConfig: {
          secure: false,
          httpOnly: true,
          sameSite: 'lax',
          domain: 'example.com',
          path: '/api'
        }
      };

      const customService = createSessionService(mockKV as any, customConfig);
      const cookie = customService.createSecureCookie('test-session');

      expect(cookie).not.toContain('Secure');
      expect(cookie).toContain('HttpOnly');
      expect(cookie).toContain('SameSite=lax');
      expect(cookie).toContain('Domain=example.com');
      expect(cookie).toContain('Path=/api');
    });
  });

  describe('Error Handling', () => {
    it('should handle KV storage errors gracefully', async () => {
      vi.spyOn(mockKV, 'get').mockRejectedValueOnce(new Error('KV error'));

      const validation = await sessionService.validateSession('test-session', mockRequest);

      expect(validation.valid).toBe(false);
    });

    it('should handle malformed session data', async () => {
      await mockKV.put('session:malformed', 'invalid-json');

      const session = await sessionService.getSession('malformed');
      expect(session).toBeNull();
    });

    it('should handle crypto errors during fingerprinting', async () => {
      vi.spyOn(global.crypto.subtle, 'digest').mockRejectedValueOnce(new Error('Crypto error'));

      // Should still create session with fallback fingerprinting
      const session = await sessionService.createSession(
        'user123',
        'business123',
        'user@example.com',
        ['user'],
        ['read:profile'],
        mockRequest
      );

      expect(session).toBeDefined();
    });
  });

  describe('Performance', () => {
    it('should meet session creation performance requirements', async () => {
      const startTime = Date.now();

      await sessionService.createSession(
        'user123',
        'business123',
        'user@example.com',
        ['user'],
        ['read:profile'],
        mockRequest
      );

      const duration = Date.now() - startTime;
      expect(duration).toBeLessThan(100); // Should complete within 100ms
    });

    it('should handle concurrent session operations', async () => {
      const promises = Array(10).fill(null).map((_, i) =>
        sessionService.createSession(
          `user${i}`,
          'business123',
          `user${i}@example.com`,
          ['user'],
          ['read:profile'],
          mockRequest
        )
      );

      const sessions = await Promise.all(promises);

      // All sessions should be created successfully
      expect(sessions).toHaveLength(10);
      sessions.forEach(session => {
        expect(session.sessionId).toBeDefined();
      });
    });
  });

  describe('Configuration', () => {
    it('should use default configuration when not provided', async () => {
      const defaultService = createSessionService(mockKV as any);

      const session = await defaultService.createSession(
        'user123',
        'business123',
        'user@example.com',
        ['user'],
        ['read:profile'],
        mockRequest
      );

      expect(session).toBeDefined();
    });

    it('should merge partial configuration with defaults', async () => {
      const partialConfig = { maxAge: 7200 }; // Only specify maxAge
      const service = createSessionService(mockKV as any, partialConfig);

      const session = await service.createSession(
        'user123',
        'business123',
        'user@example.com',
        ['user'],
        ['read:profile'],
        mockRequest
      );

      // Should use custom maxAge but default other values
      expect(session.expiresAt - session.createdAt).toBe(7200 * 1000);
    });

    it('should disable fingerprinting when configured', async () => {
      const noFingerprintConfig = { ...testConfig, enableFingerprinting: false };
      const service = createSessionService(mockKV as any, noFingerprintConfig);

      const session = await service.createSession(
        'user123',
        'business123',
        'user@example.com',
        ['user'],
        ['read:profile'],
        mockRequest
      );

      // Different IP should not cause security violation when fingerprinting is disabled
      const differentRequest = createMockRequest({
        'cf-connecting-ip': '10.0.0.100'
      });

      const validation = await service.validateSession(session.sessionId, differentRequest);
      expect(validation.valid).toBe(true);
      expect(validation.securityViolation).toBeFalsy();
    });
  });

  describe('Integration Tests', () => {
    it('should complete full session lifecycle', async () => {
      // Create session
      const session = await sessionService.createSession(
        'user123',
        'business123',
        'user@example.com',
        ['user'],
        ['read:profile'],
        mockRequest,
        'password',
        true
      );

      // Validate session
      let validation = await sessionService.validateSession(session.sessionId, mockRequest);
      expect(validation.valid).toBe(true);

      // Renew session
      const renewedSession = await sessionService.renewSession(session.sessionId, mockRequest);
      expect(renewedSession).toBeDefined();

      // Validate renewed session
      validation = await sessionService.validateSession(renewedSession!.sessionId, mockRequest);
      expect(validation.valid).toBe(true);

      // Destroy session
      await sessionService.destroySession(renewedSession!.sessionId);

      // Validate destroyed session
      validation = await sessionService.validateSession(renewedSession!.sessionId, mockRequest);
      expect(validation.valid).toBe(false);
    });

    it('should maintain security throughout session lifecycle', async () => {
      const session = await sessionService.createSession(
        'user123',
        'business123',
        'user@example.com',
        ['user'],
        ['read:profile'],
        mockRequest
      );

      // Normal validation should work
      let validation = await sessionService.validateSession(session.sessionId, mockRequest);
      expect(validation.valid).toBe(true);

      // Security violation should be detected
      const maliciousRequest = createMockRequest({
        'cf-connecting-ip': '192.168.1.200' // Different IP
      });

      validation = await sessionService.validateSession(session.sessionId, maliciousRequest);
      expect(validation.valid).toBe(false);
      expect(validation.securityViolation).toBe(true);

      // Session should be automatically destroyed after security violation
      const sessionAfterViolation = await sessionService.getSession(session.sessionId);
      expect(sessionAfterViolation).toBeNull();
    });
  });
});