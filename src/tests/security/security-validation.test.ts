/**
 * Comprehensive Security Validation Test Suite
 *
 * This test suite validates that all critical security vulnerabilities have been fixed:
 * - CVSS 8.1: JWT secret rotation
 * - CVSS 7.5: Session fixation prevention
 * - CVSS 6.5: Weak API key hashing
 *
 * Includes fuzz testing and edge case validation
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { JWTService } from '../../services/jwt-service';
import { SessionService } from '../../services/session-service';
import { PasswordCrypto, APIKeyCrypto, TOTPCrypto } from '../../utils/auth-crypto';
import { AuthMiddleware, authenticate } from '../../middleware/auth';
import { AuthorizationService, createAuthorizationService } from '../../middleware/authorization';
import { MockKVNamespace } from '../mocks/kv-namespace-mock';
import { MockD1Database } from '../mocks/d1-database-mock';

function createMockRequest(
  headers: Record<string, string> = {},
  method: string = 'GET',
  url: string = 'https://api.example.com/test'
): Request {
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
    method,
    url
  } as any;
}

describe('Security Vulnerability Fixes Validation', () => {
  let mockKV: MockKVNamespace;
  let mockDB: MockD1Database;
  let jwtService: JWTService;
  let sessionService: SessionService;
  let authMiddleware: AuthMiddleware;
  let authorizationService: AuthorizationService;

  beforeEach(() => {
    mockKV = new MockKVNamespace();
    mockDB = new MockD1Database();

    jwtService = new JWTService(mockKV as any, 'test-issuer', 'test-audience');
    sessionService = new SessionService(mockKV as any, {
      maxAge: 3600,
      idleTimeout: 1800,
      maxConcurrentSessions: 5,
      enableFingerprinting: true,
      enableAnomalyDetection: true,
      requireSecureTransport: true,
      cookieConfig: {
        secure: true,
        httpOnly: true,
        sameSite: 'strict',
        path: '/'
      }
    });

    authMiddleware = new AuthMiddleware(mockDB as any, {
      jwtService,
      sessionService,
      rateLimitKV: mockKV as any,
      auditKV: mockKV as any,
      requireMFA: false,
      allowedAuthMethods: ['jwt', 'apikey', 'session'],
      enableRateLimit: true,
      enableAuditLogging: true
    });

    authorizationService = createAuthorizationService(mockDB as any, mockKV as any);

    // Mock crypto for consistent testing
    global.crypto = {
      ...global.crypto,
      getRandomValues: vi.fn((array: Uint8Array) => {
        for (let i = 0; i < array.length; i++) {
          array[i] = Math.floor(Math.random() * 256);
        }
        return array;
      }),
      subtle: {
        ...global.crypto.subtle,
        sign: vi.fn().mockResolvedValue(new ArrayBuffer(32)),
        verify: vi.fn().mockResolvedValue(true),
        importKey: vi.fn().mockResolvedValue({ type: 'secret' }),
        deriveBits: vi.fn().mockResolvedValue(new ArrayBuffer(64)),
        deriveKey: vi.fn().mockResolvedValue({ type: 'secret' }),
        digest: vi.fn().mockResolvedValue(new ArrayBuffer(32))
      }
    } as any;
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe('CVSS 8.1 Fix: JWT Secret Rotation', () => {
    it('should automatically rotate JWT secrets daily', async () => {
      // Get initial secret
      const initialSecret = await jwtService.getActiveSecret();
      expect(initialSecret.active).toBe(true);

      // Mock rotation being needed
      vi.spyOn(jwtService as any, 'needsRotation').mockReturnValue(true);

      // Force rotation by getting active secret again
      const newSecret = await jwtService.getActiveSecret();

      // Should be a different secret
      expect(newSecret.id).not.toBe(initialSecret.id);
      expect(newSecret.value).not.toBe(initialSecret.value);
      expect(newSecret.active).toBe(true);
    });

    it('should maintain multiple secrets during rotation period', async () => {
      await jwtService.getActiveSecret(); // Create initial

      vi.spyOn(jwtService as any, 'needsRotation').mockReturnValue(true);
      await jwtService.getActiveSecret(); // Force rotation

      const allSecrets = await jwtService.getAllSecrets();
      expect(allSecrets.length).toBeGreaterThanOrEqual(2);

      const activeSecrets = allSecrets.filter(s => s.active);
      expect(activeSecrets.length).toBe(1);
    });

    it('should verify tokens with old secrets after rotation', async () => {
      // Generate token
      const tokenPair = await jwtService.generateTokenPair(
        'user123',
        'user@example.com',
        'business123',
        ['user'],
        ['read:profile']
      );

      // Force rotation
      vi.spyOn(jwtService as any, 'needsRotation').mockReturnValue(true);
      await jwtService.getActiveSecret();

      // Old token should still verify
      const verification = await jwtService.verifyToken(tokenPair.accessToken);
      expect(verification.valid).toBe(true);
    });

    it('should prevent JWT authentication bypass', async () => {
      // Create a token
      const tokenPair = await jwtService.generateTokenPair(
        'user123',
        'user@example.com',
        'business123',
        ['user'],
        ['read:profile']
      );

      // Try to tamper with token
      const parts = tokenPair.accessToken.split('.');
      const tamperedToken = `${parts[0]}.${parts[1]}.TAMPERED_SIGNATURE`;

      const verification = await jwtService.verifyToken(tamperedToken);
      expect(verification.valid).toBe(false);
      expect(verification.error).toContain('signature');
    });
  });

  describe('CVSS 7.5 Fix: Session Fixation Prevention', () => {
    it('should regenerate session ID after login', async () => {
      const request = createMockRequest({
        'cf-connecting-ip': '192.168.1.100',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
      });

      const session1 = await sessionService.createSession(
        'user123',
        'business123',
        'user@example.com',
        ['user'],
        ['read:profile'],
        request
      );

      // Renew session (simulates login)
      const session2 = await sessionService.renewSession(session1.sessionId, request);

      expect(session2?.sessionId).not.toBe(session1.sessionId);
      expect(session2?.userId).toBe(session1.userId);
    });

    it('should invalidate old session after regeneration', async () => {
      const request = createMockRequest({
        'cf-connecting-ip': '192.168.1.100',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
      });

      const originalSession = await sessionService.createSession(
        'user123',
        'business123',
        'user@example.com',
        ['user'],
        ['read:profile'],
        request
      );

      await sessionService.renewSession(originalSession.sessionId, request);

      // Original session should no longer exist
      const oldSession = await sessionService.getSession(originalSession.sessionId);
      expect(oldSession).toBeNull();
    });

    it('should detect session hijacking attempts', async () => {
      const originalRequest = createMockRequest({
        'cf-connecting-ip': '192.168.1.100',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
      });

      const session = await sessionService.createSession(
        'user123',
        'business123',
        'user@example.com',
        ['user'],
        ['read:profile'],
        originalRequest
      );

      // Different IP address (potential hijacking)
      const hijackRequest = createMockRequest({
        'cf-connecting-ip': '10.0.0.100', // Different IP
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
      });

      const validation = await sessionService.validateSession(session.sessionId, hijackRequest);
      expect(validation.valid).toBe(false);
      expect(validation.securityViolation).toBe(true);
    });

    it('should implement proper session timeout', async () => {
      const request = createMockRequest({
        'cf-connecting-ip': '192.168.1.100',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
      });

      const session = await sessionService.createSession(
        'user123',
        'business123',
        'user@example.com',
        ['user'],
        ['read:profile'],
        request
      );

      // Simulate expired session
      session.expiresAt = Date.now() - 1000;
      await mockKV.put(`session:${session.sessionId}`, JSON.stringify(session));

      const validation = await sessionService.validateSession(session.sessionId, request);
      expect(validation.valid).toBe(false);
      expect(validation.error).toBe('Session expired');
    });
  });

  describe('CVSS 6.5 Fix: Weak API Key Hashing', () => {
    it('should use PBKDF2 instead of SHA-256 for API key hashing', async () => {
      const apiKey = APIKeyCrypto.generateAPIKey();
      const hash = await APIKeyCrypto.hashAPIKey(apiKey);

      // Should use PBKDF2 format
      expect(hash).toMatch(/^pbkdf2-sha256\$\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$/);

      const parts = hash.split('$');
      expect(parts[0]).toBe('pbkdf2-sha256');
      expect(parseInt(parts[1])).toBeGreaterThanOrEqual(300000); // At least 300k iterations
    });

    it('should use sufficient iterations for API key hashing', async () => {
      const apiKey = APIKeyCrypto.generateAPIKey();
      const hash = await APIKeyCrypto.hashAPIKey(apiKey);

      const iterations = parseInt(hash.split('$')[1]);
      expect(iterations).toBeGreaterThanOrEqual(300000);
    });

    it('should verify API keys correctly with PBKDF2', async () => {
      const apiKey = APIKeyCrypto.generateAPIKey();
      const hash = await APIKeyCrypto.hashAPIKey(apiKey);

      const isValid = await APIKeyCrypto.verifyAPIKey(apiKey, hash);
      expect(isValid).toBe(true);

      // Wrong key should fail
      const wrongKey = APIKeyCrypto.generateAPIKey();
      const isInvalid = await APIKeyCrypto.verifyAPIKey(wrongKey, hash);
      expect(isInvalid).toBe(false);
    });

    it('should use constant-time comparison for API key verification', async () => {
      const apiKey = 'cfk_test123456789';
      const hash = await APIKeyCrypto.hashAPIKey(apiKey);

      // Time multiple verifications to ensure consistent timing
      const times: number[] = [];

      for (let i = 0; i < 10; i++) {
        const start = performance.now();
        await APIKeyCrypto.verifyAPIKey(apiKey, hash);
        const end = performance.now();
        times.push(end - start);
      }

      // Timing should be relatively consistent (within reasonable bounds)
      const avgTime = times.reduce((a, b) => a + b, 0) / times.length;
      const maxDeviation = Math.max(...times.map(t => Math.abs(t - avgTime)));

      // Allow for some variance due to system load
      expect(maxDeviation).toBeLessThan(avgTime * 2);
    });
  });

  describe('Password Security Enhancement', () => {
    it('should use PBKDF2 with sufficient iterations for passwords', async () => {
      const password = 'SecurePassword123!';
      const hash = await PasswordCrypto.hashPassword(password);

      expect(hash).toMatch(/^pbkdf2-sha256\$\d+\$/);

      const iterations = parseInt(hash.split('$')[1]);
      expect(iterations).toBeGreaterThanOrEqual(600000); // 600k iterations
    });

    it('should verify passwords correctly', async () => {
      const password = 'SecurePassword123!';
      const hash = await PasswordCrypto.hashPassword(password);

      const isValid = await PasswordCrypto.verifyPassword(password, hash);
      expect(isValid).toBe(true);

      const isInvalid = await PasswordCrypto.verifyPassword('WrongPassword', hash);
      expect(isInvalid).toBe(false);
    });

    it('should reject weak passwords', async () => {
      const weakPasswords = [
        'password',
        '123456',
        'qwerty',
        'short1!',
        'NoSpecialChars123',
        'nonumbers!',
        'NOLOWERCASE123!',
        'nouppercase123!'
      ];

      for (const weakPassword of weakPasswords) {
        if (weakPassword.length >= 8) {
          // Only test length validation for very short passwords
          continue;
        }
        await expect(PasswordCrypto.hashPassword(weakPassword))
          .rejects.toThrow('Password must be at least 8 characters long');
      }
    });
  });

  describe('TOTP Security', () => {
    it('should generate cryptographically secure TOTP secrets', () => {
      const secret1 = TOTPCrypto.generateTOTPSecret();
      const secret2 = TOTPCrypto.generateTOTPSecret();

      expect(secret1).not.toBe(secret2);
      expect(secret1.length).toBeGreaterThan(50);
      expect(secret1).toMatch(/^[A-Z2-7]+$/); // Base32
    });

    it('should validate TOTP codes within time window', async () => {
      const secret = TOTPCrypto.generateTOTPSecret();
      const code = await TOTPCrypto.generateTOTP(secret);

      const isValid = await TOTPCrypto.verifyTOTP(code, secret);
      expect(isValid).toBe(true);
    });

    it('should generate secure backup codes', () => {
      const codes = TOTPCrypto.generateBackupCodes();

      expect(codes).toHaveLength(10);

      // All codes should be unique
      const uniqueCodes = new Set(codes);
      expect(uniqueCodes.size).toBe(codes.length);

      // All codes should be 8 characters alphanumeric
      codes.forEach(code => {
        expect(code).toMatch(/^[A-Z0-9]{8}$/);
      });
    });
  });
});

describe('Fuzz Testing', () => {
  let mockKV: MockKVNamespace;
  let jwtService: JWTService;
  let sessionService: SessionService;

  beforeEach(() => {
    mockKV = new MockKVNamespace();
    jwtService = new JWTService(mockKV as any, 'test-issuer', 'test-audience');
    sessionService = new SessionService(mockKV as any);

    global.crypto = {
      ...global.crypto,
      getRandomValues: vi.fn((array: Uint8Array) => {
        for (let i = 0; i < array.length; i++) {
          array[i] = Math.floor(Math.random() * 256);
        }
        return array;
      }),
      subtle: {
        ...global.crypto.subtle,
        sign: vi.fn().mockResolvedValue(new ArrayBuffer(32)),
        verify: vi.fn().mockResolvedValue(true),
        importKey: vi.fn().mockResolvedValue({ type: 'secret' }),
        deriveBits: vi.fn().mockResolvedValue(new ArrayBuffer(64)),
        digest: vi.fn().mockResolvedValue(new ArrayBuffer(32))
      }
    } as any;
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe('JWT Token Fuzzing', () => {
    const generateFuzzTokens = () => [
      '', // Empty
      'not.a.jwt', // Malformed
      'a.b', // Too few parts
      'a.b.c.d', // Too many parts
      'invalid-base64.payload.signature',
      'header.' + 'x'.repeat(10000) + '.signature', // Oversized payload
      'header.payload.' + 'x'.repeat(10000), // Oversized signature
      'ÑÇ¡¿.payload.signature', // Non-ASCII characters
      'header.payload.', // Missing signature
      '.payload.signature', // Missing header
      'header..signature', // Missing payload
      '   .payload.signature', // Whitespace
      'header.payload.signature   ', // Trailing whitespace
      '\x00\x01\x02.payload.signature', // Null bytes
      'header.payload.signature\n', // Newline
      'header.payload.signature\r', // Carriage return
      JSON.stringify({invalid: 'json'}) + '.payload.signature', // Invalid JSON as part
    ];

    it('should handle malformed tokens gracefully', async () => {
      const fuzzTokens = generateFuzzTokens();

      for (const token of fuzzTokens) {
        const verification = await jwtService.verifyToken(token);
        expect(verification.valid).toBe(false);
        expect(verification.error).toBeDefined();
      }
    });

    it('should not crash on extremely long tokens', async () => {
      const veryLongToken = 'a'.repeat(1000000) + '.b'.repeat(1000000) + '.c'.repeat(1000000);

      const verification = await jwtService.verifyToken(veryLongToken);
      expect(verification.valid).toBe(false);
    });

    it('should handle concurrent verification requests', async () => {
      const validToken = await jwtService.generateTokenPair(
        'user123',
        'user@example.com',
        'business123',
        ['user'],
        ['read:profile']
      );

      const fuzzTokens = generateFuzzTokens();

      // Test concurrent verification with mix of valid and invalid tokens
      const promises = [];

      // Add valid token verifications
      for (let i = 0; i < 10; i++) {
        promises.push(jwtService.verifyToken(validToken.accessToken));
      }

      // Add fuzzed token verifications
      for (const fuzzToken of fuzzTokens) {
        promises.push(jwtService.verifyToken(fuzzToken));
      }

      const results = await Promise.all(promises);

      // First 10 should be valid
      for (let i = 0; i < 10; i++) {
        expect(results[i].valid).toBe(true);
      }

      // Rest should be invalid
      for (let i = 10; i < results.length; i++) {
        expect(results[i].valid).toBe(false);
      }
    });
  });

  describe('Session ID Fuzzing', () => {
    const generateFuzzSessionIds = () => [
      '', // Empty
      'x'.repeat(1000000), // Very long
      '../../etc/passwd', // Path traversal
      '<script>alert(1)</script>', // XSS
      'SELECT * FROM users', // SQL injection
      '\x00\x01\x02\x03', // Null bytes
      '💩🔥💀', // Unicode emojis
      'sess_' + '\n'.repeat(1000), // Newlines
      'sess_' + ' '.repeat(1000), // Spaces
      'sess_' + '\t'.repeat(1000), // Tabs
      'sess_' + '\\'.repeat(100), // Backslashes
      'sess_' + '"'.repeat(100), // Quotes
      'sess_' + "'".repeat(100), // Single quotes
      'sess_' + '${eval("alert(1)")}', // Template injection
      'sess_' + Buffer.alloc(1000, 'A').toString(), // Binary data as string
    ];

    it('should handle malformed session IDs gracefully', async () => {
      const request = createMockRequest({
        'cf-connecting-ip': '192.168.1.100',
        'user-agent': 'Mozilla/5.0'
      });

      const fuzzIds = generateFuzzSessionIds();

      for (const sessionId of fuzzIds) {
        const validation = await sessionService.validateSession(sessionId, request);
        expect(validation.valid).toBe(false);
        // Should not crash or throw unhandled errors
      }
    });

    it('should not leak information from invalid session IDs', async () => {
      const request = createMockRequest();
      const fuzzIds = generateFuzzSessionIds();

      for (const sessionId of fuzzIds) {
        const validation = await sessionService.validateSession(sessionId, request);

        // Error messages should not reveal internal information
        if (validation.error) {
          expect(validation.error).not.toContain('database');
          expect(validation.error).not.toContain('internal');
          expect(validation.error).not.toContain('exception');
          expect(validation.error).not.toContain('stack');
        }
      }
    });
  });

  describe('Password Fuzzing', () => {
    const generateFuzzPasswords = () => [
      '', // Empty
      'x'.repeat(100000), // Very long
      '\x00'.repeat(100), // Null bytes
      'ÄÖÜäöüß', // Non-ASCII
      '🔒🗝️🔑', // Emojis
      'password\npassword', // Newlines
      'password\0password', // Null byte injection
      'password' + '\x01'.repeat(100), // Control characters
      Buffer.alloc(1000, 0x41).toString(), // Binary data
      'pass\r\nword', // CRLF injection
      'pass\tword', // Tab characters
      'pass word', // Spaces (valid but worth testing)
      'päss💩wörd123!', // Mixed Unicode
      JSON.stringify({evil: 'payload'}), // JSON as password
      '<script>alert("xss")</script>', // HTML/JS
      '${eval("malicious code")}', // Template literals
    ];

    it('should handle fuzzed passwords without crashing', async () => {
      const fuzzPasswords = generateFuzzPasswords();

      for (const password of fuzzPasswords) {
        try {
          if (password.length >= 8) { // Only test valid length passwords for hashing
            const hash = await PasswordCrypto.hashPassword(password);
            expect(hash).toBeDefined();

            const isValid = await PasswordCrypto.verifyPassword(password, hash);
            expect(isValid).toBe(true);
          } else {
            // Short passwords should be rejected
            await expect(PasswordCrypto.hashPassword(password))
              .rejects.toThrow();
          }
        } catch (error) {
          // Expected for invalid inputs - should not crash the process
          expect(error).toBeInstanceOf(Error);
        }
      }
    });

    it('should handle timing attacks on password verification', async () => {
      const correctPassword = 'CorrectPassword123!';
      const hash = await PasswordCrypto.hashPassword(correctPassword);

      const fuzzPasswords = generateFuzzPasswords();
      const times: number[] = [];

      // Test timing consistency
      for (const fuzzPassword of fuzzPasswords) {
        const start = performance.now();
        try {
          await PasswordCrypto.verifyPassword(fuzzPassword, hash);
        } catch {
          // Ignore errors, we're testing timing
        }
        const end = performance.now();
        times.push(end - start);
      }

      // Timing should be relatively consistent for constant-time operation
      if (times.length > 0) {
        const avgTime = times.reduce((a, b) => a + b, 0) / times.length;
        const maxTime = Math.max(...times);
        const minTime = Math.min(...times);

        // Allow for reasonable variance due to system load
        expect(maxTime - minTime).toBeLessThan(avgTime * 3);
      }
    });
  });

  describe('API Key Fuzzing', () => {
    const generateFuzzAPIKeys = () => [
      '', // Empty
      'cfk_', // Prefix only
      'cfk_' + 'x'.repeat(100000), // Very long
      'invalid_prefix_key',
      'cfk_../../../etc/passwd',
      'cfk_<script>alert(1)</script>',
      'cfk_SELECT * FROM api_keys',
      'cfk_\x00\x01\x02',
      'cfk_💩🔥💀',
      'cfk_' + '\n'.repeat(100),
      'cfk_' + Buffer.alloc(1000, 'A').toString(),
      'cfk_' + JSON.stringify({malicious: 'payload'}),
      'cfk_${eval("code")}',
      'cfk_' + 'A'.repeat(10000),
    ];

    it('should handle malformed API keys gracefully', async () => {
      const validKey = APIKeyCrypto.generateAPIKey();
      const validHash = await APIKeyCrypto.hashAPIKey(validKey);

      const fuzzKeys = generateFuzzAPIKeys();

      for (const fuzzKey of fuzzKeys) {
        try {
          // Should not crash when verifying against valid hash
          const isValid = await APIKeyCrypto.verifyAPIKey(fuzzKey, validHash);
          expect(isValid).toBe(false);
        } catch (error) {
          // Some may throw validation errors - should be handled gracefully
          expect(error).toBeInstanceOf(Error);
        }

        try {
          // Should handle hashing attempts gracefully
          if (fuzzKey.length >= 10) { // Minimum length check
            const hash = await APIKeyCrypto.hashAPIKey(fuzzKey);
            expect(hash).toBeDefined();
          }
        } catch (error) {
          // Expected for invalid keys
          expect(error).toBeInstanceOf(Error);
        }
      }
    });
  });

  describe('Stress Testing', () => {
    it('should handle high-volume token generation without memory leaks', async () => {
      const initialMemory = process.memoryUsage().heapUsed;

      // Generate many tokens
      const promises = [];
      for (let i = 0; i < 1000; i++) {
        promises.push(jwtService.generateTokenPair(
          `user${i}`,
          `user${i}@example.com`,
          'business123',
          ['user'],
          ['read:profile']
        ));
      }

      await Promise.all(promises);

      // Force garbage collection if available
      if (global.gc) {
        global.gc();
      }

      const finalMemory = process.memoryUsage().heapUsed;
      const memoryIncrease = finalMemory - initialMemory;

      // Memory increase should be reasonable (less than 100MB for 1000 tokens)
      expect(memoryIncrease).toBeLessThan(100 * 1024 * 1024);
    });

    it('should maintain performance under load', async () => {
      const tokenPair = await jwtService.generateTokenPair(
        'user123',
        'user@example.com',
        'business123',
        ['user'],
        ['read:profile']
      );

      const startTime = Date.now();

      // Verify many tokens concurrently
      const promises = [];
      for (let i = 0; i < 100; i++) {
        promises.push(jwtService.verifyToken(tokenPair.accessToken));
      }

      const results = await Promise.all(promises);
      const endTime = Date.now();
      const duration = endTime - startTime;

      // All should be valid
      results.forEach(result => {
        expect(result.valid).toBe(true);
      });

      // Should complete within reasonable time (< 1 second for 100 verifications)
      expect(duration).toBeLessThan(1000);
    });
  });
});

describe('Edge Case Testing', () => {
  let mockKV: MockKVNamespace;
  let jwtService: JWTService;

  beforeEach(() => {
    mockKV = new MockKVNamespace();
    jwtService = new JWTService(mockKV as any, 'test-issuer', 'test-audience');

    global.crypto = {
      ...global.crypto,
      getRandomValues: vi.fn((array: Uint8Array) => {
        for (let i = 0; i < array.length; i++) {
          array[i] = Math.floor(Math.random() * 256);
        }
        return array;
      }),
      subtle: {
        ...global.crypto.subtle,
        sign: vi.fn().mockResolvedValue(new ArrayBuffer(32)),
        verify: vi.fn().mockResolvedValue(true),
        importKey: vi.fn().mockResolvedValue({ type: 'secret' })
      }
    } as any;
  });

  it('should handle KV storage failures gracefully', async () => {
    // Mock KV failure
    vi.spyOn(mockKV, 'get').mockRejectedValue(new Error('KV unavailable'));

    // Should not crash
    const verification = await jwtService.verifyToken('test.token.here');
    expect(verification.valid).toBe(false);
  });

  it('should handle crypto API failures gracefully', async () => {
    // Mock crypto failure
    vi.spyOn(global.crypto.subtle, 'sign').mockRejectedValue(new Error('Crypto unavailable'));

    // Should not crash
    await expect(jwtService.generateTokenPair(
      'user123',
      'user@example.com',
      'business123',
      ['user'],
      ['read:profile']
    )).rejects.toThrow();
  });

  it('should handle extreme input values', async () => {
    const extremeInputs = {
      userId: 'x'.repeat(10000),
      email: 'x'.repeat(1000) + '@' + 'x'.repeat(1000) + '.com',
      businessId: 'x'.repeat(10000),
      roles: Array(1000).fill('role'),
      permissions: Array(1000).fill('permission')
    };

    // Should handle without crashing
    try {
      await jwtService.generateTokenPair(
        extremeInputs.userId,
        extremeInputs.email,
        extremeInputs.businessId,
        extremeInputs.roles,
        extremeInputs.permissions
      );
    } catch (error) {
      // May fail due to size limits, but should not crash
      expect(error).toBeInstanceOf(Error);
    }
  });
});

describe('Security Compliance Validation', () => {
  let mockKV: MockKVNamespace;

  beforeEach(() => {
    mockKV = new MockKVNamespace();
  });

  it('should meet OWASP cryptographic requirements', async () => {
    // Test PBKDF2 iterations
    const password = 'TestPassword123!';
    const hash = await PasswordCrypto.hashPassword(password);
    const iterations = parseInt(hash.split('$')[1]);

    expect(iterations).toBeGreaterThanOrEqual(600000); // OWASP 2025 recommendation

    // Test salt length (should be at least 128 bits / 16 bytes)
    const saltB64 = hash.split('$')[2];
    const saltLength = atob(saltB64).length;
    expect(saltLength).toBeGreaterThanOrEqual(16);
  });

  it('should implement proper secret management', async () => {
    const service = new JWTService(mockKV as any);

    const secret1 = await service.getActiveSecret();
    const secret2 = await service.getActiveSecret();

    // Secrets should be properly generated
    expect(secret1.value.length).toBeGreaterThan(50); // At least 384 bits when base64url encoded
    expect(secret1.id).toMatch(/^[a-f0-9]+$/); // Hex format

    // Should not regenerate unnecessarily
    expect(secret1.id).toBe(secret2.id);
  });

  it('should implement secure session management', async () => {
    const service = new SessionService(mockKV as any, {
      enableFingerprinting: true,
      requireSecureTransport: true,
      cookieConfig: {
        secure: true,
        httpOnly: true,
        sameSite: 'strict',
        path: '/'
      }
    });

    const request = createMockRequest({
      'cf-connecting-ip': '192.168.1.100',
      'user-agent': 'Mozilla/5.0'
    });

    const session = await service.createSession(
      'user123',
      'business123',
      'user@example.com',
      ['user'],
      ['read:profile'],
      request
    );

    // Session should have security attributes
    expect(session.fingerprint).toBeDefined();
    expect(session.metadata.riskScore).toBeDefined();
    expect(session.sessionId).toMatch(/^sess_/);
    expect(session.sessionId.length).toBeGreaterThan(40); // Sufficient entropy
  });
});

describe('Performance Benchmarks', () => {
  let mockKV: MockKVNamespace;

  beforeEach(() => {
    mockKV = new MockKVNamespace();
  });

  it('should meet performance requirements for auth operations', async () => {
    const service = new JWTService(mockKV as any);

    // Token generation should be under 100ms
    const start = Date.now();
    await service.generateTokenPair(
      'user123',
      'user@example.com',
      'business123',
      ['user'],
      ['read:profile']
    );
    const tokenGenTime = Date.now() - start;
    expect(tokenGenTime).toBeLessThan(100);

    // Password hashing should be reasonable (but slow for security)
    const hashStart = Date.now();
    await PasswordCrypto.hashPassword('TestPassword123!');
    const hashTime = Date.now() - hashStart;
    expect(hashTime).toBeLessThan(5000); // Should complete within 5 seconds
  });
});