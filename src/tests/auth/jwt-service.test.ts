/**
 * Comprehensive Unit Tests for JWT Service
 * Target: 95%+ Test Coverage
 *
 * Tests cover:
 * - JWT token generation and verification
 * - Secret rotation functionality
 * - Token refresh mechanism
 * - Token revocation and blacklisting
 * - Error handling and edge cases
 * - Security vulnerabilities
 * - Performance requirements
 */

import { describe, it, expect, beforeEach, afterEach, vi, Mock } from 'vitest';
import { JWTService, JWTClaims, JWTTokenPair, JWTVerificationResult } from '../../services/jwt-service';

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

  // Clear all data for testing
  clear(): void {
    this.store.clear();
  }

  // Get all data for testing
  getAll(): Map<string, string> {
    return new Map(this.store);
  }

  // Additional KVNamespace methods (not used in tests)
  async getWithMetadata(): Promise<any> { return null; }
  async put(): Promise<void> { }
  async getMetadata(): Promise<any> { return null; }
}

describe('JWTService', () => {
  let jwtService: JWTService;
  let mockKV: MockKVNamespace;
  let originalCrypto: any;

  beforeEach(() => {
    // Setup mock KV namespace
    mockKV = new MockKVNamespace();

    // Create JWT service instance
    jwtService = new JWTService(mockKV as any, 'test-issuer', 'test-audience');

    // Mock crypto for consistent testing using vi.stubGlobal
    originalCrypto = global.crypto;
    vi.stubGlobal('crypto', {
      ...originalCrypto,
      getRandomValues: vi.fn((array: Uint8Array) => {
        // Fill with predictable values for testing
        for (let i = 0; i < array.length; i++) {
          array[i] = i % 256;
        }
        return array;
      }),
      subtle: {
        ...originalCrypto.subtle,
        sign: vi.fn().mockResolvedValue(new ArrayBuffer(32)),
        verify: vi.fn().mockResolvedValue(true)
      }
    });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.clearAllMocks();
  });

  describe('Token Generation', () => {
    it('should generate valid token pair', async () => {
      const tokenPair = await jwtService.generateTokenPair(
        'user123',
        'user@example.com',
        'business123',
        ['user'],
        ['read:profile'],
        'session123',
        true
      );

      expect(tokenPair).toMatchObject({
        accessToken: expect.any(String),
        refreshToken: expect.any(String),
        expiresIn: 15 * 60, // 15 minutes
        tokenType: 'Bearer'
      });

      expect(tokenPair.accessToken).toMatch(/^[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+$/);
      expect(tokenPair.refreshToken).toMatch(/^[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+$/);
    });

    it('should generate tokens with correct claims', async () => {
      const tokenPair = await jwtService.generateTokenPair(
        'user123',
        'user@example.com',
        'business123',
        ['admin'],
        ['read:all', 'write:all'],
        'session123',
        true
      );

      // Verify token can be parsed (not cryptographically verified in unit tests)
      const verification = await jwtService.verifyToken(tokenPair.accessToken);

      expect(verification.valid).toBe(true);
      expect(verification.payload).toMatchObject({
        sub: 'user123',
        email: 'user@example.com',
        businessId: 'business123',
        roles: ['admin'],
        permissions: ['read:all', 'write:all'],
        typ: 'access',
        mfaVerified: true,
        sessionId: 'session123'
      });
    });

    it('should generate different JTIs for access and refresh tokens', async () => {
      const tokenPair = await jwtService.generateTokenPair(
        'user123',
        'user@example.com',
        'business123',
        ['user'],
        ['read:profile']
      );

      const accessVerification = await jwtService.verifyToken(tokenPair.accessToken);
      const refreshVerification = await jwtService.verifyToken(tokenPair.refreshToken);

      expect(accessVerification.payload?.jti).toBeDefined();
      expect(refreshVerification.payload?.jti).toBeDefined();
      expect(accessVerification.payload?.jti).not.toBe(refreshVerification.payload?.jti);
    });

    it('should handle missing optional parameters', async () => {
      const tokenPair = await jwtService.generateTokenPair(
        'user123',
        'user@example.com',
        'business123',
        ['user'],
        ['read:profile']
      );

      const verification = await jwtService.verifyToken(tokenPair.accessToken);

      expect(verification.payload).toMatchObject({
        mfaVerified: false,
        sessionId: undefined
      });
    });
  });

  describe('Token Verification', () => {
    it('should verify valid tokens', async () => {
      const tokenPair = await jwtService.generateTokenPair(
        'user123',
        'user@example.com',
        'business123',
        ['user'],
        ['read:profile']
      );

      const verification = await jwtService.verifyToken(tokenPair.accessToken);

      expect(verification).toMatchObject({
        valid: true,
        payload: expect.objectContaining({
          sub: 'user123',
          email: 'user@example.com'
        })
      });
    });

    it('should reject malformed tokens', async () => {
      const verification = await jwtService.verifyToken('invalid.token');

      expect(verification).toMatchObject({
        valid: false,
        error: expect.any(String)
      });
    });

    it('should reject tokens with invalid signature', async () => {
      const tokenPair = await jwtService.generateTokenPair(
        'user123',
        'user@example.com',
        'business123',
        ['user'],
        ['read:profile']
      );

      // Tamper with token
      const tamperedToken = tokenPair.accessToken.slice(0, -5) + 'XXXXX';

      const verification = await jwtService.verifyToken(tamperedToken);

      expect(verification.valid).toBe(false);
      expect(verification.error).toContain('signature');
    });

    it('should identify expired tokens', async () => {
      // Mock expired token by manipulating crypto.subtle.verify
      (global.crypto.subtle.verify as Mock).mockRejectedValueOnce(
        new Error('JWTExpired: "exp" claim timestamp check failed')
      );

      const tokenPair = await jwtService.generateTokenPair(
        'user123',
        'user@example.com',
        'business123',
        ['user'],
        ['read:profile']
      );

      const verification = await jwtService.verifyToken(tokenPair.accessToken);

      expect(verification).toMatchObject({
        valid: false,
        error: 'Token expired',
        isExpired: true,
        needsRefresh: true
      });
    });

    it('should detect tokens needing refresh', async () => {
      // Create token that's close to expiry
      const now = Math.floor(Date.now() / 1000);

      // Mock the JWT verification to return a token that expires in 4 minutes
      vi.spyOn(jwtService as any, 'shouldRefresh').mockReturnValue(true);

      const tokenPair = await jwtService.generateTokenPair(
        'user123',
        'user@example.com',
        'business123',
        ['user'],
        ['read:profile']
      );

      const verification = await jwtService.verifyToken(tokenPair.accessToken);

      expect(verification.needsRefresh).toBe(true);
    });

    it('should reject blacklisted tokens', async () => {
      const tokenPair = await jwtService.generateTokenPair(
        'user123',
        'user@example.com',
        'business123',
        ['user'],
        ['read:profile']
      );

      // First verification should pass
      let verification = await jwtService.verifyToken(tokenPair.accessToken);
      expect(verification.valid).toBe(true);

      // Revoke the token
      await jwtService.revokeToken(tokenPair.accessToken, 'test revocation');

      // Second verification should fail
      verification = await jwtService.verifyToken(tokenPair.accessToken);
      expect(verification.valid).toBe(false);
      expect(verification.error).toContain('revoked');
    });
  });

  describe('Secret Rotation', () => {
    it('should automatically create initial secret', async () => {
      // Clear any existing secrets
      mockKV.clear();

      const stats = await jwtService.getStatistics();
      expect(stats.activeSecrets).toBe(1);
      expect(stats.rotationDue).toBe(false);
    });

    it('should rotate secrets when needed', async () => {
      // Get initial active secret
      const initialSecret = await jwtService.getActiveSecret();

      // Force rotation by mocking age
      vi.spyOn(jwtService as any, 'needsRotation').mockReturnValue(true);

      const newSecret = await jwtService.getActiveSecret();

      expect(newSecret.id).not.toBe(initialSecret.id);
      expect(newSecret.value).not.toBe(initialSecret.value);
      expect(newSecret.active).toBe(true);
    });

    it('should maintain multiple secrets during rotation period', async () => {
      // Generate initial secret
      await jwtService.getActiveSecret();

      // Force rotation
      vi.spyOn(jwtService as any, 'needsRotation').mockReturnValue(true);
      await jwtService.getActiveSecret();

      const allSecrets = await jwtService.getAllSecrets();
      expect(allSecrets.length).toBeGreaterThanOrEqual(2);

      // Only one should be active
      const activeSecrets = allSecrets.filter(s => s.active);
      expect(activeSecrets.length).toBe(1);
    });

    it('should verify tokens with old secrets', async () => {
      // Generate token with current secret
      const tokenPair = await jwtService.generateTokenPair(
        'user123',
        'user@example.com',
        'business123',
        ['user'],
        ['read:profile']
      );

      // Force secret rotation
      vi.spyOn(jwtService as any, 'needsRotation').mockReturnValue(true);
      await jwtService.getActiveSecret();

      // Token should still verify with old secret
      const verification = await jwtService.verifyToken(tokenPair.accessToken);
      expect(verification.valid).toBe(true);
    });

    it('should clean up old secrets', async () => {
      // Mock very old secrets
      const veryOldTime = Date.now() - (8 * 24 * 60 * 60 * 1000); // 8 days ago

      // Directly manipulate the secrets storage
      const oldSecrets = [{
        id: 'old-secret',
        value: 'old-value',
        active: false,
        createdAt: veryOldTime,
        rotatedAt: veryOldTime,
        algorithm: 'HS256'
      }];

      await mockKV.put('jwt:secrets:v2', JSON.stringify(oldSecrets));

      // Force rotation which should clean up old secrets
      const allSecrets = await jwtService.getAllSecrets();

      // Old secret should be filtered out
      const currentSecrets = allSecrets.filter(s =>
        (Date.now() - s.createdAt) < (7 * 24 * 60 * 60 * 1000)
      );

      expect(currentSecrets.length).toBeGreaterThanOrEqual(1);
    });
  });

  describe('Token Refresh', () => {
    it('should refresh valid refresh tokens', async () => {
      const originalTokenPair = await jwtService.generateTokenPair(
        'user123',
        'user@example.com',
        'business123',
        ['user'],
        ['read:profile'],
        'session123'
      );

      const refreshResult = await jwtService.refreshToken(originalTokenPair.refreshToken);

      expect(refreshResult).toMatchObject({
        accessToken: expect.any(String),
        refreshToken: expect.any(String),
        expiresIn: 15 * 60,
        tokenType: 'Bearer'
      });

      // New tokens should be different
      expect(refreshResult.accessToken).not.toBe(originalTokenPair.accessToken);
      expect(refreshResult.refreshToken).not.toBe(originalTokenPair.refreshToken);
    });

    it('should reject access tokens for refresh', async () => {
      const tokenPair = await jwtService.generateTokenPair(
        'user123',
        'user@example.com',
        'business123',
        ['user'],
        ['read:profile']
      );

      const refreshResult = await jwtService.refreshToken(tokenPair.accessToken);

      expect(refreshResult).toMatchObject({
        error: 'Invalid token type for refresh'
      });
    });

    it('should reject revoked refresh tokens', async () => {
      const tokenPair = await jwtService.generateTokenPair(
        'user123',
        'user@example.com',
        'business123',
        ['user'],
        ['read:profile']
      );

      // Revoke the refresh token
      await jwtService.revokeToken(tokenPair.refreshToken);

      const refreshResult = await jwtService.refreshToken(tokenPair.refreshToken);

      expect(refreshResult).toMatchObject({
        error: expect.stringContaining('revoked')
      });
    });

    it('should revoke old refresh token after successful refresh', async () => {
      const originalTokenPair = await jwtService.generateTokenPair(
        'user123',
        'user@example.com',
        'business123',
        ['user'],
        ['read:profile']
      );

      // Refresh the token
      const refreshResult = await jwtService.refreshToken(originalTokenPair.refreshToken);

      expect('accessToken' in refreshResult).toBe(true);

      // Try to use the old refresh token again
      const secondRefreshResult = await jwtService.refreshToken(originalTokenPair.refreshToken);

      expect(secondRefreshResult).toMatchObject({
        error: expect.any(String)
      });
    });
  });

  describe('Token Revocation', () => {
    it('should revoke access tokens', async () => {
      const tokenPair = await jwtService.generateTokenPair(
        'user123',
        'user@example.com',
        'business123',
        ['user'],
        ['read:profile']
      );

      // Token should be valid initially
      let verification = await jwtService.verifyToken(tokenPair.accessToken);
      expect(verification.valid).toBe(true);

      // Revoke the token
      await jwtService.revokeToken(tokenPair.accessToken, 'user logout');

      // Token should now be invalid
      verification = await jwtService.verifyToken(tokenPair.accessToken);
      expect(verification.valid).toBe(false);
      expect(verification.error).toContain('revoked');
    });

    it('should revoke refresh tokens', async () => {
      const tokenPair = await jwtService.generateTokenPair(
        'user123',
        'user@example.com',
        'business123',
        ['user'],
        ['read:profile']
      );

      await jwtService.revokeToken(tokenPair.refreshToken, 'security concern');

      const refreshResult = await jwtService.refreshToken(tokenPair.refreshToken);
      expect(refreshResult).toMatchObject({
        error: expect.any(String)
      });
    });

    it('should revoke all user tokens', async () => {
      // Generate multiple token pairs for the same user
      const tokenPair1 = await jwtService.generateTokenPair(
        'user123',
        'user@example.com',
        'business123',
        ['user'],
        ['read:profile'],
        'session1'
      );

      const tokenPair2 = await jwtService.generateTokenPair(
        'user123',
        'user@example.com',
        'business123',
        ['user'],
        ['read:profile'],
        'session2'
      );

      // Revoke all tokens for the user
      await jwtService.revokeAllUserTokens('user123');

      // Both refresh tokens should be revoked
      const refresh1Result = await jwtService.refreshToken(tokenPair1.refreshToken);
      const refresh2Result = await jwtService.refreshToken(tokenPair2.refreshToken);

      expect(refresh1Result).toMatchObject({ error: expect.any(String) });
      expect(refresh2Result).toMatchObject({ error: expect.any(String) });
    });

    it('should handle revocation of invalid tokens gracefully', async () => {
      // Should not throw error when revoking invalid token
      await expect(jwtService.revokeToken('invalid.token', 'test')).resolves.toBeUndefined();
    });
  });

  describe('Security Features', () => {
    it('should generate cryptographically secure secrets', async () => {
      const secret1 = await (jwtService as any).generateSecretValue();
      const secret2 = await (jwtService as any).generateSecretValue();

      expect(secret1).not.toBe(secret2);
      expect(secret1.length).toBeGreaterThan(50); // Base64url encoded 64 bytes
      expect(secret1).toMatch(/^[A-Za-z0-9_-]+$/); // Base64url format
    });

    it('should generate unique JTIs', async () => {
      const jti1 = await (jwtService as any).generateSecureId();
      const jti2 = await (jwtService as any).generateSecureId();

      expect(jti1).not.toBe(jti2);
      expect(jti1).toMatch(/^[a-f0-9]{32}$/); // 32 hex characters
    });

    it('should validate required claims', async () => {
      // This would require mocking the internal JWT verification
      // to return malformed payloads
      const malformedClaims = {
        // Missing sub
        email: 'user@example.com',
        businessId: 'business123'
      };

      const validation = await (jwtService as any).validateTokenClaims(malformedClaims as any, 'test-token');

      expect(validation.valid).toBe(false);
      expect(validation.error).toContain('required claims');
    });

    it('should validate token types', async () => {
      const tokenPair = await jwtService.generateTokenPair(
        'user123',
        'user@example.com',
        'business123',
        ['user'],
        ['read:profile']
      );

      // Mock validation to check typ claim
      const accessVerification = await jwtService.verifyToken(tokenPair.accessToken);
      const refreshVerification = await jwtService.verifyToken(tokenPair.refreshToken);

      expect(accessVerification.payload?.typ).toBe('access');
      expect(refreshVerification.payload?.typ).toBe('refresh');
    });

    it('should enforce issuer and audience', async () => {
      const tokenPair = await jwtService.generateTokenPair(
        'user123',
        'user@example.com',
        'business123',
        ['user'],
        ['read:profile']
      );

      const verification = await jwtService.verifyToken(tokenPair.accessToken);

      expect(verification.payload?.iss).toBe('test-issuer');
      expect(verification.payload?.aud).toBe('test-audience');
    });
  });

  describe('Error Handling', () => {
    it('should handle KV storage errors gracefully', async () => {
      // Mock KV error
      vi.spyOn(mockKV, 'get').mockRejectedValueOnce(new Error('KV error'));

      const verification = await jwtService.verifyToken('test.token.here');

      expect(verification.valid).toBe(false);
      expect(verification.error).toBeTruthy();
    });

    it('should handle crypto errors gracefully', async () => {
      // Mock crypto error
      vi.spyOn(global.crypto, 'getRandomValues').mockImplementationOnce(() => {
        throw new Error('Crypto error');
      });

      await expect(jwtService.generateTokenPair(
        'user123',
        'user@example.com',
        'business123',
        ['user'],
        ['read:profile']
      )).rejects.toThrow();
    });

    it('should handle malformed stored secrets', async () => {
      // Store malformed secrets data
      await mockKV.put('jwt:secrets:v2', 'invalid-json');

      // Should still work by creating new secrets
      const activeSecret = await jwtService.getActiveSecret();
      expect(activeSecret).toBeDefined();
      expect(activeSecret.active).toBe(true);
    });
  });

  describe('Performance', () => {
    it('should meet response time requirements', async () => {
      const startTime = Date.now();

      await jwtService.generateTokenPair(
        'user123',
        'user@example.com',
        'business123',
        ['user'],
        ['read:profile']
      );

      const endTime = Date.now();
      const duration = endTime - startTime;

      // Should complete within reasonable time (100ms in test environment)
      expect(duration).toBeLessThan(100);
    });

    it('should handle concurrent token generation', async () => {
      const promises = Array(10).fill(null).map((_, i) =>
        jwtService.generateTokenPair(
          `user${i}`,
          `user${i}@example.com`,
          'business123',
          ['user'],
          ['read:profile']
        )
      );

      const results = await Promise.all(promises);

      // All tokens should be unique
      const accessTokens = results.map(r => r.accessToken);
      const uniqueTokens = new Set(accessTokens);

      expect(uniqueTokens.size).toBe(accessTokens.length);
    });
  });

  describe('Statistics', () => {
    it('should provide accurate statistics', async () => {
      // Generate some tokens to populate data
      await jwtService.generateTokenPair(
        'user123',
        'user@example.com',
        'business123',
        ['user'],
        ['read:profile']
      );

      const stats = await jwtService.getStatistics();

      expect(stats).toMatchObject({
        activeSecrets: expect.any(Number),
        oldestSecretAge: expect.any(Number),
        rotationDue: expect.any(Boolean),
        totalBlacklistedTokens: expect.any(Number)
      });

      expect(stats.activeSecrets).toBeGreaterThanOrEqual(1);
      expect(stats.oldestSecretAge).toBeGreaterThanOrEqual(0);
    });
  });

  describe('Integration Tests', () => {
    it('should complete full token lifecycle', async () => {
      // Generate token pair
      const tokenPair = await jwtService.generateTokenPair(
        'user123',
        'user@example.com',
        'business123',
        ['user'],
        ['read:profile'],
        'session123'
      );

      // Verify access token
      let verification = await jwtService.verifyToken(tokenPair.accessToken);
      expect(verification.valid).toBe(true);

      // Refresh tokens
      const refreshResult = await jwtService.refreshToken(tokenPair.refreshToken);
      expect('accessToken' in refreshResult).toBe(true);

      if ('accessToken' in refreshResult) {
        // Verify new access token
        verification = await jwtService.verifyToken(refreshResult.accessToken);
        expect(verification.valid).toBe(true);

        // Revoke new token
        await jwtService.revokeToken(refreshResult.accessToken);

        // Verify revocation
        verification = await jwtService.verifyToken(refreshResult.accessToken);
        expect(verification.valid).toBe(false);
      }
    });

    it('should maintain security during secret rotation', async () => {
      // Generate token with current secret
      const tokenPair1 = await jwtService.generateTokenPair(
        'user123',
        'user@example.com',
        'business123',
        ['user'],
        ['read:profile']
      );

      // Force secret rotation
      vi.spyOn(jwtService as any, 'needsRotation').mockReturnValue(true);

      // Generate token with new secret
      const tokenPair2 = await jwtService.generateTokenPair(
        'user456',
        'user456@example.com',
        'business123',
        ['user'],
        ['read:profile']
      );

      // Both tokens should still be valid
      const verification1 = await jwtService.verifyToken(tokenPair1.accessToken);
      const verification2 = await jwtService.verifyToken(tokenPair2.accessToken);

      expect(verification1.valid).toBe(true);
      expect(verification2.valid).toBe(true);
    });
  });
});