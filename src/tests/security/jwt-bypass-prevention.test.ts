/**
 * JWT Authentication Bypass Prevention Tests
 * CRITICAL SECURITY TEST SUITE - OWASP 2025 Compliant
 *
 * This test suite specifically validates protection against JWT authentication bypass
 * vulnerabilities (CVSS 9.8) that could allow complete authentication circumvention.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { JWTSecretManager } from '../../shared/security/jwt-secret-manager';
import { EnvironmentValidator } from '../../shared/environment-validator';
import { JWTSecretRotation } from '../../modules/auth/jwt-secret-rotation';

describe('JWT Authentication Bypass Prevention (CVSS 9.8)', () => {
  describe('Critical Vulnerability: fallback-secret', () => {
    it('should BLOCK fallback-secret completely', () => {
      // This specific value was found in the codebase and causes authentication bypass
      const vulnerableSecret = 'fallback-secret';

      const validation = JWTSecretManager.validateJWTSecret(vulnerableSecret);

      expect(validation.isValid).toBe(false);
      // Check that it's detected as a blacklisted value
      const blacklistError = validation.errors.find(e => e.includes('blacklisted value'));
      expect(blacklistError).toBeDefined();
      // Check that JWT bypass vulnerability is mentioned
      const bypassError = validation.errors.find(e => e.includes('JWT Authentication Bypass vulnerability'));
      expect(bypassError).toBeDefined();
      // Ensure "secret" is detected in the value
      expect(blacklistError).toContain('secret');
    });

    it('should BLOCK fallback-secret even when padded', () => {
      // Test that padding doesn't bypass detection
      const paddedSecret = 'fallback-secret'.padEnd(64, 'x');

      const validation = JWTSecretManager.validateJWTSecret(paddedSecret);

      expect(validation.isValid).toBe(false);
      expect(validation.errors).toContainEqual(
        expect.stringContaining('JWT Authentication Bypass vulnerability')
      );
    });

    it('should BLOCK fallback-secret in any case variation', () => {
      const variations = [
        'Fallback-Secret',
        'FALLBACK-SECRET',
        'FaLlBaCk-SeCrEt',
        'fallback-secret123456789012345678901234567890123456789012345678'
      ];

      variations.forEach(secret => {
        const validation = JWTSecretManager.validateJWTSecret(secret);
        expect(validation.isValid).toBe(false);
        expect(validation.errors).toContainEqual(
          expect.stringContaining('blacklisted value')
        );
      });
    });
  });

  describe('No Automatic Fallback Generation', () => {
    it('should NEVER auto-generate secrets when JWT_SECRET is missing', async () => {
      // Mock environment without JWT_SECRET
      const mockEnv = {
        KV_AUTH: createMockKV(),
        ENVIRONMENT: 'production'
        // Deliberately no JWT_SECRET
      };

      const rotationService = new JWTSecretRotation(mockEnv as any);

      // Should throw error, not generate a fallback
      await expect(rotationService.getCurrentSecret()).rejects.toThrow(
        'JWT_SECRET is required but not configured'
      );
      await expect(rotationService.getCurrentSecret()).rejects.toThrow(
        'CVSS 9.8'
      );
    });

    it('should validate JWT_SECRET from environment before using', async () => {
      const mockEnv = {
        JWT_SECRET: 'weak-test-secret-that-should-fail',
        KV_AUTH: createMockKV(),
        ENVIRONMENT: 'production'
      };

      const rotationService = new JWTSecretRotation(mockEnv as any);

      await expect(rotationService.getCurrentSecret()).rejects.toThrow(
        'JWT_SECRET validation failed'
      );
    });
  });

  describe('Environment Validator Security', () => {
    it('should reject all known vulnerable patterns', () => {
      const vulnerableValues = [
        'fallback-secret',
        'dev-secret',
        'test-secret',
        'development-secret',
        'default',
        'secret',
        'password',
        '123456',
        'changeme',
        'admin',
        'your-secret-here'
      ];

      vulnerableValues.forEach(value => {
        expect(() => {
          EnvironmentValidator.validateJWTSecret(value);
        }).toThrow('JWT SECRET VALIDATION FAILED');
      });
    });

    it('should require minimum 64 character secrets for production', () => {
      const shortSecret = 'a'.repeat(32); // Too short

      const validation = JWTSecretManager.validateJWTSecret(shortSecret, 'production');

      expect(validation.isValid).toBe(false);
      expect(validation.errors).toContainEqual(
        expect.stringContaining('must be at least 64 characters')
      );
    });

    it('should enforce entropy requirements', () => {
      const lowEntropySecret = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

      const validation = JWTSecretManager.validateJWTSecret(lowEntropySecret);

      expect(validation.isValid).toBe(false);
      // Check for either entropy or pattern error
      const hasEntropyError = validation.errors.some(e =>
        e.includes('insufficient entropy') || e.includes('weak pattern') || e.includes('repeated characters')
      );
      expect(hasEntropyError).toBe(true);
    });
  });

  describe('Secure Secret Generation', () => {
    it('should generate cryptographically secure secrets', () => {
      const secret1 = JWTSecretManager.generateSecureSecret(64);
      const secret2 = JWTSecretManager.generateSecureSecret(64);

      // Should be different each time
      expect(secret1).not.toBe(secret2);

      // Should pass all validation
      const validation1 = JWTSecretManager.validateJWTSecret(secret1, 'production');
      const validation2 = JWTSecretManager.validateJWTSecret(secret2, 'production');

      expect(validation1.isValid).toBe(true);
      expect(validation2.isValid).toBe(true);
      expect(validation1.strength).toMatch(/strong|very-strong/);
      expect(validation2.strength).toMatch(/strong|very-strong/);
    });

    it('should enforce minimum length for generated secrets', () => {
      expect(() => {
        JWTSecretManager.generateSecureSecret(32); // Too short
      }).toThrow('Secret length must be at least 64 characters');
    });
  });

  describe('Production Environment Protection', () => {
    it('should reject development indicators in production secrets', () => {
      const devIndicatorSecrets = [
        'dev-' + 'x'.repeat(60),
        'test-' + 'y'.repeat(59),
        'local-' + 'z'.repeat(58),
        'debug-' + 'a'.repeat(58),
        'demo-' + 'b'.repeat(59)
      ];

      devIndicatorSecrets.forEach(secret => {
        const validation = JWTSecretManager.validateJWTSecret(secret, 'production');
        expect(validation.isValid).toBe(false);
        expect(validation.errors).toContainEqual(
          expect.stringContaining('development/test indicators')
        );
      });
    });

    it('should validate rotated secrets before storage', async () => {
      const mockEnv = {
        JWT_SECRET: JWTSecretManager.generateSecureSecret(64),
        KV_AUTH: createMockKV(),
        ENVIRONMENT: 'production'
      };

      const rotationService = new JWTSecretRotation(mockEnv as any);

      // Force rotation
      await rotationService.forceRotation();

      // The rotated secret should be valid
      const newSecret = await rotationService.getCurrentSecret();
      const validation = JWTSecretManager.validateJWTSecret(newSecret, 'production');

      expect(validation.isValid).toBe(true);
    });
  });


  describe('Runtime Security Checks', () => {
    it('should continuously validate JWT secrets at runtime', () => {
      const config = {
        jwtSecret: JWTSecretManager.generateSecureSecret(64),
        rotationEnabled: true,
        rotationInterval: 24 * 7,
        environment: 'production' as const
      };

      const healthCheck = JWTSecretManager.performSecurityHealthCheck(config);
      expect(healthCheck).toBe(true);
    });

    it('should fail health check with compromised secret', () => {
      const config = {
        jwtSecret: 'fallback-secret-padded-to-meet-length-requirements-xxxxxxxxxxxx',
        rotationEnabled: true,
        rotationInterval: 24 * 7,
        environment: 'production' as const
      };

      const healthCheck = JWTSecretManager.performSecurityHealthCheck(config);
      expect(healthCheck).toBe(false);
    });
  });
});

// Helper function to create mock KV namespace
function createMockKV(): any {
  const store = new Map<string, string>();

  return {
    get: async (key: string) => store.get(key) || null,
    put: async (key: string, value: string) => {
      store.set(key, value);
    },
    delete: async (key: string) => {
      store.delete(key);
    },
    list: async () => ({
      keys: Array.from(store.keys()).map(name => ({ name })),
      list_complete: true,
      cursor: ''
    })
  };
}