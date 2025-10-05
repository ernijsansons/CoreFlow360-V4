/**
 * Comprehensive JWT Secret Security Tests - OWASP 2025 Compliant
 *
 * SECURITY TESTS COVERAGE:
 * - JWT Secret validation and entropy checks
 * - Blacklist verification for weak secrets
 * - Production-grade secret generation
 * - Secret rotation functionality
 * - Runtime security health checks
 * - CVSS 9.8 Authentication Bypass prevention
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { JWTSecretManager } from '../../shared/security/jwt-secret-manager';
import { SecretRotationService } from '../../shared/security/secret-rotation-service';
import { createMockKV as mockKVFactory } from '../mocks/kv-namespace-mock';

describe('JWT Secret Security Tests - OWASP 2025', () => {
  beforeEach(() => {
    // Clear any environment variables that might interfere
    vi.clearAllMocks();
  });

  describe('JWT Secret Validation', () => {
    it('should reject undefined or null secrets', () => {
      const result1 = JWTSecretManager.validateJWTSecret(undefined);
      expect(result1.isValid).toBe(false);
      expect(result1.errors[0]).toContain('CRITICAL: JWT_SECRET is required');

      const result2 = JWTSecretManager.validateJWTSecret(null as any);
      expect(result2.isValid).toBe(false);
      expect(result2.errors[0]).toContain('CRITICAL: JWT_SECRET is required');
    });

    it('should reject non-string secrets', () => {
      const result = JWTSecretManager.validateJWTSecret(123 as any);
      expect(result.isValid).toBe(false);
      expect(result.errors[0]).toContain('CRITICAL: JWT_SECRET must be a string');
    });

    it('should reject secrets shorter than minimum length', () => {
      const shortSecret = 'short-secret';
      const result = JWTSecretManager.validateJWTSecret(shortSecret);

      expect(result.isValid).toBe(false);
      expect(result.errors[0]).toContain('CRITICAL: JWT_SECRET must be at least 64 characters long');
    });

    it('should reject blacklisted weak secrets', () => {
      const weakSecrets = [
        'test-secret',
        'dev-secret',
        'development-secret',
        'fallback-secret',
        'your-secret-here',
        'password123',
        'admin123',
        'changeme'
      ];

      weakSecrets.forEach(secret => {
        // Pad to minimum length to test blacklist specifically
        const paddedSecret = secret.padEnd(64, 'x');
        const result = JWTSecretManager.validateJWTSecret(paddedSecret);

        expect(result.isValid).toBe(false);
        expect(result.errors[0]).toContain('CRITICAL: JWT_SECRET contains blacklisted value');
      });
    });

    it('should reject secrets with insufficient entropy', () => {
      const lowEntropySecrets = [
        'a'.repeat(64), // All same character
        'abababababababababababababababababababababababababababababababab', // Repeating pattern
        '1234567890123456789012345678901234567890123456789012345678901234' // Sequential pattern
      ];

      lowEntropySecrets.forEach(secret => {
        const result = JWTSecretManager.validateJWTSecret(secret);

        expect(result.isValid).toBe(false);
        expect(result.errors.some(error =>
          error.includes('insufficient entropy') ||
          error.includes('weak pattern')
        )).toBe(true);
      });
    });

    it('should accept strong, cryptographically secure secrets', () => {
      const strongSecrets = [
        'kL9#mN2xpQ8_rT5%vW1@xZ4^yA7*bC3!dE6+fG9-hI2~jK5_lM8|nO1}pR4{sU7X9Z',
        'X8v2P9q5N1m7K3j6L4h8R2s9T6w0Y5u3I7o1E4a8D9f2G6c5V8b3N1x7Z0k9M2QW',
        'B7n4M8k2J5g9F3d6S1a8P7o4L2i9U6y3Q1w7E5r2T8u0I4p6A9s3D1f5G8c7K4YX'
      ];

      strongSecrets.forEach(secret => {
        const result = JWTSecretManager.validateJWTSecret(secret, 'production');

        // Debug: Log validation result if test fails
        if (!result.isValid) {
          console.log('Secret that failed:', secret);
          console.log('Length:', secret.length);
          console.log('Errors:', result.errors);
          console.log('Entropy:', result.entropy);
          console.log('Strength:', result.strength);
        }

        expect(result.isValid).toBe(true);
        expect(result.errors).toHaveLength(0);
        expect(result.strength).toMatch(/strong|very-strong/);
      });
    });

    it('should enforce stricter validation for production environment', () => {
      const testSecret = 'test-pattern-secret-that-meets-length-requirement-but-has-test';

      const devResult = JWTSecretManager.validateJWTSecret(testSecret, 'development');
      const prodResult = JWTSecretManager.validateJWTSecret(testSecret, 'production');

      expect(prodResult.errors.length).toBeGreaterThan(devResult.errors.length);
      expect(prodResult.errors.some(error =>
        error.includes('production secret violation') ||
        error.includes('test indicators')
      )).toBe(true);
    });
  });

  describe('Secure Secret Generation', () => {
    it('should generate cryptographically secure secrets', () => {
      const secret = JWTSecretManager.generateSecureSecret();

      expect(secret).toHaveLength(64);

      // Validate the generated secret passes all security checks
      const validation = JWTSecretManager.validateJWTSecret(secret, 'production');
      expect(validation.isValid).toBe(true);
      expect(validation.strength).toMatch(/strong|very-strong/);
    });

    it('should generate unique secrets on each call', () => {
      const secret1 = JWTSecretManager.generateSecureSecret();
      const secret2 = JWTSecretManager.generateSecureSecret();

      expect(secret1).not.toBe(secret2);
    });

    it('should support custom secret lengths', () => {
      const customLength = 128;
      const secret = JWTSecretManager.generateSecureSecret(customLength);

      expect(secret).toHaveLength(customLength);

      const validation = JWTSecretManager.validateJWTSecret(secret, 'production');
      expect(validation.isValid).toBe(true);
    });

    it('should reject custom lengths below minimum', () => {
      expect(() => {
        JWTSecretManager.generateSecureSecret(32); // Below 64 minimum
      }).toThrow('Secret length must be at least 64 characters');
    });
  });

  describe('JWT Secret Initialization', () => {
    it('should initialize with valid environment secret', () => {
      const validSecret = JWTSecretManager.generateSecureSecret();
      const mockEnv = {
        JWT_SECRET: validSecret,
        ENVIRONMENT: 'production'
      };

      const config = JWTSecretManager.initializeJWTSecret(mockEnv);

      expect(config.jwtSecret).toBe(validSecret);
      expect(config.environment).toBe('production');
      expect(config.rotationEnabled).toBe(true);
    });

    it('should throw for invalid environment secret', () => {
      const mockEnv = {
        JWT_SECRET: 'weak-secret',
        ENVIRONMENT: 'production'
      };

      expect(() => {
        JWTSecretManager.initializeJWTSecret(mockEnv);
      }).toThrow('JWT Secret validation failed');
    });

    it('should provide helpful error messages for fixing issues', () => {
      const mockEnv = {
        JWT_SECRET: 'test-secret',
        ENVIRONMENT: 'production'
      };

      try {
        JWTSecretManager.initializeJWTSecret(mockEnv);
        expect.fail('Should have thrown an error');
      } catch (error: any) {
        expect(error.message).toContain('To fix this issue:');
        expect(error.message).toContain('openssl rand -base64 64');
        expect(error.message).toContain('export JWT_SECRET');
      }
    });
  });

  describe('Runtime Security Health Checks', () => {
    it('should pass health check for valid configuration', () => {
      const validSecret = JWTSecretManager.generateSecureSecret();
      const config = {
        jwtSecret: validSecret,
        rotationEnabled: true,
        rotationInterval: 24 * 7,
        environment: 'production' as const
      };

      const isHealthy = JWTSecretManager.performSecurityHealthCheck(config);
      expect(isHealthy).toBe(true);
    });

    it('should fail health check for compromised configuration', () => {
      const config = {
        jwtSecret: 'compromised-secret-that-is-long-enough-but-weak',
        rotationEnabled: true,
        rotationInterval: 24 * 7,
        environment: 'production' as const
      };

      const isHealthy = JWTSecretManager.performSecurityHealthCheck(config);
      expect(isHealthy).toBe(false);
    });
  });

  describe('Secret Pattern Detection', () => {
    it('should detect sequential character patterns', () => {
      const sequentialSecret = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@';
      const result = JWTSecretManager.validateJWTSecret(sequentialSecret);

      // Debug: Log validation result if test fails
      if (result.isValid || !result.errors.some(error => error.includes('sequential character patterns'))) {
        console.log('Sequential pattern test failed:');
        console.log('Secret:', sequentialSecret);
        console.log('Length:', sequentialSecret.length);
        console.log('IsValid:', result.isValid);
        console.log('Errors:', result.errors);
        console.log('Pattern detection should detect abc, def, etc. in the alphabet sequence');
      }

      expect(result.isValid).toBe(false);
      expect(result.errors.some(error =>
        error.includes('sequential character patterns')
      )).toBe(true);
    });

    it('should detect keyboard patterns', () => {
      const keyboardSecret = 'qwertyuiopasdfghjklzxcvbnm1234567890QWERTYUIOPASDFGHJKLZXCVB';
      const result = JWTSecretManager.validateJWTSecret(keyboardSecret);

      expect(result.isValid).toBe(false);
      expect(result.errors.some(error =>
        error.includes('keyboard patterns')
      )).toBe(true);
    });

    it('should detect repetitive character patterns', () => {
      const repetitiveSecret = 'abcabc'.repeat(11); // 66 chars, but very repetitive
      const result = JWTSecretManager.validateJWTSecret(repetitiveSecret);

      expect(result.isValid).toBe(false);
      expect(result.errors.some(error =>
        error.includes('repeated characters')
      )).toBe(true);
    });
  });

  describe('Base64 Encoded Weak Secret Detection', () => {
    it('should detect base64 encoded weak secrets in production', () => {
      const weakSecretBase64 = btoa('test-secret'); // dGVzdC1zZWNyZXQ=
      const paddedSecret = weakSecretBase64.padEnd(64, 'x');

      const result = JWTSecretManager.validateJWTSecret(paddedSecret, 'production');

      expect(result.isValid).toBe(false);
      expect(result.errors.some(error =>
        error.includes('base64 encoded weak secret')
      )).toBe(true);
    });
  });

  describe('Environment Variable Pattern Detection', () => {
    it('should detect environment variable syntax in secrets', () => {
      const envVarSecrets = [
        '${JWT_SECRET}' + 'x'.repeat(51),
        '$JWT_SECRET' + 'x'.repeat(53),
        '%JWT_SECRET%' + 'x'.repeat(52)
      ];

      envVarSecrets.forEach(secret => {
        const result = JWTSecretManager.validateJWTSecret(secret, 'production');

        expect(result.isValid).toBe(false);
        expect(result.errors.some(error =>
          error.includes('environment variable syntax')
        )).toBe(true);
      });
    });
  });
});

describe('Secret Rotation Service Tests', () => {
  let mockKV: KVNamespace;

  beforeEach(() => {
    mockKV = createMockKV();
  });

  describe('Secret Rotation', () => {
    it('should perform successful secret rotation', async () => {
      const rotationService = new SecretRotationService(mockKV);

      const result = await rotationService.rotateSecret(true); // Force rotation

      expect(result.success).toBe(true);
      expect(result.newVersion).toBeGreaterThan(0);
      expect(result.message).toContain('Secret rotated successfully');
    });

    it('should validate rotation timing', async () => {
      const rotationService = new SecretRotationService(mockKV, {
        rotationIntervalHours: 24,
        overlappingPeriodHours: 1,
        maxVersions: 3,
        emergencyRotationEnabled: true
      });

      // Should not rotate if not due
      const result1 = await rotationService.rotateSecret(false);
      expect(result1.success).toBe(false);
      expect(result1.message).toContain('not due yet');

      // Should rotate if forced
      const result2 = await rotationService.rotateSecret(true);
      expect(result2.success).toBe(true);
    });

    it('should perform emergency rotation', async () => {
      const rotationService = new SecretRotationService(mockKV);

      const result = await rotationService.emergencyRotation('Suspected compromise');

      expect(result.success).toBe(true);
      expect(result.message).toContain('Emergency rotation completed');
    });

    it('should clean up old secret versions', async () => {
      const rotationService = new SecretRotationService(mockKV, {
        rotationIntervalHours: 24,
        overlappingPeriodHours: 1,
        maxVersions: 2, // Keep only 2 versions
        emergencyRotationEnabled: true
      });

      // Perform multiple rotations
      await rotationService.rotateSecret(true);
      await rotationService.rotateSecret(true);
      await rotationService.rotateSecret(true);

      const health = await rotationService.getRotationHealth();
      expect(health.status).not.toBe('critical');
    });
  });

  describe('Multi-Version Secret Support', () => {
    it('should support validating multiple secret versions', async () => {
      const rotationService = new SecretRotationService(mockKV);

      // Create a few versions
      await rotationService.rotateSecret(true);
      await rotationService.rotateSecret(true);

      // Should be able to validate current and previous versions
      const validation = await rotationService.validateSecretByVersion('test-token');
      expect(validation.version).toBeGreaterThan(0);
    });
  });

  describe('Rotation Health Monitoring', () => {
    it('should provide rotation health status', async () => {
      const rotationService = new SecretRotationService(mockKV);

      const health = await rotationService.getRotationHealth();

      expect(health.status).toMatch(/healthy|warning|critical/);
      expect(health.currentVersion).toBeGreaterThanOrEqual(1);
      expect(health.nextRotationDue).toBeDefined();
    });

    it('should detect overdue rotations', async () => {
      const rotationService = new SecretRotationService(mockKV, {
        rotationIntervalHours: 1, // Very short interval for testing
        overlappingPeriodHours: 1,
        maxVersions: 3,
        emergencyRotationEnabled: true
      });

      // Mock an old rotation
      const oldLog = {
        currentVersion: 1,
        lastRotation: new Date(Date.now() - (3 * 60 * 60 * 1000)).toISOString(), // 3 hours ago
        rotationCount: 1,
        emergencyRotations: 0
      };

      await mockKV.put('jwt_rotation_log', JSON.stringify(oldLog));

      const health = await rotationService.getRotationHealth();
      expect(health.status).toBe('critical');
      expect(health.issues).toContain('Secret rotation is severely overdue');
    });
  });

  describe('Secret Storage and Retrieval', () => {
    it('should get current secret from KV or environment fallback', async () => {
      const rotationService = new SecretRotationService(mockKV);

      // Store a valid secret
      const validSecret = JWTSecretManager.generateSecureSecret();
      await mockKV.put('jwt_secret_current', validSecret);

      const currentSecret = await rotationService.getCurrentSecret();
      expect(currentSecret).toBe(validSecret);
    });

    it('should throw error if no valid secret is found', async () => {
      const rotationService = new SecretRotationService(mockKV);

      // Mock environment without JWT_SECRET
      delete process.env.JWT_SECRET;

      await expect(rotationService.getCurrentSecret()).rejects.toThrow(
        'No valid JWT secret found'
      );
    });
  });
});

// Mock KV implementation for testing
function createMockKV(): KVNamespace {
  return mockKVFactory().asKVNamespace();
}