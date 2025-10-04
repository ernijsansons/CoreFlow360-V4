/**
 * Comprehensive Unit Tests for Auth Cryptography Utilities
 * Target: 95%+ Test Coverage
 *
 * Tests cover:
 * - Password hashing with PBKDF2
 * - API key cryptography
 * - TOTP generation and validation
 * - Secure random generation
 * - Key derivation functions
 * - Constant-time operations
 * - Security validations
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  PasswordCrypto,
  APIKeyCrypto,
  TOTPCrypto,
  KeyDerivation,
  SecureRandom,
  CryptoUtils
} from '../../utils/auth-crypto';

describe('PasswordCrypto', () => {
  let originalCrypto: any;

  beforeEach(() => {
    originalCrypto = global.crypto;
    // Mock crypto.getRandomValues for predictable testing
    global.crypto = {
      ...originalCrypto,
      getRandomValues: vi.fn((array: Uint8Array) => {
        for (let i = 0; i < array.length; i++) {
          array[i] = i % 256;
        }
        return array;
      }),
      subtle: {
        ...originalCrypto.subtle,
        importKey: vi.fn().mockResolvedValue({ type: 'secret' }),
        deriveBits: vi.fn().mockResolvedValue(new ArrayBuffer(64))
      }
    } as any;
  });

  afterEach(() => {
    global.crypto = originalCrypto;
    vi.clearAllMocks();
  });

  describe('Password Hashing', () => {
    it('should hash passwords with PBKDF2', async () => {
      const password = 'SecurePassword123!';
      const hash = await PasswordCrypto.hashPassword(password);

      expect(hash).toMatch(/^pbkdf2-sha256\$\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$/);

      const parts = hash.split('$');
      expect(parts).toHaveLength(4);
      expect(parts[0]).toBe('pbkdf2-sha256');
      expect(parseInt(parts[1])).toBeGreaterThanOrEqual(600000);
    });

    it('should generate unique hashes for same password', async () => {
      const password = 'SamePassword123!';

      const hash1 = await PasswordCrypto.hashPassword(password);
      const hash2 = await PasswordCrypto.hashPassword(password);

      expect(hash1).not.toBe(hash2);
    });

    it('should verify correct passwords', async () => {
      const password = 'CorrectPassword123!';
      const hash = await PasswordCrypto.hashPassword(password);

      const isValid = await PasswordCrypto.verifyPassword(password, hash);
      expect(isValid).toBe(true);
    });

    it('should reject incorrect passwords', async () => {
      const correctPassword = 'CorrectPassword123!';
      const wrongPassword = 'WrongPassword123!';

      const hash = await PasswordCrypto.hashPassword(correctPassword);
      const isValid = await PasswordCrypto.verifyPassword(wrongPassword, hash);

      expect(isValid).toBe(false);
    });

    it('should reject passwords that are too short', async () => {
      const shortPassword = '1234567'; // 7 characters

      await expect(PasswordCrypto.hashPassword(shortPassword))
        .rejects.toThrow('Password must be at least 8 characters long');
    });

    it('should handle malformed hashes gracefully', async () => {
      const password = 'TestPassword123!';
      const malformedHash = 'malformed-hash';

      const isValid = await PasswordCrypto.verifyPassword(password, malformedHash);
      expect(isValid).toBe(false);
    });

    it('should reject hashes with insufficient iterations', async () => {
      const password = 'TestPassword123!';
      const weakHash = 'pbkdf2-sha256$50000$c29tZXNhbHQ=$c29tZWhhc2g=';

      const isValid = await PasswordCrypto.verifyPassword(password, weakHash);
      expect(isValid).toBe(false);
    });

    it('should handle verification errors gracefully', async () => {
      vi.spyOn(global.crypto.subtle, 'deriveBits').mockRejectedValueOnce(new Error('Crypto error'));

      const password = 'TestPassword123!';
      const hash = 'pbkdf2-sha256$600000$c29tZXNhbHQ=$c29tZWhhc2g=';

      const isValid = await PasswordCrypto.verifyPassword(password, hash);
      expect(isValid).toBe(false);
    });

    it('should upgrade legacy hashes', async () => {
      const password = 'TestPassword123!';
      const lowIterationHash = 'pbkdf2-sha256$100000$c29tZXNhbHQ=$c29tZWhhc2g=';

      const upgradedHash = await PasswordCrypto.upgradePasswordHash(password, lowIterationHash);
      expect(upgradedHash).toBeDefined();
      expect(upgradedHash).not.toBe(lowIterationHash);

      if (upgradedHash) {
        const parts = upgradedHash.split('$');
        expect(parseInt(parts[1])).toBeGreaterThanOrEqual(600000);
      }
    });

    it('should not upgrade current format hashes', async () => {
      const password = 'TestPassword123!';
      const currentHash = await PasswordCrypto.hashPassword(password);

      const upgradedHash = await PasswordCrypto.upgradePasswordHash(password, currentHash);
      expect(upgradedHash).toBeNull();
    });
  });

  describe('Password Generation', () => {
    it('should generate secure passwords with default length', () => {
      const password = PasswordCrypto.generateSecurePassword();

      expect(password).toHaveLength(20);
      expect(password).toMatch(/[a-z]/); // Contains lowercase
      expect(password).toMatch(/[A-Z]/); // Contains uppercase
      expect(password).toMatch(/[0-9]/); // Contains numbers
      expect(password).toMatch(/[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]/); // Contains symbols
    });

    it('should generate passwords with custom length', () => {
      const password = PasswordCrypto.generateSecurePassword(16);
      expect(password).toHaveLength(16);
    });

    it('should generate different passwords each time', () => {
      const password1 = PasswordCrypto.generateSecurePassword();
      const password2 = PasswordCrypto.generateSecurePassword();

      expect(password1).not.toBe(password2);
    });
  });
});

describe('APIKeyCrypto', () => {
  let originalCrypto: any;

  beforeEach(() => {
    originalCrypto = global.crypto;
    global.crypto = {
      ...originalCrypto,
      getRandomValues: vi.fn((array: Uint8Array) => {
        for (let i = 0; i < array.length; i++) {
          array[i] = i % 256;
        }
        return array;
      }),
      subtle: {
        ...originalCrypto.subtle,
        importKey: vi.fn().mockResolvedValue({ type: 'secret' }),
        deriveBits: vi.fn().mockResolvedValue(new ArrayBuffer(32))
      }
    } as any;
  });

  afterEach(() => {
    global.crypto = originalCrypto;
    vi.clearAllMocks();
  });

  describe('API Key Generation', () => {
    it('should generate API keys with correct format', () => {
      const apiKey = APIKeyCrypto.generateAPIKey();

      expect(apiKey).toMatch(/^cfk_[A-Za-z0-9_-]+$/);
      expect(apiKey).toHaveLength(47); // cfk_ + 43 chars
    });

    it('should generate API keys with custom prefix', () => {
      const apiKey = APIKeyCrypto.generateAPIKey('sk');
      expect(apiKey).toMatch(/^sk_[A-Za-z0-9_-]+$/);
    });

    it('should generate unique API keys', () => {
      const key1 = APIKeyCrypto.generateAPIKey();
      const key2 = APIKeyCrypto.generateAPIKey();

      expect(key1).not.toBe(key2);
    });
  });

  describe('API Key Hashing', () => {
    it('should hash API keys with PBKDF2', async () => {
      const apiKey = 'cfk_test123456789';
      const hash = await APIKeyCrypto.hashAPIKey(apiKey);

      expect(hash).toMatch(/^pbkdf2-sha256\$\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$/);
    });

    it('should verify valid API keys', async () => {
      const apiKey = 'cfk_validapikey123';
      const hash = await APIKeyCrypto.hashAPIKey(apiKey);

      const isValid = await APIKeyCrypto.verifyAPIKey(apiKey, hash);
      expect(isValid).toBe(true);
    });

    it('should reject invalid API keys', async () => {
      const validKey = 'cfk_validapikey123';
      const invalidKey = 'cfk_invalidkey456';

      const hash = await APIKeyCrypto.hashAPIKey(validKey);
      const isValid = await APIKeyCrypto.verifyAPIKey(invalidKey, hash);

      expect(isValid).toBe(false);
    });

    it('should reject malformed API keys', async () => {
      await expect(APIKeyCrypto.hashAPIKey('short'))
        .rejects.toThrow('Invalid API key format');
    });

    it('should handle verification errors gracefully', async () => {
      vi.spyOn(global.crypto.subtle, 'deriveBits').mockRejectedValueOnce(new Error('Crypto error'));

      const isValid = await APIKeyCrypto.verifyAPIKey('cfk_test123', 'pbkdf2-sha256$300000$c29tZXNhbHQ=$c29tZWhhc2g=');
      expect(isValid).toBe(false);
    });
  });
});

describe('TOTPCrypto', () => {
  let originalCrypto: any;

  beforeEach(() => {
    originalCrypto = global.crypto;
    global.crypto = {
      ...originalCrypto,
      getRandomValues: vi.fn((array: Uint8Array) => {
        for (let i = 0; i < array.length; i++) {
          array[i] = i % 256;
        }
        return array;
      }),
      subtle: {
        ...originalCrypto.subtle,
        importKey: vi.fn().mockResolvedValue({ type: 'secret' }),
        sign: vi.fn().mockResolvedValue(new ArrayBuffer(20)) // HMAC-SHA1 output
      }
    } as any;
  });

  afterEach(() => {
    global.crypto = originalCrypto;
    vi.clearAllMocks();
  });

  describe('TOTP Secret Generation', () => {
    it('should generate base32 encoded secrets', () => {
      const secret = TOTPCrypto.generateTOTPSecret();

      expect(secret).toMatch(/^[A-Z2-7]+$/); // Base32 alphabet
      expect(secret.length).toBeGreaterThan(50); // 32 bytes = 52 base32 chars (approximately)
    });

    it('should generate unique secrets', () => {
      const secret1 = TOTPCrypto.generateTOTPSecret();
      const secret2 = TOTPCrypto.generateTOTPSecret();

      expect(secret1).not.toBe(secret2);
    });
  });

  describe('TOTP Code Generation', () => {
    it('should generate 6-digit TOTP codes', async () => {
      const secret = 'JBSWY3DPEHPK3PXP'; // Base32 encoded secret
      const code = await TOTPCrypto.generateTOTP(secret);

      expect(code).toMatch(/^\d{6}$/);
    });

    it('should generate codes for specific time steps', async () => {
      const secret = 'JBSWY3DPEHPK3PXP';
      const timeStep = 1000000; // Specific time step

      const code = await TOTPCrypto.generateTOTP(secret, timeStep);
      expect(code).toMatch(/^\d{6}$/);
    });

    it('should pad codes with leading zeros', async () => {
      // Mock HMAC result that would generate a small number
      vi.spyOn(global.crypto.subtle, 'sign').mockResolvedValueOnce(
        new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]).buffer
      );

      const secret = 'JBSWY3DPEHPK3PXP';
      const code = await TOTPCrypto.generateTOTP(secret);

      expect(code).toHaveLength(6);
    });
  });

  describe('TOTP Verification', () => {
    it('should verify valid TOTP codes', async () => {
      const secret = 'JBSWY3DPEHPK3PXP';
      const code = await TOTPCrypto.generateTOTP(secret);

      const isValid = await TOTPCrypto.verifyTOTP(code, secret);
      expect(isValid).toBe(true);
    });

    it('should accept codes within time window', async () => {
      const secret = 'JBSWY3DPEHPK3PXP';
      const currentTime = Math.floor(Date.now() / 1000 / 30);

      // Generate code for previous time step
      const previousCode = await TOTPCrypto.generateTOTP(secret, currentTime - 1);
      const isValid = await TOTPCrypto.verifyTOTP(previousCode, secret);

      expect(isValid).toBe(true);
    });

    it('should reject invalid codes', async () => {
      const secret = 'JBSWY3DPEHPK3PXP';
      const invalidCode = '000000';

      const isValid = await TOTPCrypto.verifyTOTP(invalidCode, secret);
      expect(isValid).toBe(false);
    });

    it('should reject malformed codes', async () => {
      const secret = 'JBSWY3DPEHPK3PXP';

      const isValid1 = await TOTPCrypto.verifyTOTP('12345', secret); // Too short
      const isValid2 = await TOTPCrypto.verifyTOTP('1234567', secret); // Too long
      const isValid3 = await TOTPCrypto.verifyTOTP('abcdef', secret); // Non-numeric

      expect(isValid1).toBe(false);
      expect(isValid2).toBe(false);
      expect(isValid3).toBe(false);
    });

    it('should handle whitespace in codes', async () => {
      const secret = 'JBSWY3DPEHPK3PXP';
      const code = await TOTPCrypto.generateTOTP(secret);
      const codeWithSpaces = `${code.slice(0, 3)} ${code.slice(3)}`;

      const isValid = await TOTPCrypto.verifyTOTP(codeWithSpaces, secret);
      expect(isValid).toBe(true);
    });
  });

  describe('Backup Code Generation', () => {
    it('should generate default number of backup codes', () => {
      const codes = TOTPCrypto.generateBackupCodes();

      expect(codes).toHaveLength(10);
      codes.forEach(code => {
        expect(code).toMatch(/^[A-Z0-9]{8}$/);
      });
    });

    it('should generate custom number of backup codes', () => {
      const codes = TOTPCrypto.generateBackupCodes(5);

      expect(codes).toHaveLength(5);
    });

    it('should generate unique backup codes', () => {
      const codes = TOTPCrypto.generateBackupCodes();
      const uniqueCodes = new Set(codes);

      expect(uniqueCodes.size).toBe(codes.length);
    });
  });
});

describe('KeyDerivation', () => {
  let originalCrypto: any;

  beforeEach(() => {
    originalCrypto = global.crypto;
    global.crypto = {
      ...originalCrypto,
      getRandomValues: vi.fn((array: Uint8Array) => {
        for (let i = 0; i < array.length; i++) {
          array[i] = i % 256;
        }
        return array;
      }),
      subtle: {
        ...originalCrypto.subtle,
        importKey: vi.fn().mockResolvedValue({ type: 'secret' }),
        deriveKey: vi.fn().mockResolvedValue({ type: 'secret', algorithm: { name: 'AES-GCM' } }),
        encrypt: vi.fn().mockResolvedValue(new ArrayBuffer(32)),
        decrypt: vi.fn().mockResolvedValue(new TextEncoder().encode('decrypted data').buffer)
      }
    } as any;
  });

  afterEach(() => {
    global.crypto = originalCrypto;
    vi.clearAllMocks();
  });

  describe('Key Derivation', () => {
    it('should derive encryption keys from passwords', async () => {
      const password = 'SecurePassword123!';
      const salt = KeyDerivation.generateSalt();

      const key = await KeyDerivation.deriveKeyFromPassword(password, salt);
      expect(key).toBeDefined();
      expect(key.type).toBe('secret');
    });

    it('should use custom iterations', async () => {
      const password = 'SecurePassword123!';
      const salt = KeyDerivation.generateSalt();
      const iterations = 200000;

      const key = await KeyDerivation.deriveKeyFromPassword(password, salt, iterations);
      expect(key).toBeDefined();
    });

    it('should generate random salts', () => {
      const salt1 = KeyDerivation.generateSalt();
      const salt2 = KeyDerivation.generateSalt();

      expect(salt1).not.toEqual(salt2);
      expect(salt1).toHaveLength(32); // Default length
    });

    it('should generate salts with custom length', () => {
      const salt = KeyDerivation.generateSalt(16);
      expect(salt).toHaveLength(16);
    });

    it('should generate random IVs', () => {
      const iv1 = KeyDerivation.generateIV();
      const iv2 = KeyDerivation.generateIV();

      expect(iv1).not.toEqual(iv2);
      expect(iv1).toHaveLength(12); // Default IV length for AES-GCM
    });
  });

  describe('Encryption/Decryption', () => {
    it('should encrypt and decrypt data', async () => {
      const data = 'sensitive data';
      const password = 'SecurePassword123!';
      const salt = KeyDerivation.generateSalt();

      const key = await KeyDerivation.deriveKeyFromPassword(password, salt);
      const encrypted = await KeyDerivation.encrypt(data, key);

      expect(encrypted.encrypted).toBeInstanceOf(Uint8Array);
      expect(encrypted.iv).toBeInstanceOf(Uint8Array);

      const decrypted = await KeyDerivation.decrypt(encrypted.encrypted, encrypted.iv, key);
      expect(decrypted).toBe(data);
    });

    it('should generate unique IVs for each encryption', async () => {
      const data = 'test data';
      const password = 'SecurePassword123!';
      const salt = KeyDerivation.generateSalt();
      const key = await KeyDerivation.deriveKeyFromPassword(password, salt);

      const encrypted1 = await KeyDerivation.encrypt(data, key);
      const encrypted2 = await KeyDerivation.encrypt(data, key);

      expect(encrypted1.iv).not.toEqual(encrypted2.iv);
    });
  });
});

describe('SecureRandom', () => {
  let originalCrypto: any;

  beforeEach(() => {
    originalCrypto = global.crypto;
    global.crypto = {
      ...originalCrypto,
      getRandomValues: vi.fn((array: Uint8Array) => {
        for (let i = 0; i < array.length; i++) {
          array[i] = i % 256;
        }
        return array;
      })
    } as any;
  });

  afterEach(() => {
    global.crypto = originalCrypto;
    vi.clearAllMocks();
  });

  describe('Random String Generation', () => {
    it('should generate random strings with default charset', () => {
      const str = SecureRandom.generateRandomString(16);

      expect(str).toHaveLength(16);
      expect(str).toMatch(/^[A-Za-z0-9]+$/);
    });

    it('should generate strings with custom charset', () => {
      const charset = 'ABCDEF';
      const str = SecureRandom.generateRandomString(10, charset);

      expect(str).toHaveLength(10);
      expect(str).toMatch(/^[ABCDEF]+$/);
    });

    it('should generate different strings each time', () => {
      const str1 = SecureRandom.generateRandomString(16);
      const str2 = SecureRandom.generateRandomString(16);

      expect(str1).not.toBe(str2);
    });
  });

  describe('UUID Generation', () => {
    it('should generate valid UUID v4', () => {
      const uuid = SecureRandom.generateUUIDv4();

      expect(uuid).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    });

    it('should generate unique UUIDs', () => {
      const uuid1 = SecureRandom.generateUUIDv4();
      const uuid2 = SecureRandom.generateUUIDv4();

      expect(uuid1).not.toBe(uuid2);
    });
  });

  describe('Random Integer Generation', () => {
    it('should generate integers in range', () => {
      const min = 10;
      const max = 20;
      const randomInt = SecureRandom.randomInt(min, max);

      expect(randomInt).toBeGreaterThanOrEqual(min);
      expect(randomInt).toBeLessThan(max);
    });

    it('should throw error for invalid range', () => {
      expect(() => SecureRandom.randomInt(20, 10))
        .toThrow('min must be less than max');
    });

    it('should handle edge case ranges', () => {
      const randomInt = SecureRandom.randomInt(0, 1);
      expect(randomInt).toBe(0);
    });
  });
});

describe('CryptoUtils', () => {
  describe('Constant Time Comparison', () => {
    it('should compare strings in constant time', () => {
      const str1 = 'hello';
      const str2 = 'hello';
      const str3 = 'world';

      expect(CryptoUtils.constantTimeStringEquals(str1, str2)).toBe(true);
      expect(CryptoUtils.constantTimeStringEquals(str1, str3)).toBe(false);
    });

    it('should compare buffers in constant time', () => {
      const buf1 = new Uint8Array([1, 2, 3, 4]);
      const buf2 = new Uint8Array([1, 2, 3, 4]);
      const buf3 = new Uint8Array([1, 2, 3, 5]);

      expect(CryptoUtils.constantTimeBufferEquals(buf1, buf2)).toBe(true);
      expect(CryptoUtils.constantTimeBufferEquals(buf1, buf3)).toBe(false);
    });

    it('should return false for different length strings', () => {
      const str1 = 'hello';
      const str2 = 'hello world';

      expect(CryptoUtils.constantTimeStringEquals(str1, str2)).toBe(false);
    });

    it('should return false for different length buffers', () => {
      const buf1 = new Uint8Array([1, 2, 3]);
      const buf2 = new Uint8Array([1, 2, 3, 4]);

      expect(CryptoUtils.constantTimeBufferEquals(buf1, buf2)).toBe(false);
    });
  });

  describe('SHA-256 Hashing', () => {
    let originalCrypto: any;

    beforeEach(() => {
      originalCrypto = global.crypto;
      global.crypto = {
        ...originalCrypto,
        subtle: {
          ...originalCrypto.subtle,
          digest: vi.fn().mockResolvedValue(new Uint8Array([1, 2, 3, 4]).buffer)
        }
      } as any;
    });

    afterEach(() => {
      global.crypto = originalCrypto;
      vi.clearAllMocks();
    });

    it('should compute SHA-256 hash', async () => {
      const data = 'test data';
      const hash = await CryptoUtils.sha256(data);

      expect(hash).toBe('01020304'); // Mocked result
      expect(global.crypto.subtle.digest).toHaveBeenCalledWith(
        'SHA-256',
        expect.any(Uint8Array)
      );
    });
  });

  describe('Password Strength Validation', () => {
    it('should validate strong passwords', () => {
      const strongPassword = 'SecureP@ssw0rd123!';
      const result = CryptoUtils.validatePasswordStrength(strongPassword);

      expect(result.isStrong).toBe(true);
      expect(result.score).toBeGreaterThanOrEqual(70);
      expect(result.feedback).toHaveLength(0);
    });

    it('should identify weak passwords', () => {
      const weakPassword = 'password';
      const result = CryptoUtils.validatePasswordStrength(weakPassword);

      expect(result.isStrong).toBe(false);
      expect(result.score).toBeLessThan(70);
      expect(result.feedback.length).toBeGreaterThan(0);
    });

    it('should detect common patterns', () => {
      const patternPassword = 'Password123';
      const result = CryptoUtils.validatePasswordStrength(patternPassword);

      expect(result.feedback).toContain('Avoid common sequences');
    });

    it('should detect repeated characters', () => {
      const repeatedPassword = 'Paaasssswwword123!';
      const result = CryptoUtils.validatePasswordStrength(repeatedPassword);

      expect(result.feedback).toContain('Avoid repeated characters');
    });

    it('should provide specific feedback', () => {
      const incompletePassword = 'password123'; // Missing uppercase and symbols
      const result = CryptoUtils.validatePasswordStrength(incompletePassword);

      expect(result.feedback).toContain('Add uppercase letters');
      expect(result.feedback).toContain('Add special characters');
    });

    it('should reward longer passwords', () => {
      const longPassword = 'ThisIsAVeryLongPasswordWithManyCharacters123!';
      const shortPassword = 'Short1!';

      const longResult = CryptoUtils.validatePasswordStrength(longPassword);
      const shortResult = CryptoUtils.validatePasswordStrength(shortPassword);

      expect(longResult.score).toBeGreaterThan(shortResult.score);
    });
  });
});

describe('Integration Tests', () => {
  it('should complete full password lifecycle', async () => {
    const password = 'SecurePassword123!';

    // Hash password
    const hash = await PasswordCrypto.hashPassword(password);
    expect(hash).toBeDefined();

    // Verify correct password
    const isValid = await PasswordCrypto.verifyPassword(password, hash);
    expect(isValid).toBe(true);

    // Reject wrong password
    const isInvalid = await PasswordCrypto.verifyPassword('WrongPassword', hash);
    expect(isInvalid).toBe(false);
  });

  it('should complete full API key lifecycle', async () => {
    // Generate API key
    const apiKey = APIKeyCrypto.generateAPIKey();
    expect(apiKey).toMatch(/^cfk_/);

    // Hash API key
    const hash = await APIKeyCrypto.hashAPIKey(apiKey);
    expect(hash).toBeDefined();

    // Verify correct key
    const isValid = await APIKeyCrypto.verifyAPIKey(apiKey, hash);
    expect(isValid).toBe(true);

    // Reject wrong key
    const wrongKey = APIKeyCrypto.generateAPIKey();
    const isInvalid = await APIKeyCrypto.verifyAPIKey(wrongKey, hash);
    expect(isInvalid).toBe(false);
  });

  it('should complete full TOTP lifecycle', async () => {
    // Generate secret
    const secret = TOTPCrypto.generateTOTPSecret();
    expect(secret).toMatch(/^[A-Z2-7]+$/);

    // Generate code
    const code = await TOTPCrypto.generateTOTP(secret);
    expect(code).toMatch(/^\d{6}$/);

    // Verify code
    const isValid = await TOTPCrypto.verifyTOTP(code, secret);
    expect(isValid).toBe(true);

    // Generate backup codes
    const backupCodes = TOTPCrypto.generateBackupCodes();
    expect(backupCodes).toHaveLength(10);
  });

  it('should complete full encryption lifecycle', async () => {
    const data = 'sensitive information';
    const password = 'SecureEncryptionPassword123!';

    // Generate salt and derive key
    const salt = KeyDerivation.generateSalt();
    const key = await KeyDerivation.deriveKeyFromPassword(password, salt);

    // Encrypt data
    const encrypted = await KeyDerivation.encrypt(data, key);
    expect(encrypted.encrypted).toBeInstanceOf(Uint8Array);
    expect(encrypted.iv).toBeInstanceOf(Uint8Array);

    // Decrypt data
    const decrypted = await KeyDerivation.decrypt(encrypted.encrypted, encrypted.iv, key);
    expect(decrypted).toBe(data);
  });
});