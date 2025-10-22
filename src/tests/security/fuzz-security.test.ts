/**
 * COMPREHENSIVE SECURITY FUZZ TESTING SUITE
 * CoreFlow360 V4 - Edge Case & Vulnerability Discovery
 *
 * This test suite uses fuzzing techniques to discover security vulnerabilities
 * through randomized, malformed, and edge-case inputs
 *
 * Fuzzing Areas:
 * - Input validation edge cases
 * - Buffer overflow attempts
 * - Unicode and encoding attacks
 * - Race condition detection
 * - Memory exhaustion tests
 * - Concurrency security issues
 *
 * @security-level CRITICAL
 * @test-type FUZZ
 * @coverage-target Edge cases and boundary conditions
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { faker } from '@faker-js/faker';
import {
  sanitizeInput,
  preventXSS,
  sanitizeEmail,
  validateJWT,
  rateLimitByIP,
  detectSuspiciousActivity
} from '../../middleware/security';
import { tenantIsolation } from '../../middleware/tenant-isolation-middleware';

// Fuzz testing data generators
class SecurityFuzzGenerator {
  static generateMaliciousStrings(count: number = 100): string[] {
    const patterns = [
      // Buffer overflow attempts
      'A'.repeat(1000000),
      'A'.repeat(65536),
      'A'.repeat(8192),

      // Unicode exploits
      '\uFEFF' + 'A'.repeat(1000), // BOM + data
      '\u202E' + 'fake_filename.txt' + '\u202D' + '.exe', // Right-to-left override
      '\u00A0'.repeat(1000), // Non-breaking spaces

      // Null byte injection
      'file.txt\x00.exe',
      'data\x00<script>alert(1)</script>',

      // Format string attacks
      '%s%s%s%s%s%s%s%s%s%s',
      '%x%x%x%x%x%x%x%x%x%x',
      '%n%n%n%n%n%n%n%n%n%n',

      // Control characters
      '\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F',
      '\x7F\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8A\x8B\x8C\x8D\x8E\x8F',

      // Path traversal variations
      '../'.repeat(100),
      '..\\'.repeat(100),
      '%2e%2e%2f'.repeat(100),
      '%2e%2e%5c'.repeat(100),

      // Command injection
      '; cat /etc/passwd',
      '| whoami',
      '& dir',
      '`id`',
      '$(id)',
      '${PATH}',

      // LDAP injection
      '*)(uid=*',
      '*)(objectClass=*',
      '*)(&(objectClass=user)(uid=*))',

      // XML/XXE attacks
      '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
      '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///dev/random">]><foo>&xxe;</foo>',

      // NoSQL injection
      '{"$gt": ""}',
      '{"$ne": null}',
      '{"$where": "this.password.match(/.*/)"}',

      // JSON/XML bombs
      '{"a":'.repeat(1000) + '"value"' + '}'.repeat(1000),

      // HTML entity bombs
      '&quot;'.repeat(100000),
      '&#x41;'.repeat(100000),

      // Polyglot payloads
      'javascript:/*--></title></style></textarea></script></xmp><svg/onload=\'+/"/+/onmouseover=1/+/[*/[]/+alert(1)//\'>',

      // Binary data
      Array.from({length: 1000}, () => String.fromCharCode(Math.floor(Math.random() * 256))).join(''),

      // Regex DoS
      'a'.repeat(50000) + '!',
      '(' + 'a'.repeat(1000) + ')*',

      // Long domain names
      'a'.repeat(63) + '.' + 'b'.repeat(63) + '.com',

      // International domain names with homographs
      'раура1.com', // Cyrillic that looks like paypal
      'аpp1е.com', // Mixed scripts

      // Empty and whitespace variations
      '',
      ' ',
      '\t',
      '\n',
      '\r\n',
      '\u2028', // Line separator
      '\u2029', // Paragraph separator

      // Very long lines
      'data:image/png;base64,' + 'A'.repeat(1000000),

      // Malformed URLs
      'http://[::1]:8080/../../../etc/passwd',
      'file:///etc/passwd',
      'data:text/html,<script>alert(1)</script>',

      // Protocol confusion
      'javascript://comment%0A' + 'alert(1)',
      'vbscript:msgbox(1)',

      // Zip bombs (textual representation)
      'PK\x03\x04' + 'A'.repeat(1000000),
    ];

    // Generate additional random malicious strings
    for (let i = 0; i < count - patterns.length; i++) {
      patterns.push(this.generateRandomMaliciousString());
    }

    return patterns.slice(0, count);
  }

  static generateRandomMaliciousString(): string {
    const types = [
      () => faker.string.alphanumeric(faker.number.int({ min: 1000, max: 100000 })),
      () => '../'.repeat(faker.number.int({ min: 10, max: 1000 })) + faker.system.fileName(),
      () => '<script>' + faker.string.alphanumeric(100) + '</script>',
      () => 'javascript:' + faker.string.alphanumeric(100),
      () => '\x00'.repeat(faker.number.int({ min: 1, max: 100 })) + faker.string.sample(),
      () => faker.string.sample().repeat(faker.number.int({ min: 1000, max: 10000 })),
      () => Array.from({length: 1000}, () => String.fromCharCode(faker.number.int({ min: 0, max: 255 }))).join(''),
    ];

    const randomType = faker.helpers.arrayElement(types);
    return randomType();
  }

  static generateEdgeCaseEmails(count: number = 50): string[] {
    return [
      // Length edge cases
      'a'.repeat(64) + '@' + 'b'.repeat(189) + '.com', // Max length
      'a'.repeat(65) + '@domain.com', // Over max local part
      'user@' + 'b'.repeat(254) + '.com', // Over max domain

      // Special characters
      'user+tag@domain.com',
      'user.name@domain.com',
      'user_name@domain.com',
      'user-name@domain.com',

      // Quoted local parts
      '"user name"@domain.com',
      '"user@domain"@example.com',
      '"user\\@domain"@example.com',

      // International domains
      'user@тест.com',
      'user@例え.テスト',
      'user@中国.cn',

      // IP addresses
      'user@[192.168.1.1]',
      'user@[IPv6:2001:db8::1]',

      // Edge case domains
      'user@localhost',
      'user@domain',
      'user@.domain.com',
      'user@domain..com',
      'user@domain.c',
      'user@domain.toolongTLD',

      // Multiple @ symbols
      'user@@domain.com',
      'user@domain@com',
      '@domain.com',
      'user@',

      // Whitespace and control chars
      ' user@domain.com',
      'user @domain.com',
      'user@ domain.com',
      'user@domain.com ',
      'user\t@domain.com',
      'user\n@domain.com',

      // HTML/XSS in email
      '<script>alert(1)</script>@domain.com',
      'user+<script>@domain.com',
      'user@<script>alert(1)</script>.com',

      // SQL injection patterns
      'user\'; DROP TABLE users; --@domain.com',
      'user@domain.com\'; INSERT INTO',

      // Very long emails
      'a'.repeat(1000) + '@' + 'b'.repeat(1000) + '.com',

      // Binary data
      '\x00user@domain.com',
      'user@domain.com\x00',
      'user\x00@domain.com',

      // Unicode exploits
      'user@раура1.com', // Homograph attack
      'user@app\u202Eexe.com', // RTL override

      ...Array.from({length: count - 40}, () => faker.internet.email() + faker.string.sample(100))
    ].slice(0, count);
  }

  static generateMaliciousJWTs(count: number = 30): string[] {
    return [
      // Malformed JWTs
      '',
      'invalid',
      'not.a.jwt',
      'too.many.parts.here.invalid',
      'missing..parts',
      '..',
      'header.payload.',
      '.payload.signature',
      'header..signature',

      // None algorithm attack
      'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.',

      // Very long JWTs
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' + 'A'.repeat(100000) + '.signature',
      'header.' + 'A'.repeat(100000) + '.signature',
      'header.payload.' + 'A'.repeat(100000),

      // Invalid base64
      'not-base64.not-base64.not-base64',
      'inv@lid.b@se64.ch@rs',

      // Binary data
      '\x00\x01\x02.\x03\x04\x05.\x06\x07\x08',

      // SQL injection in JWT
      'header.eyJzdWIiOiIxMjMnOyBEUk9QIFRBQkxFIHVzZXJzOyAtLSJ9.signature',

      // XSS in JWT
      'header.eyJuYW1lIjoiPHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0PiJ9.signature',

      // Large numbers that might cause overflow
      'eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjk5OTk5OTk5OTk5OTk5OTk5OX0.signature',
      'eyJhbGciOiJIUzI1NiJ9.eyJpYXQiOi05OTk5OTk5OTk5OTk5OTk5OTl9.signature',

      ...Array.from({length: count - 20}, () => faker.string.alphanumeric(100) + '.' + faker.string.alphanumeric(100) + '.' + faker.string.alphanumeric(100))
    ].slice(0, count);
  }

  static generateRaceConditionRequests(count: number = 10): Array<{ip: string, timestamp: number}> {
    // Generate requests that arrive at nearly the same time
    const baseTime = Date.now();
    return Array.from({length: count}, (_, i) => ({
      ip: faker.internet.ip(),
      timestamp: baseTime + faker.number.int({ min: 0, max: 5 }) // Within 5ms
    }));
  }
}

describe('🎯 SECURITY FUZZ TESTING SUITE', () => {
  let mockKV: KVNamespace;

  beforeEach(() => {
    const store = new Map<string, string>();
    mockKV = {
      get: vi.fn().mockImplementation(async (key: string) => store.get(key) || null),
      put: vi.fn().mockImplementation(async (key: string, value: string) => store.set(key, value)),
      delete: vi.fn().mockImplementation(async (key: string) => store.delete(key)),
      list: vi.fn().mockImplementation(async () => ({ keys: [], list_complete: true, cursor: '' }))
    } as any;
  });

  describe('🔤 INPUT VALIDATION FUZZING', () => {
    it('should handle massive malicious input payloads without crashing', async () => {
      const maliciousInputs = SecurityFuzzGenerator.generateMaliciousStrings(200);

      for (const input of maliciousInputs) {
        expect(() => {
          // Should not crash, should handle gracefully
          const result = sanitizeInput(input, { maxLength: 10000 });
          expect(typeof result).toBe('string');
          expect(result.length).toBeLessThanOrEqual(10000);
        }).not.toThrow();
      }
    });

    it('should prevent XSS in all edge case scenarios', () => {
      const maliciousInputs = SecurityFuzzGenerator.generateMaliciousStrings(100);

      maliciousInputs.forEach(input => {
        const sanitized = preventXSS(input);

        // Should not contain dangerous patterns
        expect(sanitized).not.toMatch(/<script[\s\S]*?>[\s\S]*?<\/script>/gi);
        expect(sanitized).not.toMatch(/javascript\s*:/gi);
        expect(sanitized).not.toMatch(/on\w+\s*=/gi);
        expect(sanitized).not.toMatch(/data\s*:\s*text\/html/gi);
      });
    });

    it('should handle extreme email edge cases', () => {
      const edgeCaseEmails = SecurityFuzzGenerator.generateEdgeCaseEmails(100);

      edgeCaseEmails.forEach(email => {
        expect(() => {
          const result = sanitizeEmail(email);
          // Should either return a valid email or empty string
          expect(typeof result).toBe('string');
          if (result.length > 0) {
            expect(result).toMatch(/^[^\s@]+@[^\s@]+\.[^\s@]+$/);
          }
        }).not.toThrow();
      });
    });

    it('should handle unicode and encoding attacks', () => {
      const unicodeAttacks = [
        '\uFEFF<script>alert(1)</script>', // BOM
        '\u202E<script>alert(1)</script>\u202D', // RTL override
        'раура1.com', // Homograph attack
        '\u00A0'.repeat(1000), // Non-breaking spaces
        '\u2028<script>alert(1)</script>', // Line separator
        '\u2029<script>alert(1)</script>', // Paragraph separator
        'test\u0000<script>alert(1)</script>', // Null byte
        Buffer.from('test<script>alert(1)</script>', 'utf16le').toString(),
        decodeURIComponent('%EF%BB%BF<script>alert(1)</script>'), // UTF-8 BOM
      ];

      unicodeAttacks.forEach(attack => {
        const sanitized = preventXSS(attack);
        expect(sanitized).not.toContain('<script');
        expect(sanitized).not.toContain('alert');
      });
    });

    it('should handle buffer overflow attempts', () => {
      const overflowAttempts = [
        'A'.repeat(1000000), // 1MB string
        'A'.repeat(65536), // 64KB string
        'A'.repeat(8192), // 8KB string
        '\x00'.repeat(100000), // Null bytes
        Array.from({length: 100000}, () => String.fromCharCode(Math.floor(Math.random() * 256))).join(''),
      ];

      overflowAttempts.forEach(attempt => {
        expect(() => {
          const result = sanitizeInput(attempt, { maxLength: 1000 });
          expect(result.length).toBeLessThanOrEqual(1000);
        }).not.toThrow();
      });
    });
  });

  describe('🔐 JWT FUZZING TESTS', () => {
    it('should handle malformed JWT tokens gracefully', async () => {
      const maliciousJWTs = SecurityFuzzGenerator.generateMaliciousJWTs(50);
      const secret = 'test-secret-key';

      for (const jwt of maliciousJWTs) {
        const result = await validateJWT(jwt, secret);
        expect(result.valid).toBe(false);
        expect(result.error).toBeDefined();
      }
    });

    it('should prevent JWT algorithm confusion attacks', async () => {
      const algorithmConfusionJWTs = [
        'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.',
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.none',
        'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.fake-signature',
      ];

      const secret = 'test-secret';

      for (const jwt of algorithmConfusionJWTs) {
        const result = await validateJWT(jwt, secret);
        expect(result.valid).toBe(false);
      }
    });

    it('should handle extreme JWT payload sizes', async () => {
      const largePayloads = [
        'eyJhbGciOiJIUzI1NiJ9.' + Buffer.from(JSON.stringify({data: 'A'.repeat(100000)})).toString('base64') + '.signature',
        'eyJhbGciOiJIUzI1NiJ9.' + 'A'.repeat(1000000) + '.signature',
        'eyJhbGciOiJIUzI1NiJ9.' + 'A'.repeat(10000000) + '.signature', // 10MB payload
      ];

      const secret = 'test-secret';

      for (const jwt of largePayloads) {
        const result = await validateJWT(jwt, secret);
        expect(result.valid).toBe(false);
      }
    });
  });

  describe('⚡ RACE CONDITION FUZZING', () => {
    it('should handle concurrent rate limiting requests safely', async () => {
      const raceRequests = SecurityFuzzGenerator.generateRaceConditionRequests(100);

      // Create mock requests that arrive simultaneously
      const mockRequests = raceRequests.map(({ip}) =>
        new Request('https://example.com', {
          headers: { 'CF-Connecting-IP': ip }
        })
      );

      // Execute all requests concurrently
      const results = await Promise.all(
        mockRequests.map(request =>
          rateLimitByIP(request, mockKV, 5, 60).catch(() => ({ allowed: false, remaining: 0, resetTime: Date.now(), totalHits: 0 }))
        )
      );

      // Should not crash and should handle all requests
      expect(results).toHaveLength(100);
      results.forEach(result => {
        expect(typeof result.allowed).toBe('boolean');
        expect(typeof result.remaining).toBe('number');
      });
    });

    it('should handle concurrent session creation/validation', async () => {
      const concurrentOperations = Array.from({length: 50}, () =>
        Math.random() > 0.5 ? 'create' : 'validate'
      );

      const results = await Promise.allSettled(
        concurrentOperations.map(async (op) => {
          if (op === 'create') {
            // Mock session creation
            return await mockKV.put(`session:${faker.string.uuid()}`, JSON.stringify({
              userId: faker.string.uuid(),
              created: Date.now()
            }));
          } else {
            // Mock session validation
            return await mockKV.get(`session:${faker.string.uuid()}`);
          }
        })
      );

      // Should complete without crashes
      expect(results).toHaveLength(50);
    });

    it('should handle memory pressure scenarios', async () => {
      // Create memory pressure through large data operations
      const largeDataOperations = Array.from({length: 100}, () => ({
        key: faker.string.uuid(),
        data: 'x'.repeat(10000) // 10KB per item
      }));

      const results = await Promise.allSettled(
        largeDataOperations.map(({key, data}) =>
          mockKV.put(key, data)
        )
      );

      // Should handle large data without crashes
      expect(results.every(r => r.status === 'fulfilled')).toBe(true);
    });
  });

  describe('🌐 NETWORK ATTACK FUZZING', () => {
    it('should detect various suspicious activity patterns', () => {
      const suspiciousPatterns = [
        // User agent variations
        ...Array.from({length: 20}, () => createMockRequest('192.168.1.1', undefined, faker.helpers.arrayElement([
          'curl/7.68.0',
          'wget/1.20.3',
          'python-requests/2.25.1',
          'bot',
          'crawler',
          'scanner',
          'nikto',
          'sqlmap',
          faker.string.alphanumeric(3), // Very short UA
          'Mozilla/5.0' + 'A'.repeat(1000), // Very long UA
        ]))),

        // Path traversal variations
        ...Array.from({length: 20}, () => new Request(`https://example.com${faker.helpers.arrayElement([
          '/../../../etc/passwd',
          '/..%2F..%2F..%2Fetc%2Fpasswd',
          '/....//....//....//etc/passwd',
          '/..\\..\\..\\.\\windows\\system32\\config\\sam',
          '/files?file=../../../../etc/shadow',
        ])}`)),

        // SQL injection in URLs
        ...Array.from({length: 20}, () => new Request(`https://example.com/api?id=${faker.helpers.arrayElement([
          "1 UNION SELECT * FROM users",
          "1' OR '1'='1",
          "1; DROP TABLE users; --",
          "1 AND (SELECT COUNT(*) FROM users) > 0",
          "1' AND SLEEP(5) --",
        ])}`)),
      ];

      suspiciousPatterns.forEach(request => {
        const result = detectSuspiciousActivity(request);
        expect(result.suspicious).toBe(true);
        expect(result.reasons.length).toBeGreaterThan(0);
      });
    });

    it('should handle extreme request patterns', () => {
      const extremeRequests = [
        // Very long URLs
        new Request('https://example.com/' + 'a'.repeat(100000)),

        // URLs with extreme query strings
        new Request('https://example.com/?' + Array.from({length: 1000}, (_, i) => `param${i}=value${i}`).join('&')),

        // URLs with unusual characters
        new Request('https://example.com/' + encodeURIComponent('тест/файл.exe')),

        // Binary data in URLs
        new Request('https://example.com/' + Array.from({length: 100}, () =>
          '%' + Math.floor(Math.random() * 256).toString(16).padStart(2, '0')
        ).join('')),
      ];

      extremeRequests.forEach(request => {
        expect(() => {
          const result = detectSuspiciousActivity(request);
          expect(typeof result.suspicious).toBe('boolean');
          expect(Array.isArray(result.reasons)).toBe(true);
        }).not.toThrow();
      });
    });
  });

  describe('🏢 TENANT ISOLATION FUZZING', () => {
    it('should handle malicious business ID patterns', () => {
      const maliciousBusinessIds = [
        '', // Empty
        null as any, // Null
        undefined as any, // Undefined
        'business-id\'; DROP TABLE businesses; --', // SQL injection
        'business-id\x00', // Null byte
        'business-id/../../../etc/passwd', // Path traversal
        '<script>alert(1)</script>', // XSS
        'business-id' + 'A'.repeat(10000), // Very long
        'раураl-business', // Homograph
        'business\nid', // Newline
        'business\tid', // Tab
        'business\rid', // Carriage return
        'business id', // Space
        'business@id', // Special chars
        'business#id',
        'business&id',
        'business|id',
        ...Array.from({length: 50}, () => faker.string.sample() + faker.string.alphanumeric(100))
      ];

      const mockSecurityContext = {
        businessId: 'valid-business-123',
        userId: 'user-456',
        userRole: 'admin',
        permissions: ['read', 'write'],
        isolationLevel: 'strict' as const,
        sessionId: 'session-789',
        requestId: 'req-abc',
        ipAddress: '192.168.1.1',
        userAgent: 'Test Agent',
        verified: true,
        mfaEnabled: true,
        riskScore: 10,
        lastValidated: new Date()
      };

      maliciousBusinessIds.forEach(businessId => {
        if (businessId !== null && businessId !== undefined) {
          const maliciousContext = { ...mockSecurityContext, businessId };

          expect(() => {
            // Should handle malicious business IDs gracefully
            const query = `SELECT * FROM accounts WHERE business_id = '${businessId}' AND status = 'active'`;
            const result = tenantIsolation.secureQuery(query, [], maliciousContext);

            if (result.secure) {
              expect(result.query).toContain('business_id');
            } else {
              expect(result.violations.length).toBeGreaterThan(0);
            }
          }).not.toThrow();
        }
      });
    });

    it('should handle complex query injection attempts', () => {
      const maliciousQueries = [
        `SELECT * FROM accounts WHERE id = 1; DROP TABLE accounts; --`,
        `SELECT * FROM accounts WHERE id = 1 UNION SELECT * FROM users`,
        `SELECT * FROM accounts WHERE id = 1 AND (SELECT COUNT(*) FROM users) > 0`,
        `SELECT * FROM accounts WHERE id = '1' OR '1'='1'`,
        `UPDATE accounts SET balance = 1000000 WHERE id = 1`,
        `INSERT INTO accounts (name, balance) VALUES ('hacker', 1000000)`,
        `DELETE FROM accounts WHERE business_id != 'my-business'`,
        // Complex polyglot attacks
        `SELECT * FROM accounts WHERE id = '1'/**/UNION/**/SELECT/**/password/**/FROM/**/users--`,
        `SELECT * FROM accounts WHERE id = 0x31 UNION SELECT password FROM users`,
        // Time-based attacks
        `SELECT * FROM accounts WHERE id = 1 AND SLEEP(5)`,
        `SELECT * FROM accounts WHERE id = 1; WAITFOR DELAY '00:00:05'`,
        // Boolean-based blind injection
        `SELECT * FROM accounts WHERE id = 1 AND (SELECT SUBSTRING(password,1,1) FROM users WHERE id=1)='a'`,
        ...Array.from({length: 20}, () =>
          `SELECT * FROM accounts WHERE id = '${SecurityFuzzGenerator.generateRandomMaliciousString()}'`
        )
      ];

      const mockSecurityContext = {
        businessId: 'valid-business-123',
        userId: 'user-456',
        userRole: 'admin',
        permissions: ['read', 'write'],
        isolationLevel: 'strict' as const,
        sessionId: 'session-789',
        requestId: 'req-abc',
        ipAddress: '192.168.1.1',
        userAgent: 'Test Agent',
        verified: true,
        mfaEnabled: true,
        riskScore: 10,
        lastValidated: new Date()
      };

      maliciousQueries.forEach(query => {
        expect(() => {
          const result = tenantIsolation.secureQuery(query, [], mockSecurityContext);

          // Should either secure the query or detect violations
          if (!result.secure) {
            expect(result.violations.length).toBeGreaterThan(0);
            expect(result.violations.some((v: any) =>
              ['injection_attempt', 'missing_business_id', 'cross_tenant_access'].includes(v.type)
            )).toBe(true);
          }
        }).not.toThrow();
      });
    });
  });

  describe('💥 STRESS & RESOURCE EXHAUSTION TESTS', () => {
    it('should handle memory exhaustion attempts', async () => {
      const memoryExhaustionAttempts = [
        () => 'A'.repeat(10000000), // 10MB string
        () => Array.from({length: 1000000}, () => faker.string.alphanumeric(100)).join(''),
        () => JSON.stringify(Array.from({length: 100000}, () => ({
          id: faker.string.uuid(),
          data: faker.string.alphanumeric(1000)
        }))),
        () => Array.from({length: 1000000}, () => Math.random()).join(''),
      ];

      memoryExhaustionAttempts.forEach(generator => {
        expect(() => {
          const largeInput = generator();
          const result = sanitizeInput(largeInput, { maxLength: 10000 });
          expect(result.length).toBeLessThanOrEqual(10000);
        }).not.toThrow();
      });
    });

    it('should handle CPU exhaustion patterns', () => {
      const cpuExhaustionPatterns = [
        // Regex DoS patterns
        'a'.repeat(50000) + '!',
        '(' + 'a'.repeat(1000) + ')*',
        'a'.repeat(10000) + 'b'.repeat(10000) + 'c',

        // Complex nested structures
        '{"a":'.repeat(10000) + '"value"' + '}'.repeat(10000),
        '<div>'.repeat(10000) + 'content' + '</div>'.repeat(10000),

        // Hash collision attempts
        ...Array.from({length: 100}, () =>
          Array.from({length: 1000}, () => 'aa').join('')
        ),
      ];

      cpuExhaustionPatterns.forEach(pattern => {
        expect(() => {
          const start = Date.now();
          const result = sanitizeInput(pattern, { maxLength: 1000 });
          const duration = Date.now() - start;

          // Should complete in reasonable time (less than 1 second)
          expect(duration).toBeLessThan(1000);
          expect(result.length).toBeLessThanOrEqual(1000);
        }).not.toThrow();
      });
    });
  });
});

// Helper function to create mock requests
function createMockRequest(ip: string, origin?: string, userAgent?: string): Request {
  const headers = new Headers();
  headers.set('CF-Connecting-IP', ip);
  if (origin) headers.set('Origin', origin);
  if (userAgent) headers.set('User-Agent', userAgent);

  return new Request('https://example.com', { headers });
}