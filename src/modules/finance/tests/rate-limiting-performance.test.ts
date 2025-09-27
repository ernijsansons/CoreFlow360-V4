/**
 * Rate Limiting Performance Tests
 * Testing rate limiting system under various load conditions
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import {
  RateLimiter,
  RateLimitError,
  RATE_LIMIT_CONFIGS,
  createRateLimitMiddleware,
  BusinessRateLimiter,
  GlobalRateLimiter
} from '../rate-limiter';

// Mock KV namespace for testing
class MockKVNamespace {
  private store: Map<string, { value: string; expiration?: number }> = new Map();
  private currentTime = Date.now();

  async get(key: string): Promise<string | null> {
    const item = this.store.get(key);
    if (!item) return null;

    // Check expiration
    if (item.expiration && this.currentTime > item.expiration) {
      this.store.delete(key);
      return null;
    }

    return item.value;
  }

  async put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void> {
    const expiration = options?.expirationTtl
      ? this.currentTime + (options.expirationTtl * 1000)
      : undefined;

    this.store.set(key, { value, expiration });
  }

  async delete(key: string): Promise<void> {
    this.store.delete(key);
  }

  // Test helper methods
  clear(): void {
    this.store.clear();
  }

  setTime(time: number): void {
    this.currentTime = time;
  }

  advanceTime(ms: number): void {
    this.currentTime += ms;
  }

  getStoreSize(): number {
    return this.store.size;
  }

  getKeys(): string[] {
    return Array.from(this.store.keys());
  }
}

describe('Rate Limiting Performance Tests', () => {
  let mockKV: MockKVNamespace;
  let rateLimiter: RateLimiter;

  beforeEach(() => {
    mockKV = new MockKVNamespace();
    rateLimiter = new RateLimiter({
      requests: 100,
      windowMs: 60000 // 1 minute
    });
  });

  afterEach(() => {
    mockKV.clear();
  });

  describe('Basic Rate Limiting Functionality', () => {
    it('should allow requests within limit', async () => {
      const businessId = 'test_business';
      const userId = 'test_user';
      const endpoint = 'test_endpoint';

      // Make 5 requests (well within 100 limit)
      for (let i = 0; i < 5; i++) {
        const result = await rateLimiter.checkLimit(businessId, userId, endpoint, mockKV as any);

        expect(result.allowed).toBe(true);
        expect(result.remaining).toBe(100 - (i + 1));
        expect(result.resetTime).toBeGreaterThan(Date.now());
      }
    });

    it('should block requests exceeding limit', async () => {
      const businessId = 'test_business';
      const userId = 'test_user';
      const endpoint = 'test_endpoint';

      const config = {
        requests: 3,
        windowMs: 60000
      };

      const testLimiter = new RateLimiter(config);

      // Make 3 requests (at limit)
      for (let i = 0; i < 3; i++) {
        const result = await testLimiter.checkLimit(businessId, userId, endpoint, mockKV as any);
        expect(result.allowed).toBe(true);
      }

      // 4th request should be blocked
      const blockedResult = await testLimiter.checkLimit(businessId, userId, endpoint, mockKV as any);
      expect(blockedResult.allowed).toBe(false);
      expect(blockedResult.remaining).toBe(0);
      expect(blockedResult.retryAfter).toBeGreaterThan(0);
    });

    it('should reset limit after window expires', async () => {
      const businessId = 'test_business';
      const userId = 'test_user';
      const endpoint = 'test_endpoint';

      const config = {
        requests: 2,
        windowMs: 1000 // 1 second
      };

      const testLimiter = new RateLimiter(config);

      // Exhaust limit
      await testLimiter.checkLimit(businessId, userId, endpoint, mockKV as any);
      await testLimiter.checkLimit(businessId, userId, endpoint, mockKV as any);

      // Should be blocked
      const blockedResult = await testLimiter.checkLimit(businessId, userId, endpoint, mockKV as any);
      expect(blockedResult.allowed).toBe(false);

      // Advance time past window
      mockKV.advanceTime(1100);

      // Should be allowed again
      const allowedResult = await testLimiter.checkLimit(businessId, userId, endpoint, mockKV as any);
      expect(allowedResult.allowed).toBe(true);
      expect(allowedResult.remaining).toBe(1);
    });
  });

  describe('Concurrent Request Handling', () => {
    it('should handle concurrent requests accurately', async () => {
      const businessId = 'test_business';
      const userId = 'test_user';
      const endpoint = 'test_endpoint';

      const config = {
        requests: 50,
        windowMs: 60000
      };

      const testLimiter = new RateLimiter(config);

      // Make 100 concurrent requests (should allow 50, block 50)
      const promises = Array.from({ length: 100 }, (_, i) =>
        testLimiter.checkLimit(businessId, userId, `${endpoint}_${i}`, mockKV as any)
      );

      const results = await Promise.all(promises);

      const allowedResults = results.filter((r: any) => r.allowed);
      const blockedResults = results.filter((r: any) => !r.allowed);

      // Note: Due to concurrent execution, results may vary slightly
      // but we should see approximately 50 allowed and 50 blocked
      expect(allowedResults.length).toBeLessThanOrEqual(50);
      expect(blockedResults.length).toBeGreaterThan(0);
      expect(allowedResults.length + blockedResults.length).toBe(100);
    });

    it('should isolate rate limits between different businesses', async () => {
      const userId = 'test_user';
      const endpoint = 'test_endpoint';

      const config = {
        requests: 5,
        windowMs: 60000
      };

      const testLimiter = new RateLimiter(config);

      // Each business should have its own limit
      const business1Promises = Array.from({ length: 5 }, () =>
        testLimiter.checkLimit('business_1', userId, endpoint, mockKV as any)
      );

      const business2Promises = Array.from({ length: 5 }, () =>
        testLimiter.checkLimit('business_2', userId, endpoint, mockKV as any)
      );

      const business1Results = await Promise.all(business1Promises);
      const business2Results = await Promise.all(business2Promises);

      // Both businesses should be allowed their full quota
      expect(business1Results.every(r => r.allowed)).toBe(true);
      expect(business2Results.every(r => r.allowed)).toBe(true);

      // Additional requests should be blocked for each business separately
      const business1Blocked = await testLimiter.checkLimit('business_1', userId, endpoint, mockKV as any);
      const business2Blocked = await testLimiter.checkLimit('business_2', userId, endpoint, mockKV as any);

      expect(business1Blocked.allowed).toBe(false);
      expect(business2Blocked.allowed).toBe(false);
    });

    it('should isolate rate limits between different users', async () => {
      const businessId = 'test_business';
      const endpoint = 'test_endpoint';

      const config = {
        requests: 3,
        windowMs: 60000
      };

      const testLimiter = new RateLimiter(config);

      // Each user should have their own limit
      for (let userNum = 1; userNum <= 5; userNum++) {
        const userId = `user_${userNum}`;

        // Each user should be able to make 3 requests
        for (let reqNum = 1; reqNum <= 3; reqNum++) {
          const result = await testLimiter.checkLimit(businessId, userId, endpoint, mockKV as any);
          expect(result.allowed).toBe(true);
        }

        // 4th request should be blocked for each user
        const blockedResult = await testLimiter.checkLimit(businessId, userId, endpoint, mockKV as any);
        expect(blockedResult.allowed).toBe(false);
      }
    });
  });

  describe('Performance Under Load', () => {
    it('should maintain performance with high request volume', async () => {
      const config = {
        requests: 1000,
        windowMs: 60000
      };

      const testLimiter = new RateLimiter(config);

      const startTime = Date.now();

      // Make 10,000 requests across 100 different users
      const promises = [];
      for (let i = 0; i < 10000; i++) {
        const businessId = `business_${i % 10}`;
        const userId = `user_${i % 100}`;
        const endpoint = `endpoint_${i % 5}`;

        promises.push(testLimiter.checkLimit(businessId, userId, endpoint, mockKV as any));
      }

      const results = await Promise.all(promises);
      const endTime = Date.now();

      const duration = endTime - startTime;
      const avgTimePerRequest = duration / results.length;

      // Should complete in reasonable time
      expect(duration).toBeLessThan(5000); // 5 seconds max
      expect(avgTimePerRequest).toBeLessThan(1); // Less than 1ms per request

      // Verify results are properly distributed
      const allowedCount = results.filter((r: any) => r.allowed).length;
      const blockedCount = results.filter((r: any) => !r.allowed).length;

      expect(allowedCount + blockedCount).toBe(10000);
      expect(allowedCount).toBeGreaterThan(0);
    });

    it('should handle memory efficiently with many rate limit keys', async () => {
      const config = {
        requests: 10,
        windowMs: 60000
      };

      const testLimiter = new RateLimiter(config);

      // Create 1000 different rate limit keys
      for (let i = 0; i < 1000; i++) {
        await testLimiter.checkLimit(`business_${i}`, `user_${i}`, `endpoint_${i}`, mockKV as any);
      }

      // Check that KV store size is reasonable
      const storeSize = mockKV.getStoreSize();
      expect(storeSize).toBe(1000); // One entry per unique key

      // Advance time to expire entries
      mockKV.advanceTime(70000); // Past the 60 second window

      // Make new requests (should create fresh entries)
      for (let i = 0; i < 10; i++) {
        await testLimiter.checkLimit(`business_new_${i}`, `user_new_${i}`, `endpoint_new_${i}`, mockKV as any);
      }

      // Memory usage should be manageable
      expect(mockKV.getStoreSize()).toBeLessThan(1100);
    });

    it('should maintain accuracy under rapid successive requests', async () => {
      const config = {
        requests: 100,
        windowMs: 1000 // 1 second window for faster testing
      };

      const testLimiter = new RateLimiter(config);
      const businessId = 'test_business';
      const userId = 'test_user';
      const endpoint = 'test_endpoint';

      // Make rapid successive requests
      const results = [];
      for (let i = 0; i < 150; i++) {
        const result = await testLimiter.checkLimit(businessId, userId, endpoint, mockKV as any);
        results.push(result);

        // Small delay to simulate real-world timing
        await new Promise(resolve => setTimeout(resolve, 1));
      }

      const allowedResults = results.filter((r: any) => r.allowed);
      const blockedResults = results.filter((r: any) => !r.allowed);

      // Should allow exactly 100 requests, block the rest
      expect(allowedResults.length).toBe(100);
      expect(blockedResults.length).toBe(50);

      // Remaining count should decrease properly
      for (let i = 0; i < 100; i++) {
        expect(allowedResults[i].remaining).toBe(100 - (i + 1));
      }

      // All blocked results should have 0 remaining
      blockedResults.forEach((result: any) => {
        expect(result.remaining).toBe(0);
        expect(result.retryAfter).toBeGreaterThan(0);
      });
    });
  });

  describe('Different Rate Limit Configurations', () => {
    it('should handle report generation rate limits correctly', async () => {
      const reportLimiter = new RateLimiter(RATE_LIMIT_CONFIGS.reportGeneration);
      const businessId = 'test_business';
      const userId = 'test_user';
      const endpoint = 'report_generation';

      // Should allow 10 requests per minute
      for (let i = 0; i < 10; i++) {
        const result = await reportLimiter.checkLimit(businessId, userId, endpoint, mockKV as any);
        expect(result.allowed).toBe(true);
        expect(result.remaining).toBe(10 - (i + 1));
      }

      // 11th request should be blocked
      const blockedResult = await reportLimiter.checkLimit(businessId, userId, endpoint, mockKV as any);
      expect(blockedResult.allowed).toBe(false);
      expect(blockedResult.retryAfter).toBeLessThanOrEqual(60);
    });

    it('should handle export rate limits correctly', async () => {
      const exportLimiter = new RateLimiter(RATE_LIMIT_CONFIGS.exports);
      const businessId = 'test_business';
      const userId = 'test_user';
      const endpoint = 'export';

      // Should allow 5 requests per minute
      for (let i = 0; i < 5; i++) {
        const result = await exportLimiter.checkLimit(businessId, userId, endpoint, mockKV as any);
        expect(result.allowed).toBe(true);
        expect(result.remaining).toBe(5 - (i + 1));
      }

      // 6th request should be blocked
      const blockedResult = await exportLimiter.checkLimit(businessId, userId, endpoint, mockKV as any);
      expect(blockedResult.allowed).toBe(false);
      expect(blockedResult.retryAfter).toBeLessThanOrEqual(60);
    });

    it('should handle authentication rate limits correctly', async () => {
      const authLimiter = new RateLimiter(RATE_LIMIT_CONFIGS.authentication);
      const businessId = 'test_business';
      const userId = 'test_user';
      const endpoint = 'auth';

      // Should allow 5 requests per 15 minutes
      for (let i = 0; i < 5; i++) {
        const result = await authLimiter.checkLimit(businessId, userId, endpoint, mockKV as any);
        expect(result.allowed).toBe(true);
        expect(result.remaining).toBe(5 - (i + 1));
      }

      // 6th request should be blocked
      const blockedResult = await authLimiter.checkLimit(businessId, userId, endpoint, mockKV as any);
      expect(blockedResult.allowed).toBe(false);
      expect(blockedResult.retryAfter).toBeLessThanOrEqual(900); // 15 minutes
    });
  });

  describe('Business and Global Rate Limiters', () => {
    it('should enforce business-level rate limits', async () => {
      const businessLimiter = new BusinessRateLimiter({
        requests: 1000,
        windowMs: 60000
      });

      const businessId = 'test_business';

      // Make 1000 requests from business
      for (let i = 0; i < 1000; i++) {
        const result = await businessLimiter.checkBusinessLimit(businessId, mockKV as any);
        expect(result.allowed).toBe(true);
      }

      // 1001st request should be blocked
      const blockedResult = await businessLimiter.checkBusinessLimit(businessId, mockKV as any);
      expect(blockedResult.allowed).toBe(false);
    });

    it('should enforce global rate limits', async () => {
      const globalLimiter = new GlobalRateLimiter({
        requests: 10000,
        windowMs: 60000
      });

      // Make 10000 requests globally
      for (let i = 0; i < 10000; i++) {
        const result = await globalLimiter.checkGlobalLimit(mockKV as any);
        expect(result.allowed).toBe(true);
      }

      // 10001st request should be blocked
      const blockedResult = await globalLimiter.checkGlobalLimit(mockKV as any);
      expect(blockedResult.allowed).toBe(false);
    });

    it('should isolate business limits from each other', async () => {
      const businessLimiter = new BusinessRateLimiter({
        requests: 5,
        windowMs: 60000
      });

      // Business A uses its full quota
      for (let i = 0; i < 5; i++) {
        const result = await businessLimiter.checkBusinessLimit('business_a', mockKV as any);
        expect(result.allowed).toBe(true);
      }

      // Business A is now blocked
      const businessABlocked = await businessLimiter.checkBusinessLimit('business_a', mockKV as any);
      expect(businessABlocked.allowed).toBe(false);

      // Business B should still have its full quota
      for (let i = 0; i < 5; i++) {
        const result = await businessLimiter.checkBusinessLimit('business_b', mockKV as any);
        expect(result.allowed).toBe(true);
      }
    });
  });

  describe('Error Handling and Edge Cases', () => {
    it('should handle KV storage failures gracefully', async () => {
      // Mock KV that always fails
      const failingKV = {
        get: () => Promise.reject(new Error('KV storage unavailable')),
        put: () => Promise.reject(new Error('KV storage unavailable')),
        delete: () => Promise.reject(new Error('KV storage unavailable'))
      };

      const businessId = 'test_business';
      const userId = 'test_user';
      const endpoint = 'test_endpoint';

      // Should fail open (allow requests) when KV is unavailable
      const result = await rateLimiter.checkLimit(businessId, userId, endpoint, failingKV as any);

      expect(result.allowed).toBe(true);
      expect(result.remaining).toBeGreaterThan(0);
    });

    it('should handle corrupted KV data gracefully', async () => {
      const corruptedKV = {
        get: () => Promise.resolve('corrupted json data {invalid'),
        put: () => Promise.resolve(),
        delete: () => Promise.resolve()
      };

      const businessId = 'test_business';
      const userId = 'test_user';
      const endpoint = 'test_endpoint';

      // Should handle corrupted data and reset the limit
      const result = await rateLimiter.checkLimit(businessId, userId, endpoint, corruptedKV as any);

      expect(result.allowed).toBe(true);
      expect(result.remaining).toBeGreaterThan(0);
    });

    it('should handle very short time windows correctly', async () => {
      const shortWindowLimiter = new RateLimiter({
        requests: 2,
        windowMs: 100 // 100ms window
      });

      const businessId = 'test_business';
      const userId = 'test_user';
      const endpoint = 'test_endpoint';

      // Make 2 requests quickly
      const result1 = await shortWindowLimiter.checkLimit(businessId, userId, endpoint, mockKV as any);
      const result2 = await shortWindowLimiter.checkLimit(businessId, userId, endpoint, mockKV as any);

      expect(result1.allowed).toBe(true);
      expect(result2.allowed).toBe(true);

      // 3rd request should be blocked
      const result3 = await shortWindowLimiter.checkLimit(businessId, userId, endpoint, mockKV as any);
      expect(result3.allowed).toBe(false);

      // Wait for window to expire
      await new Promise(resolve => setTimeout(resolve, 150));
      mockKV.advanceTime(150);

      // Should be allowed again
      const result4 = await shortWindowLimiter.checkLimit(businessId, userId, endpoint, mockKV as any);
      expect(result4.allowed).toBe(true);
    });

    it('should handle very large request limits correctly', async () => {
      const largeLimitLimiter = new RateLimiter({
        requests: 1000000, // 1 million requests
        windowMs: 60000
      });

      const businessId = 'test_business';
      const userId = 'test_user';
      const endpoint = 'test_endpoint';

      // Should handle large numbers correctly
      const result = await largeLimitLimiter.checkLimit(businessId, userId, endpoint, mockKV as any);

      expect(result.allowed).toBe(true);
      expect(result.remaining).toBe(999999);
      expect(result.resetTime).toBeGreaterThan(Date.now());
    });
  });

  describe('Rate Limiter Middleware', () => {
    it('should create functional middleware', async () => {
      const middleware = createRateLimitMiddleware(
        RATE_LIMIT_CONFIGS.general,
        'test-endpoint'
      );

      const businessId = 'test_business';
      const userId = 'test_user';

      // Test middleware function
      const result = await middleware(businessId, userId, mockKV as any);

      expect(result.allowed).toBe(true);
      expect(result.remaining).toBeLessThanOrEqual(100);
      expect(result.resetTime).toBeGreaterThan(Date.now());
    });

    it('should handle middleware rate limit exceeded', async () => {
      const strictMiddleware = createRateLimitMiddleware(
        { requests: 1, windowMs: 60000 },
        'strict-endpoint'
      );

      const businessId = 'test_business';
      const userId = 'test_user';

      // First request should succeed
      const result1 = await strictMiddleware(businessId, userId, mockKV as any);
      expect(result1.allowed).toBe(true);

      // Second request should be blocked
      const result2 = await strictMiddleware(businessId, userId, mockKV as any);
      expect(result2.allowed).toBe(false);
      expect(result2.retryAfter).toBeGreaterThan(0);
    });
  });
});