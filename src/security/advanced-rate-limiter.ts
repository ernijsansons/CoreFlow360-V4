/**
 * Advanced Rate Limiting System
 * Provides comprehensive rate limiting with multiple algorithms and security features
 */

import { Logger } from '../shared/logger';
import { SecurityError } from '../shared/security-utils';

export interface RateLimitConfig {
  windowMs: number; // Time window in milliseconds
  maxRequests: number; // Maximum requests per window
  algorithm: 'fixed_window' | 'sliding_window' | 'token_bucket' | 'leaky_bucket';
  keyGenerator?: (identifier: string, context?: any) => string;
  skipSuccessfulRequests?: boolean;
  skipFailedRequests?: boolean;
  whitelist?: string[];
  blacklist?: string[];
  customRules?: RateCustomRule[];
}

export interface RateCustomRule {
  condition: (identifier: string, context?: any) => boolean;
  config: Partial<RateLimitConfig>;
}

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  resetTime: number;
  totalRequests: number;
  reason?: string;
  retryAfter?: number;
}

export interface RateLimitStore {
  get(key: string): Promise<RateLimitData | null>;
  set(key: string, data: RateLimitData, ttl: number): Promise<void>;
  increment(key: string, amount?: number): Promise<number>;
  delete(key: string): Promise<void>;
}

export interface RateLimitData {
  count: number;
  resetTime: number;
  tokens?: number; // For token bucket
  lastRefill?: number; // For token bucket
  requests?: number[]; // For sliding window
  windowStart?: number; // For fixed window
}

export class AdvancedRateLimiter {
  private logger: Logger;
  private store: RateLimitStore;

  constructor(store: RateLimitStore) {
    this.store = store;
    this.logger = new Logger({ component: 'rate-limiter' });
  }

  /**
   * Check if request is allowed under rate limit
   */
  async checkLimit(
    identifier: string,
    config: RateLimitConfig,
    context?: any
  ): Promise<RateLimitResult> {
    const startTime = Date.now();

    try {
      // Generate rate limiting key
      const key = config.keyGenerator
        ? config.keyGenerator(identifier, context)
        : `rate_limit:${identifier}`;

      // Check whitelist/blacklist
      if (config.whitelist?.includes(identifier)) {
        return {
          allowed: true,
          remaining: config.maxRequests,
          resetTime: startTime + config.windowMs,
          totalRequests: 0
        };
      }

      if (config.blacklist?.includes(identifier)) {
        return {
          allowed: false,
          remaining: 0,
          resetTime: startTime + config.windowMs,
          totalRequests: 0,
          reason: 'Blacklisted',
          retryAfter: config.windowMs
        };
      }

      // Apply custom rules
      const customConfig = this.applyCustomRules(identifier, config, context);

      // Execute rate limiting algorithm
      const result = await this.executeAlgorithm(key, customConfig);

      this.logger.debug('Rate limit check completed', {
        identifier,
        key,
        algorithm: customConfig.algorithm,
        allowed: result.allowed,
        remaining: result.remaining,
        processingTime: Date.now() - startTime
      });

      return result;

    } catch (error: any) {
      this.logger.error('Rate limit check failed', error, {
        identifier,
        algorithm: config.algorithm
      });

      // Fail securely - deny request on error
      return {
        allowed: false,
        remaining: 0,
        resetTime: startTime + config.windowMs,
        totalRequests: 0,
        reason: 'Rate limiting service error',
        retryAfter: 60000 // 1 minute retry
      };
    }
  }

  /**
   * Execute the configured rate limiting algorithm
   */
  private async executeAlgorithm(
    key: string,
    config: RateLimitConfig
  ): Promise<RateLimitResult> {
    switch (config.algorithm) {
      case 'fixed_window':
        return this.fixedWindowAlgorithm(key, config);
      case 'sliding_window':
        return this.slidingWindowAlgorithm(key, config);
      case 'token_bucket':
        return this.tokenBucketAlgorithm(key, config);
      case 'leaky_bucket':
        return this.leakyBucketAlgorithm(key, config);
      default:
        throw new Error(`Unknown rate limiting algorithm: ${config.algorithm}`);
    }
  }

  /**
   * Fixed window rate limiting algorithm
   */
  private async fixedWindowAlgorithm(
    key: string,
    config: RateLimitConfig
  ): Promise<RateLimitResult> {
    const now = Date.now();
    const windowStart = Math.floor(now / config.windowMs) * config.windowMs;
    const windowKey = `${key}:${windowStart}`;

    const current = await this.store.get(windowKey);
    const count = current?.count || 0;

    if (count >= config.maxRequests) {
      return {
        allowed: false,
        remaining: 0,
        resetTime: windowStart + config.windowMs,
        totalRequests: count,
        retryAfter: windowStart + config.windowMs - now
      };
    }

    // Increment counter
    const newCount = await this.store.increment(windowKey, 1);
    await this.store.set(windowKey, {
      count: newCount,
      resetTime: windowStart + config.windowMs,
      windowStart
    }, config.windowMs);

    return {
      allowed: true,
      remaining: Math.max(0, config.maxRequests - newCount),
      resetTime: windowStart + config.windowMs,
      totalRequests: newCount
    };
  }

  /**
   * Sliding window rate limiting algorithm
   */
  private async slidingWindowAlgorithm(
    key: string,
    config: RateLimitConfig
  ): Promise<RateLimitResult> {
    const now = Date.now();
    const windowStart = now - config.windowMs;

    const current = await this.store.get(key);
    const requests = current?.requests || [];

    // Remove requests outside the window
    const validRequests = requests.filter((timestamp: any) => timestamp > windowStart);

    if (validRequests.length >= config.maxRequests) {
      const oldestRequest = Math.min(...validRequests);
      const retryAfter = oldestRequest + config.windowMs - now;

      return {
        allowed: false,
        remaining: 0,
        resetTime: oldestRequest + config.windowMs,
        totalRequests: validRequests.length,
        retryAfter: Math.max(0, retryAfter)
      };
    }

    // Add current request
    validRequests.push(now);

    await this.store.set(key, {
      count: validRequests.length,
      resetTime: now + config.windowMs,
      requests: validRequests
    }, config.windowMs);

    return {
      allowed: true,
      remaining: Math.max(0, config.maxRequests - validRequests.length),
      resetTime: now + config.windowMs,
      totalRequests: validRequests.length
    };
  }

  /**
   * Token bucket rate limiting algorithm
   */
  private async tokenBucketAlgorithm(
    key: string,
    config: RateLimitConfig
  ): Promise<RateLimitResult> {
    const now = Date.now();
    const current = await this.store.get(key);

    let tokens = current?.tokens || config.maxRequests;
    const lastRefill = current?.lastRefill || now;

    // Calculate tokens to add based on time passed
    const timePassed = now - lastRefill;
    const tokensToAdd = Math.floor((timePassed / config.windowMs) * config.maxRequests);

    tokens = Math.min(config.maxRequests, tokens + tokensToAdd);

    if (tokens < 1) {
      const timeToNextToken = config.windowMs / config.maxRequests;
      const retryAfter = timeToNextToken - (timePassed % timeToNextToken);

      return {
        allowed: false,
        remaining: 0,
        resetTime: now + retryAfter,
        totalRequests: current?.count || 0,
        retryAfter
      };
    }

    // Consume a token
    tokens -= 1;

    await this.store.set(key, {
      count: (current?.count || 0) + 1,
      resetTime: now + config.windowMs,
      tokens,
      lastRefill: now
    }, config.windowMs * 2); // Longer TTL for token bucket

    return {
      allowed: true,
      remaining: tokens,
      resetTime: now + config.windowMs,
      totalRequests: (current?.count || 0) + 1
    };
  }

  /**
   * Leaky bucket rate limiting algorithm
   */
  private async leakyBucketAlgorithm(
    key: string,
    config: RateLimitConfig
  ): Promise<RateLimitResult> {
    const now = Date.now();
    const current = await this.store.get(key);

    let count = current?.count || 0;
    const lastUpdate = current?.resetTime || now;

    // Calculate leakage based on time passed
    const timePassed = now - lastUpdate;
    const leakRate = config.maxRequests / config.windowMs; // requests per ms
    const leaked = Math.floor(timePassed * leakRate);

    count = Math.max(0, count - leaked);

    if (count >= config.maxRequests) {
      const timeToLeak = (count - config.maxRequests + 1) / leakRate;

      return {
        allowed: false,
        remaining: 0,
        resetTime: now + timeToLeak,
        totalRequests: count,
        retryAfter: timeToLeak
      };
    }

    // Add current request to bucket
    count += 1;

    await this.store.set(key, {
      count,
      resetTime: now,
    }, config.windowMs * 2);

    return {
      allowed: true,
      remaining: Math.max(0, config.maxRequests - count),
      resetTime: now + ((count / leakRate)),
      totalRequests: count
    };
  }

  /**
   * Apply custom rules to rate limit configuration
   */
  private applyCustomRules(
    identifier: string,
    config: RateLimitConfig,
    context?: any
  ): RateLimitConfig {
    if (!config.customRules) {
      return config;
    }

    let modifiedConfig = { ...config };

    for (const rule of config.customRules) {
      if (rule.condition(identifier, context)) {
        modifiedConfig = { ...modifiedConfig, ...rule.config };
      }
    }

    return modifiedConfig;
  }

  /**
   * Create a middleware factory for different rate limiting scenarios
   */
  createMiddleware(configs: Record<string, RateLimitConfig>) {
    return (limitType: string, keyExtractor?: (req: any) => string) => {
      return async (c: any, next: any) => {
        const config = configs[limitType];
        if (!config) {
          throw new Error(`Rate limit configuration not found: ${limitType}`);
        }

        const identifier = keyExtractor
          ? keyExtractor(c.req)
          : c.req.header('CF-Connecting-IP') || 'unknown';

        const result = await this.checkLimit(identifier, config, {
          path: c.req.path,
          method: c.req.method,
          userAgent: c.req.header('User-Agent'),
          businessId: c.get('businessId')
        });

        // Add rate limit headers
        c.header('X-RateLimit-Limit', config.maxRequests.toString());
        c.header('X-RateLimit-Remaining', result.remaining.toString());
        c.header('X-RateLimit-Reset', Math.ceil(result.resetTime / 1000).toString());

        if (!result.allowed) {
          if (result.retryAfter) {
            c.header('Retry-After', Math.ceil(result.retryAfter / 1000).toString());
          }

          this.logger.warn('Rate limit exceeded', {
            identifier,
            limitType,
            path: c.req.path,
            remaining: result.remaining,
            reason: result.reason
          });

          return c.json({
            error: 'Rate limit exceeded',
            message: result.reason || 'Too many requests',
            retryAfter: result.retryAfter
          }, 429);
        }

        await next();
      };
    };
  }
}

/**
 * CloudflareKV-based rate limit store
 */
export class CloudflareKVRateLimitStore implements RateLimitStore {
  constructor(private kv: KVNamespace) {}

  async get(key: string): Promise<RateLimitData | null> {
    const data = await this.kv.get(key);
    return data ? JSON.parse(data) : null;
  }

  async set(key: string, data: RateLimitData, ttl: number): Promise<void> {
    await this.kv.put(key, JSON.stringify(data), {
      expirationTtl: Math.ceil(ttl / 1000)
    });
  }

  async increment(key: string, amount: number = 1): Promise<number> {
    const current = await this.get(key);
    const newCount = (current?.count || 0) + amount;

    await this.set(key, {
      count: newCount,
      resetTime: Date.now() + 60000 // Default 1 minute TTL
    }, 60000);

    return newCount;
  }

  async delete(key: string): Promise<void> {
    await this.kv.delete(key);
  }
}

/**
 * Memory-based rate limit store (for development/testing)
 */
export class MemoryRateLimitStore implements RateLimitStore {
  private data = new Map<string, { data: RateLimitData; expires: number }>();

  async get(key: string): Promise<RateLimitData | null> {
    const entry = this.data.get(key);
    if (!entry || entry.expires < Date.now()) {
      this.data.delete(key);
      return null;
    }
    return entry.data;
  }

  async set(key: string, data: RateLimitData, ttl: number): Promise<void> {
    this.data.set(key, {
      data,
      expires: Date.now() + ttl
    });
  }

  async increment(key: string, amount: number = 1): Promise<number> {
    const current = await this.get(key);
    const newCount = (current?.count || 0) + amount;

    await this.set(key, {
      count: newCount,
      resetTime: Date.now() + 60000
    }, 60000);

    return newCount;
  }

  async delete(key: string): Promise<void> {
    this.data.delete(key);
  }

  // Cleanup expired entries
  cleanup(): void {
    const now = Date.now();
    for (const [key, entry] of this.data.entries()) {
      if (entry.expires < now) {
        this.data.delete(key);
      }
    }
  }
}

/**
 * Pre-configured rate limiting configurations
 */
export const RateLimitConfigs = {
  // API endpoints
  api: {
    windowMs: 60 * 1000, // 1 minute
    maxRequests: 100,
    algorithm: 'sliding_window' as const
  },

  // Authentication endpoints
  auth: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxRequests: 5,
    algorithm: 'fixed_window' as const
  },

  // AI API calls
  aiAPI: {
    windowMs: 60 * 1000, // 1 minute
    maxRequests: 10,
    algorithm: 'token_bucket' as const,
    customRules: [
      {
        condition: (id, ctx) => ctx?.businessId === 'premium_tier',
        config: { maxRequests: 50 }
      }
    ]
  },

  // Password reset
  passwordReset: {
    windowMs: 60 * 60 * 1000, // 1 hour
    maxRequests: 3,
    algorithm: 'fixed_window' as const
  },

  // Registration
  registration: {
    windowMs: 60 * 60 * 1000, // 1 hour
    maxRequests: 5,
    algorithm: 'sliding_window' as const
  },

  // File uploads
  upload: {
    windowMs: 60 * 1000, // 1 minute
    maxRequests: 20,
    algorithm: 'leaky_bucket' as const
  }
} as const;