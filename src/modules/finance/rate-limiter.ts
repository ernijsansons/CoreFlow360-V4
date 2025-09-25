/**
 * Rate Limiter for Financial Module
 * Redis-based rate limiting to prevent DoS attacks and resource exhaustion
 */

import { Logger } from '../../shared/logger';

export interface RateLimitConfig {
  requests: number;
  windowMs: number;
  keyGenerator?: (businessId: string, userId: string, endpoint: string) => string;
  skipSuccessfulRequests?: boolean;
  skipFailedRequests?: boolean;
  message?: string;
}

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  resetTime: number;
  retryAfter?: number;
}

export class RateLimiter {
  private logger: Logger;
  private config: RateLimitConfig;

  constructor(config: RateLimitConfig) {
    this.logger = new Logger();
    this.config = {
      skipSuccessfulRequests: false,
      skipFailedRequests: false,
      message: 'Too many requests',
      keyGenerator: this.defaultKeyGenerator,
      ...config
    };
  }

  /**
   * Check if request is within rate limit
   */
  async checkLimit(
    businessId: string,
    userId: string,
    endpoint: string,
    kv?: KVNamespace
  ): Promise<RateLimitResult> {
    if (!kv) {
      this.logger.warn('KV namespace not available, rate limiting disabled');
      return {
        allowed: true,
        remaining: this.config.requests,
        resetTime: Date.now() + this.config.windowMs
      };
    }

    const key = this.config.keyGenerator!(businessId, userId, endpoint);
    const now = Date.now();
    const windowStart = now - this.config.windowMs;

    try {
      // Get current request count
      const currentData = await kv.get(key);
      let requestData: { count: number; firstRequest: number } = {
        count: 0,
        firstRequest: now
      };

      if (currentData) {
        try {
          requestData = JSON.parse(currentData);
        } catch (error) {
          this.logger.warn('Invalid rate limit data, resetting', { key });
        }
      }

      // Reset window if expired
      if (requestData.firstRequest < windowStart) {
        requestData = {
          count: 0,
          firstRequest: now
        };
      }

      // Check if limit exceeded
      if (requestData.count >= this.config.requests) {
        const resetTime = requestData.firstRequest + this.config.windowMs;
        const retryAfter = Math.ceil((resetTime - now) / 1000);

        this.logger.warn('Rate limit exceeded', {
          businessId,
          userId,
          endpoint,
          count: requestData.count,
          limit: this.config.requests,
          retryAfter
        });

        return {
          allowed: false,
          remaining: 0,
          resetTime,
          retryAfter
        };
      }

      // Increment counter
      requestData.count++;

      // Save updated data with TTL
      const ttlSeconds = Math.ceil(this.config.windowMs / 1000);
      await kv.put(key, JSON.stringify(requestData), {
        expirationTtl: ttlSeconds
      });

      const remaining = this.config.requests - requestData.count;
      const resetTime = requestData.firstRequest + this.config.windowMs;

      this.logger.debug('Rate limit check passed', {
        businessId,
        userId,
        endpoint,
        count: requestData.count,
        limit: this.config.requests,
        remaining
      });

      return {
        allowed: true,
        remaining,
        resetTime
      };

    } catch (error) {
      this.logger.error('Rate limit check failed', error, {
        businessId,
        userId,
        endpoint
      });

      // Fail open - allow request if rate limiting fails
      return {
        allowed: true,
        remaining: this.config.requests,
        resetTime: now + this.config.windowMs
      };
    }
  }

  /**
   * Record successful request (for skipSuccessfulRequests option)
   */
  async recordSuccess(
    businessId: string,
    userId: string,
    endpoint: string,
    kv?: KVNamespace
  ): Promise<void> {
    if (!this.config.skipSuccessfulRequests || !kv) {
      return;
    }

    // Implementation would decrement counter for successful requests
    // if skipSuccessfulRequests is enabled
  }

  /**
   * Record failed request (for skipFailedRequests option)
   */
  async recordFailure(
    businessId: string,
    userId: string,
    endpoint: string,
    kv?: KVNamespace
  ): Promise<void> {
    if (!this.config.skipFailedRequests || !kv) {
      return;
    }

    // Implementation would decrement counter for failed requests
    // if skipFailedRequests is enabled
  }

  /**
   * Clear rate limit for a specific key
   */
  async clearLimit(
    businessId: string,
    userId: string,
    endpoint: string,
    kv?: KVNamespace
  ): Promise<void> {
    if (!kv) {
      return;
    }

    const key = this.config.keyGenerator!(businessId, userId, endpoint);
    await kv.delete(key);

    this.logger.info('Rate limit cleared', {
      businessId,
      userId,
      endpoint,
      key
    });
  }

  /**
   * Default key generator
   */
  private defaultKeyGenerator(businessId: string, userId: string, endpoint: string): string {
    return `ratelimit:${businessId}:${userId}:${endpoint}`;
  }
}

/**
 * Predefined rate limit configurations for different endpoint types
 */
export const RATE_LIMIT_CONFIGS = {
  // General API endpoints
  general: {
    requests: 100,
    windowMs: 60 * 1000, // 1 minute
    message: 'Too many requests, please try again later'
  },

  // Report generation (CPU intensive)
  reportGeneration: {
    requests: 10,
    windowMs: 60 * 1000, // 1 minute
    message: 'Too many report generation requests, please wait before generating another report'
  },

  // Export operations (bandwidth intensive)
  exports: {
    requests: 5,
    windowMs: 60 * 1000, // 1 minute
    message: 'Too many export requests, please wait before requesting another export'
  },

  // Data modification operations
  dataModification: {
    requests: 50,
    windowMs: 60 * 1000, // 1 minute
    skipFailedRequests: true,
    message: 'Too many data modification requests'
  },

  // Authentication attempts
  authentication: {
    requests: 5,
    windowMs: 15 * 60 * 1000, // 15 minutes
    message: 'Too many authentication attempts, please try again later'
  },

  // Bulk operations
  bulkOperations: {
    requests: 3,
    windowMs: 5 * 60 * 1000, // 5 minutes
    message: 'Too many bulk operation requests'
  }
};

/**
 * Rate limiting middleware factory
 */
export function createRateLimitMiddleware(
  config: RateLimitConfig,
  endpointType: string
) {
  const rateLimiter = new RateLimiter(config);

  return async (
    businessId: string,
    userId: string,
    kv?: KVNamespace
  ): Promise<RateLimitResult> => {
    return rateLimiter.checkLimit(businessId, userId, endpointType, kv);
  };
}

/**
 * Rate limit error class
 */
export class RateLimitError extends Error {
  public readonly retryAfter: number;
  public readonly resetTime: number;

  constructor(message: string, retryAfter: number, resetTime: number) {
    super(message);
    this.name = 'RateLimitError';
    this.retryAfter = retryAfter;
    this.resetTime = resetTime;
  }
}

/**
 * Rate limit decorator for methods
 */
export function RateLimit(
  config: RateLimitConfig,
  endpointType: string
) {
  return function (
    target: any,
    propertyName: string,
    descriptor: PropertyDescriptor
  ) {
    const method = descriptor.value;
    const rateLimiter = new RateLimiter(config);

    descriptor.value = async function (...args: any[]) {
      // Extract businessId, userId from arguments
      // This assumes they are typically the last parameters
      const businessId = args[args.length - 1];
      const userId = args[args.length - 2];

      // Check if KV is available in the context
      const kv = (this as any).kv || undefined;

      const result = await rateLimiter.checkLimit(
        businessId,
        userId,
        endpointType,
        kv
      );

      if (!result.allowed) {
        throw new RateLimitError(
          config.message || 'Rate limit exceeded',
          result.retryAfter || 60,
          result.resetTime
        );
      }

      // Call original method
      return method.apply(this, args);
    };

    return descriptor;
  };
}

/**
 * Per-business rate limiter
 */
export class BusinessRateLimiter {
  private rateLimiter: RateLimiter;

  constructor(config: RateLimitConfig) {
    this.rateLimiter = new RateLimiter({
      ...config,
      keyGenerator: (businessId: string) => `business:${businessId}`
    });
  }

  async checkBusinessLimit(
    businessId: string,
    kv?: KVNamespace
  ): Promise<RateLimitResult> {
    return this.rateLimiter.checkLimit(businessId, '', 'business-api', kv);
  }
}

/**
 * Global rate limiter (across all businesses)
 */
export class GlobalRateLimiter {
  private rateLimiter: RateLimiter;

  constructor(config: RateLimitConfig) {
    this.rateLimiter = new RateLimiter({
      ...config,
      keyGenerator: () => 'global'
    });
  }

  async checkGlobalLimit(kv?: KVNamespace): Promise<RateLimitResult> {
    return this.rateLimiter.checkLimit('global', '', 'global-api', kv);
  }
}