import { Context, Next } from 'hono';
import { RateLimitError } from '../shared/error-handler';
import {
  AdvancedRateLimiter,
  CloudflareKVRateLimitStore,
  MemoryRateLimitStore,
  RateLimitConfigs,
  RateLimitConfig
} from '../security/advanced-rate-limiter';
import { Logger } from '../shared/logger';

const logger = new Logger({ component: 'rate-limit-middleware' });

interface RateLimitOptions {
  key: (c: Context) => string;
  limit: number;
  window: number; // in seconds
  message?: string;
}

interface RateLimitEntry {
  count: number;
  resetAt: number;
}

/**
 * Rate limiting middleware using Cloudflare's native rate limiter or KV
 */
export function rateLimiter(options: RateLimitOptions) {
  return async (c: Context, next: Next) => {
    const key = options.key(c);
    const now = Date.now();

    // Try to use Cloudflare's rate limiter if available
    if (c.env?.RATE_LIMITER) {
      try {
        const { success } = await c.env.RATE_LIMITER.limit({ key });

        if (!success) {
          throw new RateLimitError(options.window);
        }
      } catch (error) {
        if (error instanceof RateLimitError) {
          throw error;
        }
        // Fallback to KV-based rate limiting
        await kvRateLimit(c, key, options, now);
      }
    } else {
      // Use KV-based rate limiting
      await kvRateLimit(c, key, options, now);
    }

    await next();
  };
}

/**
 * KV-based rate limiting fallback
 */
async function kvRateLimit(
  c: Context,
  key: string,
  options: RateLimitOptions,
  now: number
): Promise<void> {
  const kv = c.env?.KV_CACHE;
  if (!kv) {
    // No rate limiting available, proceed
    return;
  }

  const rateLimitKey = `ratelimit:${key}`;
  const entry = await kv.get(rateLimitKey, 'json') as RateLimitEntry | null;

  if (!entry || entry.resetAt < now) {
    // New window
    await kv.put(
      rateLimitKey,
      JSON.stringify({
        count: 1,
        resetAt: now + options.window * 1000,
      }),
      { expirationTtl: options.window }
    );
    return;
  }

  if (entry.count >= options.limit) {
    const retryAfter = Math.ceil((entry.resetAt - now) / 1000);
    c.header('Retry-After', retryAfter.toString());
    c.header('X-RateLimit-Limit', options.limit.toString());
    c.header('X-RateLimit-Remaining', '0');
    c.header('X-RateLimit-Reset', entry.resetAt.toString());

    throw new RateLimitError(retryAfter);
  }

  // Increment counter
  entry.count++;
  await kv.put(
    rateLimitKey,
    JSON.stringify(entry),
    { expirationTtl: Math.ceil((entry.resetAt - now) / 1000) }
  );

  // Set rate limit headers
  c.header('X-RateLimit-Limit', options.limit.toString());
  c.header('X-RateLimit-Remaining', (options.limit - entry.count).toString());
  c.header('X-RateLimit-Reset', entry.resetAt.toString());
}

// Initialize advanced rate limiter
let advancedRateLimiter: AdvancedRateLimiter;

/**
 * Initialize the advanced rate limiting system
 */
export function initializeRateLimiting(env: any): void {
  const store = env.KV_CACHE
    ? new CloudflareKVRateLimitStore(env.KV_CACHE)
    : new MemoryRateLimitStore();

  advancedRateLimiter = new AdvancedRateLimiter(store);

  logger.info('Advanced rate limiting initialized', {
    storeType: env.KV_CACHE ? 'CloudflareKV' : 'Memory'
  });
}

/**
 * Get or initialize rate limiter
 */
function getRateLimiter(env: any): AdvancedRateLimiter {
  if (!advancedRateLimiter) {
    initializeRateLimiting(env);
  }
  return advancedRateLimiter;
}

/**
 * High-performance advanced rate limiting middleware with O(1) operations
 */
export function createAdvancedRateLimiter(
  limitType: string,
  config?: Partial<RateLimitConfig>,
  keyExtractor?: (c: Context) => string
) {
  // Cache configuration to avoid repeated object creation
  const cachedConfigs = new Map<string, RateLimitConfig>();
  
  return async (c: Context, next: Next): Promise<Response | void> => {
    const identifier = keyExtractor
      ? keyExtractor(c)
      : c.req.header('CF-Connecting-IP') || 'unknown';
      
    // Use cached configuration or create new one
    const configKey = `${limitType}:${JSON.stringify(config || {})}`;
    let baseConfig = cachedConfigs.get(configKey);
    
    if (!baseConfig) {
      baseConfig = {
        ...RateLimitConfigs[limitType as keyof typeof RateLimitConfigs],
        ...config
      } as RateLimitConfig;
      cachedConfigs.set(configKey, baseConfig);
      
      // Limit cache size
      if (cachedConfigs.size > 100) {
        const oldestKey = cachedConfigs.keys().next().value || '';
        cachedConfigs.delete(oldestKey);
      }
    }

    const rateLimiter = getRateLimiter(c.env as any);
    
    // Optimized context extraction
    const context = {
      path: c.req.path,
      method: c.req.method,
      userAgent: c.req.header('User-Agent'),
      businessId: c.get('businessId'),
      userId: c.get('userId')
    };

    // Single rate limit check with timeout
    const checkPromise = rateLimiter.checkLimit(identifier, baseConfig, context);
    const timeoutPromise = new Promise<never>((_, reject) => {
      setTimeout(() => reject(new Error('Rate limit check timeout')), 100);
    });
    
    let result;
    try {
      result = await Promise.race([checkPromise, timeoutPromise]);
    } catch (error) {
      // Fail open on timeout to maintain availability
      console.warn('Rate limit check timed out, allowing request:', error);
      await next();
      return;
    }

    // Batch header setting for better performance
    const headers: Record<string, string> = {
      'X-RateLimit-Limit': baseConfig.maxRequests.toString(),
      'X-RateLimit-Remaining': result.remaining.toString(),
      'X-RateLimit-Reset': Math.ceil(result.resetTime / 1000).toString(),
      'X-RateLimit-Algorithm': baseConfig.algorithm
    };
    
    if (!result.allowed && result.retryAfter) {
      headers['Retry-After'] = Math.ceil(result.retryAfter / 1000).toString();
    }
    
    // Set all headers at once
    Object.entries(headers).forEach(([key, value]) => c.header(key, value));

    if (!result.allowed) {
      logger.warn('Rate limit exceeded', {
        identifier,
        limitType,
        path: context.path,
        algorithm: baseConfig.algorithm,
        remaining: result.remaining,
        reason: result.reason
      });

      return c.json({
        error: 'Rate limit exceeded',
        message: result.reason || 'Too many requests',
        retryAfter: result.retryAfter,
        limit: baseConfig.maxRequests,
        remaining: result.remaining
      }, 429);
    }

    await next();
  };
}

/**
 * Pre-configured advanced rate limiters
 */
export const rateLimiters = {
  // Authentication endpoints with strict limits
  login: createAdvancedRateLimiter('auth', {
    maxRequests: 5,
    windowMs: 15 * 60 * 1000, // 15 minutes
    algorithm: 'sliding_window'
  }, (c) => `login:${c.req.header('CF-Connecting-IP') || 'unknown'}`),

  register: createAdvancedRateLimiter('registration', {
    customRules: [
      {
        condition: (id, ctx) => ctx?.userAgent?.includes('bot'),
        config: { maxRequests: 1, windowMs: 60 * 60 * 1000 }
      }
    ]
  }, (c) => `register:${c.req.header('CF-Connecting-IP') || 'unknown'}`),

  passwordReset: createAdvancedRateLimiter('passwordReset', {},
    (c) => `reset:${c.req.header('CF-Connecting-IP') || 'unknown'}`),

  // API endpoints with tier-based limits
  api: createAdvancedRateLimiter('api', {
    customRules: [
      {
        condition: (id, ctx) => ctx?.businessId && ctx.businessId.includes('premium'),
        config: { maxRequests: 500 }
      },
      {
        condition: (id, ctx) => ctx?.businessId && ctx.businessId.includes('enterprise'),
        config: { maxRequests: 2000 }
      }
    ]
  }, (c) => {
    const userId = c.get('userId');
    return userId ? `api:user:${userId}` : `api:ip:${c.req.header('CF-Connecting-IP') || 'unknown'}`;
  }),

  // AI API calls with token bucket
  aiAPI: createAdvancedRateLimiter('aiAPI', {
    algorithm: 'token_bucket',
    customRules: [
      {
        condition: (id, ctx) => ctx?.businessId?.includes('trial'),
        config: { maxRequests: 5, windowMs: 60 * 1000 }
      }
    ]
  }, (c) => `ai:${c.get('businessId') || c.req.header('CF-Connecting-IP') || 'unknown'}`),

  // File uploads with leaky bucket
  upload: createAdvancedRateLimiter('upload', {
    algorithm: 'leaky_bucket'
  }, (c) => `upload:${c.get('userId') || c.req.header('CF-Connecting-IP') || 'unknown'}`),

  // Export operations
  export: createAdvancedRateLimiter('api', {
    maxRequests: 10,
    windowMs: 60 * 60 * 1000, // 1 hour
    algorithm: 'fixed_window'
  }, (c) => `export:${c.get('userId') || c.req.header('CF-Connecting-IP') || 'unknown'}`),

  // WebSocket connections
  websocket: createAdvancedRateLimiter('api', {
    maxRequests: 10,
    windowMs: 60 * 1000, // 1 minute
    algorithm: 'sliding_window'
  }, (c) => `ws:${c.req.header('CF-Connecting-IP') || 'unknown'}`)
};

/**
 * Dynamic rate limiter based on user tier with advanced algorithms
 */
export function tierBasedRateLimiter() {
  return async (c: Context, next: Next) => {
    const businessId = c.get('businessId');
    if (!businessId) {
      return rateLimiters.api(c, next);
    }

    // Get business tier
    const business = await c.env.DB_MAIN
      .prepare('SELECT subscription_tier FROM businesses WHERE id = ?')
      .bind(businessId)
      .first();

    const tier = business?.subscription_tier || 'trial';

    // Define limits and algorithms based on tier
    const tierConfigs: Record<string, RateLimitConfig> = {
      trial: {
        maxRequests: 50,
        windowMs: 60 * 1000,
        algorithm: 'fixed_window'
      },
      starter: {
        maxRequests: 100,
        windowMs: 60 * 1000,
        algorithm: 'sliding_window'
      },
      professional: {
        maxRequests: 500,
        windowMs: 60 * 1000,
        algorithm: 'token_bucket'
      },
      enterprise: {
        maxRequests: 2000,
        windowMs: 60 * 1000,
        algorithm: 'token_bucket'
      }
    };

    const config = tierConfigs[tier] || tierConfigs.trial;

    // Apply tier-based rate limiting
    return createAdvancedRateLimiter('api', config,
      (c) => `api:business:${businessId}`)(c, next);
  };
}

/**
 * Enhanced Distributed rate limiter using Durable Objects with advanced algorithms
 */
export class AdvancedRateLimiterDO {
  private state: DurableObjectState;
  private rateLimiter: AdvancedRateLimiter;

  constructor(state: DurableObjectState) {
    this.state = state;
    this.rateLimiter = new AdvancedRateLimiter(new MemoryRateLimitStore());
  }

  async fetch(request: Request): Promise<Response> {
    try {
      const url = new URL(request.url);
      const key = url.searchParams.get('key');
      const algorithm = url.searchParams.get('algorithm') || 'sliding_window';
      const limit = parseInt(url.searchParams.get('limit') || '100');
      const window = parseInt(url.searchParams.get('window') || '60000');

      if (!key) {
        return new Response(JSON.stringify({
          error: 'Key required'
        }), { status: 400 });
      }

      const config: RateLimitConfig = {
        maxRequests: limit,
        windowMs: window,
        algorithm: algorithm as any
      };

      const result = await this.rateLimiter.checkLimit(key, config);

      const status = result.allowed ? 200 : 429;
      const response = {
        allowed: result.allowed,
        limit,
        remaining: result.remaining,
        resetTime: result.resetTime,
        algorithm,
        ...(result.retryAfter && { retryAfter: result.retryAfter }),
        ...(result.reason && { reason: result.reason })
      };

      return new Response(JSON.stringify(response), {
        status,
        headers: {
          'Content-Type': 'application/json',
          'X-RateLimit-Limit': limit.toString(),
          'X-RateLimit-Remaining': result.remaining.toString(),
          'X-RateLimit-Reset': Math.ceil(result.resetTime / 1000).toString(),
          'X-RateLimit-Algorithm': algorithm,
          ...(result.retryAfter && {
            'Retry-After': Math.ceil(result.retryAfter / 1000).toString()
          })
        },
      });

    } catch (error) {
      logger.error('Durable Object rate limiter error', error);
      return new Response(JSON.stringify({
        error: 'Internal rate limiter error',
        allowed: false
      }), { status: 500 });
    }
  }
}

// Keep the original for backward compatibility
export const RateLimiterDO = AdvancedRateLimiterDO;