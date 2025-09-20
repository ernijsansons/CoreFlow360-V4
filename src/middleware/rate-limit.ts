import { Context, Next } from 'hono';
import { RateLimitError } from '../shared/error-handler';

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
  const entry = await kv.get<RateLimitEntry>(rateLimitKey, 'json');

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

/**
 * Pre-configured rate limiters for different endpoints
 */
export const rateLimiters = {
  // Strict rate limiting for auth endpoints
  login: rateLimiter({
    key: (c) => `login:${c.req.header('CF-Connecting-IP') || 'unknown'}`,
    limit: 5,
    window: 900, // 15 minutes
    message: 'Too many login attempts. Please try again later.',
  }),

  register: rateLimiter({
    key: (c) => `register:${c.req.header('CF-Connecting-IP') || 'unknown'}`,
    limit: 3,
    window: 3600, // 1 hour
    message: 'Too many registration attempts. Please try again later.',
  }),

  passwordReset: rateLimiter({
    key: (c) => `reset:${c.req.header('CF-Connecting-IP') || 'unknown'}`,
    limit: 3,
    window: 3600, // 1 hour
    message: 'Too many password reset attempts. Please try again later.',
  }),

  // API rate limiting per user
  api: rateLimiter({
    key: (c) => {
      const userId = c.get('userId');
      if (userId) {
        return `api:user:${userId}`;
      }
      return `api:ip:${c.req.header('CF-Connecting-IP') || 'unknown'}`;
    },
    limit: 100,
    window: 60, // 1 minute
    message: 'API rate limit exceeded. Please slow down your requests.',
  }),

  // Strict rate limiting for expensive operations
  export: rateLimiter({
    key: (c) => `export:${c.get('userId') || c.req.header('CF-Connecting-IP') || 'unknown'}`,
    limit: 10,
    window: 3600, // 1 hour
    message: 'Export rate limit exceeded. Please try again later.',
  }),

  // WebSocket connection rate limiting
  websocket: rateLimiter({
    key: (c) => `ws:${c.req.header('CF-Connecting-IP') || 'unknown'}`,
    limit: 10,
    window: 60, // 1 minute
    message: 'Too many WebSocket connection attempts.',
  }),
};

/**
 * Dynamic rate limiter based on user tier
 */
export function tierBasedRateLimiter() {
  return async (c: Context, next: Next) => {
    const businessId = c.get('businessId');
    if (!businessId) {
      // Use default rate limiting
      return rateLimiters.api(c, next);
    }

    // Get business tier
    const business = await c.env.DB_MAIN
      .prepare('SELECT subscription_tier FROM businesses WHERE id = ?')
      .bind(businessId)
      .first<any>();

    const tier = business?.subscription_tier || 'trial';

    // Define limits based on tier
    const limits: Record<string, { limit: number; window: number }> = {
      trial: { limit: 50, window: 60 },
      starter: { limit: 100, window: 60 },
      professional: { limit: 500, window: 60 },
      enterprise: { limit: 2000, window: 60 },
    };

    const tierLimit = limits[tier] || limits.trial;

    // Apply tier-based rate limiting
    return rateLimiter({
      key: (c) => `api:business:${businessId}`,
      limit: tierLimit.limit,
      window: tierLimit.window,
    })(c, next);
  };
}

/**
 * Distributed rate limiter using Durable Objects
 */
export class RateLimiterDO {
  private state: DurableObjectState;
  private entries: Map<string, RateLimitEntry> = new Map();

  constructor(state: DurableObjectState) {
    this.state = state;
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const key = url.searchParams.get('key');
    const limit = parseInt(url.searchParams.get('limit') || '100');
    const window = parseInt(url.searchParams.get('window') || '60');

    if (!key) {
      return new Response('Key required', { status: 400 });
    }

    const now = Date.now();
    const entry = this.entries.get(key);

    if (!entry || entry.resetAt < now) {
      // New window
      this.entries.set(key, {
        count: 1,
        resetAt: now + window * 1000,
      });

      // Clean up old entries
      this.cleanup(now);

      return new Response(JSON.stringify({
        allowed: true,
        limit,
        remaining: limit - 1,
        resetAt: now + window * 1000,
      }), {
        headers: { 'Content-Type': 'application/json' },
      });
    }

    if (entry.count >= limit) {
      return new Response(JSON.stringify({
        allowed: false,
        limit,
        remaining: 0,
        resetAt: entry.resetAt,
        retryAfter: Math.ceil((entry.resetAt - now) / 1000),
      }), {
        headers: { 'Content-Type': 'application/json' },
        status: 429,
      });
    }

    entry.count++;

    return new Response(JSON.stringify({
      allowed: true,
      limit,
      remaining: limit - entry.count,
      resetAt: entry.resetAt,
    }), {
      headers: { 'Content-Type': 'application/json' },
    });
  }

  private cleanup(now: number): void {
    // Remove expired entries
    for (const [key, entry] of this.entries) {
      if (entry.resetAt < now) {
        this.entries.delete(key);
      }
    }

    // Limit total entries to prevent memory issues
    if (this.entries.size > 10000) {
      const sorted = Array.from(this.entries.entries())
        .sort((a, b) => a[1].resetAt - b[1].resetAt);

      // Keep only the most recent 5000 entries
      this.entries = new Map(sorted.slice(-5000));
    }
  }
}