/**
 * Smart Caching Middleware for Hono
 * Integrates SmartCaching for high-traffic routes
 */

import { Logger } from '@/shared/logger';
import { MiddlewareHandler } from 'hono';
import { SmartCaching } from '../cloudflare/performance/SmartCaching';
import type { Env } from '../types/env';

const logger = new Logger('Caching');

interface CacheOptions {
  /**
   * Cache TTL in seconds
   */
  ttl?: number;
  /**
   * Cache key prefix
   */
  prefix?: string;
  /**
   * Whether to cache the response
   */
  enabled?: boolean;
  /**
   * Routes to cache (regex patterns)
   */
  routes?: RegExp[];
}

/**
 * Creates a caching middleware that uses SmartCaching
 */
export function cachingMiddleware(options: CacheOptions = {}): MiddlewareHandler<{ Bindings: Env }> {
  const {
    ttl = 300, // 5 minutes default
    prefix = 'api:cache',
    enabled = true,
    routes = [
      /^\/api\/v1\/dashboard\/stats$/,
      /^\/api\/v1\/crm\/leads$/,
      /^\/api\/v1\/finance\/summary$/,
      /^\/api\/v1\/observability\/health$/,
    ]
  } = options;

  return async (c, next) => {
    if (!enabled) {
      return next();
    }

    const method = c.req.method;
    const path = new URL(c.req.url).pathname;

    // Only cache GET requests
    if (method !== 'GET') {
      return next();
    }

    // Check if route should be cached
    const shouldCache = routes.some(pattern => pattern.test(path));
    if (!shouldCache) {
      return next();
    }

    // Generate cache key
    const businessId = c.req.header('X-Business-ID') || 'default';
    const cacheKey = `${prefix}:${businessId}:${path}`;

    try {
      const smartCache = new SmartCaching(c.env);

      // Try to get from cache
      const cachedResult = await smartCache.get<any>(cacheKey, {
        ttl,
        source: 'kv',
      });

      if (cachedResult.hit && cachedResult.data) {
        logger.info(`[Cache] HIT: ${cacheKey}`);

        // Return cached response
        return c.json(cachedResult.data, 200, {
          'X-Cache-Status': 'HIT',
          'X-Cache-Source': cachedResult.source,
          'Cache-Control': `public, max-age=${ttl}, stale-while-revalidate=60`,
        });
      }

      logger.info(`[Cache] MISS: ${cacheKey}`);

      // Execute handler
      await next();

      // Cache successful responses
      if (c.res.status === 200) {
        try {
          const responseBody = await c.res.clone().json();

          await smartCache.set(cacheKey, responseBody, {
            ttl,
            source: 'kv',
          });

          // Add cache headers to response
          c.res.headers.set('X-Cache-Status', 'MISS');
          c.res.headers.set('Cache-Control', `public, max-age=${ttl}, stale-while-revalidate=60`);
        } catch (err) {
          logger.warn('[Cache] Failed to cache response:', err);
        }
      }

    } catch (error) {
      logger.error('[Cache] Caching middleware error:', error);
      // Continue without caching on error
      return next();
    }
  };
}

/**
 * Cache invalidation helper
 */
export async function invalidateCache(
  env: Env,
  pattern: string
): Promise<void> {
  try {
    const smartCache = new SmartCaching(env);

    // List all keys matching pattern
    const listResult = await env.KV_CACHE.list({ prefix: pattern });

    // Delete all matching keys
    const deletePromises = listResult.keys.map(key =>
      env.KV_CACHE.delete(key.name)
    );

    await Promise.all(deletePromises);

    logger.info(`[Cache] Invalidated ${listResult.keys.length} cache entries matching: ${pattern}`);
  } catch (error) {
    logger.error('[Cache] Failed to invalidate cache:', error);
    throw error;
  }
}
