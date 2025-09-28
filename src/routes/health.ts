/**
 * Health Check Endpoints for CoreFlow360
 * Production deployment readiness checks
 */

import { Hono } from 'hono';
import type { Env } from '../types/env';

export const healthRoutes = new Hono<{ Bindings: Env }>();

/**
 * Basic health check - always returns 200 if service is running
 */
healthRoutes.get('/health', async (c) => {
  return c.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    service: 'CoreFlow360 V4',
    version: c.env.API_VERSION || 'v4',
    environment: c.env.ENVIRONMENT || 'development'
  });
});

/**
 * Liveness probe - checks if service is alive
 */
healthRoutes.get('/health/live', async (c) => {
  return c.json({
    status: 'alive',
    timestamp: new Date().toISOString()
  });
});

/**
 * Readiness probe - checks if service is ready to accept traffic
 */
healthRoutes.get('/health/ready', async (c) => {
  const checks = {
    database: false,
    cache: false,
    ai: false,
    storage: false
  };

  const errors: string[] = [];

  // Check D1 Database
  try {
    if (c.env.DB) {
      const result = await c.env.DB.prepare('SELECT 1 as test').first();
      checks.database = result?.test === 1;
    }
  } catch (error) {
    errors.push(`Database check failed: ${error}`);
  }

  // Check KV Cache
  try {
    if (c.env.KV_CACHE) {
      const testKey = '_health_check_' + Date.now();
      await c.env.KV_CACHE.put(testKey, 'test', { expirationTtl: 60 });
      const value = await c.env.KV_CACHE.get(testKey);
      checks.cache = value === 'test';
      await c.env.KV_CACHE.delete(testKey);
    }
  } catch (error) {
    errors.push(`Cache check failed: ${error}`);
  }

  // Check AI binding
  try {
    if (c.env.AI) {
      // Just check if AI binding exists
      checks.ai = true;
    }
  } catch (error) {
    errors.push(`AI check failed: ${error}`);
  }

  // Check R2 Storage
  try {
    if (c.env.R2_DOCUMENTS) {
      // List with limit 1 to test connection
      await c.env.R2_DOCUMENTS.list({ limit: 1 });
      checks.storage = true;
    }
  } catch (error) {
    errors.push(`Storage check failed: ${error}`);
  }

  const allHealthy = Object.values(checks).every(check => check);
  const status = allHealthy ? 200 : 503;

  return c.json({
    status: allHealthy ? 'ready' : 'not_ready',
    timestamp: new Date().toISOString(),
    checks,
    errors: errors.length > 0 ? errors : undefined
  }, status);
});

/**
 * Detailed system status - includes metrics
 */
healthRoutes.get('/health/status', async (c) => {
  const startTime = Date.now();

  // Collect system metrics
  const metrics = {
    uptime: process.uptime ? process.uptime() : 0,
    memory: process.memoryUsage ? process.memoryUsage() : {},
    timestamp: new Date().toISOString(),
    responseTime: 0
  };

  // Database stats
  let dbStats = null;
  try {
    if (c.env.DB) {
      const tables = await c.env.DB.prepare(`
        SELECT name FROM sqlite_master
        WHERE type='table'
        ORDER BY name
      `).all();
      dbStats = {
        connected: true,
        tables: tables.results.length
      };
    }
  } catch (error) {
    dbStats = {
      connected: false,
      error: error instanceof Error ? error.message : 'Unknown error'
    };
  }

  // Cache stats
  let cacheStats = null;
  try {
    if (c.env.KV_CACHE) {
      // KV doesn't provide stats, but we can test it works
      cacheStats = {
        connected: true,
        type: 'Cloudflare KV'
      };
    }
  } catch (error) {
    cacheStats = {
      connected: false,
      error: error instanceof Error ? error.message : 'Unknown error'
    };
  }

  metrics.responseTime = Date.now() - startTime;

  return c.json({
    service: 'CoreFlow360 V4',
    version: c.env.API_VERSION || 'v4',
    environment: c.env.ENVIRONMENT || 'development',
    status: 'operational',
    metrics,
    components: {
      database: dbStats,
      cache: cacheStats,
      ai: { available: !!c.env.AI },
      storage: { available: !!c.env.R2_DOCUMENTS }
    }
  });
});

/**
 * Deployment validation endpoint
 */
healthRoutes.get('/health/validate', async (c) => {
  const validation = {
    environment: {
      hasRequiredBindings: false,
      hasSecrets: false,
      hasDatabase: false,
      hasCache: false,
      hasStorage: false
    },
    configuration: {
      apiVersion: c.env.API_VERSION || 'missing',
      environment: c.env.ENVIRONMENT || 'missing',
      logLevel: c.env.LOG_LEVEL || 'missing'
    },
    services: [] as Array<{ name: string; status: string; details?: any }>
  };

  // Check required bindings
  validation.environment.hasDatabase = !!c.env.DB;
  validation.environment.hasCache = !!c.env.KV_CACHE;
  validation.environment.hasStorage = !!c.env.R2_DOCUMENTS;
  validation.environment.hasRequiredBindings =
    validation.environment.hasDatabase &&
    validation.environment.hasCache;

  // Check secrets (can't read them but check if they're set)
  validation.environment.hasSecrets = !!(
    c.env.AUTH_SECRET &&
    c.env.JWT_SECRET
  );

  // Test each service
  const services = [
    { name: 'D1 Database', binding: c.env.DB },
    { name: 'KV Cache', binding: c.env.KV_CACHE },
    { name: 'AI', binding: c.env.AI },
    { name: 'R2 Storage', binding: c.env.R2_DOCUMENTS }
  ];

  for (const service of services) {
    if (service.binding) {
      validation.services.push({
        name: service.name,
        status: 'configured'
      });
    } else {
      validation.services.push({
        name: service.name,
        status: 'missing'
      });
    }
  }

  const isReady =
    validation.environment.hasRequiredBindings &&
    validation.environment.hasSecrets;

  return c.json({
    ready: isReady,
    validation,
    recommendation: isReady
      ? 'System is ready for production deployment'
      : 'Missing required configuration for production'
  }, isReady ? 200 : 503);
});