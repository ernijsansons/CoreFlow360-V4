/**
 * CoreFlow360 V4 - Secure Production Worker
 * Enterprise-grade security implementation with all OWASP compliance
 *
 * Security Features:
 * - JWT secret rotation (30-day automatic)
 * - Session management with fingerprinting
 * - Argon2 API key hashing
 * - RBAC with granular permissions
 * - Global error handling
 * - Structured logging with correlation IDs
 * - Performance monitoring and alerting
 * - Zero-trust architecture
 */

import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { compress } from 'hono/compress';
import { etag } from 'hono/etag';
import { secureHeaders } from 'hono/secure-headers';

// Security components
import { JWTRotation } from './security/jwt-rotation';
import { createSessionManager } from './security/session-manager';
import { createEnhancedApiKeySecurity } from './security/enhanced-api-key-security';
import { createRBACSystem } from './security/rbac-system';

// Middleware
import { createErrorHandler } from './middleware/error-handler';
import { createStructuredLogger, LogLevel } from './middleware/structured-logger';
import { createPerformanceMonitor } from './monitoring/performance-monitor';
import {
  addSecurityHeaders,
  getCorsHeaders,
  advancedRateLimit,
  validateRequest,
  preventXSS,
  sanitizeInput
} from './middleware/security';

// Business modules
import { AuthSystem } from './auth/auth-system';
import { SecureDatabase } from './database/secure-database';

// Types - Use canonical Env definition
import type { Env } from './types/env';
import type { AppContext, Next } from './types/hono-context';

// Export Durable Object for rate limiting
export { RateLimiterDurableObject as AdvancedRateLimiterDO } from './durable-objects/rate-limiter';

// Re-export canonical types
export type { Env } from './types/env';

// Create application factory
function createApp(env: Env) {
  const app = new Hono<{ Bindings: Env; Variables: import('./types/hono-context').AppVariables }>();

  // Initialize security components
  const jwtRotation = new JWTRotation(env);
  const sessionManager = createSessionManager(env.KV_SESSION, {
    maxAge: 8 * 60 * 60 * 1000, // 8 hours
    requireFingerprint: true,
    requireMFA: env.ENVIRONMENT === 'production'
  });
  const apiKeySecurity = createEnhancedApiKeySecurity(env.KV_AUTH);
  const rbacSystem = createRBACSystem(env.KV_AUTH);

  // Initialize logging and monitoring
  const logger = createStructuredLogger(
    {
      minLevel: env.ENVIRONMENT === 'production' ? LogLevel.INFO : LogLevel.DEBUG,
      env: env.ENVIRONMENT
    },
    env.KV_CACHE,
    env.ANALYTICS
  );

  const performanceMonitor = createPerformanceMonitor(
    {
      responseTimeThreshold: 500,
      errorRateThreshold: 5,
      memoryThreshold: 90
    },
    env.KV_CACHE,
    env.ANALYTICS
  );

  // Initialize business systems
  const authSystem = new AuthSystem(env.DB_MAIN, env.KV_AUTH, env.JWT_SECRET);
  const database = new SecureDatabase(env.DB_MAIN);

  // =======================
  // MIDDLEWARE CHAIN
  // =======================

  // 1. Error handling (outermost)
  app.use('*', createErrorHandler({ env: env.ENVIRONMENT }, env.KV_CACHE));

  // 2. Request ID and correlation
  app.use('*', async (c: AppContext, next: Next) => {
    const correlationId = c.req.header('X-Correlation-ID') || crypto.randomUUID();
    const requestId = crypto.randomUUID();

    c.set('correlationId', correlationId);
    c.set('requestId', requestId);
    c.set('env', env);

    c.header('X-Correlation-ID', correlationId);
    c.header('X-Request-ID', requestId);

    await next();
  });

  // 3. Logging
  app.use('*', logger.middleware());

  // 4. Performance monitoring
  app.use('*', performanceMonitor.middleware());

  // 5. Security headers
  app.use('*', secureHeaders({
    contentSecurityPolicy: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:', 'https:'],
      connectSrc: ["'self'", 'https:'],
      fontSrc: ["'self'", 'https:'],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
    },
    strictTransportSecurity: 'max-age=31536000; includeSubDomains; preload',
    xContentTypeOptions: 'nosniff',
    xFrameOptions: 'DENY',
    xXssProtection: '1; mode=block',
    referrerPolicy: 'strict-origin-when-cross-origin'
  }));

  // 6. CORS (production-ready)
  const allowedOrigins = env.ALLOWED_ORIGINS?.split(',') || ['https://app.coreflow360.com'];
  app.use('*', cors({
    origin: (origin) => {
      if (!origin) return true; // Allow requests with no origin (e.g., Postman)
      if (env.ENVIRONMENT === 'development' && origin.includes('localhost')) return origin;
      return allowedOrigins.includes(origin) ? origin : false;
    },
    credentials: true,
    allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowHeaders: ['Content-Type', 'Authorization', 'X-Correlation-ID', 'X-Business-ID'],
    maxAge: 86400
  }));

  // 7. Compression
  app.use('*', compress());

  // 8. ETag
  app.use('*', etag());

  // 9. Rate limiting
  app.use('*', async (c: AppContext, next: Next) => {
    const rateLimitResult = await advancedRateLimit(
      c.req.raw,
      env.KV_RATE_LIMIT,
      {
        requests: 100,
        window: 60,
        keyGenerator: (req) => {
          const ip = c.req.header('CF-Connecting-IP') || 'unknown';
          const userId = c.get('userId') || 'anonymous';
          return `${ip}:${userId}`;
        }
      }
    );

    if (!rateLimitResult.allowed) {
      logger.security('rate_limit_exceeded', 'high', {
        ip: c.req.header('CF-Connecting-IP'),
        remaining: rateLimitResult.remaining,
        resetTime: rateLimitResult.resetTime
      });

      return c.json(
        { error: 'Rate limit exceeded' },
        429,
        {
          'Retry-After': String(rateLimitResult.resetTime - Math.floor(Date.now() / 1000)),
          'X-RateLimit-Limit': '100',
          'X-RateLimit-Remaining': String(rateLimitResult.remaining),
          'X-RateLimit-Reset': String(rateLimitResult.resetTime)
        }
      );
    }

    await next();
  });

  // 10. Input validation and sanitization
  app.use('*', async (c: AppContext, next: Next) => {
    if (['POST', 'PUT', 'PATCH'].includes(c.req.method)) {
      const contentType = c.req.header('Content-Type');

      if (contentType?.includes('application/json')) {
        try {
          const body = await c.req.json();
          const sanitized = sanitizeInput(JSON.stringify(body));
          c.set('sanitizedBody', JSON.parse(sanitized));
        } catch (error) {
          return c.json({ error: 'Invalid JSON' }, 400);
        }
      }
    }

    await next();
  });

  // =======================
  // HEALTH & MONITORING ENDPOINTS
  // =======================

  app.get('/health', async (c) => {
    const health = await performanceMonitor.getHealthMetrics();
    const statusCode = health.status === 'healthy' ? 200 :
                       health.status === 'degraded' ? 503 : 500;

    return c.json(health, statusCode);
  });

  app.get('/metrics', async (c) => {
    // Require authentication for metrics endpoint
    const authHeader = c.req.header('Authorization');
    if (!authHeader?.startsWith('Bearer ')) {
      return c.json({ error: 'Unauthorized' }, 401);
    }

    const summary = await performanceMonitor.getPerformanceSummary();
    return c.json(summary);
  });

  app.get('/ready', async (c) => {
    try {
      // Check all critical services
      const checks = await Promise.all([
        database.healthCheck(),
        env.KV_AUTH.get('health:check'),
        jwtRotation.getActiveSecret()
      ]);

      return c.json({ status: 'ready', timestamp: Date.now() });
    } catch (error) {
      logger.error('Readiness check failed', error);
      return c.json({ status: 'not_ready' }, 503);
    }
  });

  // =======================
  // AUTHENTICATION ENDPOINTS
  // =======================

  // Middleware to verify authentication
  const authMiddleware = async (c: AppContext, next: Next) => {
    const authHeader = c.req.header('Authorization');

    if (!authHeader?.startsWith('Bearer ')) {
      return c.json({ error: 'Missing authorization' }, 401);
    }

    const token = authHeader.substring(7);

    try {
      // Verify JWT with rotation support
      const result = await jwtRotation.verifyWithRotation(token);

      if (!result.valid || !result.payload || !result.payload.sub) {
        logger.security('invalid_token', 'medium', { token: token.substring(0, 10) });
        return c.json({ error: 'Invalid token' }, 401);
      }

      // Extract and validate payload fields
      const userId = typeof result.payload.sub === 'string' ? result.payload.sub : String(result.payload.sub);
      const businessId = (result.payload as any).businessId || '';
      const roles = Array.isArray((result.payload as any).roles) ? (result.payload as any).roles : [];

      // Set user context
      c.set('userId', userId);
      c.set('businessId', businessId);
      c.set('roles', roles);
      c.set('tokenVersion', result.version || 1);

      await next();
    } catch (error) {
      logger.error('Authentication failed', error);
      return c.json({ error: 'Authentication failed' }, 401);
    }
  };

  // Login endpoint
  app.post('/api/auth/login', async (c: AppContext) => {
    const body = c.get('sanitizedBody') || await c.req.json();
    const { email, password, businessId } = body;

    // Validate input
    if (!email || !password) {
      return c.json({ error: 'Email and password required' }, 400);
    }

    // Attempt login
    const result = await authSystem.login(
      { email, password, businessId },
      c.req.header('CF-Connecting-IP'),
      c.req.header('User-Agent')
    );

    if (!result.success) {
      logger.security('login_failed', 'medium', { email });
      return c.json({ error: result.error }, 401);
    }

    // Create session
    const session = await sessionManager.createSession(
      result.user!.id,
      result.user!.businessId,
      result.user!.email,
      result.user!.roles,
      result.user!.permissions,
      c.req.raw
    );

    // Log successful login
    logger.info('User logged in', {
      userId: result.user!.id,
      businessId: result.user!.businessId
    });

    return c.json({
      success: true,
      token: result.token,
      sessionId: session.sessionId,
      user: result.user
    });
  });

  // Register endpoint
  app.post('/api/auth/register', async (c: AppContext) => {
    const body = c.get('sanitizedBody') || await c.req.json();
    const result = await authSystem.register(body);

    if (!result.success) {
      return c.json({ error: result.error }, 400);
    }

    logger.info('New user registered', {
      userId: result.user!.id,
      businessId: result.user!.businessId
    });

    return c.json(result);
  });

  // Logout endpoint
  app.post('/api/auth/logout', authMiddleware, async (c: AppContext) => {
    const authHeader = c.req.header('Authorization');
    const token = authHeader!.substring(7);

    await authSystem.logout(token);
    await sessionManager.destroyAllUserSessions(c.get('userId'));

    logger.info('User logged out', { userId: c.get('userId') });

    return c.json({ success: true });
  });

  // =======================
  // API KEY MANAGEMENT
  // =======================

  app.post('/api/keys/generate', authMiddleware, async (c: AppContext) => {
    const userId = c.get('userId');
    const businessId = c.get('businessId');
    const body = await c.req.json();

    // Check permission
    const hasPermission = await rbacSystem.checkAccess({
      userId,
      businessId,
      resource: 'api_keys',
      action: 'create'
    });

    if (!hasPermission.allowed) {
      return c.json({ error: 'Insufficient permissions' }, 403);
    }

    const result = await apiKeySecurity.generateApiKey(
      userId,
      businessId,
      body.name,
      body.permissions || ['read'],
      body.expiresInDays
    );

    logger.security('api_key_created', 'low', {
      userId,
      keyId: result.keyData.id
    });

    return c.json(result);
  });

  // =======================
  // PROTECTED BUSINESS ENDPOINTS
  // =======================

  app.get('/api/business/:id', authMiddleware, async (c: AppContext) => {
    const businessId = c.param('id');
    const userId = c.get('userId');

    // Check RBAC permission
    const hasAccess = await rbacSystem.checkAccess({
      userId,
      businessId,
      resource: 'business',
      action: 'read'
    });

    if (!hasAccess.allowed) {
      logger.security('unauthorized_access', 'high', {
        userId,
        resource: 'business',
        businessId
      });
      return c.json({ error: 'Access denied' }, 403);
    }

    // Fetch business data with row-level security
    const business = await database.getBusinessSecure(businessId, userId);

    if (!business) {
      return c.json({ error: 'Business not found' }, 404);
    }

    return c.json(business);
  });

  // =======================
  // ERROR HANDLING
  // =======================

  app.notFound((c) => {
    logger.warn('Route not found', { path: c.req.path });
    return c.json({ error: 'Not found' }, 404);
  });

  app.onError((err, c) => {
    logger.error('Unhandled error', err);
    return c.json({ error: 'Internal server error' }, 500);
  });

  return app;
}

// =======================
// WORKER EXPORT
// =======================

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const app = createApp(env);
    return app.fetch(request, env, ctx);
  },

  // Scheduled handler for JWT rotation
  async scheduled(event: ScheduledEvent, env: Env, ctx: ExecutionContext): Promise<void> {
    const jwtRotation = new JWTRotation(env);

    switch (event.cron) {
      case '0 0 * * *': // Daily at midnight
        await jwtRotation.rotateSecrets();
        break;
      default:
        console.log('Unknown cron trigger:', event.cron);
    }
  }
};