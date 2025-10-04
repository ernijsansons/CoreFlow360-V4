/**
 * Application Factory - Creates secure application with middleware chain
 * Implements SOLID principles with modular, testable architecture
 */

import { Hono } from 'hono';
import { SecurityMiddleware } from '../middleware/security-middleware';
import { AuthenticationMiddleware } from '../middleware/authentication-middleware';
import { ValidationMiddleware } from '../middleware/validation-middleware';
import { RateLimitingMiddleware } from '../middleware/rate-limiting-middleware';
import { CorsMiddleware } from '../middleware/cors-middleware';
import { AuditMiddleware } from '../middleware/audit-middleware';
import { ErrorHandler } from '../handlers/error-handler';
import { RouteManager } from '../handlers/route-manager';
import { ObservabilityService } from '../services/observability-service';
import { SecurityConfig } from '../config/security';
import type { Env } from '../types/environment';
import type { Context } from 'hono';

export interface SecureApp {
  handle(request: Request): Promise<Response>;
  registerRoute(path: string, handler: Function): void;
  shutdown(): Promise<void>;
}

/**
 * Creates a secure application instance with defense-in-depth middleware chain
 */
export async function createSecureApp(
  env: Env,
  securityConfig: SecurityConfig,
  ctx: ExecutionContext
): Promise<SecureApp> {
  const app = new Hono<{ Bindings: Env }>();

  // Initialize core services
  const observability = new ObservabilityService(env);
  const errorHandler = new ErrorHandler(
    {
      logErrors: true,
      includeStack: env.ENVIRONMENT === 'development',
      sanitizeErrors: env.ENVIRONMENT === 'production',
      defaultMessage: 'An error occurred',
      env: (env.ENVIRONMENT as 'development' | 'staging' | 'production') || 'production'
    },
    env.KV_SESSION
  );
  const routeManager = new RouteManager(app);

  // Middleware chain - ORDER IS CRITICAL for security
  // Layer 1: Infrastructure Security
  const corsConfig = securityConfig.getCorsConfig();
  app.use('*', async (c, next) => {
    const corsMiddleware = CorsMiddleware({
      allowedOrigins: corsConfig.allowedOrigins,
      allowedMethods: corsConfig.allowedMethods,
      allowedHeaders: corsConfig.allowedHeaders,
      credentials: corsConfig.allowCredentials,
      environment: (env.ENVIRONMENT as 'development' | 'staging' | 'production') || 'production'
    });

    const result = await corsMiddleware(c.req.raw);
    if (result.response) {
      return result.response;
    }

    // Apply CORS headers to response
    await next();
    Object.entries(result.headers).forEach(([key, value]) => {
      c.res.headers.set(key, value);
    });

    return;
  });

  app.use('*', new SecurityMiddleware(securityConfig).handler());

  // Layer 2: Traffic Management
  const rateLimitConfig = securityConfig.getRateLimitConfig();
  app.use('*', async (c, next) => {
    const kvNamespace = env.KV_RATE_LIMIT_METRICS || env.KV_CACHE;
    if (!kvNamespace) {
      console.warn('Rate limiting disabled - no KV namespace available');
      await next();
      return;
    }

    const rateLimiter = RateLimitingMiddleware(
      {
        requests: rateLimitConfig.perIP.requests,
        window: rateLimitConfig.perIP.window,
        strategy: 'sliding'
      },
      kvNamespace
    );

    const result = await rateLimiter(c.req.raw);
    if (!result.allowed && result.response) {
      return result.response;
    }

    // Apply rate limit headers
    if (result.headers) {
      Object.entries(result.headers).forEach(([key, value]) => {
        c.res.headers.set(key, value);
      });
    }

    await next();
    return;
  });

  // Layer 3: Input Validation
  app.use('*', async (c, next) => {
    const validationMiddleware = ValidationMiddleware({
      maxRequestSize: 10 * 1024 * 1024,
      enableXSSProtection: true,
      enableSQLInjectionProtection: true,
      enablePathTraversalProtection: true,
      strictMode: true
    });

    const result = await validationMiddleware(c.req.raw);
    if (!result.valid && result.riskScore > 50) {
      return c.json({
        error: 'Validation failed',
        errors: result.errors,
        riskScore: result.riskScore
      }, 400);
    }

    await next();
    return;
  });

  // Layer 4: Authentication & Authorization
  app.use('/api/*', async (c, next) => {
    const authMiddleware = new AuthenticationMiddleware(c);
    return authMiddleware.authMiddleware(c, next);
  });

  // Layer 5: Audit & Monitoring
  const auditMiddleware = new AuditMiddleware(env);
  app.use('*', await auditMiddleware.middleware());

  // Register routes
  routeManager.registerRoutes();

  // Global error handler
  app.onError(errorHandler.handle.bind(errorHandler));

  return {
    async handle(request: Request): Promise<Response> {
      try {
        return await app.fetch(request, env, ctx);
      } catch (error) {
        return errorHandler.handleUnexpected(error as Error, request);
      }
    },

    registerRoute(path: string, handler: Function): void {
      routeManager.registerDynamicRoute(path, handler);
    },

    async shutdown(): Promise<void> {
      await observability.flush();
      await routeManager.cleanup();
    }
  };
}