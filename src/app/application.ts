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
  const app = new Hono();

  // Initialize core services
  const observability = new ObservabilityService(env);
  const errorHandler = new ErrorHandler(env, observability);
  const routeManager = new RouteManager(env);

  // Middleware chain - ORDER IS CRITICAL for security
  // Layer 1: Infrastructure Security
  app.use('*', new CorsMiddleware(securityConfig).handler());
  app.use('*', new SecurityMiddleware(securityConfig).handler());

  // Layer 2: Traffic Management
  app.use('*', new RateLimitingMiddleware(env).handler());

  // Layer 3: Input Validation
  app.use('*', new ValidationMiddleware(env).handler());

  // Layer 4: Authentication & Authorization
  app.use('/api/*', new AuthenticationMiddleware(env).handler());

  // Layer 5: Audit & Monitoring
  app.use('*', new AuditMiddleware(env, observability).handler());

  // Register routes
  await routeManager.registerRoutes(app);

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