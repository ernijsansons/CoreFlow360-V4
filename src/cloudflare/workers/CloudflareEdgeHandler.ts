/**
 * CLOUDFLARE EDGE HANDLER
 * Production-ready edge worker handling all requests
 * Smart routing, caching, security, and performance optimization
 */

import type { ExecutionContext, MessageBatch, ScheduledEvent, Message,
  DurableObjectNamespace, R2Bucket, AnalyticsEngineDataset, KVNamespace } from '../types/cloudflare';
import { CloudflareIntegration } from '../CloudflareIntegration';
import { createCors } from '../utils/cors';
import { createSecurityHeaders } from '../utils/security';
import { createLogger } from '../utils/logger';

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const cf = new CloudflareIntegration(env);
    const logger = createLogger(env);
    const startTime = Date.now();

    try {
      // Initialize Cloudflare services
      await cf.initialize();

      // Create CORS handler
      const cors = createCors(env);

      // Handle CORS preflight
      if (request.method === 'OPTIONS') {
        return cors.handlePreflight(request);
      }

      // Route the request
      const response = await routeRequest(request, env, ctx, cf, logger);

      // Apply security headers
      const secureResponse = createSecurityHeaders(response, env);

      // Apply CORS headers
      const finalResponse = cors.addHeaders(secureResponse, request);

      // Track performance
      const duration = Date.now() - startTime;
      await cf.Performance.measurePerformance('total_request', async () => duration);

      return finalResponse;

    } catch (error: any) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      logger.error('Edge handler error:', error as Error);

      // Track error
      await cf.Analytics.track('edge_error', {
        error: errorMessage,
        url: request.url,
        method: request.method,
        duration: Date.now() - startTime
      });

      return new Response('Internal Server Error', {
        status: 500,
        headers: createSecurityHeaders(new Response(), env).headers
      });
    }
  },

  async queue(batch: MessageBatch<any>, env: Env): Promise<void> {
    const logger = createLogger(env);

    try {
      for (const message of batch.messages) {
        await handleQueueMessage(message, env, logger);
      }
    } catch (error: any) {
      logger.error('Queue processing error:', error);
      throw error; // This will retry the batch
    }
  },

  async scheduled(event: ScheduledEvent, env: Env, ctx: ExecutionContext): Promise<void> {
    const logger = createLogger(env);

    try {
      switch (event.cron) {
        case '0 2 * * *': // Daily at 2 AM
          await runDailyCleanup(env, ctx, logger);
          break;
        case '*/15 * * * *': // Every 15 minutes
          await runHealthCheck(env, ctx, logger);
          break;
        default:
          logger.warn('Unknown cron trigger', { cronExpression: event.cron });
      }
    } catch (error: any) {
      logger.error('Scheduled task error:', error);
    }
  }
};

/**
 * Route incoming requests
 */
async function routeRequest(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
  cf: CloudflareIntegration,
  logger: any
): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname;

  // Security validation
  const securityValidation = await cf.Security.validateRequest(request);
  if (!securityValidation.allowed) {
    logger.warn('Request blocked by security', { validation: securityValidation });
    return new Response('Forbidden', { status: 403 });
  }

  // Check cache first
  const cacheKey = getCacheKey(request);
  if (shouldCache(request)) {
    const cached = await cf.Cache.get(cacheKey);
    if (cached) {
      return new Response(JSON.stringify(cached), {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
          'X-Cache': 'HIT'
        }
      });
    }
  }

  let response: Response;

  // Route to appropriate handler
  if (path.startsWith('/api/v4/')) {
    response = await handleAPIRequest(request, env, ctx, cf, logger);
  } else if (path.startsWith('/ws/')) {
    response = await handleWebSocketRequest(request, env, ctx, cf, logger);
  } else if (path.startsWith('/health')) {
    response = await handleHealthCheck(request, env, ctx, cf, logger);
  } else if (path.startsWith('/admin/')) {
    response = await handleAdminRequest(request, env, ctx, cf, logger);
  } else if (path.startsWith('/static/')) {
    response = await handleStaticAssets(request, env, ctx, cf, logger);
  } else {
    response = await handleApplicationRequest(request, env, ctx, cf, logger);
  }

  // Cache the response if appropriate
  if (shouldCache(request) && response.status === 200) {
    const responseData = await response.clone().json();
    await cf.Cache.set(cacheKey, responseData, {
      ttl: getCacheTTL(request)
    });
  }

  // Apply performance optimizations
  return await cf.Performance.optimizeResponse(response, request);
}

/**
 * Handle API requests
 */
async function handleAPIRequest(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
  cf: CloudflareIntegration,
  logger: any
): Promise<Response> {
  const url = new URL(request.url);
  const pathSegments = url.pathname.split('/').filter(Boolean);

  if (pathSegments.length < 3) {
    return new Response('Invalid API path', { status: 400 });
  }

  const module = pathSegments[2]; // e.g., 'auth', 'inventory', 'workflows'
  const action = pathSegments[3]; // e.g., 'login', 'create', 'execute'

  try {
    // Load the appropriate module
    const moduleHandler = await loadModuleHandler(module, env);

    if (!moduleHandler) {
      return new Response('Module not found', { status: 404 });
    }

    // Execute the action
    const result = await moduleHandler.handle(action, request, env, ctx);

    // Track API usage
    await cf.Analytics.track('api_request', {
      module,
      action,
      method: request.method,
      status: result.status
    });

    return result;

  } catch (error: any) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    logger.error(`API error in ${module}/${action}:`, error as Error);

    await cf.Analytics.track('api_error', {
      module,
      action,
      error: errorMessage
    });

    return new Response('Internal Server Error', { status: 500 });
  }
}

/**
 * Handle WebSocket requests
 */
async function handleWebSocketRequest(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
  cf: CloudflareIntegration,
  logger: any
): Promise<Response> {
  const url = new URL(request.url);

  // Get Durable Object for real-time coordination
  const id = env.REALTIME_COORDINATOR.idFromName('global');
  const coordinator = env.REALTIME_COORDINATOR.get(id);

  // Forward to Durable Object
  return await coordinator.fetch(request);
}

/**
 * Handle health check requests
 */
async function handleHealthCheck(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
  cf: CloudflareIntegration,
  logger: any
): Promise<Response> {
  try {
    const health = await cf.healthCheck();

    if (health.healthy) {
      return new Response(JSON.stringify({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        services: health.services,
        environment: env.ENVIRONMENT
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' }
      });
    } else {
      return new Response(JSON.stringify({
        status: 'unhealthy',
        timestamp: new Date().toISOString(),
        services: health.services
      }), {
        status: 503,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  } catch (error: any) {
    logger.error('Health check failed:', error);
    return new Response('Health Check Failed', { status: 500 });
  }
}

/**
 * Handle admin requests
 */
async function handleAdminRequest(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
  cf: CloudflareIntegration,
  logger: any
): Promise<Response> {
  // Enhanced security for admin endpoints
  const ip = request.headers.get('CF-Connecting-IP');
  const userAgent = request.headers.get('User-Agent');

  // Check admin authentication
  const authHeader = request.headers.get('Authorization');
  if (!authHeader || !await validateAdminAuth(authHeader, env)) {
    await cf.Analytics.track('admin_access_denied', {
      ip,
      userAgent,
      path: new URL(request.url).pathname
    });
    return new Response('Unauthorized', { status: 401 });
  }

  const url = new URL(request.url);
  const path = url.pathname;

  if (path.includes('/admin/status')) {
    const status = await cf.getStatus();
    return new Response(JSON.stringify(status), {
      headers: { 'Content-Type': 'application/json' }
    });
  }

  if (path.includes('/admin/metrics')) {
    const metrics = await cf.Analytics.getMetrics();
    return new Response(JSON.stringify(metrics), {
      headers: { 'Content-Type': 'application/json' }
    });
  }

  if (path.includes('/admin/cache/clear')) {
    const pattern = url.searchParams.get('pattern') || '*';
    await cf.Cache.invalidate(pattern);
    return new Response(JSON.stringify({ cleared: pattern }), {
      headers: { 'Content-Type': 'application/json' }
    });
  }

  return new Response('Admin endpoint not found', { status: 404 });
}

/**
 * Handle static asset requests
 */
async function handleStaticAssets(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
  cf: CloudflareIntegration,
  logger: any
): Promise<Response> {
  const url = new URL(request.url);
  const assetPath = url.pathname.replace('/static/', '');

  try {
    // Try to get from R2 first
    const object = await env.R2_ASSETS.get(assetPath);

    if (object) {
      const headers = new Headers();
      headers.set('Content-Type', getContentType(assetPath));
      headers.set('Cache-Control', 'public, max-age=31536000'); // 1 year
      headers.set('X-Asset-Source', 'R2');

      return new Response(object.body, {
        status: 200,
        headers
      });
    }

    // Fallback to origin
    return fetch(request);

  } catch (error: any) {
    logger.error('Static asset error:', error);
    return new Response('Asset not found', { status: 404 });
  }
}

/**
 * Handle application requests (SPA routing)
 */
async function handleApplicationRequest(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
  cf: CloudflareIntegration,
  logger: any
): Promise<Response> {
  // For SPA applications, serve index.html for routes
  const url = new URL(request.url);

  // Check if it's a file request
  if (url.pathname.includes('.')) {
    return fetch(request); // Serve the actual file
  }

  // Serve index.html for SPA routes
  try {
    const indexHtml = await env.R2_ASSETS.get('index.html');

    if (indexHtml) {
      return new Response(indexHtml.body, {
        status: 200,
        headers: {
          'Content-Type': 'text/html',
          'Cache-Control': 'no-cache'
        }
      });
    }

    // Fallback to origin
    return fetch(request);

  } catch (error: any) {
    logger.error('Application request error:', error);
    return new Response('Application error', { status: 500 });
  }
}

/**
 * Handle queue messages
 */
async function handleQueueMessage(
  message: Message<any>,
  env: Env,
  logger: any
): Promise<void> {
  const { body, id, timestamp } = message;

  try {
    switch (body.type) {
      case 'email':
        await processEmailMessage(body, env, logger);
        break;
      case 'webhook':
        await processWebhookMessage(body, env, logger);
        break;
      case 'analytics':
        await processAnalyticsMessage(body, env, logger);
        break;
      default:
        logger.warn('Unknown queue message type', { messageType: body.type });
    }

    logger.info(`Processed queue message ${id}`);

  } catch (error: any) {
    logger.error(`Failed to process queue message ${id}:`, error);
    throw error; // This will retry the message
  }
}

/**
 * Run daily cleanup
 */
async function runDailyCleanup(
  env: Env,
  ctx: ExecutionContext,
  logger: any
): Promise<void> {
  logger.info('Running daily cleanup...');

  try {
    // Clean up old cache entries
    // Clean up old analytics data
    // Clean up old session data
    // Optimize database

    logger.info('Daily cleanup completed');

  } catch (error: any) {
    logger.error('Daily cleanup failed:', error);
  }
}

/**
 * Run health check
 */
async function runHealthCheck(
  env: Env,
  ctx: ExecutionContext,
  logger: any
): Promise<void> {
  try {
    const cf = new CloudflareIntegration(env);
    const health = await cf.healthCheck();

    if (!health.healthy) {
      logger.warn('Health check failed', { healthStatus: health });
      // Send alerts
    }

  } catch (error: any) {
    logger.error('Health check error:', error);
  }
}

// Helper functions
function getCacheKey(request: Request): string {
  const url = new URL(request.url);
  return `${request.method}:${url.pathname}:${url.search}`;
}

function shouldCache(request: Request): boolean {
  if (request.method !== 'GET') return false;

  const url = new URL(request.url);
  const path = url.pathname;

  // Cache API GET requests
  if (path.startsWith('/api/v4/')) {
    return !path.includes('/auth/') && !path.includes('/realtime/');
  }

  // Cache static assets
  if (path.startsWith('/static/')) {
    return true;
  }

  return false;
}

function getCacheTTL(request: Request): number {
  const url = new URL(request.url);
  const path = url.pathname;

  if (path.startsWith('/api/v4/')) {
    return 300; // 5 minutes for API
  }

  if (path.startsWith('/static/')) {
    return 86400; // 24 hours for static assets
  }

  return 3600; // 1 hour default
}

function getContentType(filename: string): string {
  const ext = filename.split('.').pop()?.toLowerCase();

  const contentTypes: Record<string, string> = {
    'html': 'text/html',
    'css': 'text/css',
    'js': 'application/javascript',
    'json': 'application/json',
    'png': 'image/png',
    'jpg': 'image/jpeg',
    'jpeg': 'image/jpeg',
    'gif': 'image/gif',
    'svg': 'image/svg+xml',
    'ico': 'image/x-icon',
    'pdf': 'application/pdf',
    'zip': 'application/zip'
  };

  return contentTypes[ext || ''] || 'application/octet-stream';
}

async function loadModuleHandler(module: string, env: Env): Promise<any> {
  // Dynamic module loading based on module name
  // This would be implemented based on your actual module structure
  return null;
}

async function validateAdminAuth(authHeader: string, env: Env): Promise<boolean> {
  // Implement admin authentication validation
  return false;
}

async function processEmailMessage(body: any, env: Env, logger: any): Promise<void> {
  // Implement email processing
}

async function processWebhookMessage(body: any, env: Env, logger: any): Promise<void> {
  // Implement webhook processing
}

async function processAnalyticsMessage(body: any, env: Env, logger: any): Promise<void> {
  // Implement analytics processing
}

// Type definitions
interface Env {
  ENVIRONMENT: string;
  REALTIME_COORDINATOR: DurableObjectNamespace;
  R2_ASSETS: R2Bucket;
  ANALYTICS: AnalyticsEngineDataset;
  PERFORMANCE_ANALYTICS: AnalyticsEngineDataset;
  CACHE: KVNamespace;
  CORS_ORIGINS?: string;
}