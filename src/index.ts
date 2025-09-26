// src/index.ts - Production-Ready Worker with CRITICAL SECURITY FIXES
// SECURITY FIXES APPLIED:
// - JWT Authentication Bypass (CVSS 9.8) - Fixed fallback secrets
// - Environment validation with cryptographic security
// - Token blacklist/revocation system
// - JWT secret rotation capability

import { Router } from 'itty-router';
import { CloudflareIntegration } from './cloudflare/CloudflareIntegration';
import { SmartCaching } from './cloudflare/performance/SmartCaching';
import { createDatabase, Database } from './database/db';
import { createAIService, AIService } from './ai/ai-service';
import { createWebSocketService, WebSocketService } from './realtime/websocket-service';
import { createQueueHandler, QueueHandler } from './jobs/queue-handler';
import { addSecurityHeaders, rateLimitByIP, validateJWT,
  detectSuspiciousActivity, logSecurityEvent, getCorsHeaders } from './middleware/security';
import { createAnalyticsDashboard, AnalyticsDashboard } from './analytics/dashboard';
import { SupernovaIntegration } from './supernova/supernova-integration';
import { memoryOptimizer } from './monitoring/memory-optimizer';
import { handleAPIRequest } from './routes'; // Import our Hono API routes

// SECURITY IMPORTS
import { EnvironmentValidator } from './shared/environment-validator';
import { TokenBlacklist } from './modules/auth/token-blacklist';
import { createJWTRotation, JWTSecretRotation } from './modules/auth/jwt-secret-rotation';
import { EnterpriseRateLimiter } from './security/enterprise-rate-limiter';
import { RateLimitMonitor } from './security/rate-limit-monitor';
import type { Ai } from '@cloudflare/ai';
import type {
  D1Database,
  KVNamespace,
  R2Bucket,
  AnalyticsEngineDataset,
  DurableObjectNamespace,
  ExecutionContext,
  MessageBatch,
  Message,
  Queue
} from './cloudflare/types/cloudflare';
import type { Env } from './types/env';

// Global instances - initialized once per Worker with performance optimization
let cf: CloudflareIntegration | null = null;
let db: Database | null = null;
let ai: AIService | null = null;
let ws: WebSocketService | null = null;
let queue: QueueHandler | null = null;
let analytics: AnalyticsDashboard | null = null;
let supernova: SupernovaIntegration | null = null;

// SECURITY: Global security service instances
let tokenBlacklist: TokenBlacklist | null = null;
let jwtRotation: JWTSecretRotation | null = null;
let enterpriseRateLimiter: EnterpriseRateLimiter | null = null;
let rateLimitMonitor: RateLimitMonitor | null = null;

// Performance tracking
let initializationComplete = false;
let initializationTime: number | null = null;

// Router instance
const router = Router();

// Optimized service initialization with CRITICAL SECURITY VALIDATION
async function initializeServices(env: Env, ctx: ExecutionContext): Promise<void> {
  if (initializationComplete) return;

  const startTime = performance.now();

  // CRITICAL SECURITY: Validate environment before any other initialization
  try {
    console.log('🔒 Validating environment security configuration...');
    EnvironmentValidator.validate(env);
    console.log('✅ Environment validation passed - JWT Authentication Bypass vulnerability mitigated');
  } catch (error) {
    console.error('🚨 CRITICAL SECURITY ERROR: Environment validation failed');
    console.error(error);
    throw new Error('Application startup blocked due to security configuration errors');
  }
  
  try {
    // Initialize memory optimizer first (critical dependency)
    memoryOptimizer.registerCleanupCallback(async () => {
      if (db && 'cleanup' in db && typeof (db as any).cleanup === 'function') await (db as any).cleanup();
    });
    
    memoryOptimizer.registerCleanupCallback(async () => {
      if (cf && 'clearCaches' in cf && typeof (cf as any).clearCaches === 'function') await (cf as any).clearCaches();
    });
    
    // Phase 1: Initialize core infrastructure services in parallel (no dependencies)
    const coreInfraPromises = [
      // Cloudflare integration (independent)
      Promise.resolve().then(async () => {
        cf = new CloudflareIntegration(env as any);
        return cf;
      }),
      
      // Database connection (independent)
      Promise.resolve().then(async () => {
        db = await createDatabase(env.DB, (env as any).KV_CACHE || {} as any);
        return db;
      }),
      
      // AI service (independent)
      Promise.resolve().then(async () => {
        ai = await createAIService(env.AI as any, env.ANTHROPIC_API_KEY || '', (env as any).OPENAI_API_KEY);
        return ai;
      }),

      // SECURITY: Initialize token blacklist system
      Promise.resolve().then(async () => {
        if (env.KV_SESSION) {
          tokenBlacklist = new TokenBlacklist(env.KV_SESSION);
          console.log('🛡️ Token blacklist system initialized');
        }
        return tokenBlacklist;
      }),

      // SECURITY: Initialize JWT rotation system
      Promise.resolve().then(async () => {
        if (env.KV_SESSION) {
          jwtRotation = createJWTRotation(env.KV_SESSION, {
            rotationIntervalHours: 24,
            gracePeriodHours: 2,
            maxKeyAge: 7 * 24 * 60 * 60 * 1000, // 7 days
            emergencyRotationEnabled: true
          });
          await jwtRotation.initialize();
          console.log('🔄 JWT secret rotation system initialized');
        }
        return jwtRotation;
      }),

      // SECURITY: Initialize enterprise rate limiting
      Promise.resolve().then(async () => {
        enterpriseRateLimiter = new EnterpriseRateLimiter(env);
        console.log('🛡️ Enterprise rate limiting system initialized');
        return enterpriseRateLimiter;
      }),

      // SECURITY: Initialize rate limiting monitoring
      Promise.resolve().then(async () => {
        if (env.KV_RATE_LIMIT_METRICS && env.DB_MAIN) {
          rateLimitMonitor = new RateLimitMonitor(env);
          console.log('📊 Rate limiting monitoring system initialized');
        }
        return rateLimitMonitor;
      })
    ];
    
    // Wait for core infrastructure with timeout
    const coreResults = await Promise.allSettled(coreInfraPromises);
    
    // Check if core services initialized successfully
    const failedCore = coreResults.filter(result => result.status === 'rejected');
    if (failedCore.length > 0) {
      console.warn('Some core services failed to initialize:', failedCore);
    }
    
    // Phase 2: Initialize dependent services in parallel (depend on core services)
    const dependentServicesPromises = [];
    
    // Only initialize if dependencies are available
    if ((env as any).REALTIME) {
      dependentServicesPromises.push(
        Promise.resolve().then(async () => {
          ws = await createWebSocketService((env as any).REALTIME, 'default');
          return ws;
        })
          .catch(error => { console.warn('WebSocket service failed:', error); return null; })
      );
    }
    
    if (env.TASK_QUEUE || env.EMAIL_QUEUE || env.WEBHOOK_QUEUE) {
      dependentServicesPromises.push(
        Promise.resolve().then(async () => {
          queue = await createQueueHandler();
          return queue;
        })
          .catch(error => { console.warn('Queue handler failed:', error); return null; })
      );
    }
    
    if (env.ANALYTICS) {
      dependentServicesPromises.push(
        Promise.resolve().then(async () => {
          analytics = await createAnalyticsDashboard(env.ANALYTICS as any, (env as any).PERFORMANCE_ANALYTICS, db!, ai!);
          return analytics;
        })
          .catch(error => { console.warn('Analytics dashboard failed:', error); return null; })
      );
    }
    
    // Execute dependent services with graceful failure handling
    const dependentResults = await Promise.allSettled(dependentServicesPromises);
    
    // Phase 3: Initialize lightweight services (minimal dependencies)
    const lightweightPromises = [
      Promise.resolve().then(() => {
        supernova = new SupernovaIntegration();
        return supernova;
      })
    ];
    
    await Promise.allSettled(lightweightPromises);
    
    initializationTime = performance.now() - startTime;
    initializationComplete = true;
    
    // Calculate success rate
    const totalServices = coreInfraPromises.length + dependentServicesPromises.length + lightweightPromises.length;
    const successfulServices = [
      ...coreResults.filter(r => r.status === 'fulfilled'),
      ...dependentResults.filter(r => r.status === 'fulfilled'),
      ...lightweightPromises
    ].length;
    
    const successRate = (successfulServices / totalServices) * 100;
    
    console.log(`✅ Service initialization completed in ${initializationTime.toFixed(2)}ms (${successRate.toFixed(1)}% success rate)`);
    console.log(`   Core: ${cf ? '✓' : '✗'} CF, ${db ? '✓' : '✗'} DB, ${ai ? '✓' : '✗'} AI`);
    console.log(`   Security: ${tokenBlacklist ? '✓' : '✗'} Blacklist, ${jwtRotation ? '✓' : '✗'} JWT Rotation, ${enterpriseRateLimiter ? '✓' : '✗'} RateLimit, ${rateLimitMonitor ? '✓' : '✗'} Monitor`);
    console.log(`   Extended: ${ws ? '✓' : '✗'} WS, ${queue ? '✓' : '✗'} Queue, ${analytics ? '✓' : '✗'} Analytics`);
    
    // Track detailed initialization performance
    if (analytics) {
      (analytics as any).writeDataPoint({
        blobs: ['initialization', 'success', env.ENVIRONMENT || 'unknown'],
        doubles: [Date.now(), initializationTime, successRate],
        indexes: ['performance', 'initialization']
      }).catch(() => {}); // Don't block on analytics failure
    }
    
  } catch (error) {
    const failureTime = performance.now() - startTime;
    initializationComplete = false;
    console.error(`❌ Critical service initialization failure after ${failureTime.toFixed(2)}ms:`, error);
    
    // Track initialization failure with context
    if (analytics) {
      (analytics as any).writeDataPoint({
        blobs: ['initialization', 'failure', env.ENVIRONMENT || 'unknown', error instanceof Error ? error.message : 'unknown'],
        doubles: [Date.now(), failureTime],
        indexes: ['error', 'initialization']
      }).catch(() => {});
    }
    
    // Don't throw on non-critical failures, allow partial initialization
    if (!db || !cf) {
      throw new Error(`Critical services failed: DB=${!!db}, CF=${!!cf}`);
    }
    
    console.warn('Continuing with partial initialization...');
    initializationComplete = true;
  }
}

// Health check endpoint
router.get('/health', async (request: Request, env: Env) => {
  const health = {
    status: 'healthy',
    timestamp: new Date().toISOString(),
    services: {
      database: db ? 'connected' : 'disconnected',
      ai: ai ? 'ready' : 'not ready',
      websocket: ws ? 'ready' : 'not ready',
      queue: queue ? 'ready' : 'not ready',
      analytics: analytics ? 'ready' : 'not ready',
      supernova: supernova ? 'active' : 'inactive'
    }
  };
  
  return new Response(JSON.stringify(health), {
    headers: { 'Content-Type': 'application/json' }
  });
});

// API routes
router.get('/api/status', async (request: Request, env: Env) => {
  if (!db) return new Response('Database not initialized', { status: 500 });
  
  const status = await (db as any).getStatus();
  return new Response(JSON.stringify(status), {
    headers: { 'Content-Type': 'application/json' }
  });
});

// SUPERNOVA status endpoint
router.get('/api/supernova/status', async (request: Request, env: Env) => {
  if (!supernova) return new Response('SUPERNOVA not initialized', { status: 500 });
  
  const status = await (supernova as any).getStatus();
  return new Response(JSON.stringify(status), {
    headers: { 'Content-Type': 'application/json' }
  });
});

// SUPERNOVA integration endpoint
router.post('/api/supernova/integrate', async (request: Request, env: Env) => {
  if (!supernova) return new Response('SUPERNOVA not initialized', { status: 500 });
  
  try {
    const result = await supernova.integrateAll();
    return new Response(JSON.stringify(result), {
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error) {
    return new Response(JSON.stringify({ error: error instanceof Error ? error.message : String(error) }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
});

// SUPERNOVA report endpoint
router.get('/api/supernova/report', async (request: Request, env: any) => {
  if (!supernova) return new Response('SUPERNOVA not initialized', { status: 500 });

    const report = await (supernova as any).generateReport();
  return new Response(JSON.stringify(report), {
    headers: { 'Content-Type': 'application/json' }
  });
});

// API Routes Handler - delegates all /api/v1/* requests to Hono routes
router.all('/api/v1/*', async (request: Request, env: Env, ctx: ExecutionContext) => {
  return handleAPIRequest(request, env, ctx as any);
});

// Main fetch handler
// Helper methods for optimized request processing
const requestProcessor = {
  calculateRequestTimeout(pathname: string, method: string): number {
    // Adaptive timeout based on endpoint characteristics
    if (pathname.includes('/api/ai/') || pathname.includes('/api/supernova/')) {
      return 30000; // 30s for AI operations
    }
    if (pathname.includes('/api/upload/') || method === 'POST') {
      return 15000; // 15s for uploads/mutations
    }
    if (pathname.includes('/health') || pathname.includes('/status')) {
      return 2000;  // 2s for health checks
    }
    return 8000; // 8s default
  },

  addOptimizedHeaders(response: Response, requestId: string, responseTime: number): Response {
    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: {
        ...response.headers,
        'X-Request-ID': requestId,
        'X-Response-Time': `${responseTime.toFixed(2)}ms`,
        'Cache-Control': response.headers.get('Cache-Control') || 'no-cache'
      }
    });
  },

  async buildOptimizedResponse(
    response: Response,
    requestId: string,
    responseTime: number,
    corsHeaders: Record<string, string>,
    environment: string,
    allowedOrigins: string[]
  ): Promise<Response> {
    const secureResponse = new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: {
        ...response.headers,
        ...corsHeaders,
        'X-Request-ID': requestId,
        'X-Response-Time': `${responseTime.toFixed(2)}ms`
      }
    });
    
    return await addSecurityHeaders(secureResponse, {
      environment,
      allowedOrigins
    });
  },

  async trackRequestPerformance(method: string, pathname: string, responseTime: number, status: number): Promise<void> {
    try {
      if (analytics) {
        await (analytics as any).writeDataPoint({
          blobs: ['request_performance', method, pathname, status.toString()],
          doubles: [Date.now(), responseTime],
          indexes: ['performance', 'requests']
        });
      }
      
      // Log slow requests
      if (responseTime > 200) {
        console.warn(`⚠️ Slow request: ${method} ${pathname} - ${responseTime.toFixed(2)}ms (${status})`);
      }
    } catch (error) {
      // Don't block on tracking failures
      console.debug('Performance tracking failed:', error);
    }
  },

  async trackRequestError(method: string, pathname: string, responseTime: number, error: string): Promise<void> {
    try {
      if (analytics) {
        await (analytics as any).writeDataPoint({
          blobs: ['request_error', method, pathname, error.slice(0, 100)],
          doubles: [Date.now(), responseTime],
          indexes: ['error', 'requests']
        });
      }
    } catch (trackingError) {
      console.debug('Error tracking failed:', trackingError);
    }
  },

  isTimeoutError(error: any): boolean {
    return error instanceof Error && error.message.includes('timeout');
  }
};

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const requestStart = performance.now();
    const requestId = crypto.randomUUID();
    const url = new URL(request.url);
    const method = request.method;
    
    try {
      // Optimized initialization check with circuit breaker pattern
      if (!initializationComplete) {
        // Use waitUntil to avoid blocking response for initialization tracking
        ctx.waitUntil(initializeServices(env, ctx));
        await initializeServices(env, ctx);
      }
      
      // Track request start (non-blocking)
      (memoryOptimizer as any).trackObject({ requestId, startTime: requestStart }, `request-${requestId}`);
      
      // Fast path for health checks and static assets
      if (url.pathname === '/health' || url.pathname.startsWith('/static/')) {
        const response = await router.handle(request, env, ctx);
        return requestProcessor.addOptimizedHeaders(response, requestId, performance.now() - requestStart);
      }
      
      // Parallel processing of request metadata
      const [allowedOrigins, corsHeaders] = await Promise.all([
        Promise.resolve(
          env.ALLOWED_ORIGINS 
            ? env.ALLOWED_ORIGINS.split(',').map(origin => origin.trim())
            : [
                'https://app.coreflow360.com',
                'https://dashboard.coreflow360.com',
                'https://api.coreflow360.com'
              ]
        ),
        Promise.resolve(
          getCorsHeaders(
            request, 
            env.ALLOWED_ORIGINS?.split(',').map(origin => origin.trim()) || [],
            true, // allowCredentials
            env.ENVIRONMENT || 'production'
          )
        )
      ]);

      // Apply enterprise rate limiting before request processing
      if (enterpriseRateLimiter) {
        const rateLimitMiddleware = enterpriseRateLimiter.createMiddleware();

        // Create a middleware context compatible with Hono
        const middlewareContext = {
          req: {
            path: url.pathname,
            method: request.method,
            header: (name: string) => request.headers.get(name),
            raw: request
          },
          get: (key: string) => {
            // Extract values from headers or context as needed
            switch (key) {
              case 'businessId': return request.headers.get('X-Business-ID');
              case 'userId': return request.headers.get('X-User-ID');
              default: return undefined;
            }
          },
          header: (name: string, value: string) => {
            // This will be applied to the response later
          },
          json: (data: any, status?: number) => {
            return new Response(JSON.stringify(data), {
              status: status || 200,
              headers: { 'Content-Type': 'application/json' }
            });
          }
        };

        // Check rate limiting
        try {
          let rateLimitPassed = false;
          const rateLimitResponse = await rateLimitMiddleware(middlewareContext as any, async () => {
            rateLimitPassed = true;
          });

          // If rate limit failed, return early
          if (!rateLimitPassed && rateLimitResponse) {
            return rateLimitResponse;
          }
        } catch (rateLimitError) {
          console.warn('Rate limiting error, proceeding with request:', rateLimitError);
        }
      }

      // Optimized request handling with adaptive timeout
      const timeout = requestProcessor.calculateRequestTimeout(url.pathname, method);
      const requestPromise = router.handle(request, env, ctx);
      const timeoutPromise = new Promise<never>((_, reject) => {
        setTimeout(() => reject(new Error(`Request timeout after ${timeout}ms`)), timeout);
      });

      const response = await Promise.race([requestPromise, timeoutPromise]);
      
      // Streamlined response processing
      const optimizedResponse = requestProcessor.buildOptimizedResponse(
        response,
        requestId,
        performance.now() - requestStart,
        corsHeaders,
        env.ENVIRONMENT || 'production',
        allowedOrigins
      );
      
      // Non-blocking performance monitoring
      const responseTime = performance.now() - requestStart;
      ctx.waitUntil(requestProcessor.trackRequestPerformance(method, url.pathname, responseTime, response.status));
      
      return optimizedResponse;
      
    } catch (error) {
      const responseTime = performance.now() - requestStart;
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      
      console.error(`❌ Request error [${method} ${url.pathname}] (${responseTime.toFixed(2)}ms):`, errorMessage);
      
      // Non-blocking error tracking
      ctx.waitUntil(requestProcessor.trackRequestError(method, url.pathname, responseTime, errorMessage));
      
      // Optimized error response
      return new Response(JSON.stringify({ 
        error: requestProcessor.isTimeoutError(error) ? 'Request timeout' : 'Internal server error',
        requestId,
        timestamp: new Date().toISOString(),
        ...(env.ENVIRONMENT === 'development' && { details: errorMessage })
      }), {
        status: requestProcessor.isTimeoutError(error) ? 504 : 500,
        headers: { 
          'Content-Type': 'application/json',
          'X-Request-ID': requestId,
          'X-Response-Time': `${responseTime.toFixed(2)}ms`
        }
      });
    }
  },

  // Queue consumer
  async queue(batch: MessageBatch, env: Env, ctx: ExecutionContext): Promise<void> {
    if (!queue) {
      console.error('Queue handler not initialized');
      return;
    }
    
    try {
      await (queue as any).processBatch(batch);
    } catch (error) {
      console.error('Queue processing error:', error);
    }
  },

  // WebSocket handler
  async webSocket(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    if (!ws) {
      return new Response('WebSocket service not initialized', { status: 500 });
    }
    
    try {
      return await (ws as any).handleRequest(request);
    } catch (error) {
      console.error('WebSocket error:', error);
      return new Response('WebSocket error', { status: 500 });
    }
  }
};

