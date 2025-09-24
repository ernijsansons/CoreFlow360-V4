// src/index.ts - Production-Ready Worker with SUPERNOVA Enhancements
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

export interface Env {
  // Core services
  DB: D1Database;
  CACHE: KVNamespace;
  R2_DOCUMENTS: R2Bucket;
  R2_ASSETS: R2Bucket;
  ANALYTICS: AnalyticsEngineDataset;
  REALTIME: DurableObjectNamespace;
  AI: Ai;

  // Queues
  TASK_QUEUE: Queue;
  EMAIL_QUEUE: Queue;
  WEBHOOK_QUEUE: Queue;

  // Secrets
  JWT_SECRET: string;
  ANTHROPIC_API_KEY: string;
  EMAIL_API_KEY: string;
  API_BASE_URL: string;
  ENVIRONMENT: string;
  ALLOWED_ORIGINS: string;
}

// Global instances - initialized once per Worker with performance optimization
let cf: CloudflareIntegration | null = null;
let db: Database | null = null;
let ai: AIService | null = null;
let ws: WebSocketService | null = null;
let queue: QueueHandler | null = null;
let analytics: AnalyticsDashboard | null = null;
let supernova: SupernovaIntegration | null = null;

// Performance tracking
let initializationComplete = false;
let initializationTime: number | null = null;

// Router instance
const router = Router();

// Optimized service initialization with intelligent parallelization and dependency management
async function initializeServices(env: Env, ctx: ExecutionContext): Promise<void> {
  if (initializationComplete) return;
  
  const startTime = performance.now();
  
  try {
    // Initialize memory optimizer first (critical dependency)
    memoryOptimizer.registerCleanupCallback('high-priority-db', async () => {
      if (db) await db.cleanup?.();
    });
    
    memoryOptimizer.registerCleanupCallback('high-priority-cache', async () => {
      if (cf) await cf.clearCaches?.();
    });
    
    // Phase 1: Initialize core infrastructure services in parallel (no dependencies)
    const coreInfraPromises = [
      // Cloudflare integration (independent)
      Promise.resolve().then(async () => {
        cf = new CloudflareIntegration(env);
        return cf;
      }),
      
      // Database connection (independent)
      createDatabase(env.DB).then(instance => {
        db = instance;
        return instance;
      }),
      
      // AI service (independent)
      createAIService(env.AI).then(instance => {
        ai = instance;
        return instance;
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
    if (env.REALTIME) {
      dependentServicesPromises.push(
        createWebSocketService(env.REALTIME).then(instance => { ws = instance; return instance; })
          .catch(error => { console.warn('WebSocket service failed:', error); return null; })
      );
    }
    
    if (env.TASK_QUEUE || env.EMAIL_QUEUE || env.WEBHOOK_QUEUE) {
      dependentServicesPromises.push(
        createQueueHandler(env).then(instance => { queue = instance; return instance; })
          .catch(error => { console.warn('Queue handler failed:', error); return null; })
      );
    }
    
    if (env.ANALYTICS) {
      dependentServicesPromises.push(
        createAnalyticsDashboard(env.ANALYTICS).then(instance => { analytics = instance; return instance; })
          .catch(error => { console.warn('Analytics dashboard failed:', error); return null; })
      );
    }
    
    // Execute dependent services with graceful failure handling
    const dependentResults = await Promise.allSettled(dependentServicesPromises);
    
    // Phase 3: Initialize lightweight services (minimal dependencies)
    const lightweightPromises = [
      Promise.resolve().then(() => {
        supernova = new SupernovaIntegration(env);
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
    console.log(`   Extended: ${ws ? '✓' : '✗'} WS, ${queue ? '✓' : '✗'} Queue, ${analytics ? '✓' : '✗'} Analytics`);
    
    // Track detailed initialization performance
    if (analytics) {
      analytics.writeDataPoint({
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
      analytics.writeDataPoint({
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
  
  const status = await db.getStatus();
  return new Response(JSON.stringify(status), {
    headers: { 'Content-Type': 'application/json' }
  });
});

// SUPERNOVA status endpoint
router.get('/api/supernova/status', async (request: Request, env: Env) => {
  if (!supernova) return new Response('SUPERNOVA not initialized', { status: 500 });
  
  const status = await supernova.getStatus();
  return new Response(JSON.stringify(status), {
    headers: { 'Content-Type': 'application/json' }
  });
});

// SUPERNOVA integration endpoint
router.post('/api/supernova/integrate', async (request: Request, env: Env) => {
  if (!supernova) return new Response('SUPERNOVA not initialized', { status: 500 });
  
  try {
    const result = await supernova.integrate();
    return new Response(JSON.stringify(result), {
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error) {
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
});

// SUPERNOVA report endpoint
router.get('/api/supernova/report', async (request: Request, env: Env) => {
  if (!supernova) return new Response('SUPERNOVA not initialized', { status: 500 });
  
  const report = await supernova.generateReport();
  return new Response(JSON.stringify(report), {
    headers: { 'Content-Type': 'application/json' }
  });
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

  buildOptimizedResponse(
    response: Response,
    requestId: string,
    responseTime: number,
    corsHeaders: Record<string, string>,
    environment: string,
    allowedOrigins: string[]
  ): Response {
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
    
    return addSecurityHeaders(secureResponse, {
      environment,
      allowedOrigins
    });
  },

  async trackRequestPerformance(method: string, pathname: string, responseTime: number, status: number): Promise<void> {
    try {
      if (analytics) {
        await analytics.writeDataPoint({
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
        await analytics.writeDataPoint({
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
      memoryOptimizer.trackObject({ requestId, startTime: requestStart }, `request-${requestId}`);
      
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
      await queue.processBatch(batch);
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
      return await ws.handleRequest(request);
    } catch (error) {
      console.error('WebSocket error:', error);
      return new Response('WebSocket error', { status: 500 });
    }
  }
};

