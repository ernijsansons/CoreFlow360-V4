// src/index.ts - Production-Ready Worker with SUPERNOVA Enhancements
import { Router } from 'itty-router';
import { CloudflareIntegration } from './cloudflare/CloudflareIntegration.js';
import { SmartCaching } from './cloudflare/performance/SmartCaching.js';
import { createDatabase, Database } from './database/db.js';
import { createAIService, AIService } from './ai/ai-service.js';
import { createWebSocketService, WebSocketService } from './realtime/websocket-service.js';
import { createQueueHandler, QueueHandler } from './jobs/queue-handler.js';
import { addSecurityHeaders, rateLimitByIP, validateJWT,
  detectSuspiciousActivity, logSecurityEvent, corsHeaders } from './middleware/security.js';
import { createAnalyticsDashboard, AnalyticsDashboard } from './analytics/dashboard.js';
import { SupernovaIntegration } from './supernova/supernova-integration.js';
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
}

// Global instances - initialized once per Worker
let cf: CloudflareIntegration | null = null;
let cache: SmartCaching | null = null;
let db: Database | null = null;
let ai: AIService | null = null;
let websocket: WebSocketService | null = null;
let analyticsService: AnalyticsDashboard | null = null;

// Enhanced performance monitoring with security
const withMetrics = (handler: Function) => {
  return async (request: Request, env: Env, ctx: ExecutionContext) => {
    const start = Date.now();

    try {
      // Security checks
      const suspiciousActivity = detectSuspiciousActivity(request);
      if (suspiciousActivity.suspicious) {
        ctx.waitUntil(
          logSecurityEvent('suspicious_activity', {
            ip: request.headers.get('CF-Connecting-IP'),
            userAgent: request.headers.get('User-Agent'),
            url: request.url,
            reasons: suspiciousActivity.reasons,
            severity: 'medium'
          }, env.ANALYTICS)
        );
      }

      // Execute handler
      let response = await handler(request, env, ctx);

      // Add security headers
      response = await addSecurityHeaders(response, {
        environment: env.ENVIRONMENT,
        enableHSTS: true,
        reportUri: '/api/security/csp-report'
      });

      // Add CORS headers if needed
      if (request.method === 'OPTIONS') {
        const corsHeadersMap = corsHeaders(['https://app.coreflow360.com']);
        Object.entries(corsHeadersMap).forEach(([key, value]) => {
          response.headers.set(key, value);
        });
      }

      // Non-blocking analytics
      ctx.waitUntil(
        env.ANALYTICS.writeDataPoint({
          indexes: [request.method, response.status.toString()],
          blobs: [new URL(request.url).pathname, env.ENVIRONMENT],
          doubles: [Date.now() - start, response.status]
        })
      );

      return response;
    } catch (error) {
      // Track errors with security context
      ctx.waitUntil(
        env.ANALYTICS.writeDataPoint({
          indexes: [request.method, 'error'],
          blobs: [new URL(request.url).pathname, error.message],
          doubles: [Date.now() - start, 500]
        })
      );

      // Log security events on errors
      ctx.waitUntil(
        logSecurityEvent('error', {
          ip: request.headers.get('CF-Connecting-IP'),
          userAgent: request.headers.get('User-Agent'),
          url: request.url,
          error: error.message,
          severity: 'high'
        }, env.ANALYTICS)
      );

      throw error;
    }
  };
};

// Initialize Cloudflare services
const initializeServices = async (env: Env, businessId?: string) => {
  if (!cf) {
    cf = new CloudflareIntegration(env);
    cache = new SmartCaching(env);
    db = createDatabase(env.DB, env.CACHE);
    ai = createAIService(env.AI, env.ANTHROPIC_API_KEY, env.CACHE);
    analyticsService = createAnalyticsDashboard(env.ANALYTICS, env.CACHE, db, ai);

    await cf.initialize();
  }

  // Initialize WebSocket service per business
  if (businessId && (!websocket || websocket.businessId !== businessId)) {
    websocket = createWebSocketService(env.REALTIME, businessId);
  }

  return { cf, cache, db, ai, websocket, analyticsService };
};

// Enhanced authentication middleware
const authenticate = async (request: Request, env: Env) => {
  // Skip auth for health checks and some public endpoints
  const url = new URL(request.url);
  const publicPaths = ['/api/health', '/realtime/connect', '/api/security/csp-report'];

  if (publicPaths.some(path => url.pathname.startsWith(path))) {
    return;
  }

  const token = request.headers.get('Authorization')?.replace('Bearer ', '');
  if (!token) {
    return new Response(JSON.stringify({
      error: 'Authentication required',
      code: 'MISSING_TOKEN'
    }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  // Validate JWT
  const jwtValidation = await validateJWT(token, env.JWT_SECRET);
  if (!jwtValidation.valid) {
    // Log failed authentication attempt
    await logSecurityEvent('auth_failure', {
      ip: request.headers.get('CF-Connecting-IP'),
      userAgent: request.headers.get('User-Agent'),
      error: jwtValidation.error,
      severity: 'high'
    }, env.ANALYTICS);

    return new Response(JSON.stringify({
      error: 'Invalid token',
      code: 'INVALID_TOKEN',
      details: jwtValidation.error
    }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  // Add user context to request
  (request as any).user = jwtValidation.payload;

  // Validate with Cloudflare security layer if available
  try {
    const { cf } = await initializeServices(env);
    const validation = await cf.Security.validateRequest(request);

    if (!validation.allowed) {
      await logSecurityEvent('security_block', {
        ip: request.headers.get('CF-Connecting-IP'),
        userAgent: request.headers.get('User-Agent'),
        reason: validation.reason || 'Security policy violation',
        severity: 'high'
      }, env.ANALYTICS);

      return new Response(JSON.stringify({
        error: 'Access denied',
        code: 'SECURITY_BLOCK'
      }), {
        status: 403,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  } catch (error) {
    // Continue if Cloudflare security check fails
  }
};

// Enhanced rate limiting middleware
const rateLimit = async (request: Request, env: Env) => {
  // Skip rate limiting for some endpoints
  const url = new URL(request.url);
  const exemptPaths = ['/api/health'];

  if (exemptPaths.some(path => url.pathname.startsWith(path))) {
    return;
  }

  // Use enhanced rate limiting
  const rateResult = await rateLimitByIP(request, env.CACHE, 100, 60);

  if (!rateResult.allowed) {
    // Log rate limit violation
    await logSecurityEvent('rate_limit_exceeded', {
      ip: request.headers.get('CF-Connecting-IP'),
      userAgent: request.headers.get('User-Agent'),
      path: url.pathname,
      severity: 'medium'
    }, env.ANALYTICS);

    return new Response(JSON.stringify({
      error: 'Rate limit exceeded',
      code: 'RATE_LIMIT_EXCEEDED',
      retryAfter: 60
    }), {
      status: 429,
      headers: {
        'Content-Type': 'application/json',
        'X-RateLimit-Limit': '100',
        'X-RateLimit-Remaining': '0',
        'X-RateLimit-Reset': Math.floor(rateResult.resetTime / 1000).toString(),
        'Retry-After': '60'
      }
    });
  }

  // Add rate limit headers to successful responses (handled in withMetrics)
  (request as any).rateLimit = rateResult;
};

// Tenant validation middleware
const validateTenant = async (request: Request, env: Env) => {
  // Extract business ID from subdomain or header
  const businessId = request.headers.get('X-Business-ID') || 'default';

  const { db } = await initializeServices(env);

  // Validate business exists
  const business = await db.getBusiness(businessId);

  if (!business) {
    return new Response('Invalid business', { status: 400 });
  }

  // Add business to request context (for downstream use)
  (request as any).businessId = businessId;
};

// Smart cache checker
const checkCache = async (request: Request, env: Env) => {
  if (request.method !== 'GET') return null;

  const { cache } = await initializeServices(env);
  const cacheKey = `api:${new URL(request.url).pathname}`;

  const cached = await cache.get(cacheKey);
  if (cached.hit) {
    return new Response(JSON.stringify(cached.data), {
      headers: {
        'Content-Type': 'application/json',
        'X-Cache': 'HIT',
        'Cache-Control': 'public, max-age=300'
      }
    });
  }

  return null;
};

// Cache updater
const updateCache = async (request: Request, response: Response, env: Env) => {
  if (request.method !== 'GET' || !response.ok) return;

  const { cache } = await initializeServices(env);
  const cacheKey = `api:${new URL(request.url).pathname}`;
  const data = await response.clone().json();

  await cache.set(cacheKey, data, {
    ttl: 300 // 5 minutes
  });
};

// Route handlers
const health = async (request: Request, env: Env, ctx: ExecutionContext) => {
  const { cf } = await initializeServices(env);
  const health = await cf.healthCheck();

  return new Response(JSON.stringify({
    status: health.healthy ? 'healthy' : 'degraded',
    timestamp: new Date().toISOString(),
    services: health,
    environment: env.ENVIRONMENT
  }), {
    headers: { 'Content-Type': 'application/json' },
    status: health.healthy ? 200 : 503
  });
};

const aiChat = async (request: Request, env: Env, ctx: ExecutionContext) => {
  const { message, context, history, complexity } = await request.json();
  const businessId = (request as any).businessId;

  const { ai } = await initializeServices(env);

  const businessContext = {
    businessId,
    ...context
  };

  try {
    const result = await ai.route({
      prompt: message,
      messages: history,
      context: businessContext,
      complexity
    });

    // Notify realtime users of AI response
    const { websocket } = await initializeServices(env, businessId);
    if (websocket) {
      await websocket.notifyAIResponse(businessId, context?.userId || 'anonymous',
        crypto.randomUUID(), result);
    }

    return new Response(JSON.stringify({
      response: result.content,
      model: result.model,
      cached: result.cached,
      cost: result.cost
    }), {
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error) {
    return new Response(JSON.stringify({
      error: 'AI service unavailable',
      message: error.message
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};

const getData = async (request: Request, env: Env, ctx: ExecutionContext) => {
  const url = new URL(request.url);
  const table = url.pathname.split('/')[3];
  const businessId = (request as any).businessId;
  const limit = parseInt(url.searchParams.get('limit') || '10');
  const offset = parseInt(url.searchParams.get('offset') || '0');

  const { db } = await initializeServices(env);

  let results;
  switch (table) {
    case 'users':
      results = await db.getBusinessUsers(businessId, limit);
      break;
    case 'ledger':
      const accountId = url.searchParams.get('account_id');
      results = await db.getLedgerEntries(businessId, accountId || undefined, limit);
      break;
    case 'audit':
      results = await db.getAuditLogs(businessId, limit);
      break;
    default:
      return new Response('Invalid table', { status: 400 });
  }

  return new Response(JSON.stringify({ results, total: results.length }), {
    headers: { 'Content-Type': 'application/json' }
  });
};

const createData = async (request: Request, env: Env, ctx: ExecutionContext) => {
  const url = new URL(request.url);
  const table = url.pathname.split('/')[3];
  const businessId = (request as any).businessId;
  const data = await request.json();

  const { db } = await initializeServices(env);

  const id = crypto.randomUUID();

  switch (table) {
    case 'users':
      await db.createUser(id, businessId, data.email, data.role, data.settings);
      break;
    case 'ledger':
      await db.createLedgerEntry(
        id, businessId, data.account_id, data.amount, data.type,
        data.description, data.metadata
      );
      break;
    case 'businesses':
      await db.createBusiness(id, data.name, data.settings);
      break;
    default:
      return new Response('Invalid table', { status: 400 });
  }

  // Log the action
  await db.logAudit(businessId, `create_${table}`, undefined, table, { created_id: id });

  // Notify realtime users
  const { websocket } = await initializeServices(env, businessId);
  if (websocket) {
    await websocket.notifyDataUpdate(businessId, table, 'create', { id, ...data });
  }

  return new Response(JSON.stringify({ id, success: true }), {
    headers: { 'Content-Type': 'application/json' },
    status: 201
  });
};

const updateData = async (request: Request, env: Env, ctx: ExecutionContext) => {
  const url = new URL(request.url);
  const table = url.pathname.split('/')[3];
  const id = url.pathname.split('/')[4];
  const data = await request.json();

  const updates = Object.keys(data).map(key => `${key} = ?`).join(', ');

  const result = await env.DB.prepare(
    `UPDATE ${table} SET ${updates} WHERE id = ?`
  ).bind(...Object.values(data), id).run();

  return new Response(JSON.stringify(result), {
    headers: { 'Content-Type': 'application/json' }
  });
};

const deleteData = async (request: Request, env: Env, ctx: ExecutionContext) => {
  const url = new URL(request.url);
  const table = url.pathname.split('/')[3];
  const id = url.pathname.split('/')[4];

  const result = await env.DB.prepare(
    `DELETE FROM ${table} WHERE id = ?`
  ).bind(id).run();

  return new Response(JSON.stringify(result), {
    headers: { 'Content-Type': 'application/json' }
  });
};

const executeWorkflow = async (request: Request, env: Env, ctx: ExecutionContext) => {
  const { workflowId, input } = await request.json();

  // Store workflow execution request
  await env.CACHE.put(`workflow:${workflowId}:${Date.now()}`, JSON.stringify({
    type: 'workflow_execute',
    workflowId,
    input,
    timestamp: Date.now(),
    status: 'queued'
  }), { expirationTtl: 3600 });

  return new Response(JSON.stringify({
    status: 'queued',
    workflowId
  }), {
    headers: { 'Content-Type': 'application/json' }
  });
};

const getDashboard = async (request: Request, env: Env, ctx: ExecutionContext) => {
  const businessId = (request as any).businessId;
  const url = new URL(request.url);
  const period = url.searchParams.get('period') as '1h' | '24h' | '7d' | '30d' || '24h';

  try {
    const { analyticsService } = await initializeServices(env, businessId);

    // Get comprehensive dashboard data
    const dashboardData = await analyticsService!.getDashboardData(businessId, period);

    return new Response(JSON.stringify({
      success: true,
      data: dashboardData,
      businessId,
      period
    }), {
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error) {
    console.error('Dashboard error:', error);
    return new Response(JSON.stringify({
      error: 'Failed to generate dashboard',
      message: error.message
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};

// New specialized routes
const getAccountBalance = async (request: Request, env: Env, ctx: ExecutionContext) => {
  const url = new URL(request.url);
  const accountId = url.pathname.split('/')[4];
  const businessId = (request as any).businessId;

  const { db } = await initializeServices(env);
  const balance = await db.getAccountBalance(businessId, accountId);

  return new Response(JSON.stringify({
    accountId,
    balance,
    timestamp: new Date().toISOString()
  }), {
    headers: { 'Content-Type': 'application/json' }
  });
};

const createLedgerTransaction = async (request: Request, env: Env, ctx: ExecutionContext) => {
  const businessId = (request as any).businessId;
  const { entries } = await request.json();

  const { db } = await initializeServices(env);

  // Create ledger entries with proper UUIDs
  const ledgerEntries = entries.map((entry: any) => ({
    id: crypto.randomUUID(),
    business_id: businessId,
    ...entry
  }));

  await db.createLedgerTransaction(ledgerEntries);

  // Log the transaction
  await db.logAudit(businessId, 'create_transaction', undefined, 'ledger', {
    entry_count: entries.length,
    total_amount: entries.reduce((sum: number, e: any) => sum + e.amount, 0)
  });

  return new Response(JSON.stringify({
    success: true,
    entries: ledgerEntries.length,
    timestamp: new Date().toISOString()
  }), {
    headers: { 'Content-Type': 'application/json' },
    status: 201
  });
};

// AI-powered document analysis
const analyzeDocument = async (request: Request, env: Env, ctx: ExecutionContext) => {
  const { content, analysisType = 'summary' } = await request.json();
  const businessId = (request as any).businessId;

  const { ai, db } = await initializeServices(env);

  try {
    // Get business context
    const business = await db.getBusiness(businessId);
    const businessContext = {
      businessId,
      industry: business?.settings?.industry,
      preferences: business?.settings
    };

    const result = await ai.analyzeDocument(content, analysisType, businessContext);

    // Log the analysis
    await db.logAudit(businessId, 'document_analysis', undefined, 'ai', {
      analysis_type: analysisType,
      content_length: content.length,
      model: result.model
    });

    return new Response(JSON.stringify({
      analysis: result.content,
      model: result.model,
      cached: result.cached,
      cost: result.cost
    }), {
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error) {
    return new Response(JSON.stringify({
      error: 'Document analysis failed',
      message: error.message
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};

// AI-powered business insights
const generateInsights = async (request: Request, env: Env, ctx: ExecutionContext) => {
  const { insightType = 'financial' } = await request.json();
  const businessId = (request as any).businessId;

  const { ai, db } = await initializeServices(env);

  try {
    // Get business data for insights
    const [business, stats] = await Promise.all([
      db.getBusiness(businessId),
      db.getBusinessStats(businessId)
    ]);

    const businessContext = {
      businessId,
      industry: business?.settings?.industry,
      preferences: business?.settings
    };

    const result = await ai.generateInsights(stats, insightType, businessContext);

    // Log the insight generation
    await db.logAudit(businessId, 'generate_insights', undefined, 'ai', {
      insight_type: insightType,
      model: result.model
    });

    return new Response(JSON.stringify({
      insights: result.content,
      data: stats,
      model: result.model,
      cached: result.cached,
      cost: result.cost
    }), {
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error) {
    return new Response(JSON.stringify({
      error: 'Insight generation failed',
      message: error.message
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};

// Semantic search with embeddings
const semanticSearch = async (request: Request, env: Env, ctx: ExecutionContext) => {
  const { query, limit = 10 } = await request.json();
  const businessId = (request as any).businessId;

  const { ai } = await initializeServices(env);

  try {
    // Generate embedding for search query
    const queryEmbedding = await ai.generateEmbedding(query);

    // In a real implementation, you'd search a vector database
    // For now, return the embedding and a mock response
    return new Response(JSON.stringify({
      query,
      embedding: queryEmbedding,
      results: [], // Would contain actual search results
      message: 'Semantic search capability enabled (vector database integration required)'
    }), {
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error) {
    return new Response(JSON.stringify({
      error: 'Semantic search failed',
      message: error.message
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};

// AI service health check
const aiHealth = async (request: Request, env: Env, ctx: ExecutionContext) => {
  const { ai } = await initializeServices(env);

  try {
    const health = await ai.healthCheck();

    return new Response(JSON.stringify({
      status: 'healthy',
      services: health,
      timestamp: new Date().toISOString()
    }), {
      headers: { 'Content-Type': 'application/json' },
      status: Object.values(health).every(Boolean) ? 200 : 503
    });
  } catch (error) {
    return new Response(JSON.stringify({
      status: 'unhealthy',
      error: error.message,
      timestamp: new Date().toISOString()
    }), {
      status: 503,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};

// WebSocket connection handler
const handleWebSocket = async (request: Request, env: Env, ctx: ExecutionContext) => {
  const url = new URL(request.url);
  const businessId = url.searchParams.get('business') || (request as any).businessId;

  if (!businessId) {
    return new Response('Business ID required', { status: 400 });
  }

  // Get the Durable Object for this business
  const id = env.REALTIME.idFromName(`business:${businessId}`);
  const coordinator = env.REALTIME.get(id);

  // Forward the WebSocket upgrade to the Durable Object
  return coordinator.fetch(request);
};

// Realtime status endpoint
const getRealtimeStatus = async (request: Request, env: Env, ctx: ExecutionContext) => {
  const businessId = (request as any).businessId;

  const { websocket } = await initializeServices(env, businessId);

  try {
    const stats = await websocket!.getStats(businessId);

    return new Response(JSON.stringify({
      status: 'active',
      business: businessId,
      ...stats
    }), {
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error) {
    return new Response(JSON.stringify({
      status: 'error',
      error: error.message
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};

// Broadcast message to business
const broadcastMessage = async (request: Request, env: Env, ctx: ExecutionContext) => {
  const businessId = (request as any).businessId;
  const { channel, message, target } = await request.json();

  const { websocket } = await initializeServices(env, businessId);

  try {
    if (target === 'business') {
      await websocket!.broadcastToBusiness(businessId, {
        type: 'broadcast',
        data: message
      });
    } else if (target === 'channel' && channel) {
      await websocket!.broadcastToChannel(businessId, channel, {
        type: 'broadcast',
        data: message
      });
    } else if (target === 'user' && channel) {
      await websocket!.sendToUser(businessId, channel, {
        type: 'broadcast',
        data: message
      });
    } else {
      return new Response(JSON.stringify({
        error: 'Invalid broadcast target'
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    return new Response(JSON.stringify({
      success: true,
      broadcast: { target, channel, message }
    }), {
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error) {
    return new Response(JSON.stringify({
      error: 'Broadcast failed',
      message: error.message
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};

// Job management endpoints
const queueJob = async (request: Request, env: Env, ctx: ExecutionContext) => {
  const businessId = (request as any).businessId;
  const job = await request.json();

  // Add business context to job
  job.businessId = businessId;
  job.requestId = crypto.randomUUID();

  try {
    // Route to appropriate queue based on job type
    let queue: Queue;
    switch (job.type) {
      case 'send-email':
        queue = env.EMAIL_QUEUE;
        break;
      case 'webhook-delivery':
        queue = env.WEBHOOK_QUEUE;
        break;
      default:
        queue = env.TASK_QUEUE;
    }

    // Send job to queue
    await queue.send(JSON.stringify(job));

    // Log job creation
    const { db } = await initializeServices(env, businessId);
    await db.logAudit(businessId, 'job_queued', job.userId, 'jobs', {
      jobType: job.type,
      requestId: job.requestId,
      priority: job.priority || 'normal'
    });

    return new Response(JSON.stringify({
      success: true,
      requestId: job.requestId,
      jobType: job.type,
      status: 'queued'
    }), {
      headers: { 'Content-Type': 'application/json' },
      status: 201
    });

  } catch (error) {
    return new Response(JSON.stringify({
      error: 'Failed to queue job',
      message: error.message
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};

const getJobStatus = async (request: Request, env: Env, ctx: ExecutionContext) => {
  const url = new URL(request.url);
  const requestId = url.pathname.split('/')[4];
  const businessId = (request as any).businessId;

  try {
    // Get job status from cache or database
    const jobStatus = await env.CACHE.get(`job-status:${requestId}`, { type: 'json' });

    if (jobStatus) {
      return new Response(JSON.stringify(jobStatus), {
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Fallback to audit log
    const { db } = await initializeServices(env, businessId);
    const auditLogs = await db.query(
      `SELECT * FROM audit_log
       WHERE business_id = ? AND resource = 'jobs' AND json_extract(metadata, '$.requestId') = ?
       ORDER BY timestamp DESC LIMIT 1`,
      [businessId, requestId],
      { cache: 60 }
    );

    if (auditLogs.length > 0) {
      const log = auditLogs[0];
      const metadata = JSON.parse(log.metadata);

      return new Response(JSON.stringify({
        requestId,
        jobType: metadata.jobType,
        status: log.action.replace('job_', ''),
        timestamp: log.timestamp,
        metadata
      }), {
        headers: { 'Content-Type': 'application/json' }
      });
    }

    return new Response(JSON.stringify({
      error: 'Job not found'
    }), {
      status: 404,
      headers: { 'Content-Type': 'application/json' }
    });

  } catch (error) {
    return new Response(JSON.stringify({
      error: 'Failed to get job status',
      message: error.message
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};

const generateReport = async (request: Request, env: Env, ctx: ExecutionContext) => {
  const businessId = (request as any).businessId;
  const { reportType, filters, format = 'pdf' } = await request.json();

  const reportJob = {
    type: 'generate-report',
    businessId,
    reportType,
    reportId: crypto.randomUUID(),
    requestedBy: request.headers.get('X-User-ID') || 'anonymous',
    filters,
    format,
    priority: 'normal'
  };

  try {
    // Queue report generation
    await env.TASK_QUEUE.send(JSON.stringify(reportJob));

    // Log request
    const { db } = await initializeServices(env, businessId);
    await db.logAudit(businessId, 'report_requested', reportJob.requestedBy, 'reports', {
      reportType,
      reportId: reportJob.reportId,
      format
    });

    return new Response(JSON.stringify({
      success: true,
      reportId: reportJob.reportId,
      status: 'queued',
      estimatedTime: '2-5 minutes'
    }), {
      headers: { 'Content-Type': 'application/json' },
      status: 202
    });

  } catch (error) {
    return new Response(JSON.stringify({
      error: 'Failed to queue report generation',
      message: error.message
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};

const downloadReport = async (request: Request, env: Env, ctx: ExecutionContext) => {
  const url = new URL(request.url);
  const reportId = url.pathname.split('/')[4];
  const businessId = (request as any).businessId;

  try {
    // Check if report exists in R2
    const reportFiles = await env.R2_DOCUMENTS.list({
      prefix: `reports/${businessId}/`,
      include: ['customMetadata']
    });

    const report = reportFiles.objects.find(obj =>
      obj.key.includes(reportId)
    );

    if (!report) {
      return new Response(JSON.stringify({
        error: 'Report not found'
      }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Get report file
    const reportObject = await env.R2_DOCUMENTS.get(report.key);
    if (!reportObject) {
      return new Response('Report file not found', { status: 404 });
    }

    // Return file with appropriate headers
    const headers = new Headers();
    headers.set('Content-Type', reportObject.httpMetadata?.contentType || 'application/octet-stream');
    headers.set('Content-Disposition', `attachment; filename="${reportId}.${report.key.split('.').pop()}"`);
    headers.set('Content-Length', reportObject.size.toString());

    return new Response(reportObject.body, { headers });

  } catch (error) {
    return new Response(JSON.stringify({
      error: 'Failed to download report',
      message: error.message
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};

// Error handler
const handleError = async (error: any, env: Env, ctx: ExecutionContext) => {

  // Track error in analytics
  ctx.waitUntil(
    env.ANALYTICS.writeDataPoint({
      indexes: ['error', error.name || 'UnknownError'],
      blobs: [error.message || 'Unknown error', env.ENVIRONMENT],
      doubles: [Date.now(), 500]
    })
  );

  return new Response(JSON.stringify({
    error: 'Internal Server Error',
    timestamp: new Date().toISOString()
  }), {
    status: 500,
    headers: { 'Content-Type': 'application/json' }
  });
};

// Analytics endpoint handlers
const getTimeSeriesData = async (request: Request, env: Env, ctx: ExecutionContext) => {
  const businessId = (request as any).businessId;
  const url = new URL(request.url);
  const metric = url.pathname.split('/')[4];
  const period = url.searchParams.get('period') || '24h';
  const granularity = url.searchParams.get('granularity') as 'hour' | 'day' || 'hour';

  try {
    const { analyticsService } = await initializeServices(env, businessId);
    const timeSeriesData = await analyticsService!.getTimeSeriesData(
      businessId,
      metric,
      period,
      granularity
    );

    return new Response(JSON.stringify({
      success: true,
      metric,
      period,
      granularity,
      data: timeSeriesData
    }), {
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error) {
    return new Response(JSON.stringify({
      error: 'Failed to get time series data',
      message: error.message
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};

const getCustomAnalytics = async (request: Request, env: Env, ctx: ExecutionContext) => {
  const businessId = (request as any).businessId;
  const { queries } = await request.json();

  try {
    const { analyticsService } = await initializeServices(env, businessId);
    const results = await analyticsService!.getCustomMetrics(businessId, queries);

    return new Response(JSON.stringify({
      success: true,
      results
    }), {
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error) {
    return new Response(JSON.stringify({
      error: 'Failed to execute custom analytics',
      message: error.message
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};

// Security endpoint handlers
const cspReport = async (request: Request, env: Env, ctx: ExecutionContext) => {
  try {
    const report = await request.json();

    // Log CSP violation
    await logSecurityEvent('csp_violation', {
      ip: request.headers.get('CF-Connecting-IP'),
      userAgent: request.headers.get('User-Agent'),
      report,
      severity: 'medium'
    }, env.ANALYTICS);

    return new Response('OK', { status: 200 });
  } catch (error) {
    return new Response('Error processing report', { status: 400 });
  }
};

const securityStatus = async (request: Request, env: Env, ctx: ExecutionContext) => {
  try {
    // Get security metrics from analytics
    const now = Date.now();
    const last24h = now - (24 * 60 * 60 * 1000);

    return new Response(JSON.stringify({
      status: 'healthy',
      timestamp: new Date().toISOString(),
      security: {
        rateLimitActive: true,
        authenticationRequired: true,
        securityHeaders: true,
        cspEnabled: true,
        hstsEnabled: true
      },
      metrics: {
        period: '24h',
        // In a real implementation, you'd query analytics for these metrics
        authFailures: 0,
        rateLimitViolations: 0,
        cspViolations: 0,
        suspiciousActivity: 0
      }
    }), {
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error) {
    return new Response(JSON.stringify({
      error: 'Failed to get security status',
      message: error.message
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};

// SUPERNOVA Enhancement Route Handlers
const supernovaStatus = async (request: Request, env: Env, ctx: ExecutionContext) => {
  try {
    const status = SupernovaIntegration.getIntegrationStatus();
    
    return new Response(JSON.stringify({
      status: 'success',
      supernova: {
        isIntegrated: status.isIntegrated,
        overallScore: status.report?.overallScore || 0,
        lastUpdated: new Date().toISOString()
      }
    }), {
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error) {
    return new Response(JSON.stringify({
      status: 'error',
      message: 'Failed to get SUPERNOVA status',
      error: error.message
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};

const supernovaIntegrate = async (request: Request, env: Env, ctx: ExecutionContext) => {
  try {
    const { improvements } = await request.json();
    
    let result;
    if (improvements && Array.isArray(improvements)) {
      result = await SupernovaIntegration.applySpecificImprovements(improvements);
    } else {
      result = await SupernovaIntegration.integrateAll();
    }
    
    return new Response(JSON.stringify({
      status: 'success',
      result: {
        success: result.success,
        totalTime: result.totalTime,
        improvementsApplied: result.improvementsApplied || 0,
        overallScore: result.overallScore || 0
      }
    }), {
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error) {
    return new Response(JSON.stringify({
      status: 'error',
      message: 'SUPERNOVA integration failed',
      error: error.message
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};

const supernovaReport = async (request: Request, env: Env, ctx: ExecutionContext) => {
  try {
    const status = SupernovaIntegration.getIntegrationStatus();
    
    if (!status.isIntegrated) {
      return new Response(JSON.stringify({
        status: 'error',
        message: 'SUPERNOVA not integrated yet'
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    return new Response(JSON.stringify({
      status: 'success',
      report: status.report
    }), {
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error) {
    return new Response(JSON.stringify({
      status: 'error',
      message: 'Failed to generate SUPERNOVA report',
      error: error.message
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};


// Smart router with middleware
const router = Router();

// Middleware stack
router.all('*', authenticate);
router.all('*', rateLimit);
router.all('*', validateTenant);

// API Routes - RESTful and clean
router.get('/api/health', withMetrics(health));
router.post('/api/ai/chat', withMetrics(aiChat));
router.get('/api/data/:table', withMetrics(getData));
router.post('/api/data/:table', withMetrics(createData));
router.put('/api/data/:table/:id', withMetrics(updateData));
router.delete('/api/data/:table/:id', withMetrics(deleteData));
router.post('/api/workflow/execute', withMetrics(executeWorkflow));
router.get('/api/analytics/dashboard', withMetrics(getDashboard));

// SUPERNOVA Enhancement Routes
router.get('/api/supernova/status', withMetrics(supernovaStatus));
router.post('/api/supernova/integrate', withMetrics(supernovaIntegrate));
router.get('/api/supernova/report', withMetrics(supernovaReport));

// Specialized database routes
router.get('/api/accounts/:accountId/balance', withMetrics(getAccountBalance));
router.post('/api/ledger/transaction', withMetrics(createLedgerTransaction));

// AI-powered routes
router.post('/api/ai/analyze', withMetrics(analyzeDocument));
router.post('/api/ai/insights', withMetrics(generateInsights));
router.post('/api/ai/search', withMetrics(semanticSearch));
router.get('/api/ai/health', withMetrics(aiHealth));

// Realtime routes
router.get('/realtime/connect', handleWebSocket);
router.get('/api/realtime/status', withMetrics(getRealtimeStatus));
router.post('/api/realtime/broadcast', withMetrics(broadcastMessage));

// Job management routes
router.post('/api/jobs/queue', withMetrics(queueJob));
router.get('/api/jobs/status/:requestId', withMetrics(getJobStatus));
router.post('/api/reports/generate', withMetrics(generateReport));
router.get('/api/reports/:reportId/download', withMetrics(downloadReport));

// Security routes
router.post('/api/security/csp-report', withMetrics(cspReport));
router.get('/api/security/status', withMetrics(securityStatus));

// Analytics routes
router.get('/api/analytics/timeseries/:metric', withMetrics(getTimeSeriesData));
router.post('/api/analytics/custom', withMetrics(getCustomAnalytics));

// Main handler
// Export Durable Object
export { RealtimeCoordinator } from './realtime/coordinator.js';

export default {
  async fetch(
    request: Request,
    env: Env,
    ctx: ExecutionContext
  ): Promise<Response> {
    try {
      // Initialize services
      await initializeServices(env);

      // SUPERNOVA Enhancement: Initialize SUPERNOVA improvements
      try {
        const supernovaStatus = SupernovaIntegration.getIntegrationStatus();
        if (!supernovaStatus.isIntegrated) {
          await SupernovaIntegration.integrateAll();
        }
      } catch (supernovaError) {
      }

      // Check cache first
      const cached = await checkCache(request, env);
      if (cached) return cached;

      // Route request
      const response = await router.handle(request, env, ctx);

      // Cache successful responses
      if (response && response.ok) {
        ctx.waitUntil(updateCache(request, response, env));
      }

      return response || new Response('Not Found', { status: 404 });
    } catch (error) {
      return handleError(error, env, ctx);
    }
  },

  // Queue consumer
  async queue(batch: MessageBatch, env: Env): Promise<void> {
    const queueHandler = createQueueHandler();

    for (const message of batch.messages) {
      try {
        await queueHandler.processJob(message, env);
      } catch (error) {
        // QueueHandler handles retries internally
      }
    }
  }
};