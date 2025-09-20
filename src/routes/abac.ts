import { Hono } from 'hono';
import type { Env } from '../types/env';
import { ABACService } from '../modules/abac';
import { authenticate } from '../middleware/auth';
import { rateLimiters } from '../middleware/rate-limit';
import { errorHandler, asyncHandler } from '../shared/error-handler';
import {
  CheckPermissionRequestSchema,
  PolicyRuleSchema,
} from '../modules/abac/types';

const abac = new Hono<{ Bindings: Env }>();

// Apply error handler
abac.onError(errorHandler);

/**
 * Check single permission
 * POST /abac/check
 */
abac.post('/check', authenticate(), rateLimiters.api, asyncHandler(async (c) => {
  const startTime = performance.now();
  const userId = c.get('userId');
  const businessId = c.get('businessId');
  const body = await c.req.json();

  // Validate request
  const request = CheckPermissionRequestSchema.parse(body);

  // Get user context from auth middleware
  const subject = {
    userId,
    businessId,
    orgRole: c.get('orgRole') || 'employee',
    deptRoles: c.get('deptRoles') || [],
    attributes: c.get('userAttributes') || {},
    context: {
      ipAddress: c.req.header('CF-Connecting-IP') || 'unknown',
      userAgent: c.req.header('User-Agent') || 'unknown',
      sessionId: c.get('sessionId') || 'unknown',
      requestTime: Date.now(),
    },
  };

  // Initialize ABAC service
  const service = new ABACService(c.env.KV_ABAC);

  // Check permission
  const result = await service.checkPermission(
    subject,
    request.capability,
    request.resource
  );

  // Add performance headers
  const totalTime = performance.now() - startTime;
  c.header('X-Response-Time', `${totalTime.toFixed(2)}ms`);
  c.header('X-Cache-Hit', result.cacheHit ? 'true' : 'false');
  c.header('X-Fast-Path', result.fastPath || 'none');

  return c.json({
    allowed: result.allowed,
    reason: result.reason,
    fastPath: result.fastPath,
    evaluationTimeMs: result.evaluationTimeMs,
    cacheHit: result.cacheHit,
    constraints: result.constraints,
    metadata: {
      totalResponseTimeMs: totalTime,
      matched: result.matched.length,
      denied: result.denied.length,
    },
  });
}));

/**
 * Batch permission check
 * POST /abac/check-batch
 */
abac.post('/check-batch', authenticate(), rateLimiters.api, asyncHandler(async (c) => {
  const startTime = performance.now();
  const userId = c.get('userId');
  const businessId = c.get('businessId');
  const body = await c.req.json();

  const { capabilities, resource } = body;

  if (!Array.isArray(capabilities)) {
    return c.json({
      success: false,
      error: 'capabilities must be an array',
    }, 400);
  }

  // Create subject
  const subject = {
    userId,
    businessId,
    orgRole: c.get('orgRole') || 'employee',
    deptRoles: c.get('deptRoles') || [],
    attributes: c.get('userAttributes') || {},
    context: {
      ipAddress: c.req.header('CF-Connecting-IP') || 'unknown',
      userAgent: c.req.header('User-Agent') || 'unknown',
      sessionId: c.get('sessionId') || 'unknown',
      requestTime: Date.now(),
    },
  };

  const service = new ABACService(c.env.KV_ABAC);

  // Batch check
  const results = await service.checkPermissions(subject, capabilities, resource);

  // Convert Map to object
  const resultObject: Record<string, any> = {};
  results.forEach((result, capability) => {
    resultObject[capability] = {
      allowed: result.allowed,
      reason: result.reason,
      fastPath: result.fastPath,
      evaluationTimeMs: result.evaluationTimeMs,
      cacheHit: result.cacheHit,
      constraints: result.constraints,
    };
  });

  const totalTime = performance.now() - startTime;
  c.header('X-Response-Time', `${totalTime.toFixed(2)}ms`);

  return c.json({
    success: true,
    results: resultObject,
    metadata: {
      capabilityCount: capabilities.length,
      totalResponseTimeMs: totalTime,
      averageEvaluationTimeMs: totalTime / capabilities.length,
    },
  });
}));

/**
 * Get all permissions for current user
 * GET /abac/permissions
 */
abac.get('/permissions', authenticate(), asyncHandler(async (c) => {
  const userId = c.get('userId');
  const businessId = c.get('businessId');

  const subject = {
    userId,
    businessId,
    orgRole: c.get('orgRole') || 'employee',
    deptRoles: c.get('deptRoles') || [],
    attributes: c.get('userAttributes') || {},
    context: {
      ipAddress: c.req.header('CF-Connecting-IP') || 'unknown',
      userAgent: c.req.header('User-Agent') || 'unknown',
      sessionId: c.get('sessionId') || 'unknown',
      requestTime: Date.now(),
    },
  };

  const service = new ABACService(c.env.KV_ABAC);
  const bundle = await service.getAllPermissions(subject);

  return c.json({
    success: true,
    permissions: {
      capabilities: Array.from(bundle.capabilities),
      constraints: Array.from(bundle.constraints.entries()).reduce((obj, [k, v]) => {
        obj[k] = v;
        return obj;
      }, {} as Record<string, any>),
      evaluatedAt: bundle.evaluatedAt,
      expiresAt: bundle.expiresAt,
    },
    metadata: {
      capabilityCount: bundle.capabilities.size,
      constraintCount: bundle.constraints.size,
      cacheAge: Date.now() - bundle.evaluatedAt,
    },
  });
}));

/**
 * Introspect capabilities for current user
 * GET /abac/introspect
 */
abac.get('/introspect', authenticate(), asyncHandler(async (c) => {
  const userId = c.get('userId');
  const businessId = c.get('businessId');
  const resourceType = c.req.query('resourceType');

  const subject = {
    userId,
    businessId,
    orgRole: c.get('orgRole') || 'employee',
    deptRoles: c.get('deptRoles') || [],
    attributes: c.get('userAttributes') || {},
    context: {
      ipAddress: c.req.header('CF-Connecting-IP') || 'unknown',
      userAgent: c.req.header('User-Agent') || 'unknown',
      sessionId: c.get('sessionId') || 'unknown',
      requestTime: Date.now(),
    },
  };

  const service = new ABACService(c.env.KV_ABAC);
  const introspection = await service.introspectCapabilities(subject, resourceType);

  return c.json({
    success: true,
    capabilities: introspection,
    metadata: {
      allowedCount: introspection.allowed.length,
      deniedCount: introspection.denied.length,
      conditionalCount: introspection.conditional.length,
      resourceType,
    },
  });
}));

/**
 * Discover available capabilities for a resource type
 * GET /abac/capabilities/:resourceType
 */
abac.get('/capabilities/:resourceType', authenticate(), asyncHandler(async (c) => {
  const resourceType = c.req.param('resourceType');
  const service = new ABACService(c.env.KV_ABAC);

  const discovery = await service.discoverCapabilities(resourceType);

  return c.json({
    success: true,
    resourceType,
    capabilities: discovery.available,
    descriptions: discovery.descriptions,
    metadata: {
      count: discovery.available.length,
    },
  });
}));

/**
 * Debug permission evaluation
 * POST /abac/debug
 */
abac.post('/debug', authenticate(), asyncHandler(async (c) => {
  const userId = c.get('userId');
  const businessId = c.get('businessId');
  const body = await c.req.json();

  // Only allow debugging in development or for admins
  if (c.env.ENVIRONMENT === 'production' && c.get('orgRole') !== 'owner') {
    return c.json({
      success: false,
      error: 'Debug endpoint not available in production',
    }, 403);
  }

  const request = CheckPermissionRequestSchema.parse(body);

  const subject = {
    userId,
    businessId,
    orgRole: c.get('orgRole') || 'employee',
    deptRoles: c.get('deptRoles') || [],
    attributes: c.get('userAttributes') || {},
    context: {
      ipAddress: c.req.header('CF-Connecting-IP') || 'unknown',
      userAgent: c.req.header('User-Agent') || 'unknown',
      sessionId: c.get('sessionId') || 'unknown',
      requestTime: Date.now(),
    },
  };

  const service = new ABACService(c.env.KV_ABAC);
  const debugResult = await service.debugPermission(
    subject,
    request.capability,
    request.resource
  );

  return c.json({
    success: true,
    result: debugResult.result,
    debug: debugResult.debug,
  });
}));

/**
 * Invalidate permissions cache
 * POST /abac/invalidate
 */
abac.post('/invalidate', authenticate(), asyncHandler(async (c) => {
  const userId = c.get('userId');
  const businessId = c.get('businessId');

  const subject = {
    userId,
    businessId,
    orgRole: c.get('orgRole') || 'employee',
    deptRoles: c.get('deptRoles') || [],
    attributes: c.get('userAttributes') || {},
    context: {
      ipAddress: c.req.header('CF-Connecting-IP') || 'unknown',
      userAgent: c.req.header('User-Agent') || 'unknown',
      sessionId: c.get('sessionId') || 'unknown',
      requestTime: Date.now(),
    },
  };

  const service = new ABACService(c.env.KV_ABAC);
  await service.invalidatePermissions(subject, 'user_request');

  return c.json({
    success: true,
    message: 'Permissions cache invalidated',
  });
}));

/**
 * Get ABAC performance statistics
 * GET /abac/stats
 */
abac.get('/stats', authenticate(), asyncHandler(async (c) => {
  const service = new ABACService(c.env.KV_ABAC);
  const stats = service.getPerformanceStatistics();

  return c.json({
    success: true,
    statistics: stats,
  });
}));

/**
 * Get ABAC health report
 * GET /abac/health
 */
abac.get('/health', authenticate(), asyncHandler(async (c) => {
  const service = new ABACService(c.env.KV_ABAC);
  const health = await service.healthCheck();

  return c.json(health);
}));

/**
 * Export performance metrics
 * GET /abac/metrics
 */
abac.get('/metrics', authenticate(), asyncHandler(async (c) => {
  // Only allow metrics export for admins or monitoring systems
  if (c.get('orgRole') !== 'owner' && c.get('orgRole') !== 'director') {
    return c.json({
      success: false,
      error: 'Insufficient permissions for metrics export',
    }, 403);
  }

  const service = new ABACService(c.env.KV_ABAC);
  const metrics = service.exportMetrics();

  const format = c.req.query('format') || 'json';

  switch (format) {
    case 'prometheus':
      c.header('Content-Type', 'text/plain');
      return c.text(metrics.prometheus);

    case 'datadog':
      return c.json(metrics.datadog);

    case 'cloudwatch':
      return c.json(metrics.cloudwatch);

    default:
      return c.json({
        success: true,
        metrics,
      });
  }
}));

/**
 * System administration endpoints (owner only)
 */

/**
 * Get system statistics
 * GET /abac/admin/stats
 */
abac.get('/admin/stats', authenticate(), asyncHandler(async (c) => {
  if (c.get('orgRole') !== 'owner') {
    return c.json({
      success: false,
      error: 'Owner role required',
    }, 403);
  }

  const service = new ABACService(c.env.KV_ABAC);
  const systemStats = await service.getSystemStatistics();

  return c.json({
    success: true,
    statistics: systemStats,
  });
}));

/**
 * Clear ABAC cache
 * POST /abac/admin/clear-cache
 */
abac.post('/admin/clear-cache', authenticate(), asyncHandler(async (c) => {
  if (c.get('orgRole') !== 'owner') {
    return c.json({
      success: false,
      error: 'Owner role required',
    }, 403);
  }

  const service = new ABACService(c.env.KV_ABAC);
  await service.clearCache();

  return c.json({
    success: true,
    message: 'ABAC cache cleared',
  });
}));

/**
 * Health check endpoint (public)
 * GET /abac/healthz
 */
abac.get('/healthz', (c) => {
  return c.json({
    status: 'healthy',
    service: 'abac',
    timestamp: new Date().toISOString(),
    features: {
      fastPath: true,
      caching: true,
      policyEvaluation: true,
      performanceMonitoring: true,
    },
  });
});

export default abac;