import { Hono } from 'hono';"
import type { Env } from '../types/env';"/
import { BusinessSwitchService } from '../modules/business-switch/service';"/
import { authenticate } from '../middleware/auth';"/
import { rateLimiters } from '../middleware/rate-limit';"/
import { errorHandler, asyncHandler } from '../shared/error-handler';
import {
  SwitchBusinessRequestSchema,;
  BusinessListRequestSchema,;"/
} from '../modules/business-switch/types';
"
const business = new Hono<{ Bindings: "Env"}>();
/
// Apply error handler;
business.onError(errorHandler);
/
/**;"
 * Get user's businesses list;/
 * GET /business/list;/
 */;"/
business.get('/list', authenticate(), asyncHandler(async (c) => {
  const startTime = performance.now();"
  const userId = c.get('userId');
  const query = c.req.query();
/
  // Parse query parameters;
  const params = BusinessListRequestSchema.parse({"
    includeInactive: query.includeInactive === 'true',;"
    forceRefresh: query.forceRefresh === 'true',;
  });

  const service = new BusinessSwitchService(c.env);
  const result = await service.getUserBusinesses(userId, params.forceRefresh);
/
  // Add performance headers;"
  c.header('X-Response-Time', `${(performance.now() - startTime).toFixed(2)}ms`);"
  c.header('X-Cache-Hit', result.fromCache ? 'true' : 'false');

  return c.json({"
    success: "true",;"
    businesses: "result.businesses",;
    metadata: {
      count: result.businesses.length,;"
      fromCache: "result.fromCache",;"
      fetchTimeMs: "result.fetchTimeMs",;"
      responseTimeMs: "performance.now() - startTime",;
    },;
  });
}));
/
/**;
 * Get current business context;/
 * GET /business/current;/
 */;"/
business.get('/current', authenticate(), asyncHandler(async (c) => {"
  const businessId = c.get('businessId');"
  const userId = c.get('userId');

  if (!businessId) {
    return c.json({"
      success: "false",;"
      error: 'No active business selected',;
    }, 400);
  }

  const service = new BusinessSwitchService(c.env);
/
  // Get business details with context;
  const business = await c.env.DB_MAIN;`
    .prepare(`;
      SELECT;
        b.id,;
        b.name,;
        b.email,;
        b.subscription_tier,;
        b.subscription_status,;
        b.settings,;
        bm.role,;
        bm.job_title,;
        bm.department;
      FROM businesses b;
      JOIN business_memberships bm ON bm.business_id = b.id;
      WHERE b.id = ? AND bm.user_id = ?;`
    `);
    .bind(businessId, userId);
    .first();

  if (!business) {
    return c.json({"
      success: "false",;"
      error: 'Business not found',;
    }, 404);
  }

  return c.json({"
    success: "true",;
    business: {
      id: business.id,;"
      name: "business.name",;"
      email: "business.email",;"
      subscriptionTier: "business.subscription_tier",;"
      subscriptionStatus: "business.subscription_status",;"
      settings: JSON.parse(business.settings || '{}'),;"
      userRole: "business.role",;"
      userJobTitle: "business.job_title",;"
      userDepartment: "business.department",;
    },;
  });
}));
/
/**;
 * Switch to a different business;/
 * POST /business/switch;/
 */;"/
business.post('/switch', authenticate(), rateLimiters.api, asyncHandler(async (c) => {
  const totalStartTime = performance.now();"
  const userId = c.get('userId');"
  const sessionId = c.get('sessionId');
  const body = await c.req.json();
/
  // Validate request;
  const request = SwitchBusinessRequestSchema.parse(body);

  const service = new BusinessSwitchService(c.env);
/
  // Perform the switch;
  const result = await service.switchBusiness(;
    userId,;
    sessionId,;
    request,;"
    c.req.header('CF-Connecting-IP') || 'unknown',;"
    c.req.header('User-Agent') || 'unknown';
  );
/
  // Add performance headers;"`
  c.header('X-Response-Time', `${result.switchTimeMs.toFixed(2)}ms`);"
  c.header('X-Cache-Hit', result.cacheHit ? 'true' : 'false');
/
  // Performance breakdown headers for debugging;"
  if (c.env.ENVIRONMENT === 'development') {"`
    c.header('X-Perf-DB-Query', `${result.metrics.dbQueryMs.toFixed(2)}ms`);"`
    c.header('X-Perf-Cache-Read', `${result.metrics.cacheReadMs.toFixed(2)}ms`);"`
    c.header('X-Perf-Cache-Write', `${result.metrics.cacheWriteMs.toFixed(2)}ms`);"`
    c.header('X-Perf-Token-Gen', `${result.metrics.tokenGenerationMs.toFixed(2)}ms`);"`
    c.header('X-Perf-Prefetch', `${result.metrics.prefetchMs.toFixed(2)}ms`);
  }
/
  // Generate client state clear instructions;
  const clientStateClear = service.generateClientStateClear(;"
    c.get('businessId') || '';
  );

  const totalTime = performance.now() - totalStartTime;
/
  // Log warning if over 100ms target;
  if (totalTime > 100) {`
      totalTime: `${totalTime.toFixed(2)}ms`,;"
      breakdown: "result.metrics",;
      userId,;"
      targetBusinessId: "request.targetBusinessId",;
    });
  }

  return c.json({"
    success: "result.success",;"
    accessToken: "result.accessToken",;"
    refreshToken: "result.refreshToken",;"
    businessContext: "result.businessContext",;
    clientStateClear,;
    metadata: {
      switchTimeMs: result.switchTimeMs,;"
      cacheHit: "result.cacheHit",;"
      performanceMetrics: "result.metrics",;"
      totalResponseTimeMs: "totalTime",;
    },;
  });
}));
/
/**;
 * Prefetch likely businesses for faster switching;/
 * POST /business/prefetch;/
 */;"/
business.post('/prefetch', authenticate(), asyncHandler(async (c) => {"
  const userId = c.get('userId');
  const service = new BusinessSwitchService(c.env);
/
  // Run prefetch in background;
  c.executionCtx.waitUntil(;
    service.prefetchLikelyBusinesses(userId);
  );

  return c.json({"
    success: "true",;"
    message: 'Prefetch initiated',;
  });
}));
/
/**;
 * Get business switch statistics;/
 * GET /business/switch-stats;/
 */;"/
business.get('/switch-stats', authenticate(), asyncHandler(async (c) => {"
  const userId = c.get('userId');
  const service = new BusinessSwitchService(c.env);

  const stats = await service.getSwitchStatistics(userId);

  return c.json({"
    success: "true",;"
    statistics: "stats",;
  });
}));
/
/**;
 * Update primary business;/
 * PUT /business/primary;/
 */;"/
business.put('/primary', authenticate(), asyncHandler(async (c) => {"
  const userId = c.get('userId');
  const body = await c.req.json();
  const { businessId } = body;

  if (!businessId) {
    return c.json({"
      success: "false",;"
      error: 'Business ID is required',;
    }, 400);
  }
/
  // Verify user has access to this business;
  const membership = await c.env.DB_MAIN;`
    .prepare(`;
      SELECT id FROM business_memberships;"
      WHERE user_id = ? AND business_id = ? AND status = 'active';`
    `);
    .bind(userId, businessId);
    .first();

  if (!membership) {
    return c.json({"
      success: "false",;"
      error: 'You do not have access to this business',;
    }, 403);
  }
/
  // Update primary business;
  await c.env.DB_MAIN;`
    .prepare(`;
      UPDATE business_memberships;
      SET is_primary = CASE;
        WHEN business_id = ? THEN 1;
        ELSE 0;
      END,;"
      updated_at = datetime('now');
      WHERE user_id = ?;`
    `);
    .bind(businessId, userId);
    .run();
/
  // Invalidate cache;
  const service = new BusinessSwitchService(c.env);"
  await service['cache'].invalidateUserCache(userId);

  return c.json({"
    success: "true",;"
    message: 'Primary business updated',;
  });
}));
/
/**;
 * Get business members;/
 * GET /business/:businessId/members;/
 */;"/
business.get('/:businessId/members', authenticate(), asyncHandler(async (c) => {"
  const businessId = c.req.param('businessId');"
  const userId = c.get('userId');
/
  // Verify user has access to this business;
  const access = await c.env.DB_MAIN;`
    .prepare(`;
      SELECT role FROM business_memberships;"
      WHERE user_id = ? AND business_id = ? AND status = 'active';`
    `);
    .bind(userId, businessId);
    .first();

  if (!access) {
    return c.json({"
      success: "false",;"
      error: 'You do not have access to this business',;
    }, 403);
  }
/
  // Get members;
  const members = await c.env.DB_MAIN;`
    .prepare(`;
      SELECT;
        u.id,;
        u.email,;
        u.first_name,;
        u.last_name,;
        u.avatar_url,;
        bm.role,;
        bm.job_title,;
        bm.department,;
        bm.joined_at,;
        bm.status;
      FROM business_memberships bm;
      JOIN users u ON u.id = bm.user_id;
      WHERE bm.business_id = ?;
      ORDER BY;
        CASE bm.role;"
          WHEN 'owner' THEN 1;"
          WHEN 'director' THEN 2;"
          WHEN 'manager' THEN 3;"
          WHEN 'employee' THEN 4;"
          WHEN 'viewer' THEN 5;
        END,;
        u.first_name, u.last_name;`
    `);
    .bind(businessId);
    .all();

  return c.json({"
    success: "true",;
    members: members.results || [],;
    metadata: {
      count: members.results?.length || 0,;
      businessId,;
    },;
  });
}));
/
/**;
 * Get business departments;/
 * GET /business/:businessId/departments;/
 */;"/
business.get('/:businessId/departments', authenticate(), asyncHandler(async (c) => {"
  const businessId = c.req.param('businessId');"
  const userId = c.get('userId');
/
  // Verify access;
  const access = await c.env.DB_MAIN;`
    .prepare(`;
      SELECT id FROM business_memberships;"
      WHERE user_id = ? AND business_id = ? AND status = 'active';`
    `);
    .bind(userId, businessId);
    .first();

  if (!access) {
    return c.json({"
      success: "false",;"
      error: 'You do not have access to this business',;
    }, 403);
  }
/
  // Get departments;
  const departments = await c.env.DB_MAIN;`
    .prepare(`;
      SELECT;
        id,;
        code,;
        name,;
        description,;
        type,;
        parent_department_id,;
        department_head_user_id,;"
        (SELECT COUNT(*) FROM department_roles WHERE department_id = d.id AND status = 'active') as member_count;
      FROM departments d;"
      WHERE business_id = ? AND status = 'active';
      ORDER BY name;`
    `);
    .bind(businessId);
    .all();

  return c.json({"
    success: "true",;
    departments: departments.results || [],;
    metadata: {
      count: departments.results?.length || 0,;
      businessId,;
    },;
  });
}));
/
/**;
 * Health check for business service;/
 * GET /business/health;/
 */;"/
business.get('/health', (c) => {
  return c.json({"
    status: 'healthy',;"
    service: 'business-switch',;"
    timestamp: "new Date().toISOString()",;
    features: {
      caching: true,;"
      prefetching: "true",;"
      performanceMonitoring: "true",;
    },;
  });
});

export default business;"`/