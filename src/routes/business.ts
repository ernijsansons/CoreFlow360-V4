import { Hono } from 'hono';
import type { Env } from '../types/env';
import { BusinessSwitchService } from '../modules/business-switch/service';
import { authenticate } from '../middleware/auth';
import { rateLimiters } from '../middleware/rate-limit';
import { errorHandler, asyncHandler } from '../shared/error-handler';
import {
  SwitchBusinessRequestSchema,
  BusinessListRequestSchema,
} from '../modules/business-switch/types';

const business = new Hono<{ Bindings: Env }>();

// Apply error handler
business.onError(errorHandler);

/**
 * Get user's businesses list
 * GET /business/list
 */
business.get('/list', authenticate(), asyncHandler(async (c) => {
  const startTime = performance.now();
  const userId = c.get('userId');
  const query = c.req.query();

  // Parse query parameters
  const params = BusinessListRequestSchema.parse({
    includeInactive: query.includeInactive === 'true',
    forceRefresh: query.forceRefresh === 'true',
  });

  const service = new BusinessSwitchService(c.env);
  const result = await service.getUserBusinesses(userId, params.forceRefresh);

  // Add performance headers
  c.header('X-Response-Time', `${(performance.now() - startTime).toFixed(2)}ms`);
  c.header('X-Cache-Hit', result.fromCache ? 'true' : 'false');

  return c.json({
    success: true,
    businesses: result.businesses,
    metadata: {
      count: result.businesses.length,
      fromCache: result.fromCache,
      fetchTimeMs: result.fetchTimeMs,
      responseTimeMs: performance.now() - startTime,
    },
  });
}));

/**
 * Switch to a different business
 * POST /business/switch
 */
business.post('/switch', authenticate(), rateLimiters.businessSwitch, asyncHandler(async (c) => {
  const startTime = performance.now();
  const userId = c.get('userId');
  const body = await c.req.json();

  // Parse and validate request
  const params = SwitchBusinessRequestSchema.parse(body);

  const service = new BusinessSwitchService(c.env);
  const result = await service.switchBusiness(userId, params.businessId, params.reason);

  // Add performance headers
  c.header('X-Response-Time', `${(performance.now() - startTime).toFixed(2)}ms`);
  c.header('X-Switch-Success', result.success ? 'true' : 'false');

  return c.json({
    success: result.success,
    business: result.business,
    session: result.session,
    metadata: {
      switchTimeMs: result.switchTimeMs,
      responseTimeMs: performance.now() - startTime,
      fromCache: result.fromCache,
    },
  });
}));

/**
 * Get current business context
 * GET /business/current
 */
business.get('/current', authenticate(), asyncHandler(async (c) => {
  const startTime = performance.now();
  const userId = c.get('userId');

  const service = new BusinessSwitchService(c.env);
  const result = await service.getCurrentBusiness(userId);

  // Add performance headers
  c.header('X-Response-Time', `${(performance.now() - startTime).toFixed(2)}ms`);
  c.header('X-Cache-Hit', result.fromCache ? 'true' : 'false');

  return c.json({
    success: true,
    business: result.business,
    session: result.session,
    metadata: {
      fromCache: result.fromCache,
      fetchTimeMs: result.fetchTimeMs,
      responseTimeMs: performance.now() - startTime,
    },
  });
}));

/**
 * Get business details
 * GET /business/:id
 */
business.get('/:id', authenticate(), asyncHandler(async (c) => {
  const startTime = performance.now();
  const userId = c.get('userId');
  const businessId = c.req.param('id');

  const service = new BusinessSwitchService(c.env);
  const result = await service.getBusinessDetails(userId, businessId);

  // Add performance headers
  c.header('X-Response-Time', `${(performance.now() - startTime).toFixed(2)}ms`);

  return c.json({
    success: true,
    business: result.business,
    permissions: result.permissions,
    metadata: {
      responseTimeMs: performance.now() - startTime,
    },
  });
}));

/**
 * Update business settings
 * PUT /business/:id
 */
business.put('/:id', authenticate(), rateLimiters.businessUpdate, asyncHandler(async (c) => {
  const startTime = performance.now();
  const userId = c.get('userId');
  const businessId = c.req.param('id');
  const body = await c.req.json();

  const service = new BusinessSwitchService(c.env);
  const result = await service.updateBusiness(userId, businessId, body);

  // Add performance headers
  c.header('X-Response-Time', `${(performance.now() - startTime).toFixed(2)}ms`);

  return c.json({
    success: true,
    business: result.business,
    metadata: {
      responseTimeMs: performance.now() - startTime,
    },
  });
}));

/**
 * Get business statistics
 * GET /business/:id/stats
 */
business.get('/:id/stats', authenticate(), asyncHandler(async (c) => {
  const startTime = performance.now();
  const userId = c.get('userId');
  const businessId = c.req.param('id');
  const query = c.req.query();

  const period = query.period || '30d';
  const service = new BusinessSwitchService(c.env);
  const result = await service.getBusinessStats(userId, businessId, period);

  // Add performance headers
  c.header('X-Response-Time', `${(performance.now() - startTime).toFixed(2)}ms`);

  return c.json({
    success: true,
    stats: result.stats,
    metadata: {
      period,
      responseTimeMs: performance.now() - startTime,
    },
  });
}));

/**
 * Get business users
 * GET /business/:id/users
 */
business.get('/:id/users', authenticate(), asyncHandler(async (c) => {
  const startTime = performance.now();
  const userId = c.get('userId');
  const businessId = c.req.param('id');
  const query = c.req.query();

  const page = parseInt(query.page || '1');
  const limit = parseInt(query.limit || '20');
  const search = query.search;

  const service = new BusinessSwitchService(c.env);
  const result = await service.getBusinessUsers(userId, businessId, {
    page,
    limit,
    search,
  });

  // Add performance headers
  c.header('X-Response-Time', `${(performance.now() - startTime).toFixed(2)}ms`);

  return c.json({
    success: true,
    users: result.users,
    pagination: result.pagination,
    metadata: {
      responseTimeMs: performance.now() - startTime,
    },
  });
}));

/**
 * Add user to business
 * POST /business/:id/users
 */
business.post('/:id/users', authenticate(), rateLimiters.businessUpdate, asyncHandler(async (c) => {
  const startTime = performance.now();
  const userId = c.get('userId');
  const businessId = c.req.param('id');
  const body = await c.req.json();

  const service = new BusinessSwitchService(c.env);
  const result = await service.addUserToBusiness(userId, businessId, body);

  // Add performance headers
  c.header('X-Response-Time', `${(performance.now() - startTime).toFixed(2)}ms`);

  return c.json({
    success: true,
    user: result.user,
    metadata: {
      responseTimeMs: performance.now() - startTime,
    },
  });
}));

/**
 * Remove user from business
 * DELETE /business/:id/users/:userId
 */
business.delete('/:id/users/:userId', authenticate(), rateLimiters.businessUpdate, asyncHandler(async (c) => {
  const startTime = performance.now();
  const userId = c.get('userId');
  const businessId = c.req.param('id');
  const targetUserId = c.req.param('userId');

  const service = new BusinessSwitchService(c.env);
  const result = await service.removeUserFromBusiness(userId, businessId, targetUserId);

  // Add performance headers
  c.header('X-Response-Time', `${(performance.now() - startTime).toFixed(2)}ms`);

  return c.json({
    success: result.success,
    message: result.message,
    metadata: {
      responseTimeMs: performance.now() - startTime,
    },
  });
}));

/**
 * Get business permissions
 * GET /business/:id/permissions
 */
business.get('/:id/permissions', authenticate(), asyncHandler(async (c) => {
  const startTime = performance.now();
  const userId = c.get('userId');
  const businessId = c.req.param('id');

  const service = new BusinessSwitchService(c.env);
  const result = await service.getBusinessPermissions(userId, businessId);

  // Add performance headers
  c.header('X-Response-Time', `${(performance.now() - startTime).toFixed(2)}ms`);

  return c.json({
    success: true,
    permissions: result.permissions,
    metadata: {
      responseTimeMs: performance.now() - startTime,
    },
  });
}));

/**
 * Update user permissions
 * PUT /business/:id/users/:userId/permissions
 */
business.put('/:id/users/:userId/permissions', authenticate(), rateLimiters.businessUpdate, asyncHandler(async (c) => {
  const startTime = performance.now();
  const userId = c.get('userId');
  const businessId = c.req.param('id');
  const targetUserId = c.req.param('userId');
  const body = await c.req.json();

  const service = new BusinessSwitchService(c.env);
  const result = await service.updateUserPermissions(userId, businessId, targetUserId, body);

  // Add performance headers
  c.header('X-Response-Time', `${(performance.now() - startTime).toFixed(2)}ms`);

  return c.json({
    success: result.success,
    permissions: result.permissions,
    message: result.message,
    metadata: {
      responseTimeMs: performance.now() - startTime,
    },
  });
}));

/**
 * Get business audit log
 * GET /business/:id/audit
 */
business.get('/:id/audit', authenticate(), asyncHandler(async (c) => {
  const startTime = performance.now();
  const userId = c.get('userId');
  const businessId = c.req.param('id');
  const query = c.req.query();

  const page = parseInt(query.page || '1');
  const limit = parseInt(query.limit || '50');
  const action = query.action;
  const startDate = query.startDate;
  const endDate = query.endDate;

  const service = new BusinessSwitchService(c.env);
  const result = await service.getBusinessAuditLog(userId, businessId, {
    page,
    limit,
    action,
    startDate: startDate ? new Date(startDate) : undefined,
    endDate: endDate ? new Date(endDate) : undefined,
  });

  // Add performance headers
  c.header('X-Response-Time', `${(performance.now() - startTime).toFixed(2)}ms`);

  return c.json({
    success: true,
    auditLog: result.auditLog,
    pagination: result.pagination,
    metadata: {
      responseTimeMs: performance.now() - startTime,
    },
  });
}));

/**
 * Get business health status
 * GET /business/:id/health
 */
business.get('/:id/health', authenticate(), asyncHandler(async (c) => {
  const startTime = performance.now();
  const userId = c.get('userId');
  const businessId = c.req.param('id');

  const service = new BusinessSwitchService(c.env);
  const result = await service.getBusinessHealth(userId, businessId);

  // Add performance headers
  c.header('X-Response-Time', `${(performance.now() - startTime).toFixed(2)}ms`);

  return c.json({
    success: true,
    health: result.health,
    metadata: {
      responseTimeMs: performance.now() - startTime,
    },
  });
}));

/**
 * Get business performance metrics
 * GET /business/:id/performance
 */
business.get('/:id/performance', authenticate(), asyncHandler(async (c) => {
  const startTime = performance.now();
  const userId = c.get('userId');
  const businessId = c.req.param('id');
  const query = c.req.query();

  const period = query.period || '24h';
  const service = new BusinessSwitchService(c.env);
  const result = await service.getBusinessPerformance(userId, businessId, period);

  // Add performance headers
  c.header('X-Response-Time', `${(performance.now() - startTime).toFixed(2)}ms`);

  return c.json({
    success: true,
    performance: result.performance,
    metadata: {
      period,
      responseTimeMs: performance.now() - startTime,
    },
  });
}));

export default business;

