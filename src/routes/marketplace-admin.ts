/**
 * Marketplace Admin API Routes
 * Administrative operations for marketplace management
 * Requires admin role
 */

import { Logger } from '../shared/logger';
import { Hono } from 'hono';
import type { Env } from '../types/env';
import { CustomIntegrationService } from '../services/developers/custom-integration.service';
import { AnalyticsService } from '../services/developers/analytics.service';
import { JWTService } from '../modules/auth/jwt';

const logger = new Logger({ component: 'MarketplaceAdmin' });

const app = new Hono<{ Bindings: Env }>();

// ============================================================
// ADMIN MIDDLEWARE
// ============================================================

/**
 * Verify admin access
 */
async function requireAdmin(c: any, next: any) {
  const authHeader = c.req.header('Authorization');
  if (!authHeader) {
    return c.json({ error: 'Unauthorized' }, 401);
  }

  const token = authHeader.replace('Bearer ', '');
  const payload = await new JWTService(c.env.JWT_SECRET).verifyToken(token);
  if (!payload) {
    return c.json({ error: 'Invalid token' }, 401);
  }

  // Check if user has admin role
  const user = await c.env.DB_MAIN.prepare(
    'SELECT role FROM users WHERE id = ?'
  )
    .bind(payload.userId)
    .first();

  if (!user || user.role !== 'admin') {
    return c.json({ error: 'Admin access required' }, 403);
  }

  c.set('userId', payload.userId);
  await next();
}

app.use('/*', requireAdmin as any);

// ============================================================
// INTEGRATION REVIEW
// ============================================================

/**
 * GET /marketplace-admin/pending-reviews
 * List integrations pending review
 */
app.get('/pending-reviews', async (c) => {
  try {
    const result = await c.env.DB_MAIN.prepare(
      `SELECT ci.*, d.developer_name, d.company_name
       FROM custom_integrations ci
       JOIN developers d ON ci.developer_id = d.id
       WHERE ci.marketplace_status = 'review'
       ORDER BY ci.updated_at DESC`
    ).all();

    return c.json({ integrations: result.results });
  } catch (error) {
    logger.error('Get pending reviews error:', error);
    return c.json({ error: 'Failed to get pending reviews' }, 500);
  }
});

/**
 * POST /marketplace-admin/integrations/:id/approve
 * Approve integration for marketplace
 */
app.post('/integrations/:id/approve', async (c) => {
  try {
    const integrationId = c.req.param('id');
    const userId = (c as any).get('userId');

    const integrationService = new CustomIntegrationService(c.env);
    const success = await integrationService.publishIntegration(integrationId, userId);

    if (!success) {
      return c.json({ error: 'Failed to approve integration' }, 400);
    }

    return c.json({ success: true, message: 'Integration approved and published' });
  } catch (error) {
    logger.error('Approve integration error:', error);
    return c.json({ error: 'Failed to approve integration' }, 500);
  }
});

/**
 * POST /marketplace-admin/integrations/:id/reject
 * Reject integration submission
 */
app.post('/integrations/:id/reject', async (c) => {
  try {
    const integrationId = c.req.param('id');
    const userId = (c as any).get('userId');
    const body = await c.req.json();

    if (!body.reason) {
      return c.json({ error: 'Rejection reason required' }, 400);
    }

    const integrationService = new CustomIntegrationService(c.env);
    const success = await integrationService.rejectIntegration(
      integrationId,
      userId,
      body.reason
    );

    if (!success) {
      return c.json({ error: 'Failed to reject integration' }, 400);
    }

    return c.json({ success: true, message: 'Integration rejected' });
  } catch (error) {
    logger.error('Reject integration error:', error);
    return c.json({ error: 'Failed to reject integration' }, 500);
  }
});

/**
 * POST /marketplace-admin/integrations/:id/deprecate
 * Deprecate published integration
 */
app.post('/integrations/:id/deprecate', async (c) => {
  try {
    const integrationId = c.req.param('id');
    const body = await c.req.json();

    const integrationService = new CustomIntegrationService(c.env);
    const success = await integrationService.deprecateIntegration(
      integrationId,
      body.reason
    );

    if (!success) {
      return c.json({ error: 'Failed to deprecate integration' }, 400);
    }

    return c.json({ success: true, message: 'Integration deprecated' });
  } catch (error) {
    logger.error('Deprecate integration error:', error);
    return c.json({ error: 'Failed to deprecate integration' }, 500);
  }
});

// ============================================================
// SECURITY REVIEW
// ============================================================

/**
 * POST /marketplace-admin/integrations/:id/security-review
 * Mark integration as security reviewed
 */
app.post('/integrations/:id/security-review', async (c) => {
  try {
    const integrationId = c.req.param('id');
    const userId = (c as any).get('userId');
    const body = await c.req.json();

    await c.env.DB_MAIN.prepare(
      `UPDATE custom_integrations SET
        security_reviewed = 1,
        security_review_date = ?,
        security_reviewer_id = ?,
        data_privacy_compliant = ?,
        updated_at = ?
      WHERE id = ?`
    )
      .bind(
        new Date().toISOString(),
        userId,
        body.data_privacy_compliant ? 1 : 0,
        new Date().toISOString(),
        integrationId
      )
      .run();

    return c.json({ success: true, message: 'Security review completed' });
  } catch (error) {
    logger.error('Security review error:', error);
    return c.json({ error: 'Failed to complete security review' }, 500);
  }
});

// ============================================================
// MARKETPLACE ANALYTICS
// ============================================================

/**
 * GET /marketplace-admin/insights
 * Get marketplace-wide analytics
 */
app.get('/insights', async (c) => {
  try {
    const timeframe = (c.req.query('timeframe') as '7d' | '30d' | '90d') || '30d';
    const analyticsService = new AnalyticsService(c.env);
    const insights = await analyticsService.getMarketplaceInsights(timeframe);

    return c.json({ insights });
  } catch (error) {
    logger.error('Get marketplace insights error:', error);
    return c.json({ error: 'Failed to get insights' }, 500);
  }
});

/**
 * GET /marketplace-admin/integrations
 * List all integrations (all statuses)
 */
app.get('/integrations', async (c) => {
  try {
    const status = c.req.query('status');
    const category = c.req.query('category');
    const limit = c.req.query('limit') ? parseInt(c.req.query('limit')!) : 50;
    const offset = c.req.query('offset') ? parseInt(c.req.query('offset')!) : 0;

    let query = `
      SELECT ci.*, d.developer_name, d.company_name, d.developer_tier
      FROM custom_integrations ci
      JOIN developers d ON ci.developer_id = d.id
      WHERE 1=1
    `;

    const params: any[] = [];

    if (status) {
      query += ' AND ci.marketplace_status = ?';
      params.push(status);
    }

    if (category) {
      query += ' AND ci.provider_category = ?';
      params.push(category);
    }

    query += ' ORDER BY ci.updated_at DESC LIMIT ? OFFSET ?';
    params.push(limit, offset);

    const result = await c.env.DB_MAIN.prepare(query).bind(...(params as any)).all();

    return c.json({ integrations: result.results });
  } catch (error) {
    logger.error('List all integrations error:', error);
    return c.json({ error: 'Failed to list integrations' }, 500);
  }
});

/**
 * GET /marketplace-admin/integrations/:id
 * Get integration details with admin info
 */
app.get('/integrations/:id', async (c) => {
  try {
    const integrationId = c.req.param('id');

    const integration = await c.env.DB_MAIN.prepare(
      `SELECT ci.*, d.developer_name, d.developer_email, d.company_name, d.developer_tier
       FROM custom_integrations ci
       JOIN developers d ON ci.developer_id = d.id
       WHERE ci.id = ?`
    )
      .bind(integrationId)
      .first();

    if (!integration) {
      return c.json({ error: 'Integration not found' }, 404);
    }

    // Get install statistics
    const installStats = await c.env.DB_MAIN.prepare(
      `SELECT
        COUNT(*) as total_installs,
        SUM(CASE WHEN install_status = 'active' THEN 1 ELSE 0 END) as active_installs,
        SUM(CASE WHEN install_status = 'error' THEN 1 ELSE 0 END) as error_installs
       FROM custom_integration_installs
       WHERE custom_integration_id = ?`
    )
      .bind(integrationId)
      .first();

    // Get recent reviews
    const reviews = await c.env.DB_MAIN.prepare(
      `SELECT r.*, u.username
       FROM custom_integration_reviews r
       JOIN users u ON r.user_id = u.id
       WHERE r.custom_integration_id = ?
       ORDER BY r.created_at DESC
       LIMIT 10`
    )
      .bind(integrationId)
      .all();

    return c.json({
      integration,
      install_stats: installStats,
      recent_reviews: reviews.results,
    });
  } catch (error) {
    logger.error('Get integration details error:', error);
    return c.json({ error: 'Failed to get integration details' }, 500);
  }
});

// ============================================================
// DEVELOPER MANAGEMENT
// ============================================================

/**
 * GET /marketplace-admin/developers
 * List all developers
 */
app.get('/developers', async (c) => {
  try {
    const tier = c.req.query('tier');
    const status = c.req.query('status');
    const limit = c.req.query('limit') ? parseInt(c.req.query('limit')!) : 50;
    const offset = c.req.query('offset') ? parseInt(c.req.query('offset')!) : 0;

    let query = 'SELECT * FROM developers WHERE 1=1';
    const params: any[] = [];

    if (tier) {
      query += ' AND developer_tier = ?';
      params.push(tier);
    }

    if (status) {
      query += ' AND status = ?';
      params.push(status);
    }

    query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
    params.push(limit, offset);

    const result = await c.env.DB_MAIN.prepare(query).bind(...(params as any)).all();

    return c.json({ developers: result.results });
  } catch (error) {
    logger.error('List developers error:', error);
    return c.json({ error: 'Failed to list developers' }, 500);
  }
});

/**
 * POST /marketplace-admin/developers/:id/suspend
 * Suspend developer account
 */
app.post('/developers/:id/suspend', async (c) => {
  try {
    const developerId = c.req.param('id');
    const body = await c.req.json();

    await c.env.DB_MAIN.prepare(
      'UPDATE developers SET status = ?, updated_at = ? WHERE id = ?'
    )
      .bind('suspended', new Date().toISOString(), developerId)
      .run();

    // Log suspension reason
    logger.info(`Developer ${developerId} suspended. Reason: ${body.reason}`);

    return c.json({ success: true, message: 'Developer suspended' });
  } catch (error) {
    logger.error('Suspend developer error:', error);
    return c.json({ error: 'Failed to suspend developer' }, 500);
  }
});

/**
 * POST /marketplace-admin/developers/:id/activate
 * Activate suspended developer
 */
app.post('/developers/:id/activate', async (c) => {
  try {
    const developerId = c.req.param('id');

    await c.env.DB_MAIN.prepare(
      'UPDATE developers SET status = ?, updated_at = ? WHERE id = ?'
    )
      .bind('active', new Date().toISOString(), developerId)
      .run();

    return c.json({ success: true, message: 'Developer activated' });
  } catch (error) {
    logger.error('Activate developer error:', error);
    return c.json({ error: 'Failed to activate developer' }, 500);
  }
});

// ============================================================
// MODERATION
// ============================================================

/**
 * GET /marketplace-admin/flagged-reviews
 * Get flagged reviews for moderation
 */
app.get('/flagged-reviews', async (c) => {
  try {
    const result = await c.env.DB_MAIN.prepare(
      `SELECT r.*, ci.integration_name, u.username
       FROM custom_integration_reviews r
       JOIN custom_integrations ci ON r.custom_integration_id = ci.id
       JOIN users u ON r.user_id = u.id
       WHERE r.is_flagged = 1
       ORDER BY r.created_at DESC`
    ).all();

    return c.json({ reviews: result.results });
  } catch (error) {
    logger.error('Get flagged reviews error:', error);
    return c.json({ error: 'Failed to get flagged reviews' }, 500);
  }
});

/**
 * POST /marketplace-admin/reviews/:id/remove
 * Remove inappropriate review
 */
app.post('/reviews/:id/remove', async (c) => {
  try {
    const reviewId = c.req.param('id');

    await c.env.DB_MAIN.prepare(
      'DELETE FROM custom_integration_reviews WHERE id = ?'
    )
      .bind(reviewId)
      .run();

    return c.json({ success: true, message: 'Review removed' });
  } catch (error) {
    logger.error('Remove review error:', error);
    return c.json({ error: 'Failed to remove review' }, 500);
  }
});

export default app;
