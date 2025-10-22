// @ts-nocheck
/**
 * Dashboard API Routes
 * Provides aggregated metrics and insights for the main dashboard
 */

import { Hono } from 'hono';
import { Logger } from '../shared/logger';
const logger = new Logger({ component: 'dashboard' });
import { DashboardService } from '../services/dashboard-service';
import type { Env } from '../types/env';

const app = new Hono<{ Bindings: Env }>();

/**
 * GET /dashboard/stats
 * Get dashboard statistics
 * Query params:
 *  - dateRange: '7d' | '30d' | '90d' | '1y'
 */
app.get('/stats', async (c) => {
  try {
    // TODO: Get from authenticated user context
    const businessId = c.req.query('businessId') || 'business-founder-001';
    const dateRange = (c.req.query('dateRange') as '7d' | '30d' | '90d' | '1y') || '30d';

    const db = c.env.DB_MAIN || c.env.DB;
    const dashboardService = new DashboardService(db, businessId);

    const stats = await dashboardService.getStats(dateRange);

    return c.json({
      success: true,
      data: stats,
      timestamp: new Date().toISOString()
    });
  } catch (error: any) {
    logger.error('Dashboard stats error:', error);
    return c.json({
      success: false,
      error: error.message || 'Failed to fetch dashboard statistics',
      timestamp: new Date().toISOString()
    }, 500);
  }
});

/**
 * GET /dashboard/activity
 * Get recent activity feed
 * Query params:
 *  - limit: number (default 20)
 */
app.get('/activity', async (c) => {
  try {
    const businessId = c.req.query('businessId') || 'business-founder-001';
    const limit = parseInt(c.req.query('limit') || '20');

    const db = c.env.DB_MAIN || c.env.DB;

    // Try to get recent activities from audit log
    try {
      const results = await db.prepare(`
        SELECT
          id,
          event as type,
          metadata,
          created_at as timestamp,
          user_id
        FROM audit_log
        WHERE business_id = ?
        ORDER BY created_at DESC
        LIMIT ?
      `).bind(businessId, limit).all<any>();

      const activities = results.results?.map(row => {
        const metadata = typeof row.metadata === 'string' ? JSON.parse(row.metadata) : row.metadata;
        return {
          id: row.id,
          type: row.type,
          description: `${row.type} event`,
          timestamp: row.timestamp,
          user: row.user_id,
          metadata
        };
      }) || [];

      return c.json({
        success: true,
        data: activities,
        timestamp: new Date().toISOString()
      });
    } catch (dbError) {
      // Audit log table doesn't exist yet, return empty array
      return c.json({
        success: true,
        data: [],
        timestamp: new Date().toISOString()
      });
    }
  } catch (error: any) {
    logger.error('Activity feed error:', error);
    return c.json({
      success: false,
      error: error.message || 'Failed to fetch activity feed',
      timestamp: new Date().toISOString()
    }, 500);
  }
});

/**
 * GET /dashboard/tasks
 * Get tasks summary
 */
app.get('/tasks', async (c) => {
  try {
    const businessId = c.req.query('businessId') || 'business-founder-001';
    const db = c.env.DB_MAIN || c.env.DB;

    // Get task counts by status
    try {
      const result = await db.prepare(`
        SELECT
          COUNT(*) as total,
          COUNT(CASE WHEN status = 'completed' THEN 1 END) as completed,
          COUNT(CASE WHEN status = 'pending' OR status = 'in_progress' THEN 1 END) as pending,
          COUNT(CASE WHEN due_date < datetime('now') AND status != 'completed' THEN 1 END) as overdue
        FROM tasks
        WHERE business_id = ?
      `).bind(businessId).first<any>();

      return c.json({
        success: true,
        data: {
          total: result?.total || 0,
          completed: result?.completed || 0,
          pending: result?.pending || 0,
          overdue: result?.overdue || 0
        },
        timestamp: new Date().toISOString()
      });
    } catch (error) {
      // Tasks table might not exist yet
      return c.json({
        success: true,
        data: {
          total: 0,
          completed: 0,
          pending: 0,
          overdue: 0
        },
        timestamp: new Date().toISOString()
      });
    }
  } catch (error: any) {
    logger.error('Tasks summary error:', error);
    return c.json({
      success: false,
      error: error.message || 'Failed to fetch tasks summary',
      timestamp: new Date().toISOString()
    }, 500);
  }
});

/**
 * GET /dashboard/charts/:metric
 * Get chart data for specific metric
 * Params:
 *  - metric: 'revenue' | 'users' | 'deals'
 * Query params:
 *  - dateRange: '7d' | '30d' | '90d' | '1y'
 */
app.get('/charts/:metric', async (c) => {
  try {
    const businessId = c.req.query('businessId') || 'business-founder-001';
    const metric = c.req.param('metric');
    const dateRange = (c.req.query('dateRange') as '7d' | '30d' | '90d' | '1y') || '30d';

    const db = c.env.DB_MAIN || c.env.DB;

    let data: any[] = [];

    switch (metric) {
      case 'revenue':
        const days = dateRange === '7d' ? 7 : dateRange === '30d' ? 30 : dateRange === '90d' ? 90 : 365;
        const months = Math.ceil(days / 30);
        void months;

        const revenueResults = await db.prepare(`
          SELECT
            strftime('%Y-%m-%d', paid_at) as date,
            SUM(total_amount) as value
          FROM invoices
          WHERE business_id = ?
            AND status = 'paid'
            AND paid_at >= date('now', '-${days} days')
          GROUP BY strftime('%Y-%m-%d', paid_at)
          ORDER BY date ASC
        `).bind(businessId).all<any>();

        data = revenueResults.results?.map(row => ({
          date: row.date,
          value: parseFloat(row.value || 0)
        })) || [];
        break;

      case 'users':
        data = []; // TODO: Implement user growth chart
        break;

      case 'deals':
        data = []; // TODO: Implement deals pipeline chart
        break;
    }

    return c.json({
      success: true,
      data,
      metric,
      dateRange,
      timestamp: new Date().toISOString()
    });
  } catch (error: any) {
    logger.error('Chart data error:', error);
    return c.json({
      success: false,
      error: error.message || 'Failed to fetch chart data',
      timestamp: new Date().toISOString()
    }, 500);
  }
});

export default app;
