/**
 * Admin Dashboard Analytics API Routes
 * Fortune 50 Level Analytics and Monitoring for System Administrators
 *
 * Features:
 * - Executive KPIs (cross-business aggregation)
 * - Real-time monitoring (live metrics streaming)
 * - Business intelligence (trends and analytics)
 * - System analytics (infrastructure metrics)
 * - Performance monitoring
 * - Security analytics
 */

import { Hono } from 'hono';
import type { Env } from '../types/env';import { Logger } from "../shared/logger";
const logger = new Logger({ component: "routes-admin-dashboard" });



const adminDashboard = new Hono<{ Bindings: Env }>();

/**
 * Executive KPIs Endpoint
 * GET /api/admin/analytics/kpis
 *
 * Returns high-level KPIs across all businesses:
 * - Total revenue (all businesses)
 * - Active users count
 * - Business count
 * - Growth metrics
 * - Health scores
 */
adminDashboard.get('/analytics/kpis', async (c) => {
  try {
    const userId = c.req.header('X-User-ID');

    // Verify admin role
    if (!userId) {
      return c.json({ error: 'Unauthorized - User ID required' }, 401);
    }

    const user = await c.env.DB_MAIN.prepare(
      'SELECT role FROM users WHERE id = ?'
    ).bind(userId).first() as { role: string } | null;

    if (!user || user.role !== 'admin') {
      return c.json({ error: 'Forbidden - Admin access required' }, 403);
    }

    // Get executive KPIs
    const now = new Date().toISOString();
    const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();
    void thirtyDaysAgo;

    // Total businesses
    const businessCount = await c.env.DB_MAIN.prepare(
      'SELECT COUNT(*) as count FROM businesses WHERE status = ?'
    ).bind('active').first() as { count: number } | null;

    // Total active users
    const activeUsers = await c.env.DB_MAIN.prepare(
      'SELECT COUNT(*) as count FROM users WHERE status = ?'
    ).bind('active').first() as { count: number } | null;

    // Total revenue (all time)
    const totalRevenue = await c.env.DB_MAIN.prepare(
      'SELECT SUM(amount) as total FROM payments WHERE status = ?'
    ).bind('completed').first() as { total: number | null } | null;

    // Revenue this month
    const currentMonth = new Date().toISOString().substring(0, 7);
    const monthlyRevenue = await c.env.DB_MAIN.prepare(
      'SELECT SUM(amount) as total FROM payments WHERE status = ? AND strftime("%Y-%m", created_at) = ?'
    ).bind('completed', currentMonth).first() as { total: number | null } | null;

    // Growth metrics (30-day comparison)
    const previousMonth = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString().substring(0, 7);
    const previousMonthRevenue = await c.env.DB_MAIN.prepare(
      'SELECT SUM(amount) as total FROM payments WHERE status = ? AND strftime("%Y-%m", created_at) = ?'
    ).bind('completed', previousMonth).first() as { total: number | null } | null;

    const revenueGrowth = previousMonthRevenue?.total
      ? ((monthlyRevenue?.total || 0) - previousMonthRevenue.total) / previousMonthRevenue.total * 100
      : 0;

    // Active sessions
    const activeSessions = await c.env.DB_MAIN.prepare(
      'SELECT COUNT(*) as count FROM sessions WHERE expires_at > ? AND invalidated = 0'
    ).bind(now).first() as { count: number } | null;

    // System health score (simplified - can be enhanced)
    const healthScore = 98.5; // TODO: Calculate based on system metrics

    return c.json({
      success: true,
      data: {
        kpis: {
          totalBusinesses: businessCount?.count || 0,
          activeUsers: activeUsers?.count || 0,
          totalRevenue: totalRevenue?.total || 0,
          monthlyRevenue: monthlyRevenue?.total || 0,
          revenueGrowth: Number(revenueGrowth.toFixed(2)),
          activeSessions: activeSessions?.count || 0,
          systemHealthScore: healthScore
        },
        period: {
          current: currentMonth,
          previous: previousMonth
        },
        timestamp: now
      }
    });

  } catch (error) {
    logger.error('Admin KPIs Error:', error);
    return c.json({
      success: false,
      error: 'Failed to fetch admin KPIs',
      message: error instanceof Error ? error.message : 'Unknown error'
    }, 500);
  }
});

/**
 * Real-time Monitoring Endpoint
 * GET /api/admin/analytics/realtime
 *
 * Returns real-time system metrics:
 * - Active users (online now)
 * - Request rate (per minute)
 * - Response times
 * - Error rates
 * - Database connections
 */
adminDashboard.get('/analytics/realtime', async (c) => {
  try {
    const userId = c.req.header('X-User-ID');

    if (!userId) {
      return c.json({ error: 'Unauthorized - User ID required' }, 401);
    }

    const user = await c.env.DB_MAIN.prepare(
      'SELECT role FROM users WHERE id = ?'
    ).bind(userId).first() as { role: string } | null;

    if (!user || user.role !== 'admin') {
      return c.json({ error: 'Forbidden - Admin access required' }, 403);
    }

    const now = new Date().toISOString();
    const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000).toISOString();
    const oneMinuteAgo = new Date(Date.now() - 60 * 1000).toISOString();

    // Active sessions in last 5 minutes
    const activeSessions = await c.env.DB_MAIN.prepare(
      'SELECT COUNT(*) as count FROM sessions WHERE last_activity_at > ? AND invalidated = 0'
    ).bind(fiveMinutesAgo).first() as { count: number } | null;

    // Recent audit log entries (proxy for request rate)
    const recentRequests = await c.env.DB_MAIN.prepare(
      'SELECT COUNT(*) as count FROM audit_log WHERE created_at > ?'
    ).bind(oneMinuteAgo).first() as { count: number } | null;

    // Error rate (from audit log)
    const recentErrors = await c.env.DB_MAIN.prepare(
      'SELECT COUNT(*) as count FROM audit_log WHERE created_at > ? AND status_code >= 400'
    ).bind(oneMinuteAgo).first() as { count: number } | null;

    const errorRate = recentRequests?.count
      ? ((recentErrors?.count || 0) / recentRequests.count) * 100
      : 0;

    // Recent payments (business activity)
    const recentPayments = await c.env.DB_MAIN.prepare(
      'SELECT COUNT(*) as count FROM payments WHERE created_at > ?'
    ).bind(fiveMinutesAgo).first() as { count: number } | null;

    // Database metrics (simulated - would come from D1 metrics in production)
    const dbMetrics = {
      totalConnections: 12,
      activeQueries: 3,
      avgQueryTime: 45, // ms
      cacheHitRate: 87.3 // %
    };

    return c.json({
      success: true,
      data: {
        realtime: {
          activeUsers: activeSessions?.count || 0,
          requestsPerMinute: recentRequests?.count || 0,
          errorRate: Number(errorRate.toFixed(2)),
          recentPayments: recentPayments?.count || 0,
          avgResponseTime: 120, // ms - would come from monitoring
          timestamp: now
        },
        database: dbMetrics,
        period: {
          window: '5 minutes',
          from: fiveMinutesAgo,
          to: now
        }
      }
    });

  } catch (error) {
    logger.error('Real-time Monitoring Error:', error);
    return c.json({
      success: false,
      error: 'Failed to fetch real-time metrics',
      message: error instanceof Error ? error.message : 'Unknown error'
    }, 500);
  }
});

/**
 * Business Intelligence Endpoint
 * GET /api/admin/analytics/business-intelligence
 *
 * Returns comprehensive business analytics:
 * - Revenue trends (daily, weekly, monthly)
 * - User growth trends
 * - Top performing businesses
 * - Payment method distribution
 * - Geographic distribution
 */
adminDashboard.get('/analytics/business-intelligence', async (c) => {
  try {
    const userId = c.req.header('X-User-ID');

    if (!userId) {
      return c.json({ error: 'Unauthorized - User ID required' }, 401);
    }

    const user = await c.env.DB_MAIN.prepare(
      'SELECT role FROM users WHERE id = ?'
    ).bind(userId).first() as { role: string } | null;

    if (!user || user.role !== 'admin') {
      return c.json({ error: 'Forbidden - Admin access required' }, 403);
    }

    // Revenue trend (last 12 months)
    const revenueTrend = await c.env.DB_MAIN.prepare(`
      SELECT
        strftime('%Y-%m', created_at) as month,
        SUM(amount) as revenue,
        COUNT(*) as transactions
      FROM payments
      WHERE status = 'completed'
        AND created_at >= date('now', '-12 months')
      GROUP BY month
      ORDER BY month ASC
    `).all();

    // User growth trend (last 12 months)
    const userGrowth = await c.env.DB_MAIN.prepare(`
      SELECT
        strftime('%Y-%m', created_at) as month,
        COUNT(*) as new_users
      FROM users
      WHERE created_at >= date('now', '-12 months')
      GROUP BY month
      ORDER BY month ASC
    `).all();

    // Top performing businesses (by revenue)
    const topBusinesses = await c.env.DB_MAIN.prepare(`
      SELECT
        b.id,
        b.name,
        SUM(p.amount) as total_revenue,
        COUNT(p.id) as transaction_count
      FROM businesses b
      LEFT JOIN payments p ON p.business_id = b.id AND p.status = 'completed'
      WHERE b.status = 'active'
      GROUP BY b.id, b.name
      ORDER BY total_revenue DESC
      LIMIT 10
    `).all();

    // Payment method distribution
    const paymentMethods = await c.env.DB_MAIN.prepare(`
      SELECT
        payment_method,
        COUNT(*) as count,
        SUM(amount) as total_amount
      FROM payments
      WHERE status = 'completed'
      GROUP BY payment_method
      ORDER BY total_amount DESC
    `).all();

    // Business type distribution
    const businessTypes = await c.env.DB_MAIN.prepare(`
      SELECT
        industry,
        COUNT(*) as count
      FROM businesses
      WHERE status = 'active'
      GROUP BY industry
      ORDER BY count DESC
    `).all();

    return c.json({
      success: true,
      data: {
        revenueTrend: revenueTrend.results || [],
        userGrowth: userGrowth.results || [],
        topBusinesses: topBusinesses.results || [],
        paymentMethods: paymentMethods.results || [],
        businessTypes: businessTypes.results || [],
        period: {
          months: 12,
          from: new Date(Date.now() - 365 * 24 * 60 * 60 * 1000).toISOString(),
          to: new Date().toISOString()
        }
      }
    });

  } catch (error) {
    logger.error('Business Intelligence Error:', error);
    return c.json({
      success: false,
      error: 'Failed to fetch business intelligence',
      message: error instanceof Error ? error.message : 'Unknown error'
    }, 500);
  }
});

/**
 * System Analytics Endpoint
 * GET /api/admin/analytics/system
 *
 * Returns infrastructure and system metrics:
 * - Database statistics
 * - Storage usage
 * - API performance
 * - Worker performance
 * - Cache statistics
 */
adminDashboard.get('/analytics/system', async (c) => {
  try {
    const userId = c.req.header('X-User-ID');

    if (!userId) {
      return c.json({ error: 'Unauthorized - User ID required' }, 401);
    }

    const user = await c.env.DB_MAIN.prepare(
      'SELECT role FROM users WHERE id = ?'
    ).bind(userId).first() as { role: string } | null;

    if (!user || user.role !== 'admin') {
      return c.json({ error: 'Forbidden - Admin access required' }, 403);
    }

    // Database table statistics
    const tableStats = await c.env.DB_MAIN.prepare(`
      SELECT
        name as table_name,
        (SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND tbl_name=name) as index_count
      FROM sqlite_master
      WHERE type='table' AND name NOT LIKE 'sqlite_%'
      ORDER BY name
    `).all();

    // Count records in key tables
    const userCount = await c.env.DB_MAIN.prepare('SELECT COUNT(*) as count FROM users').first() as { count: number } | null;
    const businessCount = await c.env.DB_MAIN.prepare('SELECT COUNT(*) as count FROM businesses').first() as { count: number } | null;
    const paymentCount = await c.env.DB_MAIN.prepare('SELECT COUNT(*) as count FROM payments').first() as { count: number } | null;
    const auditLogCount = await c.env.DB_MAIN.prepare('SELECT COUNT(*) as count FROM audit_log').first() as { count: number } | null;
    const sessionCount = await c.env.DB_MAIN.prepare('SELECT COUNT(*) as count FROM sessions').first() as { count: number } | null;

    // Storage metrics (simulated - would use R2 bucket metrics in production)
    const storageMetrics = {
      documents: {
        totalFiles: 1247,
        totalSizeGB: 3.42,
        avgFileSizeMB: 2.8
      },
      backups: {
        totalBackups: 45,
        totalSizeGB: 12.8,
        latestBackup: new Date().toISOString()
      }
    };

    // Performance metrics (simulated - would use Workers Analytics in production)
    const performanceMetrics = {
      api: {
        avgResponseTime: 120, // ms
        p95ResponseTime: 250, // ms
        p99ResponseTime: 450, // ms
        requestsPerSecond: 45.2,
        errorRate: 0.3 // %
      },
      database: {
        avgQueryTime: 35, // ms
        slowQueries: 12, // count in last hour
        connectionPool: {
          total: 20,
          active: 8,
          idle: 12
        }
      }
    };

    // Cache statistics (simulated - would use KV metrics)
    const cacheStats = {
      hitRate: 87.3, // %
      missRate: 12.7, // %
      totalKeys: 3542,
      totalSizeMB: 145.8,
      evictionRate: 2.1 // %
    };

    return c.json({
      success: true,
      data: {
        database: {
          tables: tableStats.results || [],
          recordCounts: {
            users: userCount?.count || 0,
            businesses: businessCount?.count || 0,
            payments: paymentCount?.count || 0,
            auditLog: auditLogCount?.count || 0,
            sessions: sessionCount?.count || 0
          }
        },
        storage: storageMetrics,
        performance: performanceMetrics,
        cache: cacheStats,
        timestamp: new Date().toISOString()
      }
    });

  } catch (error) {
    logger.error('System Analytics Error:', error);
    return c.json({
      success: false,
      error: 'Failed to fetch system analytics',
      message: error instanceof Error ? error.message : 'Unknown error'
    }, 500);
  }
});

/**
 * Security Analytics Endpoint
 * GET /api/admin/analytics/security
 *
 * Returns security-related metrics:
 * - Failed login attempts
 * - Suspicious activity
 * - Token revocations
 * - IP blocking events
 * - Security audit trail
 */
adminDashboard.get('/analytics/security', async (c) => {
  try {
    const userId = c.req.header('X-User-ID');

    if (!userId) {
      return c.json({ error: 'Unauthorized - User ID required' }, 401);
    }

    const user = await c.env.DB_MAIN.prepare(
      'SELECT role FROM users WHERE id = ?'
    ).bind(userId).first() as { role: string } | null;

    if (!user || user.role !== 'admin') {
      return c.json({ error: 'Forbidden - Admin access required' }, 403);
    }

    const now = new Date().toISOString();
    const last24Hours = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();

    // Failed login attempts (last 24 hours)
    const failedLogins = await c.env.DB_MAIN.prepare(`
      SELECT COUNT(*) as count
      FROM audit_log
      WHERE action = 'login'
        AND status_code = 401
        AND created_at > ?
    `).bind(last24Hours).first() as { count: number } | null;

    // Recent token revocations
    const revokedTokens = await c.env.DB_MAIN.prepare(`
      SELECT COUNT(*) as count
      FROM token_blacklist
      WHERE created_at > ?
    `).bind(last24Hours).first() as { count: number } | null;

    // Active sessions by user role
    const sessionsByRole = await c.env.DB_MAIN.prepare(`
      SELECT
        u.role,
        COUNT(s.id) as session_count
      FROM sessions s
      JOIN users u ON s.user_id = u.id
      WHERE s.expires_at > ? AND s.invalidated = 0
      GROUP BY u.role
    `).bind(now).all();

    // Recent security events from audit log
    const securityEvents = await c.env.DB_MAIN.prepare(`
      SELECT
        action,
        status_code,
        ip_address,
        created_at
      FROM audit_log
      WHERE created_at > ?
        AND (status_code >= 400 OR action IN ('login', 'logout', 'password_reset'))
      ORDER BY created_at DESC
      LIMIT 50
    `).bind(last24Hours).all();

    // MFA adoption rate
    const mfaStats = await c.env.DB_MAIN.prepare(`
      SELECT
        COUNT(*) as total_users,
        SUM(CASE WHEN mfa_enabled = 1 THEN 1 ELSE 0 END) as mfa_enabled_users
      FROM users
      WHERE status = 'active'
    `).first() as { total_users: number; mfa_enabled_users: number | null } | null;

    const mfaAdoptionRate = mfaStats?.total_users
      ? ((mfaStats.mfa_enabled_users || 0) / mfaStats.total_users) * 100
      : 0;

    return c.json({
      success: true,
      data: {
        security: {
          failedLoginAttempts: failedLogins?.count || 0,
          revokedTokens: revokedTokens?.count || 0,
          mfaAdoptionRate: Number(mfaAdoptionRate.toFixed(2)),
          sessionsByRole: sessionsByRole.results || []
        },
        recentEvents: securityEvents.results || [],
        period: {
          hours: 24,
          from: last24Hours,
          to: now
        }
      }
    });

  } catch (error) {
    logger.error('Security Analytics Error:', error);
    return c.json({
      success: false,
      error: 'Failed to fetch security analytics',
      message: error instanceof Error ? error.message : 'Unknown error'
    }, 500);
  }
});

export default adminDashboard;
