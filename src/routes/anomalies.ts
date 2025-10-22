// @ts-nocheck
/**
 * Anomaly Detection API Routes
 * Handles fraud detection and anomaly management
 */

import { Hono } from 'hono';
import type { Env } from '../types/env';
import { AnomalyDetector } from '../services/ai/anomaly-detector';
import { authenticate } from '../middleware/auth';import { Logger } from "../shared/logger";
const logger = new Logger({ component: "routes-anomalies" });



const anomalies = new Hono<{ Bindings: Env }>();

// Apply authentication to all routes
anomalies.use('*', authenticate);

/**
 * GET /api/anomalies
 * List anomalies
 */
anomalies.get('/', async (c) => {
  try {
    const { businessId } = c.get('auth');
    const { status = 'open', severity, limit = '50', offset = '0' } = c.req.query();

    let query = `
      SELECT
        id, transaction_type, transaction_id, anomaly_type,
        severity, description, details, status, created_at
      FROM transaction_anomalies
      WHERE business_id = ?
    `;

    const params: any[] = [businessId];

    if (status) {
      query += ` AND status = ?`;
      params.push(status);
    }

    if (severity) {
      query += ` AND severity = ?`;
      params.push(severity);
    }

    query += `
      ORDER BY
        CASE severity
          WHEN 'critical' THEN 1
          WHEN 'high' THEN 2
          WHEN 'medium' THEN 3
          WHEN 'low' THEN 4
        END,
        created_at DESC
      LIMIT ? OFFSET ?
    `;

    params.push(parseInt(limit), parseInt(offset));

    const result = await c.env.DB.prepare(query)
      .bind(...params)
      .all();

    // Parse details JSON
    const anomaliesData = result.results.map((a: any) => ({
      ...a,
      details: JSON.parse(a.details)
    }));

    return c.json({
      success: true,
      data: {
        anomalies: anomaliesData,
        total: anomaliesData.length,
        limit: parseInt(limit),
        offset: parseInt(offset)
      }
    });
  } catch (error) {
    logger.error('List anomalies error:', error);
    return c.json({
      success: false,
      error: 'Failed to list anomalies'
    }, 500);
  }
});

/**
 * GET /api/anomalies/:id
 * Get anomaly details
 */
anomalies.get('/:id', async (c) => {
  try {
    const { businessId } = c.get('auth');
    const { id } = c.req.param();

    const anomaly = await c.env.DB.prepare(`
      SELECT * FROM transaction_anomalies
      WHERE id = ? AND business_id = ?
    `).bind(id, businessId).first();

    if (!anomaly) {
      return c.json({
        success: false,
        error: 'Anomaly not found'
      }, 404);
    }

    return c.json({
      success: true,
      data: {
        ...anomaly,
        details: JSON.parse(anomaly.details as string)
      }
    });
  } catch (error) {
    logger.error('Get anomaly error:', error);
    return c.json({
      success: false,
      error: 'Failed to get anomaly'
    }, 500);
  }
});

/**
 * POST /api/anomalies/scan
 * Scan for anomalies
 */
anomalies.post('/scan', async (c) => {
  try {
    const { businessId } = c.get('auth');
    const { days_back = 30 } = await c.req.json().catch(() => ({}));

    const detector = new AnomalyDetector(c.env);
    const detectedAnomalies = await detector.scanForAnomalies(businessId, days_back);

    return c.json({
      success: true,
      data: {
        anomalies_found: detectedAnomalies.length,
        anomalies: detectedAnomalies,
        scan_period_days: days_back
      }
    });
  } catch (error) {
    logger.error('Scan anomalies error:', error);
    return c.json({
      success: false,
      error: 'Failed to scan for anomalies'
    }, 500);
  }
});

/**
 * POST /api/anomalies/:id/resolve
 * Resolve an anomaly
 */
anomalies.post('/:id/resolve', async (c) => {
  try {
    const { businessId, userId } = c.get('auth');
    const { id } = c.req.param();
    const { resolution = 'resolved' } = await c.req.json();

    if (!['resolved', 'false_positive'].includes(resolution)) {
      return c.json({
        success: false,
        error: 'Invalid resolution. Must be "resolved" or "false_positive"'
      }, 400);
    }

    const detector = new AnomalyDetector(c.env);
    const success = await detector.resolveAnomaly(id, businessId, userId, resolution);

    if (!success) {
      return c.json({
        success: false,
        error: 'Failed to resolve anomaly'
      }, 500);
    }

    return c.json({
      success: true,
      data: {
        message: 'Anomaly resolved',
        anomaly_id: id,
        resolution
      }
    });
  } catch (error) {
    logger.error('Resolve anomaly error:', error);
    return c.json({
      success: false,
      error: 'Failed to resolve anomaly'
    }, 500);
  }
});

/**
 * GET /api/anomalies/stats
 * Get anomaly statistics
 */
anomalies.get('/stats', async (c) => {
  try {
    const { businessId } = c.get('auth');

    const stats = await c.env.DB.prepare(`
      SELECT
        COUNT(*) as total_anomalies,
        SUM(CASE WHEN status = 'open' THEN 1 ELSE 0 END) as open_count,
        SUM(CASE WHEN status = 'resolved' THEN 1 ELSE 0 END) as resolved_count,
        SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical_count,
        SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high_count,
        SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END) as medium_count,
        SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END) as low_count
      FROM transaction_anomalies
      WHERE business_id = ?
        AND created_at >= datetime('now', '-30 days')
    `).bind(businessId).first();

    // Get anomaly types breakdown
    const typeBreakdown = await c.env.DB.prepare(`
      SELECT
        anomaly_type,
        COUNT(*) as count
      FROM transaction_anomalies
      WHERE business_id = ?
        AND status = 'open'
      GROUP BY anomaly_type
      ORDER BY count DESC
    `).bind(businessId).all();

    return c.json({
      success: true,
      data: {
        summary: stats,
        by_type: typeBreakdown.results
      }
    });
  } catch (error) {
    logger.error('Get stats error:', error);
    return c.json({
      success: false,
      error: 'Failed to get stats'
    }, 500);
  }
});

export default anomalies;
