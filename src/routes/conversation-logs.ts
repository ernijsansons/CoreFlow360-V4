// @ts-nocheck
/**
 * Conversation Logs API Routes
 * View and search captured interactions from all integrations
 */

import { Hono } from 'hono';
import { Logger } from '../shared/logger';
const logger = new Logger({ component: 'conversation-logs' });
import type { Env } from '../types/env';
import { authenticate } from '../middleware/auth';

const app = new Hono<{ Bindings: Env }>();

/**
 * Get conversation logs with filtering and pagination
 */
app.get('/', authenticate, async (c) => {
  try {
    const { businessId } = c.get('user');

    // Parse query parameters
    const limit = parseInt(c.req.query('limit') || '20');
    const offset = parseInt(c.req.query('offset') || '0');
    const search = c.req.query('search');
    const sourceType = c.req.query('source_type');

    let query = `
      SELECT
        id, source_type, external_id, subject, body, transcript,
        participants, direction, occurred_at, metadata,
        ai_extracted_data, linked_contacts, linked_companies,
        linked_deals, created_at
      FROM crm_conversation_logs
      WHERE business_id = ?
    `;

    const params: any[] = [businessId];

    // Add source type filter
    if (sourceType && sourceType !== 'all') {
      query += ' AND source_type = ?';
      params.push(sourceType);
    }

    // Add search filter
    if (search) {
      query += ' AND (subject LIKE ? OR body LIKE ? OR transcript LIKE ?)';
      const searchPattern = `%${search}%`;
      params.push(searchPattern, searchPattern, searchPattern);
    }

    // Order and pagination
    query += ' ORDER BY occurred_at DESC LIMIT ? OFFSET ?';
    params.push(limit, offset);

    // Get logs
    const logs = await c.env.DB_MAIN
      .prepare(query)
      .bind(...params)
      .all();

    // Get total count
    let countQuery = `
      SELECT COUNT(*) as total
      FROM crm_conversation_logs
      WHERE business_id = ?
    `;
    const countParams: any[] = [businessId];

    if (sourceType && sourceType !== 'all') {
      countQuery += ' AND source_type = ?';
      countParams.push(sourceType);
    }

    if (search) {
      countQuery += ' AND (subject LIKE ? OR body LIKE ? OR transcript LIKE ?)';
      const searchPattern = `%${search}%`;
      countParams.push(searchPattern, searchPattern, searchPattern);
    }

    const countResult = await c.env.DB_MAIN
      .prepare(countQuery)
      .bind(...countParams)
      .first<{ total: number }>();

    const total = countResult?.total || 0;

    // Parse JSON fields
    const parsedLogs = (logs.results || []).map((log: any) => ({
      ...log,
      participants: log.participants ? JSON.parse(log.participants) : [],
      metadata: log.metadata ? JSON.parse(log.metadata) : {},
      ai_extracted_data: log.ai_extracted_data ? JSON.parse(log.ai_extracted_data) : null,
      linked_contacts: log.linked_contacts ? JSON.parse(log.linked_contacts) : [],
      linked_companies: log.linked_companies ? JSON.parse(log.linked_companies) : [],
      linked_deals: log.linked_deals ? JSON.parse(log.linked_deals) : []
    }));

    return c.json({
      success: true,
      data: {
        logs: parsedLogs,
        total: total,
        has_more: offset + limit < total
      }
    });
  } catch (error: any) {
    logger.error('Conversation logs fetch error:', error);
    return c.json({ success: false, error: error.message }, 500);
  }
});

/**
 * Get conversation log by ID
 */
app.get('/:id', authenticate, async (c) => {
  try {
    const { businessId } = c.get('user');
    const id = c.req.param('id');

    const log = await c.env.DB_MAIN
      .prepare(`
        SELECT
          id, source_type, external_id, subject, body, transcript,
          participants, direction, occurred_at, metadata,
          ai_extracted_data, linked_contacts, linked_companies,
          linked_deals, created_at, updated_at
        FROM crm_conversation_logs
        WHERE id = ? AND business_id = ?
      `)
      .bind(id, businessId)
      .first();

    if (!log) {
      return c.json({ success: false, error: 'Conversation log not found' }, 404);
    }

    // Parse JSON fields
    const parsedLog = {
      ...log,
      participants: log.participants ? JSON.parse(log.participants as string) : [],
      metadata: log.metadata ? JSON.parse(log.metadata as string) : {},
      ai_extracted_data: log.ai_extracted_data ? JSON.parse(log.ai_extracted_data as string) : null,
      linked_contacts: log.linked_contacts ? JSON.parse(log.linked_contacts as string) : [],
      linked_companies: log.linked_companies ? JSON.parse(log.linked_companies as string) : [],
      linked_deals: log.linked_deals ? JSON.parse(log.linked_deals as string) : []
    };

    return c.json({
      success: true,
      data: parsedLog
    });
  } catch (error: any) {
    logger.error('Conversation log fetch error:', error);
    return c.json({ success: false, error: error.message }, 500);
  }
});

/**
 * Get conversation logs stats
 */
app.get('/stats/summary', authenticate, async (c) => {
  try {
    const { businessId } = c.get('user');

    // Get counts by source type
    const stats = await c.env.DB_MAIN
      .prepare(`
        SELECT
          source_type,
          COUNT(*) as count,
          MAX(occurred_at) as last_occurred
        FROM crm_conversation_logs
        WHERE business_id = ?
        GROUP BY source_type
      `)
      .bind(businessId)
      .all();

    // Get total count
    const total = await c.env.DB_MAIN
      .prepare('SELECT COUNT(*) as total FROM crm_conversation_logs WHERE business_id = ?')
      .bind(businessId)
      .first<{ total: number }>();

    // Get today's count
    const today = new Date().toISOString().split('T')[0];
    const todayCount = await c.env.DB_MAIN
      .prepare(`
        SELECT COUNT(*) as count
        FROM crm_conversation_logs
        WHERE business_id = ? AND DATE(occurred_at) = ?
      `)
      .bind(businessId, today)
      .first<{ count: number }>();

    return c.json({
      success: true,
      data: {
        total: total?.total || 0,
        today: todayCount?.count || 0,
        by_source: stats.results || []
      }
    });
  } catch (error: any) {
    logger.error('Conversation logs stats error:', error);
    return c.json({ success: false, error: error.message }, 500);
  }
});

export default app;
