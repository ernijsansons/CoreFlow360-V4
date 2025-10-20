/**
 * CRM Enrichment API Routes
 * Multi-source data enrichment with automated queue processing
 * Part of Phase 1 Sprint 1 - Feature #2
 */

import { Hono } from 'hono';
import { z } from 'zod';
import { zValidator } from '@hono/zod-validator';
import { EnrichmentService } from '../services/crm/enrichment.service';
import type { Env } from '../types/env';

const app = new Hono<{ Bindings: Env }>();

// ============================================================================
// VALIDATION SCHEMAS
// ============================================================================

const EnrichContactSchema = z.object({
  contact_id: z.string().min(1),
  preferred_sources: z.array(z.enum([
    'clearbit',
    'hunter',
    'peopledatalabs',
    'zoominfo',
    'linkedin_api',
    'crunchbase',
    'fullcontact'
  ])).optional(),
});

const QueueEnrichmentSchema = z.object({
  entity_id: z.string().min(1),
  entity_type: z.enum(['contact', 'company', 'lead']),
  priority: z.number().min(0).max(100).optional(),
  triggered_by: z.string().optional(),
});

const SaveCredentialsSchema = z.object({
  data_source: z.enum([
    'clearbit',
    'hunter',
    'peopledatalabs',
    'zoominfo',
    'linkedin_api',
    'crunchbase',
    'fullcontact'
  ]),
  api_key: z.string().min(1),
  api_secret: z.string().optional(),
  monthly_quota: z.number().optional(),
});

// ============================================================================
// ENRICHMENT ENDPOINTS
// ============================================================================

/**
 * Enrich a contact immediately
 * POST /api/v1/crm/enrichment/contact
 */
app.post('/contact', zValidator('json', EnrichContactSchema), async (c) => {
  try {
    const businessId = c.req.header('X-Business-ID') || 'business-founder-001';
    const { contact_id, preferred_sources } = c.req.valid('json');

    const service = new EnrichmentService(c.env);
    const result = await service.enrichContact(businessId, contact_id, preferred_sources);

    if (!result.success) {
      return c.json({
        success: false,
        error: result.error || 'Enrichment failed',
        result
      }, 400);
    }

    return c.json({
      success: true,
      message: `Contact enriched successfully from ${result.source}`,
      data: result
    });
  } catch (error: any) {
    console.error('Enrichment error:', error);
    return c.json({
      success: false,
      error: 'Failed to enrich contact',
      message: error.message
    }, 500);
  }
});

/**
 * Queue entity for enrichment
 * POST /api/v1/crm/enrichment/queue
 */
app.post('/queue', zValidator('json', QueueEnrichmentSchema), async (c) => {
  try {
    const businessId = c.req.header('X-Business-ID') || 'business-founder-001';
    const { entity_id, entity_type, priority, triggered_by } = c.req.valid('json');

    const service = new EnrichmentService(c.env);
    await service.queueEnrichment(
      businessId,
      entity_id,
      entity_type,
      priority,
      triggered_by || 'manual'
    );

    return c.json({
      success: true,
      message: `${entity_type} queued for enrichment`,
      queue_position: 'pending'
    });
  } catch (error: any) {
    console.error('Queue enrichment error:', error);
    return c.json({
      success: false,
      error: 'Failed to queue enrichment',
      message: error.message
    }, 500);
  }
});

/**
 * Get enrichment queue status
 * GET /api/v1/crm/enrichment/queue/status
 */
app.get('/queue/status', async (c) => {
  try {
    const businessId = c.req.header('X-Business-ID') || 'business-founder-001';

    const stats = await c.env.DB_MAIN.prepare(`
      SELECT
        status,
        COUNT(*) as count,
        AVG(priority) as avg_priority
      FROM crm_enrichment_queue
      WHERE business_id = ?
      GROUP BY status
    `).bind(businessId).all();

    const total = await c.env.DB_MAIN.prepare(`
      SELECT COUNT(*) as total FROM crm_enrichment_queue WHERE business_id = ?
    `).bind(businessId).first() as { total: number } | null;

    return c.json({
      success: true,
      data: {
        total: total?.total || 0,
        by_status: stats.results || []
      }
    });
  } catch (error: any) {
    console.error('Queue status error:', error);
    return c.json({
      success: false,
      error: 'Failed to get queue status',
      message: error.message
    }, 500);
  }
});

/**
 * Process enrichment queue manually (for testing)
 * POST /api/v1/crm/enrichment/queue/process
 */
app.post('/queue/process', async (c) => {
  try {
    const batchSize = parseInt(c.req.query('batch_size') || '10');

    const service = new EnrichmentService(c.env);
    const processed = await service.processQueue(batchSize);

    return c.json({
      success: true,
      message: `Processed ${processed} items from queue`,
      processed_count: processed
    });
  } catch (error: any) {
    console.error('Process queue error:', error);
    return c.json({
      success: false,
      error: 'Failed to process queue',
      message: error.message
    }, 500);
  }
});

// ============================================================================
// ENRICHMENT HISTORY & ANALYTICS
// ============================================================================

/**
 * Get enrichment history for an entity
 * GET /api/v1/crm/enrichment/history/:entityType/:entityId
 */
app.get('/history/:entityType/:entityId', async (c) => {
  try {
    const businessId = c.req.header('X-Business-ID') || 'business-founder-001';
    const entityType = c.req.param('entityType');
    const entityId = c.req.param('entityId');
    const limit = parseInt(c.req.query('limit') || '50');

    const history = await c.env.DB_MAIN.prepare(`
      SELECT * FROM crm_enrichment_history
      WHERE business_id = ? AND entity_id = ? AND entity_type = ?
      ORDER BY enriched_at DESC
      LIMIT ?
    `).bind(businessId, entityId, entityType, limit).all();

    return c.json({
      success: true,
      data: (history.results || []).map((h: any) => ({
        ...h,
        fields_updated: JSON.parse(h.fields_updated || '[]'),
        fields_added: JSON.parse(h.fields_added || '[]'),
      })),
      total: history.results?.length || 0
    });
  } catch (error: any) {
    console.error('Get history error:', error);
    return c.json({
      success: false,
      error: 'Failed to get enrichment history',
      message: error.message
    }, 500);
  }
});

/**
 * Get enrichment success rates by source
 * GET /api/v1/crm/enrichment/analytics/success-rates
 */
app.get('/analytics/success-rates', async (c) => {
  try {
    const businessId = c.req.header('X-Business-ID') || 'business-founder-001';
    const days = parseInt(c.req.query('days') || '30');

    const stats = await c.env.DB_MAIN.prepare(`
      SELECT * FROM view_enrichment_success_rates
    `).all();

    return c.json({
      success: true,
      data: stats.results || [],
      period_days: days
    });
  } catch (error: any) {
    console.error('Success rates error:', error);
    return c.json({
      success: false,
      error: 'Failed to get success rates',
      message: error.message
    }, 500);
  }
});

/**
 * Get contacts needing enrichment
 * GET /api/v1/crm/enrichment/analytics/needs-enrichment
 */
app.get('/analytics/needs-enrichment', async (c) => {
  try {
    const limit = parseInt(c.req.query('limit') || '100');
    const priority = c.req.query('priority') || 'all'; // high, medium, low, all

    let query = 'SELECT * FROM view_contacts_needing_enrichment';

    if (priority !== 'all') {
      query += ` WHERE enrichment_priority = '${priority}'`;
    }

    query += ' ORDER BY completeness_percentage ASC LIMIT ?';

    const contacts = await c.env.DB_MAIN.prepare(query).bind(limit).all();

    return c.json({
      success: true,
      data: contacts.results || [],
      total: contacts.results?.length || 0
    });
  } catch (error: any) {
    console.error('Needs enrichment error:', error);
    return c.json({
      success: false,
      error: 'Failed to get contacts needing enrichment',
      message: error.message
    }, 500);
  }
});

/**
 * Get data completeness score for an entity
 * GET /api/v1/crm/enrichment/completeness/:entityType/:entityId
 */
app.get('/completeness/:entityType/:entityId', async (c) => {
  try {
    const businessId = c.req.header('X-Business-ID') || 'business-founder-001';
    const entityType = c.req.param('entityType');
    const entityId = c.req.param('entityId');

    const score = await c.env.DB_MAIN.prepare(`
      SELECT * FROM crm_data_completeness
      WHERE business_id = ? AND entity_id = ? AND entity_type = ?
    `).bind(businessId, entityId, entityType).first();

    if (!score) {
      return c.json({
        success: false,
        error: 'Completeness score not found'
      }, 404);
    }

    return c.json({
      success: true,
      data: score
    });
  } catch (error: any) {
    console.error('Completeness error:', error);
    return c.json({
      success: false,
      error: 'Failed to get completeness score',
      message: error.message
    }, 500);
  }
});

// ============================================================================
// CREDENTIALS MANAGEMENT
// ============================================================================

/**
 * Save enrichment source credentials
 * POST /api/v1/crm/enrichment/credentials
 */
app.post('/credentials', zValidator('json', SaveCredentialsSchema), async (c) => {
  try {
    const businessId = c.req.header('X-Business-ID') || 'business-founder-001';
    const { data_source, api_key, api_secret, monthly_quota } = c.req.valid('json');

    // Check if credentials already exist
    const existing = await c.env.DB_MAIN.prepare(`
      SELECT id FROM crm_enrichment_credentials
      WHERE business_id = ? AND data_source = ?
    `).bind(businessId, data_source).first();

    const now = new Date().toISOString();

    if (existing) {
      // Update existing
      await c.env.DB_MAIN.prepare(`
        UPDATE crm_enrichment_credentials
        SET api_key = ?, api_secret = ?, monthly_quota = ?, status = 'active', updated_at = ?
        WHERE business_id = ? AND data_source = ?
      `).bind(
        api_key,
        api_secret || null,
        monthly_quota || null,
        now,
        businessId,
        data_source
      ).run();
    } else {
      // Insert new
      const id = crypto.randomUUID().replace(/-/g, '');
      await c.env.DB_MAIN.prepare(`
        INSERT INTO crm_enrichment_credentials (
          id, business_id, data_source, api_key, api_secret,
          monthly_quota, quota_used, status, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, 0, 'active', ?, ?)
      `).bind(
        id,
        businessId,
        data_source,
        api_key,
        api_secret || null,
        monthly_quota || null,
        now,
        now
      ).run();
    }

    return c.json({
      success: true,
      message: `Credentials saved for ${data_source}`
    });
  } catch (error: any) {
    console.error('Save credentials error:', error);
    return c.json({
      success: false,
      error: 'Failed to save credentials',
      message: error.message
    }, 500);
  }
});

/**
 * Get all saved credentials (api_key hidden)
 * GET /api/v1/crm/enrichment/credentials
 */
app.get('/credentials', async (c) => {
  try {
    const businessId = c.req.header('X-Business-ID') || 'business-founder-001';

    const credentials = await c.env.DB_MAIN.prepare(`
      SELECT
        id, data_source, status, monthly_quota, quota_used,
        quota_reset_at, last_used_at, created_at
      FROM crm_enrichment_credentials
      WHERE business_id = ?
      ORDER BY data_source
    `).bind(businessId).all();

    return c.json({
      success: true,
      data: credentials.results || []
    });
  } catch (error: any) {
    console.error('Get credentials error:', error);
    return c.json({
      success: false,
      error: 'Failed to get credentials',
      message: error.message
    }, 500);
  }
});

/**
 * Delete credentials
 * DELETE /api/v1/crm/enrichment/credentials/:source
 */
app.delete('/credentials/:source', async (c) => {
  try {
    const businessId = c.req.header('X-Business-ID') || 'business-founder-001';
    const source = c.req.param('source');

    await c.env.DB_MAIN.prepare(`
      DELETE FROM crm_enrichment_credentials
      WHERE business_id = ? AND data_source = ?
    `).bind(businessId, source).run();

    return c.json({
      success: true,
      message: `Credentials deleted for ${source}`
    });
  } catch (error: any) {
    console.error('Delete credentials error:', error);
    return c.json({
      success: false,
      error: 'Failed to delete credentials',
      message: error.message
    }, 500);
  }
});

export default app;
