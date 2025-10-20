/**
 * CRM Signals & Webhooks API Routes
 * Job change detection (Feature #3) and Intent signals (Feature #9)
 */

import { Hono } from 'hono';
import { z } from 'zod';
import { zValidator } from '@hono/zod-validator';
import { JobChangeDetectionService } from '../services/crm/job-change-detection.service';
import type { Env } from '../types/env';

const app = new Hono<{ Bindings: Env }>();

// ============================================================================
// JOB CHANGE DETECTION (Feature #3)
// ============================================================================

/**
 * Webhook endpoint for PeopleDataLabs job change notifications
 * POST /api/v1/crm/webhooks/job-change
 */
app.post('/webhooks/job-change', async (c) => {
  try {
    const payload = await c.req.json();

    const service = new JobChangeDetectionService(c.env);
    const jobChange = await service.processJobChangeWebhook(payload);

    if (!jobChange) {
      return c.json({
        success: false,
        message: 'Job change could not be processed (contact not found or invalid data)'
      }, 400);
    }

    return c.json({
      success: true,
      message: 'Job change processed successfully',
      data: jobChange
    });
  } catch (error: any) {
    console.error('Job change webhook error:', error);
    return c.json({
      success: false,
      error: 'Failed to process job change webhook',
      message: error.message
    }, 500);
  }
});

/**
 * Manually check for job changes
 * POST /api/v1/crm/job-changes/check/:contactId
 */
app.post('/job-changes/check/:contactId', async (c) => {
  const businessId = c.req.header('X-Business-ID') || 'business-founder-001';
  const contactId = c.req.param('contactId');

  const service = new JobChangeDetectionService(c.env);
  const result = await service.checkJobChangesForContact(businessId, contactId);

  return c.json(result);
});

/**
 * Get recent job changes
 * GET /api/v1/crm/job-changes/recent
 */
app.get('/job-changes/recent', async (c) => {
  const businessId = c.req.header('X-Business-ID') || 'business-founder-001';
  const days = parseInt(c.req.query('days') || '30');

  const service = new JobChangeDetectionService(c.env);
  const changes = await service.getRecentJobChanges(businessId, days);

  return c.json({
    success: true,
    data: changes,
    count: changes.length
  });
});

// ============================================================================
// INTENT SIGNAL MONITORING (Feature #9)
// ============================================================================

const TrackIntentSignalSchema = z.object({
  entity_type: z.enum(['contact', 'company', 'lead']),
  entity_id: z.string(),
  signal_type: z.string(),
  signal_source: z.string(),
  intent_score: z.number().min(0).max(100),
  topic: z.string().optional(),
  url: z.string().optional(),
  metadata: z.any().optional(),
});

/**
 * Track intent signal
 * POST /api/v1/crm/intent-signals
 */
app.post('/intent-signals', zValidator('json', TrackIntentSignalSchema), async (c) => {
  const businessId = c.req.header('X-Business-ID') || 'business-founder-001';
  const data = c.req.valid('json');

  const intentLevel =
    data.intent_score >= 80 ? 'very_high' :
    data.intent_score >= 60 ? 'high' :
    data.intent_score >= 40 ? 'medium' : 'low';

  const id = crypto.randomUUID().replace(/-/g, '');
  const now = new Date().toISOString();

  await c.env.DB_MAIN.prepare(`
    INSERT INTO crm_intent_signals (
      id, business_id, entity_type, entity_id,
      signal_type, signal_source, intent_score, intent_level,
      topic, url, metadata, signal_timestamp, expires_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(
    id, businessId, data.entity_type, data.entity_id,
    data.signal_type, data.signal_source, data.intent_score, intentLevel,
    data.topic || null,
    data.url || null,
    JSON.stringify(data.metadata || {}),
    now,
    new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString() // 30 days expiry
  ).run();

  // If high intent, create next action
  if (intentLevel === 'high' || intentLevel === 'very_high') {
    const actionId = crypto.randomUUID().replace(/-/g, '');
    await c.env.DB_MAIN.prepare(`
      INSERT INTO crm_next_actions (
        id, business_id, entity_type, entity_id, user_id,
        action_type, priority, action_title, action_description, reasoning,
        expires_at
      ) VALUES (?, ?, ?, ?, 'user-founder-001', 'follow_up', ?, ?, ?, ?, ?)
    `).bind(
      actionId, businessId, data.entity_type, data.entity_id,
      data.intent_score,
      `High intent signal detected: ${data.signal_type}`,
      `${data.entity_type} showing strong buying signals (${data.topic || 'relevant topic'}). Intent score: ${data.intent_score}/100`,
      'High intent signals indicate active research and near-term buying decision',
      new Date(Date.now() + 2 * 24 * 60 * 60 * 1000).toISOString() // 2 days
    ).run();
  }

  return c.json({
    success: true,
    message: 'Intent signal tracked',
    data: { id, intent_level: intentLevel }
  });
});

/**
 * Get high intent signals
 * GET /api/v1/crm/intent-signals/high-intent
 */
app.get('/intent-signals/high-intent', async (c) => {
  const businessId = c.req.header('X-Business-ID') || 'business-founder-001';

  const signals = await c.env.DB_MAIN.prepare(`
    SELECT * FROM view_high_intent_signals
    WHERE business_id = ?
    LIMIT 100
  `).bind(businessId).all();

  return c.json({
    success: true,
    data: signals.results || []
  });
});

/**
 * Get intent signals for entity
 * GET /api/v1/crm/intent-signals/:entityType/:entityId
 */
app.get('/intent-signals/:entityType/:entityId', async (c) => {
  const businessId = c.req.header('X-Business-ID') || 'business-founder-001';
  const entityType = c.req.param('entityType');
  const entityId = c.req.param('entityId');

  const signals = await c.env.DB_MAIN.prepare(`
    SELECT * FROM crm_intent_signals
    WHERE business_id = ? AND entity_type = ? AND entity_id = ?
      AND (expires_at IS NULL OR expires_at > datetime('now'))
    ORDER BY signal_timestamp DESC
    LIMIT 50
  `).bind(businessId, entityType, entityId).all();

  return c.json({
    success: true,
    data: signals.results || []
  });
});

/**
 * Webhook for Bombora intent data
 * POST /api/v1/crm/webhooks/bombora-intent
 */
app.post('/webhooks/bombora-intent', async (c) => {
  try {
    const payload = await c.req.json() as any;

    // Extract Bombora intent data
    const companyDomain = payload.company_domain || payload.domain;
    const topic = payload.topic || payload.intent_topic;
    const intentScore = payload.composite_score || payload.score || 50;

    if (!companyDomain) {
      return c.json({ success: false, error: 'No company domain in payload' }, 400);
    }

    // Find company in CRM
    const company = await c.env.DB_MAIN.prepare(`
      SELECT id, business_id FROM crm_companies
      WHERE company_domain = ? OR company_website LIKE ?
      LIMIT 1
    `).bind(companyDomain, `%${companyDomain}%`).first() as any;

    if (!company) {
      return c.json({ success: false, message: 'Company not found in CRM' }, 404);
    }

    // Track intent signal
    const id = crypto.randomUUID().replace(/-/g, '');
    const intentLevel = intentScore >= 80 ? 'very_high' : intentScore >= 60 ? 'high' : 'medium';

    await c.env.DB_MAIN.prepare(`
      INSERT INTO crm_intent_signals (
        id, business_id, entity_type, entity_id,
        signal_type, signal_source, intent_score, intent_level,
        topic, metadata, signal_timestamp
      ) VALUES (?, ?, 'company', ?, 'product_research', 'bombora', ?, ?, ?, ?, ?)
    `).bind(
      id, company.business_id, company.id,
      intentScore, intentLevel,
      topic,
      JSON.stringify(payload),
      new Date().toISOString()
    ).run();

    return c.json({ success: true, message: 'Bombora intent signal tracked', data: { id } });
  } catch (error: any) {
    console.error('Bombora webhook error:', error);
    return c.json({ success: false, error: error.message }, 500);
  }
});

export default app;
