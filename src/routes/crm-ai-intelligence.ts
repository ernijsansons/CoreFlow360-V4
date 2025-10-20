/**
 * CRM AI Intelligence API Routes
 * Unified routes for sentiment, next actions, forecasting, validation, duplicates
 * Features #7, #8, #10, #11, #12 - Phase 1 Sprint 1
 */

import { Hono } from 'hono';
import { z } from 'zod';
import { zValidator } from '@hono/zod-validator';
import { AIIntelligenceService } from '../services/crm/ai-intelligence.service';
import type { Env } from '../types/env';

const app = new Hono<{ Bindings: Env }>();

const AnalyzeSentimentSchema = z.object({
  activity_id: z.string(),
  text: z.string().min(10),
});

const GenerateActionsSchema = z.object({
  entity_type: z.enum(['contact', 'deal', 'lead']),
  entity_id: z.string(),
});

const GenerateForecastSchema = z.object({
  period: z.string(),
  forecast_type: z.enum(['monthly', 'quarterly', 'annual']),
});

// Sentiment Analysis (Feature #7)
app.post('/sentiment', zValidator('json', AnalyzeSentimentSchema), async (c) => {
  const businessId = c.req.header('X-Business-ID') || 'business-founder-001';
  const { activity_id, text } = c.req.valid('json');

  const service = new AIIntelligenceService(c.env);
  const result = await service.analyzeSentiment(businessId, activity_id, text);

  return c.json({ success: true, data: result });
});

// Next Best Actions (Feature #8)
app.post('/next-actions', zValidator('json', GenerateActionsSchema), async (c) => {
  const businessId = c.req.header('X-Business-ID') || 'business-founder-001';
  const userId = c.req.header('X-User-ID') || 'user-founder-001';
  const { entity_type, entity_id } = c.req.valid('json');

  const service = new AIIntelligenceService(c.env);
  const actions = await service.generateNextActions(businessId, entity_type, entity_id, userId);

  return c.json({ success: true, data: actions });
});

// Get pending actions for user
app.get('/next-actions/pending', async (c) => {
  const businessId = c.req.header('X-Business-ID') || 'business-founder-001';
  const userId = c.req.header('X-User-ID') || 'user-founder-001';

  const actions = await c.env.DB_MAIN.prepare(`
    SELECT * FROM crm_next_actions
    WHERE business_id = ? AND user_id = ? AND status = 'pending'
    ORDER BY priority DESC, generated_at DESC
    LIMIT 20
  `).bind(businessId, userId).all();

  return c.json({ success: true, data: actions.results || [] });
});

// Revenue Forecasting (Feature #10)
app.post('/forecast', zValidator('json', GenerateForecastSchema), async (c) => {
  const businessId = c.req.header('X-Business-ID') || 'business-founder-001';
  const { period, forecast_type } = c.req.valid('json');

  const service = new AIIntelligenceService(c.env);
  const forecast = await service.generateRevenueForecast(businessId, period, forecast_type);

  return c.json({ success: true, data: forecast });
});

// Data Validation (Feature #11)
app.post('/validate/:entityType/:entityId', async (c) => {
  const businessId = c.req.header('X-Business-ID') || 'business-founder-001';
  const entityType = c.req.param('entityType');
  const entityId = c.req.param('entityId');

  const service = new AIIntelligenceService(c.env);
  const issues = await service.validateData(businessId, entityType, entityId);

  return c.json({ success: true, data: { issues, count: issues.length } });
});

// Duplicate Detection (Feature #12)
app.post('/duplicates/:entityType/:entityId', async (c) => {
  const businessId = c.req.header('X-Business-ID') || 'business-founder-001';
  const entityType = c.req.param('entityType');
  const entityId = c.req.param('entityId');

  const service = new AIIntelligenceService(c.env);
  const duplicates = await service.detectDuplicates(businessId, entityType, entityId);

  return c.json({ success: true, data: duplicates });
});

// Get all duplicate pairs
app.get('/duplicates', async (c) => {
  const businessId = c.req.header('X-Business-ID') || 'business-founder-001';

  const duplicates = await c.env.DB_MAIN.prepare(`
    SELECT * FROM crm_duplicate_pairs
    WHERE business_id = ? AND status = 'pending'
    ORDER BY overall_confidence DESC
    LIMIT 50
  `).bind(businessId).all();

  return c.json({ success: true, data: duplicates.results || [] });
});

export default app;
