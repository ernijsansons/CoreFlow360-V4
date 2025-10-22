/**
 * CRM Deal Health Scoring API Routes
 * Feature #5 - Phase 1 Sprint 1
 */

import { Hono } from 'hono';
import { z } from 'zod';
import { zValidator } from '@hono/zod-validator';
import { DealHealthService } from '../services/crm/deal-health.service';
import type { Env } from '../types/env';

const app = new Hono<{ Bindings: Env }>();

const TrackEventSchema = z.object({
  event_type: z.string(),
  stakeholder_id: z.string().optional(),
  sales_rep_id: z.string().optional(),
  engagement_value: z.number().optional(),
});

// Calculate deal health
app.post('/:dealId/calculate', async (c) => {
  const businessId = c.req.header('X-Business-ID') || 'business-founder-001';
  const dealId = c.req.param('dealId');

  const service = new DealHealthService(c.env);
  const health = await service.calculateDealHealth(businessId, dealId);

  return c.json({ success: true, data: health });
});

// Track engagement event
app.post('/:dealId/events', zValidator('json', TrackEventSchema), async (c) => {
  const businessId = c.req.header('X-Business-ID') || 'business-founder-001';
  const dealId = c.req.param('dealId');
  const { event_type, stakeholder_id, sales_rep_id, engagement_value } = c.req.valid('json');

  const service = new DealHealthService(c.env);
  await service.trackEngagementEvent(businessId, dealId, event_type, {
    stakeholder_id, sales_rep_id, engagement_value
  });

  return c.json({ success: true, message: 'Event tracked' });
});

// Get at-risk deals
app.get('/at-risk', async (c) => {
  const businessId = c.req.header('X-Business-ID') || 'business-founder-001';

  const deals = await c.env.DB_MAIN.prepare(`
    SELECT * FROM view_at_risk_deals WHERE business_id = ? LIMIT 50
  `).bind(businessId).all();

  return c.json({ success: true, data: deals.results || [] });
});

export default app;
