/**
 * CRM Lead Scoring API Routes
 * ML-powered predictive lead scoring
 * Feature #4 - Phase 1 Sprint 1
 */

import { Hono } from 'hono';
import { z } from 'zod';
import { zValidator } from '@hono/zod-validator';
import { LeadScoringService } from '../services/crm/lead-scoring.service';
import type { Env } from '../types/env';

const app = new Hono<{ Bindings: Env }>();

// ============================================================================
// VALIDATION SCHEMAS
// ============================================================================

const CalculateScoreSchema = z.object({
  entity_id: z.string().min(1),
  entity_type: z.enum(['contact', 'lead', 'company']),
});

const CreateModelSchema = z.object({
  model_name: z.string().min(1),
  model_type: z.enum(['ml_regression', 'rule_based', 'hybrid', 'custom']),
  feature_weights: z.record(z.number().min(0).max(1)),
  conversion_threshold: z.number().min(0).max(100).default(70),
  workers_ai_model: z.string().optional(),
});

const AddScoringRuleSchema = z.object({
  model_id: z.string().min(1),
  rule_name: z.string().min(1),
  rule_type: z.enum(['demographic', 'firmographic', 'behavioral', 'engagement', 'intent']),
  field_name: z.string().min(1),
  operator: z.enum(['equals', 'not_equals', 'contains', 'not_contains', 'greater_than', 'less_than', 'in_list', 'matches_regex']),
  field_value: z.string().min(1),
  points_if_match: z.number(),
  weight: z.number().min(0).max(1).default(1.0),
});

const RecordOutcomeSchema = z.object({
  score_id: z.string().min(1),
  actual_outcome: z.enum(['converted', 'lost']),
  actual_deal_size: z.number().optional(),
  actual_days_to_close: z.number().optional(),
});

// ============================================================================
// SCORING ENDPOINTS
// ============================================================================

/**
 * Calculate lead score
 * POST /api/v1/crm/lead-scoring/calculate
 */
app.post('/calculate', zValidator('json', CalculateScoreSchema), async (c) => {
  try {
    const businessId = c.req.header('X-Business-ID') || 'business-founder-001';
    const { entity_id, entity_type } = c.req.valid('json');

    const service = new LeadScoringService(c.env);
    const score = await service.calculateLeadScore(businessId, entity_id, entity_type);

    return c.json({
      success: true,
      message: 'Lead score calculated successfully',
      data: score
    });
  } catch (error: any) {
    console.error('Calculate score error:', error);
    return c.json({
      success: false,
      error: 'Failed to calculate lead score',
      message: error.message
    }, 500);
  }
});

/**
 * Get lead score by entity
 * GET /api/v1/crm/lead-scoring/:entityType/:entityId
 */
app.get('/:entityType/:entityId', async (c) => {
  try {
    const businessId = c.req.header('X-Business-ID') || 'business-founder-001';
    const entityType = c.req.param('entityType');
    const entityId = c.req.param('entityId');

    const score = await c.env.DB_MAIN.prepare(`
      SELECT
        id, score, confidence_level, conversion_probability,
        predicted_deal_size, predicted_time_to_close,
        primary_drivers, negative_factors, recommended_actions,
        ai_reasoning, score_trend, scored_at
      FROM crm_lead_scores
      WHERE business_id = ? AND entity_id = ? AND entity_type = ?
        AND (expires_at IS NULL OR expires_at > datetime('now'))
      ORDER BY scored_at DESC
      LIMIT 1
    `).bind(businessId, entityId, entityType).first() as any;

    if (!score) {
      return c.json({
        success: false,
        error: 'No score found for this entity'
      }, 404);
    }

    return c.json({
      success: true,
      data: {
        ...score,
        primary_drivers: JSON.parse(score.primary_drivers || '[]'),
        negative_factors: JSON.parse(score.negative_factors || '[]'),
        recommended_actions: JSON.parse(score.recommended_actions || '[]')
      }
    });
  } catch (error: any) {
    console.error('Get score error:', error);
    return c.json({
      success: false,
      error: 'Failed to retrieve lead score',
      message: error.message
    }, 500);
  }
});

/**
 * Get high-value leads
 * GET /api/v1/crm/lead-scoring/high-value
 */
app.get('/high-value', async (c) => {
  try {
    const businessId = c.req.header('X-Business-ID') || 'business-founder-001';
    const minScore = parseInt(c.req.query('min_score') || '70');
    const limit = parseInt(c.req.query('limit') || '50');

    const leads = await c.env.DB_MAIN.prepare(`
      SELECT * FROM view_high_value_leads
      WHERE business_id = ? AND score >= ?
      LIMIT ?
    `).bind(businessId, minScore, limit).all();

    return c.json({
      success: true,
      data: (leads.results || []).map((lead: any) => ({
        ...lead,
        primary_drivers: JSON.parse(lead.primary_drivers || '[]'),
        recommended_actions: JSON.parse(lead.recommended_actions || '[]')
      })),
      total: leads.results?.length || 0
    });
  } catch (error: any) {
    console.error('Get high-value leads error:', error);
    return c.json({
      success: false,
      error: 'Failed to get high-value leads',
      message: error.message
    }, 500);
  }
});

/**
 * Record actual outcome (for model training)
 * POST /api/v1/crm/lead-scoring/outcome
 */
app.post('/outcome', zValidator('json', RecordOutcomeSchema), async (c) => {
  try {
    const businessId = c.req.header('X-Business-ID') || 'business-founder-001';
    const { score_id, actual_outcome, actual_deal_size, actual_days_to_close } = c.req.valid('json');

    const now = new Date().toISOString();

    await c.env.DB_MAIN.prepare(`
      UPDATE crm_lead_scores
      SET actual_outcome = ?,
          actual_deal_size = ?,
          actual_days_to_close = ?,
          outcome_recorded_at = ?
      WHERE id = ? AND business_id = ?
    `).bind(
      actual_outcome,
      actual_deal_size || null,
      actual_days_to_close || null,
      now,
      score_id,
      businessId
    ).run();

    return c.json({
      success: true,
      message: 'Outcome recorded successfully'
    });
  } catch (error: any) {
    console.error('Record outcome error:', error);
    return c.json({
      success: false,
      error: 'Failed to record outcome',
      message: error.message
    }, 500);
  }
});

// ============================================================================
// MODEL MANAGEMENT
// ============================================================================

/**
 * Create scoring model
 * POST /api/v1/crm/lead-scoring/models
 */
app.post('/models', zValidator('json', CreateModelSchema), async (c) => {
  try {
    const businessId = c.req.header('X-Business-ID') || 'business-founder-001';
    const userId = c.req.header('X-User-ID') || 'user-founder-001';
    const data = c.req.valid('json');

    const id = crypto.randomUUID().replace(/-/g, '');
    const now = new Date().toISOString();

    await c.env.DB_MAIN.prepare(`
      INSERT INTO crm_lead_scoring_models (
        id, business_id, model_name, model_type, feature_weights,
        conversion_threshold, workers_ai_model, status, created_by_user_id,
        created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, 'draft', ?, ?, ?)
    `).bind(
      id,
      businessId,
      data.model_name,
      data.model_type,
      JSON.stringify(data.feature_weights),
      data.conversion_threshold,
      data.workers_ai_model || '@cf/meta/llama-3-8b-instruct',
      userId,
      now,
      now
    ).run();

    return c.json({
      success: true,
      message: 'Scoring model created',
      data: { id, ...data }
    }, 201);
  } catch (error: any) {
    console.error('Create model error:', error);
    return c.json({
      success: false,
      error: 'Failed to create scoring model',
      message: error.message
    }, 500);
  }
});

/**
 * Get all models
 * GET /api/v1/crm/lead-scoring/models
 */
app.get('/models', async (c) => {
  try {
    const businessId = c.req.header('X-Business-ID') || 'business-founder-001';

    const models = await c.env.DB_MAIN.prepare(`
      SELECT * FROM view_scoring_model_performance
      WHERE business_id = ?
      ORDER BY is_default DESC, accuracy_rate DESC
    `).bind(businessId).all();

    return c.json({
      success: true,
      data: models.results || []
    });
  } catch (error: any) {
    console.error('Get models error:', error);
    return c.json({
      success: false,
      error: 'Failed to get scoring models',
      message: error.message
    }, 500);
  }
});

/**
 * Activate model
 * POST /api/v1/crm/lead-scoring/models/:modelId/activate
 */
app.post('/models/:modelId/activate', async (c) => {
  try {
    const businessId = c.req.header('X-Business-ID') || 'business-founder-001';
    const modelId = c.req.param('modelId');

    // Deactivate other default models
    await c.env.DB_MAIN.prepare(`
      UPDATE crm_lead_scoring_models
      SET is_default = 0
      WHERE business_id = ? AND is_default = 1
    `).bind(businessId).run();

    // Activate this model
    await c.env.DB_MAIN.prepare(`
      UPDATE crm_lead_scoring_models
      SET status = 'active', is_default = 1, updated_at = datetime('now')
      WHERE id = ? AND business_id = ?
    `).bind(modelId, businessId).run();

    return c.json({
      success: true,
      message: 'Model activated successfully'
    });
  } catch (error: any) {
    console.error('Activate model error:', error);
    return c.json({
      success: false,
      error: 'Failed to activate model',
      message: error.message
    }, 500);
  }
});

/**
 * Add scoring rule
 * POST /api/v1/crm/lead-scoring/rules
 */
app.post('/rules', zValidator('json', AddScoringRuleSchema), async (c) => {
  try {
    const businessId = c.req.header('X-Business-ID') || 'business-founder-001';
    const data = c.req.valid('json');

    const id = crypto.randomUUID().replace(/-/g, '');
    const now = new Date().toISOString();

    await c.env.DB_MAIN.prepare(`
      INSERT INTO crm_scoring_rules (
        id, business_id, model_id, rule_name, rule_type,
        field_name, operator, field_value, points_if_match,
        weight, is_active, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
    `).bind(
      id,
      businessId,
      data.model_id,
      data.rule_name,
      data.rule_type,
      data.field_name,
      data.operator,
      data.field_value,
      data.points_if_match,
      data.weight,
      now,
      now
    ).run();

    return c.json({
      success: true,
      message: 'Scoring rule added',
      data: { id, ...data }
    }, 201);
  } catch (error: any) {
    console.error('Add rule error:', error);
    return c.json({
      success: false,
      error: 'Failed to add scoring rule',
      message: error.message
    }, 500);
  }
});

export default app;
