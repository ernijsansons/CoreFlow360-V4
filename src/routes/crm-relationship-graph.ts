/**
 * CRM Relationship Graph API Routes
 * LinkedIn-style network intelligence and warm intro path finding
 * Part of Phase 1 Sprint 1 - Feature #1
 */

import { Hono } from 'hono';
import { Logger } from '../shared/logger';
const logger = new Logger({ component: 'crm-relationship-graph' });
import { z } from 'zod';
import { zValidator } from '@hono/zod-validator';
import { RelationshipGraphService } from '../services/crm/relationship-graph.service';
import type { Env } from '../types/env';

const app = new Hono<{ Bindings: Env }>();

// ============================================================================
// VALIDATION SCHEMAS
// ============================================================================

const CreateRelationshipSchema = z.object({
  source_id: z.string().min(1),
  source_type: z.enum(['contact', 'company', 'user', 'lead']),
  target_id: z.string().min(1),
  target_type: z.enum(['contact', 'company', 'user', 'lead']),
  relationship_type: z.enum([
    'works_at',
    'reports_to',
    'peer_of',
    'mentor_of',
    'partner_with',
    'vendor_of',
    'customer_of',
    'invested_in',
    'founded',
    'board_member',
    'shared_network',
    'same_household',
    'linkedin_connection',
    'twitter_follower',
    'email_thread',
    'meeting_attendee',
    'deal_stakeholder',
    'deal_blocker',
    'deal_champion'
  ]),
  strength_score: z.number().min(0).max(100).optional(),
  confidence_level: z.enum(['low', 'medium', 'high', 'verified']).optional(),
  detected_via: z.string().optional(),
  detection_confidence: z.number().min(0).max(1).optional(),
  is_bidirectional: z.boolean().optional(),
  notes: z.string().optional(),
  metadata: z.record(z.any()).optional(),
  tags: z.array(z.string()).optional(),
});

const LogActivitySchema = z.object({
  activity_type: z.enum([
    'email_sent',
    'email_received',
    'meeting_scheduled',
    'meeting_completed',
    'call_made',
    'call_received',
    'linkedin_message',
    'linkedin_connection_accepted',
    'deal_progressed',
    'introduction_made',
    'referral_given'
  ]),
  subject: z.string().optional(),
  description: z.string().optional(),
  outcome: z.enum(['positive', 'neutral', 'negative', 'no_response']).optional(),
  sentiment_score: z.number().min(-1).max(1).optional(),
  strength_impact: z.number().int().optional(),
  occurred_at: z.string().optional(),
});

// ============================================================================
// RELATIONSHIP CRUD
// ============================================================================

/**
 * Create a new relationship
 * POST /api/crm/relationships
 */
app.post('/', zValidator('json', CreateRelationshipSchema), async (c) => {
  try {
    const businessId = c.req.header('X-Business-ID') || 'business-founder-001';
    const data = c.req.valid('json');

    const service = new RelationshipGraphService(c.env);
    const relationship = await service.createRelationship(businessId, data);

    return c.json({
      success: true,
      data: relationship
    }, 201);
  } catch (error: any) {
    logger.error('Create relationship error:', error);
    return c.json({
      success: false,
      error: 'Failed to create relationship',
      message: error.message
    }, 500);
  }
});

/**
 * Get all relationships for an entity
 * GET /api/crm/relationships/:entityType/:entityId
 */
app.get('/:entityType/:entityId', async (c) => {
  try {
    const businessId = c.req.header('X-Business-ID') || 'business-founder-001';
    const entityType = c.req.param('entityType');
    const entityId = c.req.param('entityId');

    if (!['contact', 'company', 'user', 'lead'].includes(entityType)) {
      return c.json({
        success: false,
        error: 'Invalid entity type. Must be: contact, company, user, or lead'
      }, 400);
    }

    const service = new RelationshipGraphService(c.env);
    const relationships = await service.getRelationships(businessId, entityId, entityType);

    return c.json({
      success: true,
      data: relationships,
      total: relationships.length
    });
  } catch (error: any) {
    logger.error('Get relationships error:', error);
    return c.json({
      success: false,
      error: 'Failed to get relationships',
      message: error.message
    }, 500);
  }
});

// ============================================================================
// NETWORK PATH FINDING
// ============================================================================

/**
 * Find warm introduction path between two contacts
 * GET /api/crm/relationships/path/:startId/:endId
 */
app.get('/path/:startId/:endId', async (c) => {
  try {
    const businessId = c.req.header('X-Business-ID') || 'business-founder-001';
    const startId = c.req.param('startId');
    const endId = c.req.param('endId');
    const maxHops = parseInt(c.req.query('maxHops') || '3');

    const service = new RelationshipGraphService(c.env);
    const path = await service.findWarmIntroPath(businessId, startId, endId, maxHops);

    if (!path) {
      return c.json({
        success: false,
        error: 'No path found',
        message: `No connection path found between contacts within ${maxHops} hops`
      }, 404);
    }

    // Enrich path with contact details
    const contactIds = path.path_nodes;
    const contacts = await c.env.DB_MAIN.prepare(`
      SELECT id, first_name, last_name, full_name, job_title, company_id, email
      FROM crm_contacts
      WHERE id IN (${contactIds.map(() => '?').join(',')})
        AND deleted_at IS NULL
    `).bind(...contactIds).all();

    const contactMap = new Map(
      (contacts.results || []).map((c: any) => [c.id, c])
    );

    return c.json({
      success: true,
      data: {
        ...path,
        path_details: path.path_nodes.map(id => contactMap.get(id)),
        recommendation: path.intro_success_probability > 0.7
          ? 'High likelihood of successful introduction'
          : path.intro_success_probability > 0.4
          ? 'Moderate likelihood - strengthen relationship first'
          : 'Low likelihood - consider alternative paths'
      }
    });
  } catch (error: any) {
    logger.error('Find path error:', error);
    return c.json({
      success: false,
      error: 'Failed to find path',
      message: error.message
    }, 500);
  }
});

/**
 * Get all cached paths for a contact
 * GET /api/crm/relationships/paths/:contactId
 */
app.get('/paths/:contactId', async (c) => {
  try {
    const businessId = c.req.header('X-Business-ID') || 'business-founder-001';
    const contactId = c.req.param('contactId');

    const paths = await c.env.DB_MAIN.prepare(`
      SELECT * FROM crm_network_paths
      WHERE business_id = ?
        AND (start_contact_id = ? OR end_contact_id = ?)
        AND expires_at > datetime('now')
      ORDER BY intro_success_probability DESC, path_length ASC
      LIMIT 50
    `).bind(businessId, contactId, contactId).all();

    return c.json({
      success: true,
      data: (paths.results || []).map((p: any) => ({
        ...p,
        path_nodes: JSON.parse(p.path_nodes),
        path_types: JSON.parse(p.path_types),
      })),
      total: paths.results?.length || 0
    });
  } catch (error: any) {
    logger.error('Get paths error:', error);
    return c.json({
      success: false,
      error: 'Failed to get paths',
      message: error.message
    }, 500);
  }
});

// ============================================================================
// RELATIONSHIP INSIGHTS
// ============================================================================

/**
 * Get AI-powered relationship insights for an entity
 * GET /api/crm/relationships/insights/:entityType/:entityId
 */
app.get('/insights/:entityType/:entityId', async (c) => {
  try {
    const businessId = c.req.header('X-Business-ID') || 'business-founder-001';
    const entityType = c.req.param('entityType');
    const entityId = c.req.param('entityId');

    if (!['contact', 'company', 'deal'].includes(entityType)) {
      return c.json({
        success: false,
        error: 'Invalid entity type. Must be: contact, company, or deal'
      }, 400);
    }

    const service = new RelationshipGraphService(c.env);
    const insights = await service.getRelationshipInsights(
      businessId,
      entityId,
      entityType as 'contact' | 'company' | 'deal'
    );

    return c.json({
      success: true,
      data: insights,
      total: insights.length
    });
  } catch (error: any) {
    logger.error('Get insights error:', error);
    return c.json({
      success: false,
      error: 'Failed to get insights',
      message: error.message
    }, 500);
  }
});

/**
 * Generate fresh AI insights for a contact
 * POST /api/crm/relationships/insights/generate/:contactId
 */
app.post('/insights/generate/:contactId', async (c) => {
  try {
    const businessId = c.req.header('X-Business-ID') || 'business-founder-001';
    const contactId = c.req.param('contactId');

    const service = new RelationshipGraphService(c.env);
    const insights = await service.generateInsights(businessId, contactId);

    return c.json({
      success: true,
      data: insights,
      total: insights.length,
      message: `Generated ${insights.length} new insights`
    });
  } catch (error: any) {
    logger.error('Generate insights error:', error);
    return c.json({
      success: false,
      error: 'Failed to generate insights',
      message: error.message
    }, 500);
  }
});

/**
 * Mark insight as acted upon
 * PATCH /api/crm/relationships/insights/:insightId/act
 */
app.patch('/insights/:insightId/act', async (c) => {
  try {
    const insightId = c.req.param('insightId');
    const now = new Date().toISOString();

    await c.env.DB_MAIN.prepare(`
      UPDATE crm_relationship_insights
      SET status = 'acted_on', acted_on_at = ?, updated_at = ?
      WHERE id = ?
    `).bind(now, now, insightId).run();

    return c.json({
      success: true,
      message: 'Insight marked as acted upon'
    });
  } catch (error: any) {
    logger.error('Update insight error:', error);
    return c.json({
      success: false,
      error: 'Failed to update insight',
      message: error.message
    }, 500);
  }
});

/**
 * Dismiss insight
 * PATCH /api/crm/relationships/insights/:insightId/dismiss
 */
app.patch('/insights/:insightId/dismiss', async (c) => {
  try {
    const insightId = c.req.param('insightId');
    const now = new Date().toISOString();

    await c.env.DB_MAIN.prepare(`
      UPDATE crm_relationship_insights
      SET status = 'dismissed', dismissed_at = ?, updated_at = ?
      WHERE id = ?
    `).bind(now, now, insightId).run();

    return c.json({
      success: true,
      message: 'Insight dismissed'
    });
  } catch (error: any) {
    logger.error('Dismiss insight error:', error);
    return c.json({
      success: false,
      error: 'Failed to dismiss insight',
      message: error.message
    }, 500);
  }
});

// ============================================================================
// ACTIVITY LOGGING
// ============================================================================

/**
 * Log activity for a relationship
 * POST /api/crm/relationships/:relationshipId/activity
 */
app.post('/:relationshipId/activity', zValidator('json', LogActivitySchema), async (c) => {
  try {
    const businessId = c.req.header('X-Business-ID') || 'business-founder-001';
    const relationshipId = c.req.param('relationshipId');
    const data = c.req.valid('json');

    const service = new RelationshipGraphService(c.env);
    await service.logActivity(relationshipId, businessId, data.activity_type, data);

    return c.json({
      success: true,
      message: 'Activity logged successfully'
    });
  } catch (error: any) {
    logger.error('Log activity error:', error);
    return c.json({
      success: false,
      error: 'Failed to log activity',
      message: error.message
    }, 500);
  }
});

/**
 * Get activity history for a relationship
 * GET /api/crm/relationships/:relationshipId/activity
 */
app.get('/:relationshipId/activity', async (c) => {
  try {
    const relationshipId = c.req.param('relationshipId');
    const limit = parseInt(c.req.query('limit') || '50');

    const activities = await c.env.DB_MAIN.prepare(`
      SELECT * FROM crm_relationship_activities
      WHERE relationship_id = ?
      ORDER BY occurred_at DESC
      LIMIT ?
    `).bind(relationshipId, limit).all();

    return c.json({
      success: true,
      data: activities.results || [],
      total: activities.results?.length || 0
    });
  } catch (error: any) {
    logger.error('Get activity error:', error);
    return c.json({
      success: false,
      error: 'Failed to get activity',
      message: error.message
    }, 500);
  }
});

// ============================================================================
// NETWORK ANALYTICS
// ============================================================================

/**
 * Get network strength for a contact
 * GET /api/crm/relationships/analytics/network-strength/:contactId
 */
app.get('/analytics/network-strength/:contactId', async (c) => {
  try {
    const businessId = c.req.header('X-Business-ID') || 'business-founder-001';
    const contactId = c.req.param('contactId');

    const stats = await c.env.DB_MAIN.prepare(`
      SELECT * FROM view_contact_network_strength
      WHERE contact_id = ?
    `).bind(contactId).first();

    if (!stats) {
      return c.json({
        success: false,
        error: 'Contact not found'
      }, 404);
    }

    return c.json({
      success: true,
      data: stats
    });
  } catch (error: any) {
    logger.error('Get network strength error:', error);
    return c.json({
      success: false,
      error: 'Failed to get network strength',
      message: error.message
    }, 500);
  }
});

/**
 * Get company relationship map
 * GET /api/crm/relationships/analytics/company-map/:companyId
 */
app.get('/analytics/company-map/:companyId', async (c) => {
  try {
    const companyId = c.req.param('companyId');

    const stats = await c.env.DB_MAIN.prepare(`
      SELECT * FROM view_company_relationships
      WHERE company_id = ?
    `).bind(companyId).first();

    if (!stats) {
      return c.json({
        success: false,
        error: 'Company not found'
      }, 404);
    }

    // Get detailed relationships
    const relationships = await c.env.DB_MAIN.prepare(`
      SELECT * FROM crm_relationships
      WHERE (source_id = ? AND source_type = 'company')
         OR (target_id = ? AND target_type = 'company')
        AND deleted_at IS NULL
      ORDER BY strength_score DESC
      LIMIT 100
    `).bind(companyId, companyId).all();

    return c.json({
      success: true,
      data: {
        summary: stats,
        relationships: relationships.results || []
      }
    });
  } catch (error: any) {
    logger.error('Get company map error:', error);
    return c.json({
      success: false,
      error: 'Failed to get company map',
      message: error.message
    }, 500);
  }
});

/**
 * Get top connectors in network
 * GET /api/crm/relationships/analytics/top-connectors
 */
app.get('/analytics/top-connectors', async (c) => {
  try {
    const businessId = c.req.header('X-Business-ID') || 'business-founder-001';
    const limit = parseInt(c.req.query('limit') || '10');

    const topConnectors = await c.env.DB_MAIN.prepare(`
      SELECT * FROM view_contact_network_strength
      ORDER BY total_connections DESC, avg_connection_strength DESC
      LIMIT ?
    `).bind(limit).all();

    return c.json({
      success: true,
      data: topConnectors.results || [],
      total: topConnectors.results?.length || 0
    });
  } catch (error: any) {
    logger.error('Get top connectors error:', error);
    return c.json({
      success: false,
      error: 'Failed to get top connectors',
      message: error.message
    }, 500);
  }
});

export default app;
