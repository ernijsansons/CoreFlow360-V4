/**
 * Admin Compliance Management Routes
 * Configure company guidelines, agent policies, and monitor violations
 */

import { Hono } from 'hono';
import type { Context } from 'hono';
import { z } from 'zod';
import type { Env } from '@/types/env';
import { authenticate } from '../../middleware/auth';
import { errorHandler, asyncHandler } from '../../shared/error-handler';
import { CorrelationId } from '../../shared/security-utils';

const complianceAdmin = new Hono<{ Bindings: Env }>();

// Apply error handler
complianceAdmin.onError(errorHandler);

// ============================================================================
// VALIDATION SCHEMAS
// ============================================================================

const CreateGuidelineSchema = z.object({
  name: z.string().min(1),
  description: z.string().optional(),
  category: z.enum([
    'tone_and_style',
    'content_restrictions',
    'data_boundaries',
    'privacy_and_security',
    'brand_voice',
    'compliance_rules',
    'escalation_triggers',
    'response_limits'
  ]),
  severity: z.enum(['low', 'medium', 'high', 'critical']),
  rules: z.record(z.any()),
  enforcementMode: z.enum(['monitor', 'warn', 'enforce']),
  autoRemediation: z.boolean().optional().default(false),
  appliesToAgents: z.array(z.string()).optional().default([]),
  appliesToDepartments: z.array(z.string()).optional().default([]),
  priority: z.number().optional().default(100)
});

const CreatePolicySchema = z.object({
  agentId: z.string(),
  policyName: z.string(),
  policyType: z.enum([
    'capability_restriction',
    'data_access_control',
    'rate_limiting',
    'response_filtering',
    'escalation_rules',
    'quality_requirements',
    'cost_limits'
  ]),
  policyConfig: z.record(z.any()),
  enabled: z.boolean().optional().default(true),
  enforcementLevel: z.enum(['lenient', 'moderate', 'strict']).optional().default('moderate')
});

// ============================================================================
// GUIDELINES ROUTES
// ============================================================================

/**
 * Create company guideline
 * POST /api/v1/admin/compliance/guidelines
 */
complianceAdmin.post(
  '/guidelines',
  authenticate() as any,
  asyncHandler(async (c: Context) => {
    const userId = c.get('userId');
    const businessId = c.get('businessId');

    if (!userId || !businessId) {
      return c.json({ error: 'Unauthorized' }, 401);
    }

    // Check admin permission
    const hasPermission = await checkAdminPermission(c.env, userId, businessId);
    if (!hasPermission) {
      return c.json({ error: 'Forbidden: Admin access required' }, 403);
    }

    const body = await c.req.json();
    const validatedData = CreateGuidelineSchema.parse(body);

    const guidelineId = CorrelationId.generate();

    await c.env.DB_MAIN.prepare(`
      INSERT INTO company_guidelines (
        id, business_id, name, description, category, severity,
        rules, enforcement_mode, auto_remediation,
        applies_to_agents, applies_to_departments,
        status, priority, created_by
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?)
    `)
      .bind(
        guidelineId,
        businessId,
        validatedData.name,
        validatedData.description || null,
        validatedData.category,
        validatedData.severity,
        JSON.stringify(validatedData.rules),
        validatedData.enforcementMode,
        validatedData.autoRemediation ? 1 : 0,
        JSON.stringify(validatedData.appliesToAgents),
        JSON.stringify(validatedData.appliesToDepartments),
        validatedData.priority,
        userId
      )
      .run();

    return c.json(
      {
        success: true,
        guidelineId,
        message: 'Guideline created successfully'
      },
      201
    );
  })
);

/**
 * Get all guidelines
 * GET /api/v1/admin/compliance/guidelines
 */
complianceAdmin.get(
  '/guidelines',
  authenticate() as any,
  asyncHandler(async (c: Context) => {
    const userId = c.get('userId');
    const businessId = c.get('businessId');

    if (!userId || !businessId) {
      return c.json({ error: 'Unauthorized' }, 401);
    }

    const category = c.req.query('category');
    const status = c.req.query('status') || 'active';

    let query = `
      SELECT *
      FROM company_guidelines
      WHERE business_id = ?
    `;
    const params: any[] = [businessId];

    if (category) {
      query += ` AND category = ?`;
      params.push(category);
    }

    if (status) {
      query += ` AND status = ?`;
      params.push(status);
    }

    query += ` ORDER BY priority DESC, created_at DESC`;

    const result = await c.env.DB_MAIN.prepare(query).bind(...(params as any)).all();

    return c.json({
      success: true,
      guidelines: result.results || []
    });
  })
);

/**
 * Update guideline
 * PUT /api/v1/admin/compliance/guidelines/:id
 */
complianceAdmin.put(
  '/guidelines/:id',
  authenticate() as any,
  asyncHandler(async (c: Context) => {
    const userId = c.get('userId');
    const businessId = c.get('businessId');
    const guidelineId = c.req.param('id');

    if (!userId || !businessId) {
      return c.json({ error: 'Unauthorized' }, 401);
    }

    const hasPermission = await checkAdminPermission(c.env, userId, businessId);
    if (!hasPermission) {
      return c.json({ error: 'Forbidden' }, 403);
    }

    const body = await c.req.json();
    const updates: string[] = [];
    const params: any[] = [];

    if (body.name !== undefined) {
      updates.push('name = ?');
      params.push(body.name);
    }
    if (body.description !== undefined) {
      updates.push('description = ?');
      params.push(body.description);
    }
    if (body.rules !== undefined) {
      updates.push('rules = ?');
      params.push(JSON.stringify(body.rules));
    }
    if (body.enforcementMode !== undefined) {
      updates.push('enforcement_mode = ?');
      params.push(body.enforcementMode);
    }
    if (body.status !== undefined) {
      updates.push('status = ?');
      params.push(body.status);
    }

    if (updates.length === 0) {
      return c.json({ error: 'No updates provided' }, 400);
    }

    updates.push('updated_at = datetime(\'now\')');
    params.push(guidelineId, businessId);

    await c.env.DB_MAIN.prepare(`
      UPDATE company_guidelines
      SET ${updates.join(', ')}
      WHERE id = ? AND business_id = ?
    `)
      .bind(...(params as any))
      .run();

    return c.json({
      success: true,
      message: 'Guideline updated successfully'
    });
  })
);

/**
 * Delete guideline
 * DELETE /api/v1/admin/compliance/guidelines/:id
 */
complianceAdmin.delete(
  '/guidelines/:id',
  authenticate() as any,
  asyncHandler(async (c: Context) => {
    const userId = c.get('userId');
    const businessId = c.get('businessId');
    const guidelineId = c.req.param('id');

    if (!userId || !businessId) {
      return c.json({ error: 'Unauthorized' }, 401);
    }

    const hasPermission = await checkAdminPermission(c.env, userId, businessId);
    if (!hasPermission) {
      return c.json({ error: 'Forbidden' }, 403);
    }

    await c.env.DB_MAIN.prepare(`
      UPDATE company_guidelines
      SET status = 'archived',
          updated_at = datetime('now')
      WHERE id = ? AND business_id = ?
    `)
      .bind(guidelineId, businessId)
      .run();

    return c.json({
      success: true,
      message: 'Guideline archived successfully'
    });
  })
);

// ============================================================================
// AGENT POLICIES ROUTES
// ============================================================================

/**
 * Create agent policy
 * POST /api/v1/admin/compliance/policies
 */
complianceAdmin.post(
  '/policies',
  authenticate() as any,
  asyncHandler(async (c: Context) => {
    const userId = c.get('userId');
    const businessId = c.get('businessId');

    if (!userId || !businessId) {
      return c.json({ error: 'Unauthorized' }, 401);
    }

    const hasPermission = await checkAdminPermission(c.env, userId, businessId);
    if (!hasPermission) {
      return c.json({ error: 'Forbidden' }, 403);
    }

    const body = await c.req.json();
    const validatedData = CreatePolicySchema.parse(body);

    const policyId = CorrelationId.generate();

    await c.env.DB_MAIN.prepare(`
      INSERT INTO agent_policies (
        id, business_id, agent_id, policy_name, policy_type,
        policy_config, enabled, enforcement_level, status, created_by
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', ?)
    `)
      .bind(
        policyId,
        businessId,
        validatedData.agentId,
        validatedData.policyName,
        validatedData.policyType,
        JSON.stringify(validatedData.policyConfig),
        validatedData.enabled ? 1 : 0,
        validatedData.enforcementLevel,
        userId
      )
      .run();

    return c.json(
      {
        success: true,
        policyId,
        message: 'Agent policy created successfully'
      },
      201
    );
  })
);

/**
 * Get policies for agent
 * GET /api/v1/admin/compliance/policies/:agentId
 */
complianceAdmin.get(
  '/policies/:agentId',
  authenticate() as any,
  asyncHandler(async (c: Context) => {
    const userId = c.get('userId');
    const businessId = c.get('businessId');
    const agentId = c.req.param('agentId');

    if (!userId || !businessId) {
      return c.json({ error: 'Unauthorized' }, 401);
    }

    const result = await c.env.DB_MAIN.prepare(`
      SELECT *
      FROM agent_policies
      WHERE business_id = ? AND agent_id = ?
      ORDER BY created_at DESC
    `)
      .bind(businessId, agentId)
      .all();

    return c.json({
      success: true,
      policies: result.results || []
    });
  })
);

/**
 * Update policy
 * PUT /api/v1/admin/compliance/policies/:id
 */
complianceAdmin.put(
  '/policies/:id',
  authenticate() as any,
  asyncHandler(async (c: Context) => {
    const userId = c.get('userId');
    const businessId = c.get('businessId');
    const policyId = c.req.param('id');

    if (!userId || !businessId) {
      return c.json({ error: 'Unauthorized' }, 401);
    }

    const hasPermission = await checkAdminPermission(c.env, userId, businessId);
    if (!hasPermission) {
      return c.json({ error: 'Forbidden' }, 403);
    }

    const body = await c.req.json();

    await c.env.DB_MAIN.prepare(`
      UPDATE agent_policies
      SET policy_config = ?,
          enabled = ?,
          updated_at = datetime('now')
      WHERE id = ? AND business_id = ?
    `)
      .bind(
        JSON.stringify(body.policyConfig),
        body.enabled ? 1 : 0,
        policyId,
        businessId
      )
      .run();

    return c.json({
      success: true,
      message: 'Policy updated successfully'
    });
  })
);

// ============================================================================
// VIOLATIONS ROUTES
// ============================================================================

/**
 * Get compliance violations
 * GET /api/v1/admin/compliance/violations
 */
complianceAdmin.get(
  '/violations',
  authenticate() as any,
  asyncHandler(async (c: Context) => {
    const userId = c.get('userId');
    const businessId = c.get('businessId');

    if (!userId || !businessId) {
      return c.json({ error: 'Unauthorized' }, 401);
    }

    const page = parseInt(c.req.query('page') || '1');
    const limit = parseInt(c.req.query('limit') || '50');
    const offset = (page - 1) * limit;
    const severity = c.req.query('severity');
    const status = c.req.query('status');
    const agentId = c.req.query('agentId');

    let query = `
      SELECT
        cv.*,
        cg.name as guideline_name,
        ap.policy_name
      FROM compliance_violations cv
      LEFT JOIN company_guidelines cg ON cv.guideline_id = cg.id
      LEFT JOIN agent_policies ap ON cv.policy_id = ap.id
      WHERE cv.business_id = ?
    `;
    const params: any[] = [businessId];

    if (severity) {
      query += ` AND cv.severity = ?`;
      params.push(severity);
    }

    if (status) {
      query += ` AND cv.status = ?`;
      params.push(status);
    }

    if (agentId) {
      query += ` AND cv.agent_id = ?`;
      params.push(agentId);
    }

    query += ` ORDER BY cv.occurred_at DESC LIMIT ? OFFSET ?`;
    params.push(limit, offset);

    const result = await c.env.DB_MAIN.prepare(query).bind(...(params as any)).all();

    // Get total count
    let countQuery = `SELECT COUNT(*) as total FROM compliance_violations WHERE business_id = ?`;
    const countParams: any[] = [businessId];

    if (severity) {
      countQuery += ` AND severity = ?`;
      countParams.push(severity);
    }
    if (status) {
      countQuery += ` AND status = ?`;
      countParams.push(status);
    }
    if (agentId) {
      countQuery += ` AND agent_id = ?`;
      countParams.push(agentId);
    }

    const countResult = await c.env.DB_MAIN.prepare(countQuery).bind(...(countParams as any)).first() as any;

    return c.json({
      success: true,
      violations: result.results || [],
      pagination: {
        page,
        limit,
        total: (countResult?.total as number) || 0,
        pages: Math.ceil(((countResult?.total as number) || 0) / limit)
      }
    });
  })
);

/**
 * Resolve violation
 * PUT /api/v1/admin/compliance/violations/:id/resolve
 */
complianceAdmin.put(
  '/violations/:id/resolve',
  authenticate() as any,
  asyncHandler(async (c: Context) => {
    const userId = c.get('userId');
    const businessId = c.get('businessId');
    const violationId = c.req.param('id');

    if (!userId || !businessId) {
      return c.json({ error: 'Unauthorized' }, 401);
    }

    const body = await c.req.json();
    const { resolutionNotes } = body;

    await c.env.DB_MAIN.prepare(`
      UPDATE compliance_violations
      SET status = 'resolved',
          resolved_by = ?,
          resolved_at = datetime('now'),
          resolution_notes = ?
      WHERE id = ? AND business_id = ?
    `)
      .bind(userId, resolutionNotes || null, violationId, businessId)
      .run();

    return c.json({
      success: true,
      message: 'Violation resolved successfully'
    });
  })
);

/**
 * Get violations summary
 * GET /api/v1/admin/compliance/violations/summary
 */
complianceAdmin.get(
  '/violations/summary',
  authenticate() as any,
  asyncHandler(async (c: Context) => {
    const userId = c.get('userId');
    const businessId = c.get('businessId');

    if (!userId || !businessId) {
      return c.json({ error: 'Unauthorized' }, 401);
    }

    const result = await c.env.DB_MAIN.prepare(`
      SELECT * FROM v_compliance_violations_summary
      WHERE business_id = ?
      ORDER BY violation_count DESC
    `)
      .bind(businessId)
      .all();

    return c.json({
      success: true,
      summary: result.results || []
    });
  })
);

// ============================================================================
// CONFIGURATION TEMPLATES
// ============================================================================

/**
 * Get guideline templates
 * GET /api/v1/admin/compliance/templates/guidelines
 */
complianceAdmin.get(
  '/templates/guidelines',
  authenticate() as any,
  asyncHandler(async (c: Context) => {
    const templates = [
      {
        name: 'Professional Tone Required',
        category: 'tone_and_style',
        severity: 'medium',
        rules: {
          requiredTone: 'professional',
          prohibitedPhrases: ['cheap', 'obviously', 'clearly', 'just']
        },
        enforcementMode: 'enforce'
      },
      {
        name: 'No Competitor Mentions',
        category: 'content_restrictions',
        severity: 'high',
        rules: {
          prohibitedCompetitors: ['Competitor A', 'Competitor B'],
          prohibitedTopics: ['competitors', 'alternatives']
        },
        enforcementMode: 'enforce'
      },
      {
        name: 'PII Protection',
        category: 'privacy_and_security',
        severity: 'critical',
        rules: {
          detectPII: true,
          autoRedact: true
        },
        enforcementMode: 'enforce',
        autoRemediation: true
      },
      {
        name: 'Response Length Limits',
        category: 'response_limits',
        severity: 'low',
        rules: {
          maxResponseLength: 500,
          minResponseLength: 20
        },
        enforcementMode: 'warn'
      }
    ];

    return c.json({
      success: true,
      templates
    });
  })
);

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

async function checkAdminPermission(
  env: Env,
  userId: string,
  _businessId: string
): Promise<boolean> {
  const result = await env.DB_MAIN.prepare(`
    SELECT COUNT(*) as count
    FROM user_roles ur
    INNER JOIN users u ON ur.user_id = u.id
    WHERE ur.user_id = ?
      AND ur.role IN ('admin', 'owner')
  `)
    .bind(userId)
    .first() as any;

  return (result?.count as number) > 0;
}

export default complianceAdmin;
