// @ts-nocheck
/**
 * Onboarding Agent API Routes
 * REST endpoints for autonomous onboarding operations
 */

import { Hono } from 'hono';
import type { Context } from 'hono';
import { z } from 'zod';
import type { Env } from '@/types/env';
import { authenticate } from '../middleware/auth';
import { errorHandler, asyncHandler } from '../shared/error-handler';
import { AgentOrchestrator } from '../modules/agents/orchestrator';
import { CapabilityManager } from '../modules/capabilities';
import { AuditService } from '../modules/audit/audit-service';
import type { BusinessContext, AgentTask } from '../modules/agents/types';
import { CorrelationId } from '../shared/security-utils';

const onboarding = new Hono<{ Bindings: Env }>();

// Apply error handler
onboarding.onError(errorHandler);

// ============================================================================
// VALIDATION SCHEMAS
// ============================================================================

const StartOnboardingSchema = z.object({
  flowType: z.enum(['initial_setup', 'data_migration', 'integration_setup', 'team_onboarding']),
  industry: z.string().optional(),
  companySize: z.enum(['micro', 'small', 'medium', 'large', 'enterprise']).optional()
});

const ImportDataSchema = z.object({
  fileName: z.string(),
  fileData: z.string(),
  dataType: z.string(),
  mapping: z.record(z.string()).optional(),
  validateOnly: z.boolean().optional().default(false)
});

const SetupAccountSchema = z.object({
  companyName: z.string(),
  industry: z.string(),
  companySize: z.string(),
  currency: z.string(),
  timezone: z.string(),
  fiscalYearStart: z.number().min(1).max(12),
  createDefaultAccounts: z.boolean().optional().default(true),
  setupWorkflows: z.boolean().optional().default(true),
  notifications: z.record(z.any()).optional()
});

const IntegrationSetupSchema = z.object({
  integrationType: z.enum(['stripe', 'plaid', 'quickbooks', 'salesforce', 'mailchimp', 'slack']),
  credentials: z.record(z.string()),
  configuration: z.record(z.any()).optional().default({}),
  testConnection: z.boolean().optional().default(true)
});

const TeamOnboardingSchema = z.object({
  teamMembers: z.array(
    z.object({
      email: z.string().email(),
      firstName: z.string(),
      lastName: z.string(),
      role: z.string(),
      department: z.string(),
      permissions: z.array(z.string())
    })
  )
});

// ============================================================================
// ROUTES
// ============================================================================

/**
 * Start onboarding flow
 * POST /api/v1/onboarding/start
 */
onboarding.post(
  '/start',
  authenticate() as any,
  asyncHandler(async (c: Context) => {
    const userId = c.get('userId');
    const businessId = c.get('businessId');

    if (!userId || !businessId) {
      return c.json({ error: 'Unauthorized' }, 401);
    }

    const body = await c.req.json();
    const validatedData = StartOnboardingSchema.parse(body);

    // Create onboarding configuration
    const configId = CorrelationId.generate();
    await c.env.DB_MAIN.prepare(`
      INSERT INTO onboarding_configurations (
        id, business_id, flow_name, flow_type,
        industry_template, company_size_template,
        enable_ai_guidance, status, created_by
      ) VALUES (?, ?, ?, ?, ?, ?, 1, 'active', ?)
    `)
      .bind(
        configId,
        businessId,
        `${validatedData.flowType} Flow`,
        validatedData.flowType,
        validatedData.industry || null,
        validatedData.companySize || null,
        userId
      )
      .run();

    // Create progress record
    const progressId = CorrelationId.generate();
    await c.env.DB_MAIN.prepare(`
      INSERT INTO onboarding_progress (
        id, business_id, user_id, configuration_id,
        current_step, status, started_at
      ) VALUES (?, ?, ?, ?, 'account_setup', 'in_progress', datetime('now'))
    `)
      .bind(progressId, businessId, userId, configId)
      .run();

    return c.json(
      {
        success: true,
        configurationId: configId,
        progressId: progressId,
        flowType: validatedData.flowType,
        nextStep: 'account_setup',
        message: 'Onboarding flow started successfully'
      },
      201
    );
  })
);

/**
 * Import data
 * POST /api/v1/onboarding/import-data
 */
onboarding.post(
  '/import-data',
  authenticate() as any,
  asyncHandler(async (c: Context) => {
    const userId = c.get('userId');
    const businessId = c.get('businessId');

    if (!userId || !businessId) {
      return c.json({ error: 'Unauthorized' }, 401);
    }

    const body = await c.req.json();
    const validatedData = ImportDataSchema.parse(body);

    // Create business context
    const context: BusinessContext = await buildBusinessContext(c, userId, businessId);

    // Create agent task
    const task: AgentTask = {
      id: CorrelationId.generate(),
      capability: 'data_import',
      type: 'action',
      priority: 'high',
      input: {
        data: validatedData
      },
      context
    };

    // Execute via orchestrator
    const orchestrator = await getOrchestrator(c.env);
    const result = await orchestrator.executeTask(task, context);

    if (result.status === 'failed') {
      return c.json(
        {
          success: false,
          error: result.error?.message || 'Import failed',
          details: result.error?.details
        },
        400
      );
    }

    return c.json({
      success: true,
      ...(result as any).result?.data,
      executionTime: result.metrics.executionTime
    });
  })
);

/**
 * Setup account
 * POST /api/v1/onboarding/setup-account
 */
onboarding.post(
  '/setup-account',
  authenticate() as any,
  asyncHandler(async (c: Context) => {
    const userId = c.get('userId');
    const businessId = c.get('businessId');

    if (!userId || !businessId) {
      return c.json({ error: 'Unauthorized' }, 401);
    }

    const body = await c.req.json();
    const validatedData = SetupAccountSchema.parse(body);

    const context: BusinessContext = await buildBusinessContext(c, userId, businessId);

    const task: AgentTask = {
      id: CorrelationId.generate(),
      capability: 'account_setup',
      type: 'action',
      priority: 'high',
      input: { data: validatedData },
      context
    };

    const orchestrator = await getOrchestrator(c.env);
    const result = await orchestrator.executeTask(task, context);

    if (result.status === 'failed') {
      return c.json(
        {
          success: false,
          error: result.error?.message || 'Account setup failed'
        },
        400
      );
    }

    // Update onboarding progress
    await updateOnboardingProgress(c.env, businessId, userId, 'account_setup', 20);

    return c.json({
      success: true,
      ...(result as any).result?.data,
      progress: 20
    });
  })
);

/**
 * Setup integration
 * POST /api/v1/onboarding/setup-integration
 */
onboarding.post(
  '/setup-integration',
  authenticate() as any,
  asyncHandler(async (c: Context) => {
    const userId = c.get('userId');
    const businessId = c.get('businessId');

    if (!userId || !businessId) {
      return c.json({ error: 'Unauthorized' }, 401);
    }

    const body = await c.req.json();
    const validatedData = IntegrationSetupSchema.parse(body);

    const context: BusinessContext = await buildBusinessContext(c, userId, businessId);

    const task: AgentTask = {
      id: CorrelationId.generate(),
      capability: 'integration_wizard',
      type: 'action',
      priority: 'high',
      input: { data: validatedData },
      context
    };

    const orchestrator = await getOrchestrator(c.env);
    const result = await orchestrator.executeTask(task, context);

    if (result.status === 'failed') {
      return c.json(
        {
          success: false,
          error: result.error?.message || 'Integration setup failed'
        },
        400
      );
    }

    // Update progress
    await updateOnboardingProgress(c.env, businessId, userId, 'integration_setup', 40);

    return c.json({
      success: true,
      ...(result as any).result?.data,
      progress: 40
    });
  })
);

/**
 * Onboard team members
 * POST /api/v1/onboarding/team-members
 */
onboarding.post(
  '/team-members',
  authenticate() as any,
  asyncHandler(async (c: Context) => {
    const userId = c.get('userId');
    const businessId = c.get('businessId');

    if (!userId || !businessId) {
      return c.json({ error: 'Unauthorized' }, 401);
    }

    const body = await c.req.json();
    const validatedData = TeamOnboardingSchema.parse(body);

    const context: BusinessContext = await buildBusinessContext(c, userId, businessId);

    const task: AgentTask = {
      id: CorrelationId.generate(),
      capability: 'team_onboarding',
      type: 'action',
      priority: 'high',
      input: { data: validatedData },
      context
    };

    const orchestrator = await getOrchestrator(c.env);
    const result = await orchestrator.executeTask(task, context);

    if (result.status === 'failed') {
      return c.json(
        {
          success: false,
          error: result.error?.message || 'Team onboarding failed'
        },
        400
      );
    }

    // Update progress
    await updateOnboardingProgress(c.env, businessId, userId, 'team_onboarding', 60);

    return c.json({
      success: true,
      ...(result as any).result?.data,
      progress: 60
    });
  })
);

/**
 * Get onboarding progress
 * GET /api/v1/onboarding/progress/:businessId
 */
onboarding.get(
  '/progress/:businessId',
  authenticate() as any,
  asyncHandler(async (c: Context) => {
    const userId = c.get('userId');
    const businessId = c.req.param('businessId');

    if (!userId) {
      return c.json({ error: 'Unauthorized' }, 401);
    }

    const context: BusinessContext = await buildBusinessContext(c, userId, businessId);

    const task: AgentTask = {
      id: CorrelationId.generate(),
      capability: 'progress_tracking',
      type: 'query',
      priority: 'normal',
      input: { data: {} },
      context
    };

    const orchestrator = await getOrchestrator(c.env);
    const result = await orchestrator.executeTask(task, context);

    if (result.status === 'failed') {
      return c.json(
        {
          success: false,
          error: 'Failed to retrieve progress'
        },
        400
      );
    }

    return c.json({
      success: true,
      progress: result.result?.data
    });
  })
);

/**
 * Validate onboarding readiness
 * POST /api/v1/onboarding/validate
 */
onboarding.post(
  '/validate',
  authenticate() as any,
  asyncHandler(async (c: Context) => {
    const userId = c.get('userId');
    const businessId = c.get('businessId');

    if (!userId || !businessId) {
      return c.json({ error: 'Unauthorized' }, 401);
    }

    const context: BusinessContext = await buildBusinessContext(c, userId, businessId);

    const task: AgentTask = {
      id: CorrelationId.generate(),
      capability: 'validation_checks',
      type: 'query',
      priority: 'normal',
      input: { data: {} },
      context
    };

    const orchestrator = await getOrchestrator(c.env);
    const result = await orchestrator.executeTask(task, context);

    if (result.status === 'failed') {
      return c.json(
        {
          success: false,
          error: 'Validation failed'
        },
        400
      );
    }

    return c.json({
      success: true,
      validation: result.result?.data
    });
  })
);

/**
 * Complete onboarding
 * POST /api/v1/onboarding/complete
 */
onboarding.post(
  '/complete',
  authenticate() as any,
  asyncHandler(async (c: Context) => {
    const userId = c.get('userId');
    const businessId = c.get('businessId');

    if (!userId || !businessId) {
      return c.json({ error: 'Unauthorized' }, 401);
    }

    // Update progress to completed
    await c.env.DB_MAIN.prepare(`
      UPDATE onboarding_progress
      SET status = 'completed',
          completion_percentage = 100,
          completed_at = datetime('now'),
          updated_at = datetime('now')
      WHERE business_id = ? AND user_id = ?
        AND status = 'in_progress'
    `)
      .bind(businessId, userId)
      .run();

    return c.json({
      success: true,
      message: 'Onboarding completed successfully',
      nextSteps: [
        'Explore the dashboard',
        'Create your first transaction',
        'Invite additional team members',
        'Set up automated workflows'
      ]
    });
  })
);

/**
 * Get onboarding analytics
 * GET /api/v1/onboarding/analytics/:businessId
 */
onboarding.get(
  '/analytics/:businessId',
  authenticate() as any,
  asyncHandler(async (c: Context) => {
    const userId = c.get('userId');
    const businessId = c.req.param('businessId');

    if (!userId) {
      return c.json({ error: 'Unauthorized' }, 401);
    }

    const context: BusinessContext = await buildBusinessContext(c, userId, businessId);

    const task: AgentTask = {
      id: CorrelationId.generate(),
      capability: 'onboarding_analytics',
      type: 'query',
      priority: 'normal',
      input: { data: {} },
      context
    };

    const orchestrator = await getOrchestrator(c.env);
    const result = await orchestrator.executeTask(task, context);

    return c.json({
      success: true,
      analytics: result.result?.data || {}
    });
  })
);

/**
 * Get industry templates
 * GET /api/v1/onboarding/templates
 */
onboarding.get(
  '/templates',
  authenticate() as any,
  asyncHandler(async (c: Context) => {
    const templates = [
      {
        id: 'saas',
        name: 'SaaS/Software',
        steps: ['Account Setup', 'Stripe Integration', 'Subscription Plans', 'Team Onboarding'],
        estimatedTime: 30
      },
      {
        id: 'ecommerce',
        name: 'E-commerce',
        steps: ['Account Setup', 'Product Import', 'Payment Gateway', 'Shipping Setup'],
        estimatedTime: 45
      },
      {
        id: 'consulting',
        name: 'Consulting/Services',
        steps: ['Account Setup', 'Client Import', 'Project Templates', 'Time Tracking'],
        estimatedTime: 25
      },
      {
        id: 'retail',
        name: 'Retail',
        steps: ['Account Setup', 'Inventory Import', 'POS Integration', 'Supplier Setup'],
        estimatedTime: 40
      },
      {
        id: 'nonprofit',
        name: 'Non-Profit',
        steps: ['Account Setup', 'Donor Import', 'Grant Tracking', 'Compliance Setup'],
        estimatedTime: 35
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

async function buildBusinessContext(
  c: Context,
  userId: string,
  businessId: string
): Promise<BusinessContext> {
  // Get business data
  const business = await c.env.DB_MAIN.prepare(`
    SELECT * FROM businesses WHERE id = ?
  `)
    .bind(businessId)
    .first();

  // Get user data
  const user = await c.env.DB_MAIN.prepare(`
    SELECT * FROM users WHERE id = ?
  `)
    .bind(userId)
    .first();

  return {
    userId,
    businessId,
    sessionId: CorrelationId.generate(),
    correlationId: CorrelationId.generate(),
    businessData: {
      companyName: (business?.name as string) || 'Unknown',
      industry: (business?.industry as string) || 'general',
      size: (business?.size as any) || 'small',
      timezone: (business?.timezone as string) || 'UTC',
      locale: 'en',
      currency: (business?.currency as string) || 'USD',
      fiscalYearStart: '01-01'
    },
    userContext: {
      name: `${user?.first_name} ${user?.last_name}`,
      email: (user?.email as string) || '',
      role: 'admin',
      department: 'operations',
      permissions: ['*'],
      preferences: {}
    },
    requestContext: {
      timestamp: Date.now(),
      ipAddress: c.req.header('CF-Connecting-IP') || '',
      userAgent: c.req.header('User-Agent') || '',
      platform: 'web',
      requestId: CorrelationId.generate()
    }
  };
}

async function getOrchestrator(env: Env): Promise<AgentOrchestrator> {
  const capabilityManager = new CapabilityManager(null as any, null as any);
  const auditService = new AuditService(env.DB_MAIN);
  return new AgentOrchestrator(env.KV_CACHE as any, env.DB_MAIN, capabilityManager, auditService);
}

async function updateOnboardingProgress(
  env: Env,
  businessId: string,
  userId: string,
  step: string,
  percentage: number
): Promise<void> {
  await env.DB_MAIN.prepare(`
    UPDATE onboarding_progress
    SET current_step = ?,
        completion_percentage = ?,
        updated_at = datetime('now')
    WHERE business_id = ? AND user_id = ?
      AND status = 'in_progress'
  `)
    .bind(step, percentage, businessId, userId)
    .run();
}

export default onboarding;
