import { Hono } from 'hono';
import { z } from 'zod';
import type { Env } from '../types/env';
import { QuantumDataAuditor } from '../data-integrity/quantum-data-auditor';
import { AutomatedDataFixer } from '../data-integrity/automated-data-fixer';
import { Logger } from '../shared/logger';
import type {
  DataAuditConfig,
  DataAuditReport,
  DataIssue,
  FixStrategy,
  FixPreview,
  FixExecution,
  AutomatedDataFixerConfig
} from '../data-integrity/quantum-data-auditor';

const app = new Hono<{ Bindings: Env }>();
const logger = new Logger();

// Validation schemas
const AuditConfigSchema = z.object({
  businessId: z.string().min(1),
  scope: z.enum(['full', 'database', 'replication', 'cache', 'anomalies']).default('full'),
  tables: z.array(z.string()).optional(),
  severity: z.enum(['low', 'medium', 'high', 'critical']).default('medium'),
  includeRecommendations: z.boolean().default(true),
  performanceMode: z.enum(['fast', 'thorough']).default('thorough')
});

const FixStrategyRequestSchema = z.object({
  issueId: z.string().min(1),
  maxRiskLevel: z.enum(['low', 'medium', 'high', 'critical']).default('medium')
});

const FixPreviewRequestSchema = z.object({
  issueId: z.string().min(1),
  strategyId: z.string().min(1)
});

const ExecuteFixRequestSchema = z.object({
  issueId: z.string().min(1),
  strategyId: z.string().min(1),
  approvedBy: z.string().min(1),
  skipValidation: z.boolean().default(false),
  createBackup: z.boolean().default(true)
});

const FixerConfigSchema = z.object({
  enableAutomatedFixes: z.boolean().default(false),
  maxRiskLevel: z.enum(['low', 'medium', 'high']).default('low'),
  requireApprovalThreshold: z.number().min(0).max(10).default(1),
  backupBeforeFix: z.boolean().default(true),
  verificationEnabled: z.boolean().default(true),
  rollbackWindowHours: z.number().min(1).max(168).default(24),
  concurrentFixesLimit: z.number().min(1).max(10).default(3)
});

// Authentication middleware
app.use('*', async (c, next) => {
  const authHeader = c.req.header('Authorization');
  if (!authHeader?.startsWith('Bearer ')) {
    return c.json({ error: 'Missing or invalid authorization header' }, 401);
  }

  // In production, validate the JWT token here
  const token = authHeader.substring(7);
  if (!token) {
    return c.json({ error: 'Invalid token' }, 401);
  }

  // Set user context (mock implementation)
  c.set('user', {
    id: 'user-id',
    businessId: 'business-id',
    role: 'admin'
  });

  await next();
});

// Business isolation middleware
app.use('*', async (c, next) => {
  const user = c.get('user');
  if (!user?.businessId) {
    return c.json({ error: 'Business context required' }, 400);
  }
  await next();
});

/**
 * GET /audit - Trigger comprehensive data integrity audit
 */
app.get('/audit', async (c: any) => {
  try {
    const user = c.get('user');
    const query = c.req.query();

    const config = AuditConfigSchema.parse({
      businessId: user.businessId,
      ...query,
      tables: query.tables ? query.tables.split(',') : undefined,
      includeRecommendations: query.includeRecommendations !== 'false',
    });

    logger.info('Starting data integrity audit', {
      businessId: config.businessId,
      scope: config.scope,
      userId: user.id
    });

    const auditor = new QuantumDataAuditor(c.env, config);
    const report = await auditor.auditDataIntegrity();

    logger.info('Data integrity audit completed', {
      businessId: config.businessId,
      issuesFound: report.summary.totalIssues,
      duration: report.metadata.executionTime
    });

    return c.json({
      success: true,
      data: report,
      timestamp: new Date().toISOString()
    });

  } catch (error: any) {
    logger.error('Data integrity audit failed', error);

    if (error instanceof z.ZodError) {
      return c.json({
        error: 'Invalid request parameters',
        details: error.errors
      }, 400);
    }

    return c.json({
      error: 'Audit execution failed',
      message: error instanceof Error ? error.message : 'Unknown error'
    }, 500);
  }
});

/**
 * POST /audit - Trigger audit with detailed configuration
 */
app.post('/audit', async (c: any) => {
  try {
    const user = c.get('user');
    const body = await c.req.json();

    const config = AuditConfigSchema.parse({
      businessId: user.businessId,
      ...body
    });

    logger.info('Starting configured data integrity audit', {
      businessId: config.businessId,
      config: config,
      userId: user.id
    });

    const auditor = new QuantumDataAuditor(c.env, config);
    const report = await auditor.auditDataIntegrity();

    return c.json({
      success: true,
      data: report,
      timestamp: new Date().toISOString()
    });

  } catch (error: any) {
    logger.error('Configured data integrity audit failed', error);

    if (error instanceof z.ZodError) {
      return c.json({
        error: 'Invalid configuration',
        details: error.errors
      }, 400);
    }

    return c.json({
      error: 'Audit execution failed',
      message: error instanceof Error ? error.message : 'Unknown error'
    }, 500);
  }
});

/**
 * GET /issues - Get paginated list of data integrity issues
 */
app.get('/issues', async (c: any) => {
  try {
    const user = c.get('user');
    const query = c.req.query();

    const page = parseInt(query.page || '1');
    const limit = Math.min(parseInt(query.limit || '50'), 100);
    const offset = (page - 1) * limit;

    const severity = query.severity as 'low' | 'medium' | 'high' | 'critical' | undefined;
    const type = query.type;
    const status = query.status || 'open';

    let whereClause = 'WHERE business_id = ?';
    const params: any[] = [user.businessId];

    if (severity) {
      whereClause += ' AND severity = ?';
      params.push(severity);
    }

    if (type) {
      whereClause += ' AND type = ?';
      params.push(type);
    }

    if (status) {
      whereClause += ' AND status = ?';
      params.push(status);
    }

    // Get total count
    const countResult = await c.env.DB.prepare(`
      SELECT COUNT(*) as total FROM data_issues ${whereClause}
    `).bind(...params).first();

    const total = (countResult as any)?.total || 0;

    // Get paginated results
    const issues = await c.env.DB.prepare(`
      SELECT * FROM data_issues ${whereClause}
      ORDER BY severity DESC, detected_at DESC
      LIMIT ? OFFSET ?
    `).bind(...params, limit, offset).all();

    return c.json({
      success: true,
      data: {
        issues: issues.results || [],
        pagination: {
          page,
          limit,
          total,
          pages: Math.ceil(total / limit),
          hasNext: offset + limit < total,
          hasPrev: page > 1
        }
      },
      timestamp: new Date().toISOString()
    });

  } catch (error: any) {
    logger.error('Failed to retrieve data issues', error);
    return c.json({
      error: 'Failed to retrieve issues',
      message: error instanceof Error ? error.message : 'Unknown error'
    }, 500);
  }
});

/**
 * GET /issues/:issueId - Get specific data integrity issue
 */
app.get('/issues/:issueId', async (c: any) => {
  try {
    const user = c.get('user');
    const issueId = c.req.param('issueId');

    const issue = await c.env.DB.prepare(`
      SELECT * FROM data_issues
      WHERE id = ? AND business_id = ?
    `).bind(issueId, user.businessId).first();

    if (!issue) {
      return c.json({ error: 'Issue not found' }, 404);
    }

    return c.json({
      success: true,
      data: issue,
      timestamp: new Date().toISOString()
    });

  } catch (error: any) {
    logger.error('Failed to retrieve data issue', error);
    return c.json({
      error: 'Failed to retrieve issue',
      message: error instanceof Error ? error.message : 'Unknown error'
    }, 500);
  }
});

/**
 * POST /issues/:issueId/strategies - Get fix strategies for an issue
 */
app.post('/issues/:issueId/strategies', async (c: any) => {
  try {
    const user = c.get('user');
    const issueId = c.req.param('issueId');
    const body = await c.req.json();

    const request = FixStrategyRequestSchema.parse(body);

    // Get the issue
    const issueResult = await c.env.DB.prepare(`
      SELECT * FROM data_issues
      WHERE id = ? AND business_id = ?
    `).bind(issueId, user.businessId).first();

    if (!issueResult) {
      return c.json({ error: 'Issue not found' }, 404);
    }

    const issue = issueResult as DataIssue;

    // Initialize fixer with config
    const fixerConfig: AutomatedDataFixerConfig = {
      enableAutomatedFixes: false,
      maxRiskLevel: request.maxRiskLevel,
      requireApprovalThreshold: 1,
      backupBeforeFix: true,
      verificationEnabled: true,
      rollbackWindowHours: 24,
      businessId: user.businessId,
      concurrentFixesLimit: 3
    };

    const fixer = new AutomatedDataFixer(c.env, fixerConfig);
    const strategies = await fixer.analyzeIssue(issue);

    logger.info('Fix strategies generated', {
      issueId,
      strategiesCount: strategies.length,
      businessId: user.businessId
    });

    return c.json({
      success: true,
      data: {
        issue,
        strategies,
        applicableStrategies: strategies.length
      },
      timestamp: new Date().toISOString()
    });

  } catch (error: any) {
    logger.error('Failed to generate fix strategies', error);

    if (error instanceof z.ZodError) {
      return c.json({
        error: 'Invalid request parameters',
        details: error.errors
      }, 400);
    }

    return c.json({
      error: 'Failed to generate strategies',
      message: error instanceof Error ? error.message : 'Unknown error'
    }, 500);
  }
});

/**
 * POST /issues/:issueId/preview - Preview fix execution
 */
app.post('/issues/:issueId/preview', async (c: any) => {
  try {
    const user = c.get('user');
    const issueId = c.req.param('issueId');
    const body = await c.req.json();

    const request = FixPreviewRequestSchema.parse(body);

    // Get the issue
    const issueResult = await c.env.DB.prepare(`
      SELECT * FROM data_issues
      WHERE id = ? AND business_id = ?
    `).bind(issueId, user.businessId).first();

    if (!issueResult) {
      return c.json({ error: 'Issue not found' }, 404);
    }

    const issue = issueResult as DataIssue;

    // Get the strategy (this would be stored in database in real implementation)
    const fixerConfig: AutomatedDataFixerConfig = {
      enableAutomatedFixes: false,
      maxRiskLevel: 'medium',
      requireApprovalThreshold: 1,
      backupBeforeFix: true,
      verificationEnabled: true,
      rollbackWindowHours: 24,
      businessId: user.businessId,
      concurrentFixesLimit: 3
    };

    const fixer = new AutomatedDataFixer(c.env, fixerConfig);
    const strategies = await fixer.analyzeIssue(issue);
    const strategy = strategies.find(s => s.id === request.strategyId);

    if (!strategy) {
      return c.json({ error: 'Strategy not found' }, 404);
    }

    // Generate preview
    const preview = await fixer.generateFixPreview(issue, strategy);

    // Validate the fix
    const validation = await fixer.validateFix(issue, strategy);

    return c.json({
      success: true,
      data: {
        preview,
        validation,
        canExecute: validation.valid && (strategy.automated || !strategy.requiresApproval)
      },
      timestamp: new Date().toISOString()
    });

  } catch (error: any) {
    logger.error('Failed to generate fix preview', error);

    if (error instanceof z.ZodError) {
      return c.json({
        error: 'Invalid request parameters',
        details: error.errors
      }, 400);
    }

    return c.json({
      error: 'Failed to generate preview',
      message: error instanceof Error ? error.message : 'Unknown error'
    }, 500);
  }
});

/**
 * POST /issues/:issueId/fix - Execute fix for an issue
 */
app.post('/issues/:issueId/fix', async (c: any) => {
  try {
    const user = c.get('user');
    const issueId = c.req.param('issueId');
    const body = await c.req.json();

    const request = ExecuteFixRequestSchema.parse(body);

    // Check user permissions for fix execution
    if (user.role !== 'admin' && user.role !== 'data_manager') {
      return c.json({ error: 'Insufficient permissions to execute fixes' }, 403);
    }

    // Get the issue
    const issueResult = await c.env.DB.prepare(`
      SELECT * FROM data_issues
      WHERE id = ? AND business_id = ?
    `).bind(issueId, user.businessId).first();

    if (!issueResult) {
      return c.json({ error: 'Issue not found' }, 404);
    }

    const issue = issueResult as DataIssue;

    // Initialize fixer
    const fixerConfig: AutomatedDataFixerConfig = {
      enableAutomatedFixes: true,
      maxRiskLevel: 'medium',
      requireApprovalThreshold: 1,
      backupBeforeFix: request.createBackup,
      verificationEnabled: !request.skipValidation,
      rollbackWindowHours: 24,
      businessId: user.businessId,
      concurrentFixesLimit: 3
    };

    const fixer = new AutomatedDataFixer(c.env, fixerConfig);
    const strategies = await fixer.analyzeIssue(issue);
    const strategy = strategies.find(s => s.id === request.strategyId);

    if (!strategy) {
      return c.json({ error: 'Strategy not found' }, 404);
    }

    // Validate before execution
    if (!request.skipValidation) {
      const validation = await fixer.validateFix(issue, strategy);
      if (!validation.valid) {
        return c.json({
          error: 'Fix validation failed',
          details: validation.errors
        }, 400);
      }
    }

    // Execute the fix
    const execution = await fixer.executeFix(issue, strategy, request.approvedBy);

    // Update issue status if fix was successful
    if (execution.status === 'completed') {
      await c.env.DB.prepare(`
        UPDATE data_issues
        SET status = 'resolved', resolved_at = ?, resolved_by = ?
        WHERE id = ? AND business_id = ?
      `).bind(
        new Date().toISOString(),
        request.approvedBy,
        issueId,
        user.businessId
      ).run();
    }

    logger.info('Fix execution completed', {
      issueId,
      strategyId: request.strategyId,
      status: execution.status,
      recordsAffected: execution.results.recordsAffected,
      executedBy: request.approvedBy
    });

    return c.json({
      success: execution.status === 'completed',
      data: execution,
      timestamp: new Date().toISOString()
    });

  } catch (error: any) {
    logger.error('Failed to execute fix', error);

    if (error instanceof z.ZodError) {
      return c.json({
        error: 'Invalid request parameters',
        details: error.errors
      }, 400);
    }

    return c.json({
      error: 'Fix execution failed',
      message: error instanceof Error ? error.message : 'Unknown error'
    }, 500);
  }
});

/**
 * GET /executions - Get fix execution history
 */
app.get('/executions', async (c: any) => {
  try {
    const user = c.get('user');
    const query = c.req.query();

    const page = parseInt(query.page || '1');
    const limit = Math.min(parseInt(query.limit || '50'), 100);
    const offset = (page - 1) * limit;

    const status = query.status;

    let whereClause = 'WHERE business_id = ?';
    const params: any[] = [user.businessId];

    if (status) {
      whereClause += ' AND status = ?';
      params.push(status);
    }

    // Get total count
    const countResult = await c.env.DB.prepare(`
      SELECT COUNT(*) as total FROM fix_executions ${whereClause}
    `).bind(...params).first();

    const total = (countResult as any)?.total || 0;

    // Get paginated results
    const executions = await c.env.DB.prepare(`
      SELECT * FROM fix_executions ${whereClause}
      ORDER BY started_at DESC
      LIMIT ? OFFSET ?
    `).bind(...params, limit, offset).all();

    return c.json({
      success: true,
      data: {
        executions: executions.results || [],
        pagination: {
          page,
          limit,
          total,
          pages: Math.ceil(total / limit),
          hasNext: offset + limit < total,
          hasPrev: page > 1
        }
      },
      timestamp: new Date().toISOString()
    });

  } catch (error: any) {
    logger.error('Failed to retrieve fix executions', error);
    return c.json({
      error: 'Failed to retrieve executions',
      message: error instanceof Error ? error.message : 'Unknown error'
    }, 500);
  }
});

/**
 * POST /executions/:executionId/rollback - Rollback a fix execution
 */
app.post('/executions/:executionId/rollback', async (c: any) => {
  try {
    const user = c.get('user');
    const executionId = c.req.param('executionId');

    // Check user permissions
    if (user.role !== 'admin') {
      return c.json({ error: 'Insufficient permissions to rollback fixes' }, 403);
    }

    // Get execution to verify ownership
    const executionResult = await c.env.DB.prepare(`
      SELECT * FROM fix_executions
      WHERE id = ? AND business_id = ?
    `).bind(executionId, user.businessId).first();

    if (!executionResult) {
      return c.json({ error: 'Execution not found' }, 404);
    }

    // Initialize fixer and attempt rollback
    const fixerConfig: AutomatedDataFixerConfig = {
      enableAutomatedFixes: false,
      maxRiskLevel: 'medium',
      requireApprovalThreshold: 1,
      backupBeforeFix: true,
      verificationEnabled: true,
      rollbackWindowHours: 24,
      businessId: user.businessId,
      concurrentFixesLimit: 3
    };

    const fixer = new AutomatedDataFixer(c.env, fixerConfig);
    const success = await fixer.rollbackFix(executionId);

    if (success) {
      logger.info('Fix rollback completed', {
        executionId,
        businessId: user.businessId,
        rolledBackBy: user.id
      });

      return c.json({
        success: true,
        message: 'Fix rolled back successfully',
        timestamp: new Date().toISOString()
      });
    } else {
      return c.json({
        error: 'Rollback failed',
        message: 'Unable to rollback the fix execution'
      }, 400);
    }

  } catch (error: any) {
    logger.error('Failed to rollback fix', error);
    return c.json({
      error: 'Rollback failed',
      message: error instanceof Error ? error.message : 'Unknown error'
    }, 500);
  }
});

/**
 * GET /config - Get data fixer configuration
 */
app.get('/config', async (c: any) => {
  try {
    const user = c.get('user');

    // Get configuration from database or return defaults
    const configResult = await c.env.DB.prepare(`
      SELECT * FROM data_fixer_config WHERE business_id = ?
    `).bind(user.businessId).first();

    const defaultConfig = {
      enableAutomatedFixes: false,
      maxRiskLevel: 'low',
      requireApprovalThreshold: 1,
      backupBeforeFix: true,
      verificationEnabled: true,
      rollbackWindowHours: 24,
      concurrentFixesLimit: 3
    };

    const config = configResult ? {
      ...defaultConfig,
      ...JSON.parse((configResult as any).config)
    } : defaultConfig;

    return c.json({
      success: true,
      data: config,
      timestamp: new Date().toISOString()
    });

  } catch (error: any) {
    logger.error('Failed to retrieve fixer configuration', error);
    return c.json({
      error: 'Failed to retrieve configuration',
      message: error instanceof Error ? error.message : 'Unknown error'
    }, 500);
  }
});

/**
 * PUT /config - Update data fixer configuration
 */
app.put('/config', async (c: any) => {
  try {
    const user = c.get('user');
    const body = await c.req.json();

    // Check user permissions
    if (user.role !== 'admin') {
      return c.json({ error: 'Insufficient permissions to modify configuration' }, 403);
    }

    const config = FixerConfigSchema.parse(body);

    // Save configuration
    await c.env.DB.prepare(`
      INSERT OR REPLACE INTO data_fixer_config (business_id, config, updated_at, updated_by)
      VALUES (?, ?, ?, ?)
    `).bind(
      user.businessId,
      JSON.stringify(config),
      new Date().toISOString(),
      user.id
    ).run();

    logger.info('Data fixer configuration updated', {
      businessId: user.businessId,
      updatedBy: user.id,
      config
    });

    return c.json({
      success: true,
      data: config,
      timestamp: new Date().toISOString()
    });

  } catch (error: any) {
    logger.error('Failed to update fixer configuration', error);

    if (error instanceof z.ZodError) {
      return c.json({
        error: 'Invalid configuration',
        details: error.errors
      }, 400);
    }

    return c.json({
      error: 'Failed to update configuration',
      message: error instanceof Error ? error.message : 'Unknown error'
    }, 500);
  }
});

/**
 * GET /dashboard - Get data integrity dashboard data
 */
app.get('/dashboard', async (c: any) => {
  try {
    const user = c.get('user');

    // Get issue summary by severity
    const severityStats = await c.env.DB.prepare(`
      SELECT severity, COUNT(*) as count
      FROM data_issues
      WHERE business_id = ? AND status = 'open'
      GROUP BY severity
    `).bind(user.businessId).all();

    // Get issue summary by type
    const typeStats = await c.env.DB.prepare(`
      SELECT type, COUNT(*) as count
      FROM data_issues
      WHERE business_id = ? AND status = 'open'
      GROUP BY type
    `).bind(user.businessId).all();

    // Get recent executions
    const recentExecutions = await c.env.DB.prepare(`
      SELECT * FROM fix_executions
      WHERE business_id = ?
      ORDER BY started_at DESC
      LIMIT 10
    `).bind(user.businessId).all();

    // Get resolution rate
    const resolutionStats = await c.env.DB.prepare(`
      SELECT
        status,
        COUNT(*) as count
      FROM data_issues
      WHERE business_id = ?
      GROUP BY status
    `).bind(user.businessId).all();

    const dashboard = {
      summary: {
        openIssues: severityStats.results?.reduce((sum, stat) => sum + (stat as any).count, 0) || 0,
        criticalIssues: severityStats.results?.find((stat: any) => stat.severity === 'critical')?.count || 0,
        recentExecutions: recentExecutions.results?.length || 0
      },
      severityBreakdown: severityStats.results || [],
      typeBreakdown: typeStats.results || [],
      resolutionStats: resolutionStats.results || [],
      recentActivity: recentExecutions.results || []
    };

    return c.json({
      success: true,
      data: dashboard,
      timestamp: new Date().toISOString()
    });

  } catch (error: any) {
    logger.error('Failed to retrieve dashboard data', error);
    return c.json({
      error: 'Failed to retrieve dashboard',
      message: error instanceof Error ? error.message : 'Unknown error'
    }, 500);
  }
});

export const dataIntegrityRoutes = app;