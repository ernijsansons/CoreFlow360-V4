/**
 * Company Knowledge Agent API Routes
 * REST endpoints for company knowledge learning and management
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

const knowledge = new Hono<{ Bindings: Env }>();

// Apply error handler
knowledge.onError(errorHandler);

// ============================================================================
// VALIDATION SCHEMAS
// ============================================================================

const ScrapeWebsiteSchema = z.object({
  url: z.string().url(),
  maxDepth: z.number().min(1).max(5).optional().default(3),
  maxPages: z.number().min(1).max(500).optional().default(100)
});

const AddKnowledgeSourceSchema = z.object({
  sourceName: z.string(),
  sourceType: z.enum(['website', 'api', 'document', 'rss_feed', 'knowledge_base', 'manual_entry']),
  sourceUrl: z.string().url(),
  scrapingConfig: z
    .object({
      maxDepth: z.number().optional().default(3),
      followExternal: z.boolean().optional().default(false),
      rateLimit: z.number().optional().default(1),
      includePatterns: z.array(z.string()).optional().default([]),
      excludePatterns: z.array(z.string()).optional().default([])
    })
    .optional()
    .default({}),
  crawlFrequency: z.enum(['daily', 'weekly', 'monthly', 'manual']).optional().default('weekly')
});

const SearchKnowledgeSchema = z.object({
  query: z.string().min(1),
  contentType: z.string().optional(),
  limit: z.number().min(1).max(50).optional().default(10)
});

const ValidateContentSchema = z.object({
  contentId: z.string()
});

// ============================================================================
// ROUTES
// ============================================================================

/**
 * Scrape company website
 * POST /api/v1/knowledge/scrape
 */
knowledge.post(
  '/scrape',
  authenticate() as any,
  asyncHandler(async (c: Context) => {
    const userId = c.get('userId');
    const businessId = c.get('businessId');

    if (!userId || !businessId) {
      return c.json({ error: 'Unauthorized' }, 401);
    }

    const body = await c.req.json();
    const validatedData = ScrapeWebsiteSchema.parse(body);

    const context: BusinessContext = await buildBusinessContext(c, userId, businessId);

    const task: AgentTask = {
      id: CorrelationId.generate(),
      capability: 'website_scraping',
      type: 'action',
      priority: 'normal',
      input: { data: validatedData },
      context
    };

    const orchestrator = await getOrchestrator(c.env);
    const result = await orchestrator.executeTask(task, context);

    if (result.status === 'failed') {
      return c.json(
        {
          success: false,
          error: result.error?.message || 'Website scraping failed'
        },
        400
      );
    }

    return c.json(
      {
        success: true,
        ...(result as any).result?.data,
        executionTime: result.metrics.executionTime
      },
      201
    );
  })
);

/**
 * Get learned content
 * GET /api/v1/knowledge/content/:businessId
 */
knowledge.get(
  '/content/:businessId',
  authenticate() as any,
  asyncHandler(async (c: Context) => {
    const userId = c.get('userId');
    const businessId = c.req.param('businessId');
    const contentType = c.req.query('contentType');
    const page = parseInt(c.req.query('page') || '1');
    const limit = parseInt(c.req.query('limit') || '20');
    const offset = (page - 1) * limit;

    if (!userId) {
      return c.json({ error: 'Unauthorized' }, 401);
    }

    let query = `
      SELECT
        id, content_type, title, summary, source_url,
        verified, accuracy_score, freshness_score,
        times_referenced, created_at, updated_at
      FROM company_knowledge_base
      WHERE business_id = ? AND status = 'active'
    `;
    const params: any[] = [businessId];

    if (contentType) {
      query += ` AND content_type = ?`;
      params.push(contentType);
    }

    query += ` ORDER BY created_at DESC LIMIT ? OFFSET ?`;
    params.push(limit, offset);

    const result = await c.env.DB_MAIN.prepare(query).bind(...(params as any)).all();

    // Get total count
    let countQuery = `
      SELECT COUNT(*) as total
      FROM company_knowledge_base
      WHERE business_id = ? AND status = 'active'
    `;
    const countParams: any[] = [businessId];

    if (contentType) {
      countQuery += ` AND content_type = ?`;
      countParams.push(contentType);
    }

    const countResult = await c.env.DB_MAIN.prepare(countQuery).bind(...(countParams as any)).first();

    return c.json({
      success: true,
      content: result.results || [],
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
 * Learn about products
 * POST /api/v1/knowledge/learn-products
 */
knowledge.post(
  '/learn-products',
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
      capability: 'product_learning',
      type: 'analysis',
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
          error: 'Product learning failed'
        },
        400
      );
    }

    return c.json({
      success: true,
      products: result.result?.data
    });
  })
);

/**
 * Analyze brand voice
 * POST /api/v1/knowledge/analyze-brand-voice
 */
knowledge.post(
  '/analyze-brand-voice',
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
      capability: 'brand_voice_analysis',
      type: 'analysis',
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
          error: 'Brand voice analysis failed'
        },
        400
      );
    }

    return c.json({
      success: true,
      brandVoice: result.result?.data,
      message: 'Brand voice analyzed and saved as compliance guideline'
    });
  })
);

/**
 * Generate FAQs
 * POST /api/v1/knowledge/generate-faqs
 */
knowledge.post(
  '/generate-faqs',
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
      capability: 'faq_generation',
      type: 'generation',
      priority: 'normal',
      input: { data: {} },
      context
    };

    const orchestrator = await getOrchestrator(c.env);
    const result = await orchestrator.executeTask(task, context);

    return c.json({
      success: true,
      faqs: result.result?.data || {}
    });
  })
);

/**
 * Search knowledge base
 * POST /api/v1/knowledge/search
 */
knowledge.post(
  '/search',
  authenticate() as any,
  asyncHandler(async (c: Context) => {
    const userId = c.get('userId');
    const businessId = c.get('businessId');

    if (!userId || !businessId) {
      return c.json({ error: 'Unauthorized' }, 401);
    }

    const body = await c.req.json();
    const validatedData = SearchKnowledgeSchema.parse(body);

    const context: BusinessContext = await buildBusinessContext(c, userId, businessId);

    const task: AgentTask = {
      id: CorrelationId.generate(),
      capability: 'content_recommendation',
      type: 'query',
      priority: 'high',
      input: { data: validatedData },
      context
    };

    const orchestrator = await getOrchestrator(c.env);
    const result = await orchestrator.executeTask(task, context);

    return c.json({
      success: true,
      results: (result.result?.data as any)?.recommendations || []
    });
  })
);

/**
 * Validate knowledge content
 * POST /api/v1/knowledge/validate
 */
knowledge.post(
  '/validate',
  authenticate() as any,
  asyncHandler(async (c: Context) => {
    const userId = c.get('userId');
    const businessId = c.get('businessId');

    if (!userId || !businessId) {
      return c.json({ error: 'Unauthorized' }, 401);
    }

    const body = await c.req.json();
    const { contentId } = ValidateContentSchema.parse(body);

    // Mark content as verified
    await c.env.DB_MAIN.prepare(`
      UPDATE company_knowledge_base
      SET verified = 1,
          verified_by = ?,
          verified_at = datetime('now'),
          updated_at = datetime('now')
      WHERE id = ? AND business_id = ?
    `)
      .bind(userId, contentId, businessId)
      .run();

    return c.json({
      success: true,
      message: 'Content validated successfully'
    });
  })
);

/**
 * Refresh knowledge
 * POST /api/v1/knowledge/refresh
 */
knowledge.post(
  '/refresh',
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
      capability: 'knowledge_refresh',
      type: 'action',
      priority: 'low',
      input: { data: {} },
      context
    };

    const orchestrator = await getOrchestrator(c.env);
    const result = await orchestrator.executeTask(task, context);

    return c.json({
      success: true,
      ...(result as any).result?.data
    });
  })
);

/**
 * Add knowledge source
 * POST /api/v1/knowledge/sources
 */
knowledge.post(
  '/sources',
  authenticate() as any,
  asyncHandler(async (c: Context) => {
    const userId = c.get('userId');
    const businessId = c.get('businessId');

    if (!userId || !businessId) {
      return c.json({ error: 'Unauthorized' }, 401);
    }

    const body = await c.req.json();
    const validatedData = AddKnowledgeSourceSchema.parse(body);

    const sourceId = CorrelationId.generate();

    await c.env.DB_MAIN.prepare(`
      INSERT INTO knowledge_sources (
        id, business_id, source_name, source_type, source_url,
        scraping_config, crawl_frequency, status, priority,
        auto_refresh, created_by
      ) VALUES (?, ?, ?, ?, ?, ?, ?, 'active', 100, 1, ?)
    `)
      .bind(
        sourceId,
        businessId,
        validatedData.sourceName,
        validatedData.sourceType,
        validatedData.sourceUrl,
        JSON.stringify(validatedData.scrapingConfig),
        validatedData.crawlFrequency,
        userId
      )
      .run();

    return c.json(
      {
        success: true,
        sourceId,
        message: 'Knowledge source added successfully'
      },
      201
    );
  })
);

/**
 * Get knowledge sources
 * GET /api/v1/knowledge/sources/:businessId
 */
knowledge.get(
  '/sources/:businessId',
  authenticate() as any,
  asyncHandler(async (c: Context) => {
    const userId = c.get('userId');
    const businessId = c.req.param('businessId');

    if (!userId) {
      return c.json({ error: 'Unauthorized' }, 401);
    }

    const result = await c.env.DB_MAIN.prepare(`
      SELECT
        id, source_name, source_type, source_url,
        status, pages_crawled, content_extracted,
        last_crawl_at, next_crawl_at, created_at
      FROM knowledge_sources
      WHERE business_id = ?
      ORDER BY created_at DESC
    `)
      .bind(businessId)
      .all();

    return c.json({
      success: true,
      sources: result.results || []
    });
  })
);

/**
 * Delete knowledge source
 * DELETE /api/v1/knowledge/sources/:sourceId
 */
knowledge.delete(
  '/sources/:sourceId',
  authenticate() as any,
  asyncHandler(async (c: Context) => {
    const userId = c.get('userId');
    const businessId = c.get('businessId');
    const sourceId = c.req.param('sourceId');

    if (!userId || !businessId) {
      return c.json({ error: 'Unauthorized' }, 401);
    }

    // Delete source
    await c.env.DB_MAIN.prepare(`
      DELETE FROM knowledge_sources
      WHERE id = ? AND business_id = ?
    `)
      .bind(sourceId, businessId)
      .run();

    // Mark related content as archived
    await c.env.DB_MAIN.prepare(`
      UPDATE company_knowledge_base
      SET status = 'archived',
          updated_at = datetime('now')
      WHERE source_id = ? AND business_id = ?
    `)
      .bind(sourceId, businessId)
      .run();

    return c.json({
      success: true,
      message: 'Knowledge source deleted successfully'
    });
  })
);

/**
 * Get knowledge statistics
 * GET /api/v1/knowledge/stats/:businessId
 */
knowledge.get(
  '/stats/:businessId',
  authenticate() as any,
  asyncHandler(async (c: Context) => {
    const userId = c.get('userId');
    const businessId = c.req.param('businessId');

    if (!userId) {
      return c.json({ error: 'Unauthorized' }, 401);
    }

    // Get content statistics
    const contentStats = await c.env.DB_MAIN.prepare(`
      SELECT
        content_type,
        COUNT(*) as count,
        AVG(accuracy_score) as avg_accuracy,
        AVG(freshness_score) as avg_freshness,
        SUM(times_referenced) as total_references
      FROM company_knowledge_base
      WHERE business_id = ? AND status = 'active'
      GROUP BY content_type
    `)
      .bind(businessId)
      .all();

    // Get source statistics
    const sourceStats = await c.env.DB_MAIN.prepare(`
      SELECT
        COUNT(*) as total_sources,
        SUM(pages_crawled) as total_pages,
        SUM(content_extracted) as total_content,
        AVG(success_rate) as avg_success_rate
      FROM knowledge_sources
      WHERE business_id = ? AND status = 'active'
    `)
      .bind(businessId)
      .first();

    return c.json({
      success: true,
      statistics: {
        contentByType: contentStats.results || [],
        sources: sourceStats || {}
      }
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
  const business = await c.env.DB_MAIN.prepare(`SELECT * FROM businesses WHERE id = ?`)
    .bind(businessId)
    .first();

  const user = await c.env.DB_MAIN.prepare(`SELECT * FROM users WHERE id = ?`)
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
      department: 'marketing',
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

export default knowledge;
