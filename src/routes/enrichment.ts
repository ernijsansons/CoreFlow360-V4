import { Hono } from 'hono';
import { z } from 'zod';
import { zValidator } from '@hono/zod-validator';
import { EnrichmentPipeline } from '../services/enrichment-pipeline';
import type { Env } from '../types/env';
import type {
  EnrichmentRequest,
  EnrichmentSource,
  EnrichmentPriority,
  EnrichmentConfig
} from '../types/enrichment';

const app = new Hono<{ Bindings: Env }>();

// Validation schemas
const EnrichmentRequestSchema = z.object({
  lead_id: z.string().optional(),
  contact_id: z.string().optional(),
  company_id: z.string().optional(),
  email: z.string().email().optional(),
  domain: z.string().optional(),
  company_name: z.string().optional(),
  linkedin_url: z.string().url().optional(),
  phone: z.string().optional(),
  priority: z.enum(['low', 'medium', 'high', 'urgent']).default('medium'),
  sources: z.array(z.enum(['clearbit', 'apollo', 'linkedin',
  'hunter', 'zoominfo', 'news', 'social', 'github', 'crunchbase'])).min(1),
  force_refresh: z.boolean().default(false)
});

const BulkEnrichmentSchema = z.object({
  requests: z.array(EnrichmentRequestSchema).min(1).max(100)
});

const EnrichmentSourcesSchema = z.object({
  sources: z.array(z.enum(['clearbit', 'apollo', 'linkedin',
  'hunter', 'zoominfo', 'news', 'social', 'github', 'crunchbase']))
});

// Middleware to setup enrichment pipeline
app.use('*', async (c, next) => {
  const config: EnrichmentConfig = {
    sources: {
      clearbit: {
        api_key: c.env.CLEARBIT_API_KEY || '',
        endpoints: {
          person: 'https://person-stream.clearbit.com/v2/combined/find',
          company: 'https://company-stream.clearbit.com/v2/companies/find',
          prospector: 'https://prospector.clearbit.com/v1/people/search'
        },
        rate_limits: {
          requests_per_minute: 600,
          cost_per_request: 2
        }
      },
      apollo: {
        api_key: c.env.APOLLO_API_KEY || '',
        endpoints: {
          person_search: 'https://api.apollo.io/v1/mixed_people/search',
          company_search: 'https://api.apollo.io/v1/mixed_companies/search',
          email_finder: 'https://api.apollo.io/v1/emailfinder'
        },
        rate_limits: {
          requests_per_minute: 120,
          cost_per_request: 1
        }
      },
      linkedin: {
        username: c.env.LINKEDIN_USERNAME || '',
        password: c.env.LINKEDIN_PASSWORD || '',
        proxy_endpoints: [],
        rate_limits: {
          requests_per_hour: 100
        }
      },
      hunter: {
        api_key: c.env.HUNTER_API_KEY || '',
        endpoints: {
          email_finder: 'https://api.hunter.io/v2/email-finder',
          email_verifier: 'https://api.hunter.io/v2/email-verifier',
          domain_search: 'https://api.hunter.io/v2/domain-search'
        }
      },
      news: {
        google_news_api_key: c.env.GOOGLE_NEWS_API_KEY || '',
        newsapi_key: c.env.NEWSAPI_KEY || '',
        serpapi_key: c.env.SERPAPI_KEY || ''
      }
    },
    ai_analysis: {
      model: '@cf/meta/llama-3.1-8b-instruct',
      temperature: 0.3,
      max_tokens: 512,
      analysis_prompts: {
        qualification: 'Analyze this lead for BANT qualification...',
        personalization: 'Generate personalization insights...',
        risk_analysis: 'Identify potential risk factors...'
      }
    },
    caching: {
      cache_ttl: {
        clearbit: 86400,  // 24 hours
        apollo: 86400,
        linkedin: 43200,  // 12 hours
        hunter: 86400,
        zoominfo: 86400,
        news: 3600,       // 1 hour
        social: 43200,
        github: 86400,
        crunchbase: 86400
      },
      cache_prefix: 'enrichment:'
    },
    processing: {
      max_concurrent_requests: 10,
      timeout_ms: 30000,
      retry_attempts: 3,
      batch_size: 10
    }
  };

  c.set('enrichmentPipeline', new EnrichmentPipeline(c.env, config));
  await next();
});

// Single lead enrichment
app.post('/enrich', zValidator('json', EnrichmentRequestSchema), async (c: any) => {
  const pipeline = c.get('enrichmentPipeline') as EnrichmentPipeline;
  const request = c.req.valid('json') as EnrichmentRequest;

  try {
    // Validate that we have enough data to enrich
    if (!request.email && !request.domain && !request.company_name && !request.lead_id) {
      return c.json({
        success: false,
        error: 'At least one of email, domain, company_name, or lead_id is required'
      }, 400);
    }

    // Validate sources are available
    const sourceValidation = await pipeline.validateEnrichmentSources(request.sources);
    if (!sourceValidation.valid) {
      return c.json({
        success: false,
        error: 'Some enrichment sources are not available',
        details: {
          available_sources: sourceValidation.available_sources,
          unavailable_sources: sourceValidation.unavailable_sources,
          errors: sourceValidation.errors
        }
      }, 400);
    }

    // Get cost estimate
    const costEstimate = await pipeline.getEnrichmentCost(request);

    // Perform enrichment
    const result = await pipeline.enrichLead(request);

    if (result.success) {
      return c.json({
        success: true,
        enriched_lead: result.enriched_lead,
        metadata: result.enrichment_metadata,
        cost_estimate: costEstimate
      });
    } else {
      return c.json({
        success: false,
        error: result.error,
        metadata: result.enrichment_metadata
      }, 500);
    }
  } catch (error: any) {
    return c.json({
      success: false,
      error: 'Enrichment pipeline failed',
      message: error instanceof Error ? error.message : 'Unknown error'
    }, 500);
  }
});

// Bulk lead enrichment
app.post('/enrich/bulk', zValidator('json', BulkEnrichmentSchema), async (c: any) => {
  const pipeline = c.get('enrichmentPipeline') as EnrichmentPipeline;
  const { requests } = c.req.valid('json');

  try {
    // Validate all requests
    for (const request of requests) {
      if (!request.email && !request.domain && !request.company_name && !request.lead_id) {
        return c.json({
          success: false,
          error: 'Each request must have at least one of email, domain, company_name, or lead_id'
        }, 400);
      }
    }

    // Calculate total cost estimate
    let totalEstimatedCost = 0;
    for (const request of requests) {
      const costEstimate = await pipeline.getEnrichmentCost(request);
      totalEstimatedCost += costEstimate.estimated_cost;
    }

    // Perform bulk enrichment
    const result = await pipeline.bulkEnrichLeads(requests);

    return c.json({
      success: result.failed === 0,
      total_processed: result.total_processed,
      successful: result.successful,
      failed: result.failed,
      results: result.results,
      total_cost: result.total_cost,
      estimated_cost: totalEstimatedCost,
      processing_time_ms: result.processing_time_ms
    });
  } catch (error: any) {
    return c.json({
      success: false,
      error: 'Bulk enrichment failed',
      message: error instanceof Error ? error.message : 'Unknown error'
    }, 500);
  }
});

// Get enrichment cost estimate
app.post('/cost-estimate', zValidator('json', EnrichmentRequestSchema), async (c: any) => {
  const pipeline = c.get('enrichmentPipeline') as EnrichmentPipeline;
  const request = c.req.valid('json') as EnrichmentRequest;

  try {
    const costEstimate = await pipeline.getEnrichmentCost(request);
    const sourceValidation = await pipeline.validateEnrichmentSources(request.sources);

    return c.json({
      success: true,
      estimated_cost: costEstimate.estimated_cost,
      cost_breakdown: costEstimate.cost_breakdown,
      available_sources: sourceValidation.available_sources,
      unavailable_sources: sourceValidation.unavailable_sources
    });
  } catch (error: any) {
    return c.json({
      success: false,
      error: 'Failed to calculate cost estimate'
    }, 500);
  }
});

// Validate enrichment sources
app.post('/validate-sources', zValidator('json', EnrichmentSourcesSchema), async (c: any) => {
  const pipeline = c.get('enrichmentPipeline') as EnrichmentPipeline;
  const { sources } = c.req.valid('json');

  try {
    const validation = await pipeline.validateEnrichmentSources(sources);

    return c.json({
      success: validation.valid,
      available_sources: validation.available_sources,
      unavailable_sources: validation.unavailable_sources,
      errors: validation.errors
    });
  } catch (error: any) {
    return c.json({
      success: false,
      error: 'Source validation failed'
    }, 500);
  }
});

// Get enrichment status (for async operations)
app.get('/status/:requestId', async (c: any) => {
  const requestId = c.req.param('requestId');

  try {
    // Check status in KV storage
    const status = await c.env.KV_CACHE.get(`enrichment_status:${requestId}`);

    if (!status) {
      return c.json({
        success: false,
        error: 'Enrichment request not found'
      }, 404);
    }

    return c.json({
      success: true,
      status: JSON.parse(status)
    });
  } catch (error: any) {
    return c.json({
      success: false,
      error: 'Failed to get enrichment status'
    }, 500);
  }
});

// Lead enrichment by ID
app.post('/leads/:leadId/enrich', zValidator('json', z.object({
  sources: z.array(z.enum(['clearbit', 'apollo', 'linkedin', 'hunter',
  'zoominfo', 'news', 'social', 'github', 'crunchbase'])).default(['clearbit', 'apollo', 'news']),
  priority: z.enum(['low', 'medium', 'high', 'urgent']).default('medium'),
  force_refresh: z.boolean().default(false)
})), async (c: any) => {
  const pipeline = c.get('enrichmentPipeline') as EnrichmentPipeline;
  const leadId = c.req.param('leadId');
  const { sources, priority, force_refresh } = c.req.valid('json');

  try {
    const request: EnrichmentRequest = {
      lead_id: leadId,
      sources,
      priority,
      force_refresh
    };

    const result = await pipeline.enrichLead(request);

    if (result.success) {
      return c.json({
        success: true,
        enriched_lead: result.enriched_lead,
        metadata: result.enrichment_metadata
      });
    } else {
      return c.json({
        success: false,
        error: result.error,
        metadata: result.enrichment_metadata
      }, 500);
    }
  } catch (error: any) {
    return c.json({
      success: false,
      error: 'Lead enrichment failed'
    }, 500);
  }
});

// Company enrichment by domain
app.post('/companies/:domain/enrich', zValidator('json', z.object({
  sources: z.array(z.enum(['clearbit', 'apollo', 'news', 'crunchbase'])).default(['clearbit', 'apollo', 'news']),
  priority: z.enum(['low', 'medium', 'high', 'urgent']).default('medium'),
  force_refresh: z.boolean().default(false)
})), async (c: any) => {
  const pipeline = c.get('enrichmentPipeline') as EnrichmentPipeline;
  const domain = c.req.param('domain');
  const { sources, priority, force_refresh } = c.req.valid('json');

  try {
    const request: EnrichmentRequest = {
      domain,
      sources,
      priority,
      force_refresh
    };

    const result = await pipeline.enrichLead(request);

    return c.json({
      success: result.success,
      company_data: result.enriched_lead?.enrichment_data.company,
      news_data: result.enriched_lead?.enrichment_data.news,
      ai_insights: result.enriched_lead?.enrichment_data.ai_insights,
      metadata: result.enrichment_metadata,
      error: result.error
    });
  } catch (error: any) {
    return c.json({
      success: false,
      error: 'Company enrichment failed'
    }, 500);
  }
});

// Contact enrichment by email
app.post('/contacts/:email/enrich', zValidator('json', z.object({
  sources: z.array(z.enum(['clearbit', 'apollo', 'linkedin', 'hunter'])).default(['clearbit', 'apollo']),
  priority: z.enum(['low', 'medium', 'high', 'urgent']).default('medium'),
  force_refresh: z.boolean().default(false)
})), async (c: any) => {
  const pipeline = c.get('enrichmentPipeline') as EnrichmentPipeline;
  const email = c.req.param('email');
  const { sources, priority, force_refresh } = c.req.valid('json');

  try {
    const request: EnrichmentRequest = {
      email,
      sources,
      priority,
      force_refresh
    };

    const result = await pipeline.enrichLead(request);

    return c.json({
      success: result.success,
      contact_data: result.enriched_lead?.enrichment_data.contact,
      company_data: result.enriched_lead?.enrichment_data.company,
      ai_insights: result.enriched_lead?.enrichment_data.ai_insights,
      metadata: result.enrichment_metadata,
      error: result.error
    });
  } catch (error: any) {
    return c.json({
      success: false,
      error: 'Contact enrichment failed'
    }, 500);
  }
});

// Analytics endpoint
app.get('/analytics', async (c: any) => {
  const period = c.req.query('period') || '24h';

  try {
    // This would query actual analytics data from the database
    return c.json({
      success: true,
      period,
      metrics: {
        total_enrichments: 245,
        successful_enrichments: 220,
        failed_enrichments: 25,
        success_rate: 0.898,
        avg_processing_time_ms: 3250,
        total_cost: 567.50,
        sources_used: {
          clearbit: 180,
          apollo: 145,
          news: 200,
          linkedin: 65
        },
        top_error_types: [
          { type: 'rate_limit', count: 12 },
          { type: 'not_found', count: 8 },
          { type: 'auth_error', count: 3 }
        ]
      }
    });
  } catch (error: any) {
    return c.json({
      success: false,
      error: 'Failed to get analytics'
    }, 500);
  }
});

// Health check
app.get('/health', async (c: any) => {
  const pipeline = c.get('enrichmentPipeline') as EnrichmentPipeline;

  try {
    const sources = ['clearbit', 'apollo', 'news'] as EnrichmentSource[];
    const validation = await pipeline.validateEnrichmentSources(sources);

    return c.json({
      status: 'healthy',
      service: 'Enrichment Pipeline',
      timestamp: new Date().toISOString(),
      sources: {
        available: validation.available_sources,
        unavailable: validation.unavailable_sources
      }
    });
  } catch (error: any) {
    return c.json({
      status: 'unhealthy',
      error: error instanceof Error ? error.message : 'Unknown error'
    }, 500);
  }
});

// Error handling
app.onError((error, c) => {

  return c.json({
    success: false,
    error: 'Internal server error',
    message: error.message,
    timestamp: new Date().toISOString()
  }, 500);
});

export default app;