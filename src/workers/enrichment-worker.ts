import { EnrichmentPipeline } from '../services/enrichment-pipeline';
import type { Env } from '../types/env';
import type {
  EnrichmentRequest,
  EnrichmentConfig,
  EnrichmentSource
} from '../types/enrichment';

export interface EnrichmentJob {
  id: string;
  type: 'lead_enrichment' | 'bulk_enrichment' | 'scheduled_enrichment' | 'webhook_enrichment';
  priority: 'low' | 'medium' | 'high' | 'urgent';
  payload: EnrichmentJobPayload;
  retry_count: number;
  max_retries: number;
  created_at: string;
  scheduled_at?: string;
  business_id: string;
}

export interface EnrichmentJobPayload {
  enrichment_request?: EnrichmentRequest;
  bulk_requests?: EnrichmentRequest[];
  lead_id?: string;
  trigger?: string;
  webhook_data?: any;
  force_refresh?: boolean;
}

export interface EnrichmentJobResult {
  job_id: string;
  success: boolean;
  processed_count: number;
  failed_count: number;
  total_cost: number;
  processing_time_ms: number;
  errors: string[];
  next_run_at?: string;
}

export class EnrichmentWorker {
  private env: Env;
  private pipeline: EnrichmentPipeline;

  constructor(env: Env) {
    this.env = env;

    // Initialize enrichment pipeline with configuration
    const config: EnrichmentConfig = this.getEnrichmentConfig(env);
    this.pipeline = new EnrichmentPipeline(env, config);
  }

  async processJob(job: EnrichmentJob): Promise<EnrichmentJobResult> {
    const startTime = Date.now();

    try {
      switch (job.type) {
        case 'lead_enrichment':
          return await this.processLeadEnrichment(job, startTime);
        case 'bulk_enrichment':
          return await this.processBulkEnrichment(job, startTime);
        case 'scheduled_enrichment':
          return await this.processScheduledEnrichment(job, startTime);
        case 'webhook_enrichment':
          return await this.processWebhookEnrichment(job, startTime);
        default:
          throw new Error(`Unknown job type: ${job.type}`);
      }
    } catch (error: any) {

      return {
        job_id: job.id,
        success: false,
        processed_count: 0,
        failed_count: 1,
        total_cost: 0,
        processing_time_ms: Date.now() - startTime,
        errors: [error instanceof Error ? error.message : 'Unknown error']
      };
    }
  }

  private async processLeadEnrichment(job: EnrichmentJob, startTime: number): Promise<EnrichmentJobResult> {
    const { enrichment_request } = job.payload;

    if (!enrichment_request) {
      throw new Error('No enrichment request provided');
    }

    // Add business context
    const request: EnrichmentRequest = {
      ...enrichment_request,
      sources: enrichment_request.sources || this.getDefaultSources(),
      priority: job.priority
    };

    const result = await this.pipeline.enrichLead(request);

    // Update CRM with enrichment results
    if (result.success && result.enriched_lead) {
      await this.updateCRMWithEnrichment(result.enriched_lead, job.business_id);

      // Schedule follow-up enrichment for high-value leads
      if (result.enriched_lead.enrichment_data.ai_insights.icp_fit_score > 80) {
        await this.scheduleFollowUpEnrichment(result.enriched_lead.id, job.business_id);
      }

      // Trigger AI actions based on insights
      await this.triggerAIActions(result.enriched_lead, job.business_id);
    }

    return {
      job_id: job.id,
      success: result.success,
      processed_count: result.success ? 1 : 0,
      failed_count: result.success ? 0 : 1,
      total_cost: result.enrichment_metadata.cost.total_cost,
      processing_time_ms: Date.now() - startTime,
      errors: result.error ? [result.error] : []
    };
  }

  private async processBulkEnrichment(job: EnrichmentJob, startTime: number): Promise<EnrichmentJobResult> {
    const { bulk_requests } = job.payload;

    if (!bulk_requests || bulk_requests.length === 0) {
      throw new Error('No bulk requests provided');
    }

    // Add business context and defaults
    const requests: EnrichmentRequest[] = bulk_requests.map((req: any) => ({
      ...req,
      sources: req.sources || this.getDefaultSources(),
      priority: job.priority
    }));

    const result = await this.pipeline.bulkEnrichLeads(requests);

    // Update CRM for successful enrichments
    let updatedCount = 0;
    for (const enrichmentResult of result.results) {
      if (enrichmentResult.success && enrichmentResult.enriched_lead) {
        await this.updateCRMWithEnrichment(enrichmentResult.enriched_lead, job.business_id);
        await this.triggerAIActions(enrichmentResult.enriched_lead, job.business_id);
        updatedCount++;
      }
    }


    return {
      job_id: job.id,
      success: result.failed === 0,
      processed_count: result.successful,
      failed_count: result.failed,
      total_cost: result.total_cost,
      processing_time_ms: Date.now() - startTime,
      errors: result.results
        .filter((r: any) => !r.success)
        .map((r: any) => r.error || 'Unknown error')
    };
  }

  private async processScheduledEnrichment(job: EnrichmentJob, startTime: number): Promise<EnrichmentJobResult> {
    const { lead_id, force_refresh } = job.payload;

    if (!lead_id) {
      throw new Error('No lead ID provided for scheduled enrichment');
    }

    // Get lead data from CRM
    const leadData = await this.getLeadFromCRM(lead_id, job.business_id);
    if (!leadData) {
      throw new Error(`Lead ${lead_id} not found`);
    }

    // Create enrichment request
    const request: EnrichmentRequest = {
      lead_id: lead_id,
      email: leadData.email,
      domain: leadData.company_domain,
      company_name: leadData.company_name,
      sources: this.getDefaultSources(),
      priority: job.priority,
      force_refresh: force_refresh || false
    };

    const result = await this.pipeline.enrichLead(request);

    if (result.success && result.enriched_lead) {
      await this.updateCRMWithEnrichment(result.enriched_lead, job.business_id);
      await this.triggerAIActions(result.enriched_lead, job.business_id);

      // Schedule next enrichment based on lead value
      const nextRun = this.calculateNextEnrichmentDate(result.enriched_lead);
      if (nextRun) {
        await this.scheduleEnrichmentJob(lead_id, job.business_id, nextRun);
      }
    }

    return {
      job_id: job.id,
      success: result.success,
      processed_count: result.success ? 1 : 0,
      failed_count: result.success ? 0 : 1,
      total_cost: result.enrichment_metadata.cost.total_cost,
      processing_time_ms: Date.now() - startTime,
      errors: result.error ? [result.error] : [],
      next_run_at: this.calculateNextEnrichmentDate(result.enriched_lead!)?.toISOString()
    };
  }

  private async processWebhookEnrichment(job: EnrichmentJob, startTime: number): Promise<EnrichmentJobResult> {
    const { webhook_data, trigger } = job.payload;

    if (!webhook_data) {
      throw new Error('No webhook data provided');
    }

    // Convert webhook data to enrichment request
    const request = this.convertWebhookToEnrichmentRequest(webhook_data, trigger || 'webhook');

    const result = await this.pipeline.enrichLead(request);

    if (result.success && result.enriched_lead) {
      await this.updateCRMWithEnrichment(result.enriched_lead, job.business_id);
      await this.triggerAIActions(result.enriched_lead, job.business_id);

      // Send webhook response if needed
      await this.sendWebhookResponse(webhook_data, result.enriched_lead);
    }

    return {
      job_id: job.id,
      success: result.success,
      processed_count: result.success ? 1 : 0,
      failed_count: result.success ? 0 : 1,
      total_cost: result.enrichment_metadata.cost.total_cost,
      processing_time_ms: Date.now() - startTime,
      errors: result.error ? [result.error] : []
    };
  }

  // Helper methods
  private async updateCRMWithEnrichment(enrichedLead: any, businessId: string): Promise<void> {
    try {
      // Update lead qualification score
      if (enrichedLead.id && enrichedLead.enrichment_data.ai_insights) {
        const insights = enrichedLead.enrichment_data.ai_insights;

        // Update lead status based on AI insights
        let newStatus = enrichedLead.status;
        if (insights.icp_fit_score > 80 && insights.buying_intent_score > 70) {
          newStatus = 'qualified';
        } else if (insights.icp_fit_score > 60) {
          newStatus = 'qualifying';
        }

        // Update in CRM (would integrate with actual CRM service)
      }

      // Store enrichment data in analytics
      await this.storeEnrichmentAnalytics(enrichedLead, businessId);
    } catch (error: any) {
    }
  }

  private async triggerAIActions(enrichedLead: any, businessId: string): Promise<void> {
    try {
      const insights = enrichedLead.enrichment_data.ai_insights;

      // Trigger high-priority actions for qualified leads
      if (insights.icp_fit_score > 80) {
        // Schedule immediate follow-up
        await this.scheduleAITask({
          business_id: businessId,
          type: 'send_followup',
          priority: 'high',
          payload: JSON.stringify({
            lead_id: enrichedLead.id,
            template_type: 'qualified_follow_up',
            personalization: insights.personalized_messaging[0]
          })
        });

        // Notify sales team for high-value leads
        if (insights.conversion_probability > 0.7) {
          await this.scheduleAITask({
            business_id: businessId,
            type: 'notify_sales_team',
            priority: 'urgent',
            payload: JSON.stringify({
              lead_id: enrichedLead.id,
              reason: 'high_conversion_probability',
              score: insights.conversion_probability
            })
          });
        }
      }

      // Schedule research tasks for incomplete data
      if (!enrichedLead.enrichment_data.company.funding_total) {
        await this.scheduleAITask({
          business_id: businessId,
          type: 'research_funding',
          priority: 'medium',
          payload: JSON.stringify({
            company_id: enrichedLead.company_id,
            company_name: enrichedLead.enrichment_data.company.legal_name
          })
        });
      }
    } catch (error: any) {
    }
  }

  private async scheduleFollowUpEnrichment(leadId: string, businessId: string): Promise<void> {
    const nextEnrichment = new Date();
    nextEnrichment.setDate(nextEnrichment.getDate() + 7); // Weekly enrichment

    await this.scheduleEnrichmentJob(leadId, businessId, nextEnrichment);
  }

  private async scheduleEnrichmentJob(leadId: string, businessId: string, scheduledAt: Date): Promise<void> {
    const job: EnrichmentJob = {
      id: this.generateJobId(),
      type: 'scheduled_enrichment',
      priority: 'medium',
      payload: {
        lead_id: leadId,
        force_refresh: true
      },
      retry_count: 0,
      max_retries: 3,
      created_at: new Date().toISOString(),
      scheduled_at: scheduledAt.toISOString(),
      business_id: businessId
    };

    // Queue the job
    if (this.env.TASK_QUEUE) {
      await this.env.TASK_QUEUE.send(job, {
        delaySeconds: Math.floor((scheduledAt.getTime() - Date.now()) / 1000)
      });
    }
  }

  private async scheduleAITask(task: any): Promise<void> {
    if (this.env.TASK_QUEUE) {
      await this.env.TASK_QUEUE.send({
        type: 'ai_task',
        ...task,
        created_at: new Date().toISOString()
      });
    }
  }

  private async getLeadFromCRM(leadId: string, businessId: string): Promise<any> {
    // This would integrate with the CRM service
    // For now, return mock data
    return {
      id: leadId,
      business_id: businessId,
      email: 'example@company.com',
      company_name: 'Example Company',
      company_domain: 'example.com',
      status: 'new'
    };
  }

  private async storeEnrichmentAnalytics(enrichedLead: any, businessId: string): Promise<void> {
    try {
      if (this.env.ANALYTICS) {
        await this.env.ANALYTICS.writeDataPoint({
          blobs: [
            businessId,
            enrichedLead.id,
            'enrichment_completed'
          ],
          doubles: [
            enrichedLead.enrichment_data.ai_insights.icp_fit_score,
            enrichedLead.enrichment_data.ai_insights.buying_intent_score,
            enrichedLead.enrichment_data.enrichment_metadata.cost.total_cost
          ],
          indexes: [
            enrichedLead.source,
            enrichedLead.status
          ]
        });
      }
    } catch (error: any) {
    }
  }

  private calculateNextEnrichmentDate(enrichedLead: any): Date | null {
    const insights = enrichedLead.enrichment_data.ai_insights;

    // High-value leads get more frequent enrichment
    if (insights.icp_fit_score > 80) {
      const nextDate = new Date();
      nextDate.setDate(nextDate.getDate() + 3); // Every 3 days
      return nextDate;
    } else if (insights.icp_fit_score > 60) {
      const nextDate = new Date();
      nextDate.setDate(nextDate.getDate() + 7); // Weekly
      return nextDate;
    } else if (insights.icp_fit_score > 40) {
      const nextDate = new Date();
      nextDate.setMonth(nextDate.getMonth() + 1); // Monthly
      return nextDate;
    }

    return null; // No follow-up for low-score leads
  }

  private convertWebhookToEnrichmentRequest(webhookData: any, trigger: string): EnrichmentRequest {
    // Convert various webhook formats to enrichment request
    switch (trigger) {
      case 'salesforce':
        return {
          email: webhookData.Email,
          company_name: webhookData.Company,
          sources: ['clearbit', 'apollo'],
          priority: 'medium'
        };

      case 'hubspot':
        return {
          email: webhookData.properties?.email?.value,
          company_name: webhookData.properties?.company?.value,
          domain: webhookData.properties?.website?.value,
          sources: ['clearbit', 'news'],
          priority: 'medium'
        };

      default:
        return {
          email: webhookData.email,
          company_name: webhookData.company,
          domain: webhookData.domain,
          sources: this.getDefaultSources(),
          priority: 'medium'
        };
    }
  }

  private async sendWebhookResponse(webhookData: any, enrichedLead: any): Promise<void> {
    // Send enriched data back to source system
    if (webhookData.response_url) {
      try {
        await fetch(webhookData.response_url, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            lead_id: enrichedLead.id,
            enrichment_data: enrichedLead.enrichment_data,
            timestamp: new Date().toISOString()
          })
        });
      } catch (error: any) {
      }
    }
  }

  private getDefaultSources(): EnrichmentSource[] {
    return ['clearbit', 'apollo', 'news'];
  }

  private getEnrichmentConfig(env: Env): EnrichmentConfig {
    return {
      sources: {
        clearbit: {
          api_key: env.CLEARBIT_API_KEY || '',
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
          api_key: env.APOLLO_API_KEY || '',
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
          username: env.LINKEDIN_USERNAME || '',
          password: env.LINKEDIN_PASSWORD || '',
          proxy_endpoints: [],
          rate_limits: {
            requests_per_hour: 100
          }
        },
        hunter: {
          api_key: env.HUNTER_API_KEY || '',
          endpoints: {
            email_finder: 'https://api.hunter.io/v2/email-finder',
            email_verifier: 'https://api.hunter.io/v2/email-verifier',
            domain_search: 'https://api.hunter.io/v2/domain-search'
          }
        },
        news: {
          google_news_api_key: env.GOOGLE_NEWS_API_KEY || '',
          newsapi_key: env.NEWSAPI_KEY || '',
          serpapi_key: env.SERPAPI_KEY || ''
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
          clearbit: 86400,
          apollo: 86400,
          linkedin: 43200,
          hunter: 86400,
          zoominfo: 86400,
          news: 3600,
          social: 43200,
          github: 86400,
          crunchbase: 86400
        },
        cache_prefix: 'enrichment:'
      },
      processing: {
        max_concurrent_requests: 5, // Lower for background jobs
        timeout_ms: 60000, // Longer timeout for background processing
        retry_attempts: 3,
        batch_size: 5
      }
    };
  }

  private generateJobId(): string {
    return 'enrich_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
  }
}

// Export for Cloudflare Workers
export default {
  async queue(batch: MessageBatch<EnrichmentJob>, env: Env): Promise<void> {
    const worker = new EnrichmentWorker(env);

    for (const message of batch.messages) {
      try {
        const job = message.body;
        const result = await worker.processJob(job);


        // Store job result
        await env.KV_CACHE.put(
          `enrichment_result:${job.id}`,
          JSON.stringify(result),
          { expirationTtl: 86400 } // 24 hours
        );

        message.ack();
      } catch (error: any) {

        const job = message.body;
        if (job.retry_count < job.max_retries) {
          // Retry with exponential backoff
          const delay = Math.pow(2, job.retry_count) * 1000;
          setTimeout(() => message.retry(), delay);
        } else {
          message.ack(); // Don't retry forever
        }
      }
    }
  }
};