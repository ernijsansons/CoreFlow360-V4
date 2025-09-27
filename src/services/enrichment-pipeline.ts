import { ClearbitService } from './data-sources/clearbit-service';
import { ApolloService } from './data-sources/apollo-service';
import { NewsService } from './data-sources/news-service';
import { AIEnrichmentEngine } from './ai-enrichment-engine';
import { CRMService } from './crm-service';
import type { Env } from '../types/env';
import type {
  EnrichmentRequest,
  EnrichedLead,
  EnrichmentResult,
  BulkEnrichmentResult,
  EnrichmentMetadata,
  EnrichmentConfig,
  CompanyEnrichment,
  ContactEnrichment,
  NewsEnrichment,
  SocialEnrichment,
  AIInsights,
  EnrichmentSource,
  RateLimit,
  EnrichmentError
} from '../types/enrichment';
import type { Lead, Contact, Company } from '../types/crm';

export class EnrichmentPipeline {
  private clearbitService: ClearbitService;
  private apolloService: ApolloService;
  private newsService: NewsService;
  private aiEngine: AIEnrichmentEngine;
  private crmService: CRMService;
  private env: Env;
  private config: EnrichmentConfig;

  constructor(env: Env, config: EnrichmentConfig) {
    this.env = env;
    this.config = config;

    // Initialize data source services
    this.clearbitService = new ClearbitService(config.sources.clearbit.api_key);
    this.apolloService = new ApolloService(config.sources.apollo.api_key);
    this.newsService = new NewsService({
      newsApiKey: config.sources.news.newsapi_key,
      googleApiKey: config.sources.news.google_news_api_key,
      serpApiKey: config.sources.news.serpapi_key
    });

    // Initialize AI engine and CRM service
    this.aiEngine = new AIEnrichmentEngine(env);
    this.crmService = new CRMService(env);
  }

  async enrichLead(request: EnrichmentRequest): Promise<EnrichmentResult> {
    const startTime = Date.now();
    const metadata: Partial<EnrichmentMetadata> = {
      enriched_at: new Date().toISOString(),
      sources_used: request.sources,
      data_freshness: {},
      confidence_scores: {},
      cost: { total_cost: 0, cost_by_source: {} },
      rate_limits: {},
      errors: []
    };

    try {
      // Get base lead data
      const lead = await this.getLeadData(request);
      if (!lead) {
        return {
          success: false,
          error: 'Lead not found',
          enrichment_metadata: metadata as EnrichmentMetadata
        };
      }

      // Parallel enrichment from multiple sources
      const enrichmentResults = await this.performParallelEnrichment(request, metadata);

      // AI analysis of enriched data
      const aiInsights = await this.aiEngine.analyzeEnrichmentData({
        lead,
        company: enrichmentResults.company,
        contact: enrichmentResults.contact,
        news: enrichmentResults.news,
        social: enrichmentResults.social
      });

      // Create enriched lead
      const enrichedLead: EnrichedLead = {
        ...lead,
        enrichment_data: {
          company: enrichmentResults.company || {} as CompanyEnrichment,
          contact: enrichmentResults.contact || {} as ContactEnrichment,
          social: enrichmentResults.social || {} as SocialEnrichment,
          news: enrichmentResults.news || {} as NewsEnrichment,
          ai_insights: aiInsights,
          enrichment_metadata: {
            ...metadata,
            processing_time_ms: Date.now() - startTime
          } as EnrichmentMetadata
        }
      };

      // Update CRM with enriched data
      await this.updateCRM(enrichedLead);

      // Schedule follow-up enrichment if needed
      await this.scheduleFollowUpEnrichment(enrichedLead);

      return {
        success: true,
        enriched_lead: enrichedLead,
        enrichment_metadata: enrichedLead.enrichment_data.enrichment_metadata
      };
    } catch (error: any) {
      const errorMsg = error instanceof Error ? error.message : 'Unknown error';
      metadata.errors?.push({
        source: 'pipeline',
        error_type: 'service_error',
        message: errorMsg,
        timestamp: new Date().toISOString()
      });

      return {
        success: false,
        error: errorMsg,
        enrichment_metadata: {
          ...metadata,
          processing_time_ms: Date.now() - startTime
        } as EnrichmentMetadata
      };
    }
  }

  async bulkEnrichLeads(requests: EnrichmentRequest[]): Promise<BulkEnrichmentResult> {
    const startTime = Date.now();
    const results: EnrichmentResult[] = [];
    let totalCost = 0;
    let successful = 0;
    let failed = 0;

    // Process in batches to respect rate limits
    const batchSize = this.config.processing.batch_size || 10;
    const batches = this.chunkArray(requests, batchSize);

    for (const batch of batches) {
      const batchPromises = batch.map((request: any) =>
        this.enrichLead(request).catch((error: any) => ({
          success: false,
          error: error.message,
          enrichment_metadata: {
            enriched_at: new Date().toISOString(),
            sources_used: [],
            data_freshness: {},
            confidence_scores: {},
            processing_time_ms: 0,
            cost: { total_cost: 0, cost_by_source: {} },
            rate_limits: {},
            errors: []
          }
        }))
      );

      const batchResults = await Promise.all(batchPromises);
      results.push(...batchResults);

      // Calculate metrics
      batchResults.forEach((result: any) => {
        if (result.success) {
          successful++;
        } else {
          failed++;
        }
        totalCost += result.enrichment_metadata.cost.total_cost;
      });

      // Rate limiting between batches
      if (batches.indexOf(batch) < batches.length - 1) {
        await this.delay(1000); // 1 second between batches
      }
    }

    return {
      total_processed: requests.length,
      successful,
      failed,
      results,
      total_cost: totalCost,
      processing_time_ms: Date.now() - startTime
    };
  }

  private async performParallelEnrichment(
    request: EnrichmentRequest,
    metadata: Partial<EnrichmentMetadata>
  ): Promise<{
    company?: CompanyEnrichment;
    contact?: ContactEnrichment;
    news?: NewsEnrichment;
    social?: SocialEnrichment;
  }> {
    const promises: Promise<any>[] = [];
    const results: any = {};

    // Check cache first
    const cacheKey = this.generateCacheKey(request);
    const cached = await this.getFromCache(cacheKey);
    if (cached && !request.force_refresh) {
      return cached;
    }

    // Company enrichment
    if (request.sources.includes('clearbit') && (request.domain || request.company_name)) {
      promises.push(
        this.enrichWithClearbitCompany(request.domain!, metadata)
          .then(result => { results.clearbitCompany = result; })
          .catch((error: any) => this.handleEnrichmentError('clearbit', error, metadata))
      );
    }

    if (request.sources.includes('apollo') && (request.domain || request.company_name)) {
      promises.push(
        this.enrichWithApollo(request.domain!, metadata)
          .then(result => { results.apolloCompany = result; })
          .catch((error: any) => this.handleEnrichmentError('apollo', error, metadata))
      );
    }

    // Contact enrichment
    if (request.sources.includes('clearbit') && request.email) {
      promises.push(
        this.enrichWithClearbitPerson(request.email, metadata)
          .then(result => { results.clearbitPerson = result; })
          .catch((error: any) => this.handleEnrichmentError('clearbit', error, metadata))
      );
    }

    // News enrichment
    if (request.sources.includes('news') && (request.company_name || request.domain)) {
      promises.push(
        this.enrichWithNews(request.company_name || request.domain!, metadata)
          .then(result => { results.news = result; })
          .catch((error: any) => this.handleEnrichmentError('news', error, metadata))
      );
    }

    // Social enrichment
    if (request.sources.includes('linkedin') && request.linkedin_url) {
      promises.push(
        this.enrichWithLinkedIn(request.linkedin_url, metadata)
          .then(result => { results.social = result; })
          .catch((error: any) => this.handleEnrichmentError('linkedin', error, metadata))
      );
    }

    // Wait for all enrichments to complete
    await Promise.allSettled(promises);

    // Merge results
    const merged = this.mergeEnrichmentResults(results);

    // Cache results
    await this.saveToCache(cacheKey, merged);

    return merged;
  }

  private async enrichWithClearbitCompany(
    domain: string,
    metadata: Partial<EnrichmentMetadata>
  ): Promise<{ company: CompanyEnrichment | null; rateLimit: RateLimit }> {
    const result = await this.clearbitService.enrichCompany(domain);

    metadata.rate_limits!['clearbit'] = result.rateLimit;
    metadata.cost!.cost_by_source!['clearbit'] = result.rateLimit.cost_per_request;
    metadata.cost!.total_cost += result.rateLimit.cost_per_request;

    if (result.error) {
      throw new Error(`Clearbit company enrichment failed: ${result.error}`);
    }

    return result;
  }

  private async enrichWithClearbitPerson(
    email: string,
    metadata: Partial<EnrichmentMetadata>
  ): Promise<{ contact: ContactEnrichment | null; company: CompanyEnrichment | null; rateLimit: RateLimit }> {
    const result = await this.clearbitService.enrichPerson(email);

    metadata.rate_limits!['clearbit'] = result.rateLimit;
    metadata.cost!.cost_by_source!['clearbit'] =
      (metadata.cost!.cost_by_source!['clearbit'] || 0) + result.rateLimit.cost_per_request;
    metadata.cost!.total_cost += result.rateLimit.cost_per_request;

    if (result.error) {
      throw new Error(`Clearbit person enrichment failed: ${result.error}`);
    }

    return result;
  }

  private async enrichWithApollo(
    domain: string,
    metadata: Partial<EnrichmentMetadata>
  ): Promise<{ company: CompanyEnrichment | null; rateLimit: RateLimit }> {
    const result = await this.apolloService.enrichCompany(domain);

    metadata.rate_limits!['apollo'] = result.rateLimit;
    metadata.cost!.cost_by_source!['apollo'] = result.rateLimit.cost_per_request;
    metadata.cost!.total_cost += result.rateLimit.cost_per_request;

    if (result.error) {
      throw new Error(`Apollo enrichment failed: ${result.error}`);
    }

    return result;
  }

  private async enrichWithNews(
    companyName: string,
    metadata: Partial<EnrichmentMetadata>
  ): Promise<{ news: NewsEnrichment | null }> {
    const result = await this.newsService.enrichWithNews(companyName);

    metadata.cost!.cost_by_source!['news'] = 0.1; // News APIs are typically cheaper
    metadata.cost!.total_cost += 0.1;

    if (result.error) {
      throw new Error(`News enrichment failed: ${result.error}`);
    }

    return result;
  }

  private async enrichWithLinkedIn(
    linkedinUrl: string,
    metadata: Partial<EnrichmentMetadata>
  ): Promise<{ social: SocialEnrichment | null }> {
    // LinkedIn scraping would be implemented here
    // For now, return placeholder
    return { social: null };
  }

  private mergeEnrichmentResults(results: any): {
    company?: CompanyEnrichment;
    contact?: ContactEnrichment;
    news?: NewsEnrichment;
    social?: SocialEnrichment;
  } {
    const merged: any = {};

    // Merge company data (Clearbit takes priority)
    if (results.clearbitCompany?.company || results.apolloCompany?.company) {
      merged.company = {
        ...results.apolloCompany?.company,
        ...results.clearbitCompany?.company // Clearbit overwrites Apollo
      };
    }

    // Contact data (primarily from Clearbit)
    if (results.clearbitPerson?.contact) {
      merged.contact = results.clearbitPerson.contact;
    }

    // News data
    if (results.news?.news) {
      merged.news = results.news.news;
    }

    // Social data
    if (results.social?.social) {
      merged.social = results.social.social;
    }

    return merged;
  }

  private async getLeadData(request: EnrichmentRequest): Promise<Lead | null> {
    if (request.lead_id) {
      // Get lead from CRM
      // This would call the CRM service to get lead data
      return null; // Placeholder
    }

    // Create lead from provided data
    return {
      id: 'temp-lead-id',
      business_id: 'business-id',
      source: 'enrichment',
      status: 'new',
      assigned_type: 'ai',
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      email: request.email,
      company_name: request.company_name
    } as Lead;
  }

  private async updateCRM(enrichedLead: EnrichedLead): Promise<void> {
    try {
      // Update company data
      if (enrichedLead.enrichment_data.company && enrichedLead.company_id) {
        const companyData = enrichedLead.enrichment_data.company;
        // Update company in CRM with enriched data
      }

      // Update contact data
      if (enrichedLead.enrichment_data.contact && enrichedLead.contact_id) {
        const contactData = enrichedLead.enrichment_data.contact;
        // Update contact in CRM with enriched data
      }

      // Update lead with AI insights
      if (enrichedLead.enrichment_data.ai_insights) {
        // Update lead qualification score and next actions
      }
    } catch (error: any) {
    }
  }

  private async scheduleFollowUpEnrichment(enrichedLead: EnrichedLead): Promise<void> {
    // Schedule periodic re-enrichment for high-value leads
    if (enrichedLead.enrichment_data.ai_insights.icp_fit_score > 80) {
      // Schedule weekly enrichment
      const nextEnrichment = new Date();
      nextEnrichment.setDate(nextEnrichment.getDate() + 7);

      // Queue background job for re-enrichment
      if (this.env.TASK_QUEUE) {
        await this.env.TASK_QUEUE.send({
          type: 'lead_enrichment',
          lead_id: enrichedLead.id,
          scheduled_at: nextEnrichment.toISOString(),
          priority: 'medium'
        });
      }
    }
  }

  private handleEnrichmentError(
    source: EnrichmentSource,
    error: any,
    metadata: Partial<EnrichmentMetadata>
  ): void {
    const enrichmentError: EnrichmentError = {
      source,
      error_type: 'service_error',
      message: error.message || 'Unknown error',
      timestamp: new Date().toISOString()
    };

    if (error.message?.includes('rate limit')) {
      enrichmentError.error_type = 'rate_limit';
      enrichmentError.retry_after = '3600'; // 1 hour
    }

    metadata.errors = metadata.errors || [];
    metadata.errors.push(enrichmentError);
  }

  private generateCacheKey(request: EnrichmentRequest): string {
    const keyParts = [
      request.email || '',
      request.domain || '',
      request.company_name || '',
      request.sources.sort().join(',')
    ];
    return 'enrichment:' + btoa(keyParts.join('|'));
  }

  private async getFromCache(key: string): Promise<any | null> {
    try {
      const cached = await this.env.KV_CACHE.get(key);
      return cached ? JSON.parse(cached) : null;
    } catch (error: any) {
      return null;
    }
  }

  private async saveToCache(key: string, data: any): Promise<void> {
    try {
      const ttl = 86400; // 24 hours
      await this.env.KV_CACHE.put(key, JSON.stringify(data), { expirationTtl: ttl });
    } catch (error: any) {
    }
  }

  private chunkArray<T>(array: T[], size: number): T[][] {
    const chunks: T[][] = [];
    for (let i = 0; i < array.length; i += size) {
      chunks.push(array.slice(i, i + size));
    }
    return chunks;
  }

  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  // Public utility methods
  async validateEnrichmentSources(sources: EnrichmentSource[]): Promise<{
    valid: boolean;
    available_sources: EnrichmentSource[];
    unavailable_sources: EnrichmentSource[];
    errors: string[];
  }> {
    const available: EnrichmentSource[] = [];
    const unavailable: EnrichmentSource[] = [];
    const errors: string[] = [];

    for (const source of sources) {
      try {
        switch (source) {
          case 'clearbit':
            if (this.config.sources.clearbit.api_key) {
              available.push(source);
            } else {
              unavailable.push(source);
              errors.push('Clearbit API key not configured');
            }
            break;
          case 'apollo':
            if (this.config.sources.apollo.api_key) {
              available.push(source);
            } else {
              unavailable.push(source);
              errors.push('Apollo API key not configured');
            }
            break;
          case 'news':
            if (this.config.sources.news.newsapi_key) {
              available.push(source);
            } else {
              unavailable.push(source);
              errors.push('News API key not configured');
            }
            break;
          default:
            unavailable.push(source);
            errors.push(`Unknown source: ${source}`);
        }
      } catch (error: any) {
        unavailable.push(source);
        errors.push(`Error validating ${source}: ${error}`);
      }
    }

    return {
      valid: unavailable.length === 0,
      available_sources: available,
      unavailable_sources: unavailable,
      errors
    };
  }

  async getEnrichmentCost(request: EnrichmentRequest): Promise<{
    estimated_cost: number;
    cost_breakdown: Record<EnrichmentSource, number>;
  }> {
    const costBreakdown: Record<string, number> = {};
    let totalCost = 0;

    for (const source of request.sources) {
      let cost = 0;
      switch (source) {
        case 'clearbit':
          cost = 2; // $2 per enrichment
          break;
        case 'apollo':
          cost = 1; // $1 per enrichment
          break;
        case 'news':
          cost = 0.1; // $0.10 per enrichment
          break;
        default:
          cost = 0.5; // Default cost
      }
      costBreakdown[source] = cost;
      totalCost += cost;
    }

    return {
      estimated_cost: totalCost,
      cost_breakdown: costBreakdown as Record<EnrichmentSource, number>
    };
  }
}