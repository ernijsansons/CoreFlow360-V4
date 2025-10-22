/**
 * CRM Data Enrichment Service
 * Multi-source data enrichment with cost tracking and quality scoring
 * Part of Phase 1 Sprint 1 - Feature #2
 */

import type { Env } from '../../types/env';import { Logger } from "../../shared/logger";
const logger = new Logger({ component: "services-crm-enrichmentservice" });



export interface EnrichmentSource {
  name: 'apollo' | 'clearbit' | 'hunter' | 'peopledatalabs' | 'zoominfo' | 'linkedin_api' | 'crunchbase' | 'fullcontact';
  priority: number;
  costPerContact: number;
}

export interface EnrichmentResult {
  success: boolean;
  source: string;
  fieldsUpdated: string[];
  fieldsAdded: string[];
  confidenceScore: number;
  completenessImprovement: number;
  cost: number;
  error?: string;
}

export interface ContactData {
  email?: string;
  first_name?: string;
  last_name?: string;
  job_title?: string;
  company_name?: string;
  company_domain?: string;
  phone?: string;
  linkedin_url?: string;
  twitter_handle?: string;
  location?: string;
  seniority_level?: string;
  department?: string;
}

export class EnrichmentService {
  private sources: EnrichmentSource[] = [
    { name: 'apollo', priority: 1, costPerContact: 0.10 },
    { name: 'hunter', priority: 2, costPerContact: 0.10 },
    { name: 'peopledatalabs', priority: 3, costPerContact: 0.15 },
    { name: 'clearbit', priority: 4, costPerContact: 0.25 },
    { name: 'zoominfo', priority: 5, costPerContact: 0.50 },
  ];

  constructor(private env: Env) {}

  /**
   * Enrich a contact with data from multiple sources
   */
  async enrichContact(
    businessId: string,
    contactId: string,
    preferredSources?: string[]
  ): Promise<EnrichmentResult> {
    try {
      // Get current contact data
      const contact = await this.env.DB_MAIN.prepare(
        'SELECT * FROM crm_contacts WHERE id = ? AND business_id = ?'
      ).bind(contactId, businessId).first() as any;

      if (!contact) {
        throw new Error('Contact not found');
      }

      // Calculate current completeness
      const completenessBefore = this.calculateCompleteness(contact);

      // Determine which sources to try
      const sourcesToTry = preferredSources || this.sources.map(s => s.name);

      // Try each source in priority order until we get data
      let enrichmentResult: EnrichmentResult | null = null;

      for (const sourceName of sourcesToTry) {
        const source = this.sources.find(s => s.name === sourceName);
        if (!source) continue;

        try {
          // Check if we have credentials for this source
          const credentials = await this.getSourceCredentials(businessId, source.name);
          if (!credentials) {
            logger.info(`No credentials for ${source.name}, skipping`);
            continue;
          }

          // Enrich from source
          const data = await this.enrichFromSource(source.name, contact, credentials);

          if (data) {
            // Update contact with enriched data
            const updateResult = await this.updateContact(contactId, contact, data);

            // Calculate new completeness
            const updatedContact = { ...contact, ...data };
            const completenessAfter = this.calculateCompleteness(updatedContact);

            enrichmentResult = {
              success: true,
              source: source.name,
              fieldsUpdated: updateResult.fieldsUpdated,
              fieldsAdded: updateResult.fieldsAdded,
              confidenceScore: 0.85, // Default confidence
              completenessImprovement: completenessAfter - completenessBefore,
              cost: source.costPerContact,
            };

            // Log enrichment history
            await this.logEnrichment(
              businessId,
              contactId,
              'contact',
              source.name,
              enrichmentResult,
              completenessBefore,
              completenessAfter
            );

            // Update data completeness score
            await this.updateCompletenessScore(
              businessId,
              contactId,
              'contact',
              completenessAfter
            );

            break; // Success, stop trying other sources
          }
        } catch (error) {
          logger.error(`Enrichment from ${source.name} failed:`, error);
          continue; // Try next source
        }
      }

      if (!enrichmentResult) {
        return {
          success: false,
          source: 'none',
          fieldsUpdated: [],
          fieldsAdded: [],
          confidenceScore: 0,
          completenessImprovement: 0,
          cost: 0,
          error: 'All enrichment sources failed or no data found',
        };
      }

      return enrichmentResult;
    } catch (error: any) {
      logger.error('Enrichment error:', error);
      throw error;
    }
  }

  /**
   * Enrich contact from specific source
   */
  private async enrichFromSource(
    source: string,
    contact: any,
    credentials: any
  ): Promise<ContactData | null> {
    switch (source) {
      case 'apollo':
        return this.enrichFromApollo(contact, credentials);
      case 'clearbit':
        return this.enrichFromClearbit(contact, credentials);
      case 'hunter':
        return this.enrichFromHunter(contact, credentials);
      case 'peopledatalabs':
        return this.enrichFromPeopleDataLabs(contact, credentials);
      case 'zoominfo':
        return this.enrichFromZoomInfo(contact, credentials);
      default:
        return null;
    }
  }

  /**
   * Clearbit Enrichment API
   */
  private async enrichFromClearbit(contact: any, credentials: any): Promise<ContactData | null> {
    try {
      const email = contact.email;
      if (!email) return null;

      const response = await fetch(
        `https://person.clearbit.com/v2/people/find?email=${encodeURIComponent(email)}`,
        {
          headers: {
            'Authorization': `Bearer ${credentials.api_key}`,
          },
        }
      );

      if (!response.ok) {
        if (response.status === 404) return null; // Not found is okay
        throw new Error(`Clearbit API error: ${response.status}`);
      }

      const data = await response.json() as any;

      return {
        first_name: data.name?.givenName,
        last_name: data.name?.familyName,
        job_title: data.employment?.title,
        company_name: data.employment?.name,
        company_domain: data.employment?.domain,
        linkedin_url: data.linkedin?.handle ? `https://linkedin.com/in/${data.linkedin.handle}` : undefined,
        twitter_handle: data.twitter?.handle,
        location: data.geo?.city,
        seniority_level: this.mapClearbitSeniority(data.employment?.seniority),
      };
    } catch (error) {
      logger.error('Clearbit enrichment error:', error);
      return null;
    }
  }

  /**
   * Apollo.io Contact & Company Enrichment
   */
  private async enrichFromApollo(contact: any, credentials: any): Promise<ContactData | null> {
    try {
      const email = contact.email;
      const company_domain = contact.company_domain;

      if (!email && !company_domain) return null;

      // Apollo Person Enrichment API
      const payload: any = {};
      if (email) payload.email = email;
      if (contact.first_name) payload.first_name = contact.first_name;
      if (contact.last_name) payload.last_name = contact.last_name;
      if (company_domain) payload.organization_name = company_domain;

      const response = await fetch(
        'https://api.apollo.io/v1/people/match',
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Cache-Control': 'no-cache',
            'X-Api-Key': credentials.api_key,
          },
          body: JSON.stringify(payload),
        }
      );

      if (!response.ok) {
        if (response.status === 404) return null;
        throw new Error(`Apollo.io API error: ${response.status}`);
      }

      const data = await response.json() as any;
      const person = data.person;

      if (!person) return null;

      return {
        first_name: person.first_name,
        last_name: person.last_name,
        job_title: person.title,
        company_name: person.organization?.name,
        company_domain: person.organization?.website_url,
        email: person.email || contact.email,
        phone: person.phone_numbers?.[0]?.sanitized_number,
        linkedin_url: person.linkedin_url,
        twitter_handle: person.twitter_url,
        location: person.city && person.state ? `${person.city}, ${person.state}` : person.city,
        seniority_level: this.mapApolloSeniority(person.seniority),
        department: person.departments?.[0],
      };
    } catch (error) {
      logger.error('Apollo enrichment error:', error);
      return null;
    }
  }

  /**
   * Hunter.io Email Verification & Enrichment
   */
  private async enrichFromHunter(contact: any, credentials: any): Promise<ContactData | null> {
    try {
      const email = contact.email;
      if (!email) return null;

      const response = await fetch(
        `https://api.hunter.io/v2/email-verifier?email=${encodeURIComponent(email)}&api_key=${credentials.api_key}`
      );

      if (!response.ok) {
        throw new Error(`Hunter.io API error: ${response.status}`);
      }

      const result = await response.json() as any;
      const data = result.data;

      // Hunter mainly validates emails, but provides some extra data
      return {
        first_name: data.first_name,
        last_name: data.last_name,
        company_name: data.organization,
      };
    } catch (error) {
      logger.error('Hunter enrichment error:', error);
      return null;
    }
  }

  /**
   * PeopleDataLabs Enrichment API
   */
  private async enrichFromPeopleDataLabs(contact: any, credentials: any): Promise<ContactData | null> {
    try {
      const params = new URLSearchParams();
      if (contact.email) params.append('email', contact.email);
      if (contact.linkedin_url) params.append('profile', contact.linkedin_url);

      if (params.toString().length === 0) return null;

      const response = await fetch(
        `https://api.peopledatalabs.com/v5/person/enrich?${params.toString()}`,
        {
          headers: {
            'X-Api-Key': credentials.api_key,
          },
        }
      );

      if (!response.ok) {
        if (response.status === 404) return null;
        throw new Error(`PeopleDataLabs API error: ${response.status}`);
      }

      const data = await response.json() as any;

      return {
        first_name: data.first_name,
        last_name: data.last_name,
        job_title: data.job_title,
        company_name: data.job_company_name,
        linkedin_url: data.linkedin_url,
        twitter_handle: data.twitter_url,
        phone: data.phone_numbers?.[0],
        location: data.location_name,
        seniority_level: this.mapPDLSeniority(data.job_title_levels?.[0]),
      };
    } catch (error) {
      logger.error('PeopleDataLabs enrichment error:', error);
      return null;
    }
  }

  /**
   * ZoomInfo Enrichment API
   */
  private async enrichFromZoomInfo(_contact: any, _credentials: any): Promise<ContactData | null> {
    // ZoomInfo requires enterprise contract - placeholder for now
    logger.info('ZoomInfo enrichment not yet implemented');
    return null;
  }

  /**
   * Update contact with enriched data
   */
  private async updateContact(
    contactId: string,
    currentData: any,
    newData: ContactData
  ): Promise<{ fieldsUpdated: string[]; fieldsAdded: string[] }> {
    const fieldsUpdated: string[] = [];
    const fieldsAdded: string[] = [];

    const updates: Record<string, any> = {};

    // Check each field
    for (const [key, value] of Object.entries(newData)) {
      if (value !== undefined && value !== null && value !== '') {
        if (currentData[key] && currentData[key] !== value) {
          fieldsUpdated.push(key);
          updates[key] = value;
        } else if (!currentData[key]) {
          fieldsAdded.push(key);
          updates[key] = value;
        }
      }
    }

    if (Object.keys(updates).length === 0) {
      return { fieldsUpdated: [], fieldsAdded: [] };
    }

    // Build UPDATE query
    const setClause = Object.keys(updates).map(key => `${key} = ?`).join(', ');
    const values = Object.values(updates);

    await this.env.DB_MAIN.prepare(
      `UPDATE crm_contacts SET ${setClause}, updated_at = ? WHERE id = ?`
    ).bind(...values, new Date().toISOString(), contactId).run();

    return { fieldsUpdated, fieldsAdded };
  }

  /**
   * Calculate data completeness score (0-100)
   */
  private calculateCompleteness(contact: any): number {
    const criticalFields = [
      'email',
      'first_name',
      'last_name',
      'job_title',
      'company_id',
      'phone',
      'linkedin_url',
      'location',
      'seniority_level',
      'department',
    ];

    const filledFields = criticalFields.filter(field => {
      const value = contact[field];
      return value !== null && value !== undefined && value !== '';
    });

    return Math.round((filledFields.length / criticalFields.length) * 100);
  }

  /**
   * Log enrichment to history table
   */
  private async logEnrichment(
    businessId: string,
    entityId: string,
    entityType: string,
    source: string,
    result: EnrichmentResult,
    completenessBefore: number,
    completenessAfter: number
  ): Promise<void> {
    const id = crypto.randomUUID().replace(/-/g, '');
    const now = new Date().toISOString();

    await this.env.DB_MAIN.prepare(`
      INSERT INTO crm_enrichment_history (
        id, business_id, entity_id, entity_type, data_source,
        fields_updated, fields_added, confidence_score,
        completeness_before, completeness_after, fields_improved,
        status, cost_usd, api_credits_used, enriched_at, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      id,
      businessId,
      entityId,
      entityType,
      source,
      JSON.stringify(result.fieldsUpdated),
      JSON.stringify(result.fieldsAdded),
      result.confidenceScore,
      completenessBefore,
      completenessAfter,
      result.fieldsUpdated.length + result.fieldsAdded.length,
      result.success ? 'success' : 'failed',
      result.cost,
      1,
      now,
      now
    ).run();
  }

  /**
   * Update data completeness score
   */
  private async updateCompletenessScore(
    businessId: string,
    entityId: string,
    entityType: string,
    score: number
  ): Promise<void> {
    const now = new Date().toISOString();

    await this.env.DB_MAIN.prepare(`
      INSERT OR REPLACE INTO crm_data_completeness (
        business_id, entity_id, entity_type, total_fields, filled_fields,
        quality_score, last_enriched_at, data_staleness_days, needs_refresh,
        calculated_at, updated_at
      ) VALUES (?, ?, ?, 10, ?, ?, ?, 0, 0, ?, ?)
    `).bind(
      businessId,
      entityId,
      entityType,
      Math.round((score / 100) * 10),
      score,
      now,
      now,
      now
    ).run();
  }

  /**
   * Get source credentials
   */
  private async getSourceCredentials(businessId: string, source: string): Promise<any> {
    const creds = await this.env.DB_MAIN.prepare(`
      SELECT * FROM crm_enrichment_credentials
      WHERE business_id = ? AND data_source = ? AND status = 'active'
    `).bind(businessId, source).first();

    return creds || null;
  }

  /**
   * Queue contact for enrichment
   */
  async queueEnrichment(
    businessId: string,
    entityId: string,
    entityType: 'contact' | 'company' | 'lead',
    priority: number = 50,
    triggeredBy: string = 'manual'
  ): Promise<void> {
    const id = crypto.randomUUID().replace(/-/g, '');
    const now = new Date().toISOString();

    await this.env.DB_MAIN.prepare(`
      INSERT INTO crm_enrichment_queue (
        id, business_id, entity_id, entity_type, priority,
        scheduled_for, triggered_by, status, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)
    `).bind(
      id,
      businessId,
      entityId,
      entityType,
      priority,
      now,
      triggeredBy,
      now,
      now
    ).run();
  }

  /**
   * Process enrichment queue (called by cron job)
   */
  async processQueue(batchSize: number = 10): Promise<number> {
    // Get pending items from queue
    const items = await this.env.DB_MAIN.prepare(`
      SELECT * FROM crm_enrichment_queue
      WHERE status = 'pending'
        AND scheduled_for <= datetime('now')
      ORDER BY priority DESC, created_at ASC
      LIMIT ?
    `).bind(batchSize).all();

    if (!items.results || items.results.length === 0) {
      return 0;
    }

    let processed = 0;

    for (const item of items.results as any[]) {
      try {
        // Mark as processing
        await this.env.DB_MAIN.prepare(`
          UPDATE crm_enrichment_queue
          SET status = 'processing', started_at = ?, updated_at = ?
          WHERE id = ?
        `).bind(new Date().toISOString(), new Date().toISOString(), item.id).run();

        // Enrich
        if (item.entity_type === 'contact') {
          await this.enrichContact(item.business_id, item.entity_id);
        }

        // Mark as completed
        await this.env.DB_MAIN.prepare(`
          UPDATE crm_enrichment_queue
          SET status = 'completed', completed_at = ?, updated_at = ?
          WHERE id = ?
        `).bind(new Date().toISOString(), new Date().toISOString(), item.id).run();

        processed++;
      } catch (error: any) {
        logger.error(`Failed to enrich ${item.entity_id}:`, error);

        // Mark as failed
        await this.env.DB_MAIN.prepare(`
          UPDATE crm_enrichment_queue
          SET status = 'failed', error_message = ?, updated_at = ?
          WHERE id = ?
        `).bind(error.message, new Date().toISOString(), item.id).run();
      }
    }

    return processed;
  }

  /**
   * Map Clearbit seniority to our levels
   */
  private mapClearbitSeniority(seniority?: string): string | undefined {
    const mapping: Record<string, string> = {
      'executive': 'c-level',
      'vp': 'vp',
      'director': 'director',
      'manager': 'manager',
      'individual': 'individual',
    };
    return seniority ? mapping[seniority.toLowerCase()] : undefined;
  }

  /**
   * Map PeopleDataLabs seniority to our levels
   */
  private mapPDLSeniority(level?: string): string | undefined {
    const mapping: Record<string, string> = {
      'c_suite': 'c-level',
      'owner': 'owner',
      'vp': 'vp',
      'director': 'director',
      'manager': 'manager',
      'senior': 'individual',
      'entry': 'individual',
    };
    return level ? mapping[level.toLowerCase()] : undefined;
  }

  /**
   * Map Apollo.io seniority to our levels
   */
  private mapApolloSeniority(seniority?: string): string | undefined {
    const mapping: Record<string, string> = {
      'c_suite': 'c-level',
      'founder': 'owner',
      'owner': 'owner',
      'partner': 'owner',
      'vp': 'vp',
      'director': 'director',
      'manager': 'manager',
      'senior': 'individual',
      'entry': 'individual',
      'individual_contributor': 'individual',
    };
    return seniority ? mapping[seniority.toLowerCase()] : undefined;
  }
}
