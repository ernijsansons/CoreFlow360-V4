import { BaseIntegration } from './base-integration';
import type { Env } from '../../types/env';
import type { Integration, SyncResult } from '../../types/integration';

// =====================================================
// META ADS INTEGRATION
// =====================================================

export class MetaAdsIntegration extends BaseIntegration {
  private baseUrl = 'https://graph.facebook.com/v18.0';

  async connect(): Promise<boolean> {
    try {
      const testUrl = `${this.baseUrl}/me?access_token=${this.integration.config.accessToken}`;
      const response = await this.makeApiRequest(testUrl);
      return response.id !== undefined;
    } catch (error: any) {
      return false;
    }
  }

  async disconnect(): Promise<void> {
    this.isConnected = false;
    await this.updateStatus('disconnected');
  }

  async testConnection(): Promise<boolean> {
    return await this.connect();
  }

  async sync(): Promise<SyncResult> {
    const startTime = new Date().toISOString();
    const errors: any[] = [];
    let recordsSynced = 0;
    let recordsFailed = 0;

    try {
      await this.updateStatus('syncing');

      // Sync leads from Meta
      const leads = await this.fetchMetaLeads();

      for (const lead of leads) {
        try {
          await this.syncLeadToCRM(lead);
          recordsSynced++;
        } catch (error: any) {
          errors.push(this.createSyncError(lead.id, error));
          recordsFailed++;
        }
      }

      await this.updateStatus('connected');
      await this.updateLastSync();

      return {
        integrationId: this.integration.id,
        status: errors.length === 0 ? 'success' : 'partial',
        recordsSynced,
        recordsFailed,
        errors,
        startTime,
        endTime: new Date().toISOString(),
        duration: Date.now() - new Date(startTime).getTime()
      };
    } catch (error: any) {
      await this.updateStatus('error');
      throw error;
    }
  }

  async syncInbound(): Promise<SyncResult> {
    return await this.sync();
  }

  async syncOutbound(): Promise<SyncResult> {
    // Push CRM data to Meta (custom audiences, conversions, etc.)
    const startTime = new Date().toISOString();

    try {
      await this.updateStatus('syncing');

      // Sync conversions to Meta
      const conversions = await this.getRecentConversions();
      await this.pushConversionsToMeta(conversions);

      // Update custom audiences
      const audiences = await this.getCustomAudiences();
      await this.updateMetaAudiences(audiences);

      await this.updateStatus('connected');

      return {
        integrationId: this.integration.id,
        status: 'success',
        recordsSynced: conversions.length + audiences.length,
        recordsFailed: 0,
        startTime,
        endTime: new Date().toISOString(),
        duration: Date.now() - new Date(startTime).getTime()
      };
    } catch (error: any) {
      await this.updateStatus('error');
      throw error;
    }
  }

  getWebhookUrl(): string {
    return `https://api.coreflow360.com/webhooks/meta/${this.integration.id}`;
  }

  private async fetchMetaLeads(): Promise<any[]> {
    const formId = this.integration.config.options?.formId;
    if (!formId) return [];

    const url = `${this.baseUrl}/${formId}/leads?access_token=${this.integration.config.accessToken}`;
    const response = await this.makeApiRequest(url);

    return response.data || [];
  }

  private async syncLeadToCRM(metaLead: any): Promise<void> {
    const mappedData = await this.applyFieldMappings(metaLead);

    const db = this.env.DB_CRM;
    await db.prepare(`
      INSERT OR REPLACE INTO leads (
        id, business_id, first_name, last_name, email, phone,
        source, source_id, metadata, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      `meta_${metaLead.id}`,
      this.integration.config.options?.businessId,
      mappedData.first_name,
      mappedData.last_name,
      mappedData.email,
      mappedData.phone,
      'meta_ads',
      metaLead.id,
      JSON.stringify(metaLead),
      metaLead.created_time || new Date().toISOString()
    ).run();
  }

  private async getRecentConversions(): Promise<any[]> {
    // Get conversions from CRM to push to Meta
    const db = this.env.DB_CRM;
    const conversions = await db.prepare(`
      SELECT * FROM opportunities
      WHERE status = 'closed_won'
        AND close_date >= datetime('now', '-7 days')
        AND metadata->>'$.synced_to_meta' IS NULL
    `).all();

    return conversions.results;
  }

  private async pushConversionsToMeta(conversions: any[]): Promise<void> {
    // Push conversion events to Meta Conversions API
    for (const conversion of conversions) {
      const event = {
        event_name: 'Purchase',
        event_time: Math.floor(new Date(conversion.close_date).getTime() / 1000),
        user_data: {
          em: conversion.email_hash, // Hashed email
          ph: conversion.phone_hash  // Hashed phone
        },
        custom_data: {
          currency: 'USD',
          value: conversion.value
        },
        event_source_url: 'https://coreflow360.com'
      };

      await this.makeApiRequest(
        `${this.baseUrl}/${this.integration.config.options?.pixelId}/events`,
        'POST',
        { data: [event] },
        { 'Authorization': `Bearer ${this.integration.config.accessToken}` }
      );
    }
  }

  private async getCustomAudiences(): Promise<any[]> {
    const db = this.env.DB_CRM;
    const segments = await db.prepare(`
      SELECT * FROM customer_segments
      WHERE active = 1
        AND metadata->>'$.sync_to_meta' = 'true'
    `).all();

    return segments.results;
  }

  private async updateMetaAudiences(audiences: any[]): Promise<void> {
    // Update custom audiences in Meta
    for (const audience of audiences) {
      const audienceId = audience.metadata?.meta_audience_id;
      if (!audienceId) continue;

      // Get leads for this segment
      const leads = await this.getLeadsForSegment(audience.id);

      // Update audience in Meta
      await this.makeApiRequest(
        `${this.baseUrl}/${audienceId}/users`,
        'POST',
        {
          schema: ['EMAIL', 'PHONE'],
          data: leads.map((l: any) => [l.email_hash, l.phone_hash])
        },
        { 'Authorization': `Bearer ${this.integration.config.accessToken}` }
      );
    }
  }

  private async getLeadsForSegment(segmentId: string): Promise<any[]> {
    const db = this.env.DB_CRM;
    const leads = await db.prepare(`
      SELECT * FROM leads
      WHERE segment_id = ?
        AND status = 'qualified'
    `).bind(segmentId).all();

    return leads.results;
  }
}

// =====================================================
// GOOGLE ADS INTEGRATION
// =====================================================

export class GoogleAdsIntegration extends BaseIntegration {
  private baseUrl = 'https://googleads.googleapis.com/v15';

  async connect(): Promise<boolean> {
    try {
      const headers = {
        'Authorization': `Bearer ${this.integration.config.accessToken}`,
        'developer-token': this.integration.config.options?.developerToken
      };

      const response = await this.makeApiRequest(
        `${this.baseUrl}/customers:listAccessibleCustomers`,
        'GET',
        null,
        headers
      );

      return response.resourceNames !== undefined;
    } catch (error: any) {
      return false;
    }
  }

  async disconnect(): Promise<void> {
    this.isConnected = false;
    await this.updateStatus('disconnected');
  }

  async testConnection(): Promise<boolean> {
    return await this.connect();
  }

  async sync(): Promise<SyncResult> {
    const startTime = new Date().toISOString();
    const errors: any[] = [];
    let recordsSynced = 0;
    let recordsFailed = 0;

    try {
      await this.updateStatus('syncing');

      // Sync leads from Google Ads
      const leads = await this.fetchGoogleAdsLeads();

      for (const lead of leads) {
        try {
          await this.syncLeadToCRM(lead);
          recordsSynced++;
        } catch (error: any) {
          errors.push(this.createSyncError(lead.resourceName, error));
          recordsFailed++;
        }
      }

      // Sync campaign performance
      await this.syncCampaignPerformance();

      await this.updateStatus('connected');
      await this.updateLastSync();

      return {
        integrationId: this.integration.id,
        status: errors.length === 0 ? 'success' : 'partial',
        recordsSynced,
        recordsFailed,
        errors,
        startTime,
        endTime: new Date().toISOString(),
        duration: Date.now() - new Date(startTime).getTime()
      };
    } catch (error: any) {
      await this.updateStatus('error');
      throw error;
    }
  }

  async syncInbound(): Promise<SyncResult> {
    return await this.sync();
  }

  async syncOutbound(): Promise<SyncResult> {
    const startTime = new Date().toISOString();

    try {
      await this.updateStatus('syncing');

      // Push conversions to Google Ads
      const conversions = await this.getRecentConversions();
      await this.uploadConversions(conversions);

      // Update customer match lists
      await this.updateCustomerMatchLists();

      await this.updateStatus('connected');

      return {
        integrationId: this.integration.id,
        status: 'success',
        recordsSynced: conversions.length,
        recordsFailed: 0,
        startTime,
        endTime: new Date().toISOString(),
        duration: Date.now() - new Date(startTime).getTime()
      };
    } catch (error: any) {
      await this.updateStatus('error');
      throw error;
    }
  }

  getWebhookUrl(): string | undefined {
    // Google Ads doesn't support webhooks directly
    return undefined;
  }

  private async fetchGoogleAdsLeads(): Promise<any[]> {
    const customerId = this.integration.config.options?.customerId;
    if (!customerId) return [];

    const query = `
      SELECT
        lead_form_submission.id,
        lead_form_submission.campaign,
        lead_form_submission.ad_group,
        lead_form_submission.submission_date_time,
        lead_form_submission.lead_form_submission_data
      FROM lead_form_submission_data
      WHERE segments.date DURING LAST_7_DAYS
    `;

    const headers = {
      'Authorization': `Bearer ${this.integration.config.accessToken}`,
      'developer-token': this.integration.config.options?.developerToken
    };

    const response = await this.makeApiRequest(
      `${this.baseUrl}/customers/${customerId}/googleAds:search`,
      'POST',
      { query },
      headers
    );

    return response.results || [];
  }

  private async syncLeadToCRM(googleLead: any): Promise<void> {
    const mappedData = await this.applyFieldMappings(googleLead);

    const db = this.env.DB_CRM;
    await db.prepare(`
      INSERT OR REPLACE INTO leads (
        id, business_id, first_name, last_name, email, phone,
        source, source_id, metadata, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      `google_${googleLead.leadFormSubmission.id}`,
      this.integration.config.options?.businessId,
      mappedData.first_name,
      mappedData.last_name,
      mappedData.email,
      mappedData.phone,
      'google_ads',
      googleLead.leadFormSubmission.id,
      JSON.stringify(googleLead),
      googleLead.leadFormSubmission.submissionDateTime || new Date().toISOString()
    ).run();
  }

  private async syncCampaignPerformance(): Promise<void> {
    // Sync campaign performance metrics
    const customerId = this.integration.config.options?.customerId;
    if (!customerId) return;

    const query = `
      SELECT
        campaign.id,
        campaign.name,
        metrics.impressions,
        metrics.clicks,
        metrics.cost_micros,
        metrics.conversions
      FROM campaign
      WHERE segments.date DURING LAST_30_DAYS
    `;

    const headers = {
      'Authorization': `Bearer ${this.integration.config.accessToken}`,
      'developer-token': this.integration.config.options?.developerToken
    };

    const response = await this.makeApiRequest(
      `${this.baseUrl}/customers/${customerId}/googleAds:search`,
      'POST',
      { query },
      headers
    );

    // Store performance data
    const db = this.env.DB_ANALYTICS;
    for (const result of response.results || []) {
      await db.prepare(`
        INSERT OR REPLACE INTO campaign_performance (
          campaign_id, campaign_name, platform, impressions, clicks,
          cost, conversions, date, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(
        result.campaign.id,
        result.campaign.name,
        'google_ads',
        result.metrics.impressions,
        result.metrics.clicks,
        result.metrics.costMicros / 1000000,
        result.metrics.conversions,
        new Date().toISOString().split('T')[0],
        new Date().toISOString()
      ).run();
    }
  }

  private async getRecentConversions(): Promise<any[]> {
    const db = this.env.DB_CRM;
    const conversions = await db.prepare(`
      SELECT * FROM opportunities
      WHERE status = 'closed_won'
        AND close_date >= datetime('now', '-7 days')
        AND metadata->>'$.synced_to_google' IS NULL
    `).all();

    return conversions.results;
  }

  private async uploadConversions(conversions: any[]): Promise<void> {
    const customerId = this.integration.config.options?.customerId;
    const conversionActionId = this.integration.config.options?.conversionActionId;

    if (!customerId || !conversionActionId) return;

    for (const conversion of conversions) {
      const conversionUpload = {
        conversionAction: `customers/${customerId}/conversionActions/${conversionActionId}`,
        conversionDateTime: conversion.close_date,
        conversionValue: conversion.value,
        currencyCode: 'USD'
      };

      const headers = {
        'Authorization': `Bearer ${this.integration.config.accessToken}`,
        'developer-token': this.integration.config.options?.developerToken
      };

      await this.makeApiRequest(
        `${this.baseUrl}/customers/${customerId}/conversions:upload`,
        'POST',
        { conversions: [conversionUpload] },
        headers
      );
    }
  }

  private async updateCustomerMatchLists(): Promise<void> {
    // Update customer match lists in Google Ads
    const db = this.env.DB_CRM;
    const segments = await db.prepare(`
      SELECT * FROM customer_segments
      WHERE active = 1
        AND metadata->>'$.sync_to_google' = 'true'
    `).all();

    for (const segment of segments.results) {
      const userListId = (segment as any).metadata?.google_user_list_id;
      if (!userListId) continue;

      const leads = await db.prepare(`
        SELECT email, phone FROM leads
        WHERE segment_id = ?
          AND status = 'qualified'
      `).bind((segment as any).id).all();

      // Upload to Google Ads customer match
      // Implementation would follow Google Ads API documentation
    }
  }
}

// =====================================================
// HUBSPOT INTEGRATION
// =====================================================

export class HubSpotIntegration extends BaseIntegration {
  private baseUrl = 'https://api.hubapi.com';

  async connect(): Promise<boolean> {
    try {
      const headers = {
        'Authorization': `Bearer ${this.integration.config.accessToken}`
      };

      const response = await this.makeApiRequest(
        `${this.baseUrl}/account-info/v3/details`,
        'GET',
        null,
        headers
      );

      return response.portalId !== undefined;
    } catch (error: any) {
      return false;
    }
  }

  async disconnect(): Promise<void> {
    this.isConnected = false;
    await this.updateStatus('disconnected');
  }

  async testConnection(): Promise<boolean> {
    return await this.connect();
  }

  async sync(): Promise<SyncResult> {
    const startTime = new Date().toISOString();
    const errors: any[] = [];
    let recordsSynced = 0;
    let recordsFailed = 0;

    try {
      await this.updateStatus('syncing');

      // Sync contacts
      const contacts = await this.fetchHubSpotContacts();
      for (const contact of contacts) {
        try {
          await this.syncContactToCRM(contact);
          recordsSynced++;
        } catch (error: any) {
          errors.push(this.createSyncError(contact.id, error));
          recordsFailed++;
        }
      }

      // Sync companies
      const companies = await this.fetchHubSpotCompanies();
      for (const company of companies) {
        try {
          await this.syncCompanyToCRM(company);
          recordsSynced++;
        } catch (error: any) {
          errors.push(this.createSyncError(company.id, error));
          recordsFailed++;
        }
      }

      // Sync deals
      const deals = await this.fetchHubSpotDeals();
      for (const deal of deals) {
        try {
          await this.syncDealToCRM(deal);
          recordsSynced++;
        } catch (error: any) {
          errors.push(this.createSyncError(deal.id, error));
          recordsFailed++;
        }
      }

      await this.updateStatus('connected');
      await this.updateLastSync();

      return {
        integrationId: this.integration.id,
        status: errors.length === 0 ? 'success' : 'partial',
        recordsSynced,
        recordsFailed,
        errors,
        startTime,
        endTime: new Date().toISOString(),
        duration: Date.now() - new Date(startTime).getTime()
      };
    } catch (error: any) {
      await this.updateStatus('error');
      throw error;
    }
  }

  async syncInbound(): Promise<SyncResult> {
    return await this.sync();
  }

  async syncOutbound(): Promise<SyncResult> {
    const startTime = new Date().toISOString();
    let recordsSynced = 0;

    try {
      await this.updateStatus('syncing');

      // Push CRM data to HubSpot
      const leads = await this.getCRMLeadsToSync();
      for (const lead of leads) {
        await this.pushLeadToHubSpot(lead);
        recordsSynced++;
      }

      await this.updateStatus('connected');

      return {
        integrationId: this.integration.id,
        status: 'success',
        recordsSynced,
        recordsFailed: 0,
        startTime,
        endTime: new Date().toISOString(),
        duration: Date.now() - new Date(startTime).getTime()
      };
    } catch (error: any) {
      await this.updateStatus('error');
      throw error;
    }
  }

  getWebhookUrl(): string {
    return `https://api.coreflow360.com/webhooks/hubspot/${this.integration.id}`;
  }

  private async fetchHubSpotContacts(): Promise<any[]> {
    const headers = {
      'Authorization': `Bearer ${this.integration.config.accessToken}`
    };

    const response = await this.makeApiRequest(
      `${this.baseUrl}/crm/v3/objects/contacts?limit=100`,
      'GET',
      null,
      headers
    );

    return response.results || [];
  }

  private async fetchHubSpotCompanies(): Promise<any[]> {
    const headers = {
      'Authorization': `Bearer ${this.integration.config.accessToken}`
    };

    const response = await this.makeApiRequest(
      `${this.baseUrl}/crm/v3/objects/companies?limit=100`,
      'GET',
      null,
      headers
    );

    return response.results || [];
  }

  private async fetchHubSpotDeals(): Promise<any[]> {
    const headers = {
      'Authorization': `Bearer ${this.integration.config.accessToken}`
    };

    const response = await this.makeApiRequest(
      `${this.baseUrl}/crm/v3/objects/deals?limit=100`,
      'GET',
      null,
      headers
    );

    return response.results || [];
  }

  private async syncContactToCRM(contact: any): Promise<void> {
    const mappedData = await this.applyFieldMappings(contact.properties);

    const db = this.env.DB_CRM;
    await db.prepare(`
      INSERT OR REPLACE INTO leads (
        id, business_id, first_name, last_name, email, phone,
        company, source, source_id, metadata, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      `hubspot_${contact.id}`,
      this.integration.config.options?.businessId,
      mappedData.firstname,
      mappedData.lastname,
      mappedData.email,
      mappedData.phone,
      mappedData.company,
      'hubspot',
      contact.id,
      JSON.stringify(contact),
      contact.createdAt || new Date().toISOString()
    ).run();
  }

  private async syncCompanyToCRM(company: any): Promise<void> {
    const mappedData = await this.applyFieldMappings(company.properties);

    const db = this.env.DB_CRM;
    await db.prepare(`
      INSERT OR REPLACE INTO accounts (
        id, business_id, name, domain, industry, size,
        source, source_id, metadata, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      `hubspot_${company.id}`,
      this.integration.config.options?.businessId,
      mappedData.name,
      mappedData.domain,
      mappedData.industry,
      mappedData.numberofemployees,
      'hubspot',
      company.id,
      JSON.stringify(company),
      company.createdAt || new Date().toISOString()
    ).run();
  }

  private async syncDealToCRM(deal: any): Promise<void> {
    const mappedData = await this.applyFieldMappings(deal.properties);

    const db = this.env.DB_CRM;
    await db.prepare(`
      INSERT OR REPLACE INTO opportunities (
        id, business_id, name, amount, stage, close_date,
        source, source_id, metadata, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      `hubspot_${deal.id}`,
      this.integration.config.options?.businessId,
      mappedData.dealname,
      mappedData.amount,
      mappedData.dealstage,
      mappedData.closedate,
      'hubspot',
      deal.id,
      JSON.stringify(deal),
      deal.createdAt || new Date().toISOString()
    ).run();
  }

  private async getCRMLeadsToSync(): Promise<any[]> {
    const db = this.env.DB_CRM;
    const leads = await db.prepare(`
      SELECT * FROM leads
      WHERE updated_at >= datetime('now', '-1 day')
        AND (source != 'hubspot' OR source IS NULL)
    `).all();

    return leads.results;
  }

  private async pushLeadToHubSpot(lead: any): Promise<void> {
    const headers = {
      'Authorization': `Bearer ${this.integration.config.accessToken}`
    };

    const hubspotContact = {
      properties: {
        firstname: lead.first_name,
        lastname: lead.last_name,
        email: lead.email,
        phone: lead.phone,
        company: lead.company
      }
    };

    await this.makeApiRequest(
      `${this.baseUrl}/crm/v3/objects/contacts`,
      'POST',
      hubspotContact,
      headers
    );
  }
}