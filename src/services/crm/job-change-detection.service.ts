/**
 * Job Change Detection Service
 * Real-time job change monitoring with PeopleDataLabs webhooks
 * Feature #3 - Phase 1 Sprint 1
 */

import type { Env } from '../../types/env';import { Logger } from "../../shared/logger";
const logger = new Logger({ component: "services-crm-job-change-detectionservice" });



export interface JobChange {
  id: string;
  contact_id: string;
  previous_company: string;
  new_company: string;
  previous_title: string;
  new_title: string;
  change_type: 'promotion' | 'lateral' | 'new_company' | 'demotion';
  detected_at: string;
  confidence: number;
}

export class JobChangeDetectionService {
  constructor(private env: Env) {}

  /**
   * Process job change webhook from PeopleDataLabs
   */
  async processJobChangeWebhook(payload: any): Promise<JobChange | null> {
    try {
      // Extract job change data from PDL webhook
      const email = payload.email || payload.data?.email;
      if (!email) {
        logger.error('No email in job change webhook');
        return null;
      }

      // Find contact in CRM
      const contact = await this.env.DB_MAIN.prepare(`
        SELECT * FROM crm_contacts
        WHERE email = ?
        LIMIT 1
      `).bind(email).first() as any;

      if (!contact) {
        logger.info(`Job change detected for unknown contact: ${email}`);
        // Could optionally create new contact or lead here
        return null;
      }

      const previousCompany = contact.company_name;
      const previousTitle = contact.job_title;
      const newCompany = payload.data?.job_company_name || payload.company;
      const newTitle = payload.data?.job_title || payload.title;

      // Determine change type
      const changeType = this.determineChangeType(
        previousCompany,
        newCompany,
        previousTitle,
        newTitle
      );

      // Create job change record
      const id = crypto.randomUUID().replace(/-/g, '');
      const now = new Date().toISOString();

      await this.env.DB_MAIN.prepare(`
        INSERT INTO crm_enrichment_history (
          id, business_id, entity_id, entity_type, enrichment_source,
          fields_updated, data_before, data_after, quality_improvement,
          cost, created_at
        ) VALUES (?, ?, ?, 'contact', 'peopledatalabs', ?, ?, ?, ?, 0, ?)
      `).bind(
        id,
        contact.business_id,
        contact.id,
        JSON.stringify(['company_name', 'job_title']),
        JSON.stringify({ company_name: previousCompany, job_title: previousTitle }),
        JSON.stringify({ company_name: newCompany, job_title: newTitle }),
        10, // Quality improvement points
        now
      ).run();

      // Update contact with new information
      await this.env.DB_MAIN.prepare(`
        UPDATE crm_contacts
        SET company_name = ?,
            job_title = ?,
            last_enriched_at = ?,
            updated_at = ?
        WHERE id = ?
      `).bind(newCompany, newTitle, now, now, contact.id).run();

      // Create notification/alert for sales team
      await this.createJobChangeAlert(contact, previousCompany, newCompany, previousTitle, newTitle);

      // Track engagement event
      await this.trackJobChangeEvent(contact.business_id, contact.id, changeType);

      const jobChange: JobChange = {
        id,
        contact_id: contact.id,
        previous_company: previousCompany || '',
        new_company: newCompany || '',
        previous_title: previousTitle || '',
        new_title: newTitle || '',
        change_type: changeType,
        detected_at: now,
        confidence: payload.confidence || 0.9
      };

      return jobChange;
    } catch (error) {
      logger.error('Job change processing error:', error);
      return null;
    }
  }

  /**
   * Manually check for job changes (batch processing)
   */
  async checkJobChangesForContact(businessId: string, contactId: string): Promise<any> {
    const contact = await this.env.DB_MAIN.prepare(`
      SELECT * FROM crm_contacts
      WHERE id = ? AND business_id = ?
    `).bind(contactId, businessId).first() as any;

    if (!contact || !contact.email) {
      return { success: false, error: 'Contact not found or no email' };
    }

    // Get credentials for PeopleDataLabs
    const credentials = await this.env.DB_MAIN.prepare(`
      SELECT api_key FROM crm_enrichment_credentials
      WHERE business_id = ? AND data_source = 'peopledatalabs' AND status = 'active'
      LIMIT 1
    `).bind(businessId).first() as any;

    if (!credentials) {
      return { success: false, error: 'PeopleDataLabs not configured' };
    }

    try {
      // Call PDL API to get latest data
      const response = await fetch(
        `https://api.peopledatalabs.com/v5/person/enrich?email=${encodeURIComponent(contact.email)}`,
        {
          headers: {
            'X-Api-Key': credentials.api_key
          }
        }
      );

      if (!response.ok) {
        return { success: false, error: `PDL API error: ${response.status}` };
      }

      const data = await response.json() as any;

      // Check if company or title changed
      const currentCompany = data.job_company_name;
      const currentTitle = data.job_title;

      if (currentCompany !== contact.company_name || currentTitle !== contact.job_title) {
        // Job change detected!
        const changeType = this.determineChangeType(
          contact.company_name,
          currentCompany,
          contact.job_title,
          currentTitle
        );

        await this.processJobChangeWebhook({
          email: contact.email,
          data: {
            job_company_name: currentCompany,
            job_title: currentTitle
          },
          confidence: 0.95
        });

        return {
          success: true,
          job_change_detected: true,
          change_type: changeType,
          previous: {
            company: contact.company_name,
            title: contact.job_title
          },
          current: {
            company: currentCompany,
            title: currentTitle
          }
        };
      }

      return {
        success: true,
        job_change_detected: false,
        message: 'No job change detected'
      };
    } catch (error: any) {
      logger.error('Job change check error:', error);
      return { success: false, error: error.message };
    }
  }

  /**
   * Determine the type of job change
   */
  private determineChangeType(
    oldCompany: string,
    newCompany: string,
    oldTitle: string,
    newTitle: string
  ): 'promotion' | 'lateral' | 'new_company' | 'demotion' {
    // Company changed = new company
    if (oldCompany !== newCompany) {
      return 'new_company';
    }

    // Same company, check title seniority
    const oldSeniority = this.extractSeniority(oldTitle);
    const newSeniority = this.extractSeniority(newTitle);

    if (newSeniority > oldSeniority) {
      return 'promotion';
    } else if (newSeniority < oldSeniority) {
      return 'demotion';
    }

    return 'lateral';
  }

  /**
   * Extract seniority level from title
   */
  private extractSeniority(title: string): number {
    const titleLower = (title || '').toLowerCase();

    if (titleLower.includes('chief') || titleLower.includes('ceo') || titleLower.includes('president')) {
      return 5; // C-level
    }
    if (titleLower.includes('vp') || titleLower.includes('vice president')) {
      return 4; // VP
    }
    if (titleLower.includes('director') || titleLower.includes('head of')) {
      return 3; // Director
    }
    if (titleLower.includes('manager') || titleLower.includes('lead')) {
      return 2; // Manager
    }
    if (titleLower.includes('senior') || titleLower.includes('sr.')) {
      return 1.5; // Senior IC
    }

    return 1; // IC
  }

  /**
   * Create alert for sales team
   */
  private async createJobChangeAlert(
    contact: any,
    oldCompany: string,
    newCompany: string,
    oldTitle: string,
    newTitle: string
  ): Promise<void> {
    // Find assigned sales rep
    const deal = await this.env.DB_MAIN.prepare(`
      SELECT user_id FROM crm_deals
      WHERE primary_contact_id = ? AND stage NOT IN ('won', 'lost')
      ORDER BY created_at DESC
      LIMIT 1
    `).bind(contact.id).first() as any;

    const userId = deal?.user_id || 'user-founder-001';

    // Create next action
    const actionId = crypto.randomUUID().replace(/-/g, '');
    await this.env.DB_MAIN.prepare(`
      INSERT INTO crm_next_actions (
        id, business_id, entity_type, entity_id, user_id,
        action_type, priority, action_title, action_description, reasoning,
        expires_at
      ) VALUES (?, ?, 'contact', ?, ?, 'follow_up', 95, ?, ?, ?, ?)
    `).bind(
      actionId,
      contact.business_id,
      contact.id,
      userId,
      `Follow up on ${contact.first_name}'s job change`,
      `${contact.first_name} ${contact.last_name} moved from ${oldCompany} (${oldTitle}) to ${newCompany} (${newTitle}). This is a great opportunity to reconnect and discuss their new priorities.`,
      `Job changes create buying windows - new priorities, budget, and decision authority. Strike while the iron is hot!`,
      new Date(Date.now() + 3 * 24 * 60 * 60 * 1000).toISOString() // 3 days
    ).run();
  }

  /**
   * Track job change as engagement event
   */
  private async trackJobChangeEvent(
    businessId: string,
    contactId: string,
    changeType: string
  ): Promise<void> {
    const eventId = crypto.randomUUID().replace(/-/g, '');
    const now = new Date().toISOString();

    await this.env.DB_MAIN.prepare(`
      INSERT INTO crm_deal_engagement_events (
        id, business_id, deal_id, event_type, event_timestamp,
        stakeholder_id, engagement_value, event_metadata
      )
      SELECT
        ?, ?, d.id, 'stakeholder_added', ?, ?, 8,
        ?
      FROM crm_deals d
      WHERE d.primary_contact_id = ? AND d.stage NOT IN ('won', 'lost')
    `).bind(
      eventId,
      businessId,
      now,
      contactId,
      JSON.stringify({ change_type: changeType, auto_detected: true }),
      contactId
    ).run();
  }

  /**
   * Get recent job changes for a business
   */
  async getRecentJobChanges(businessId: string, days: number = 30): Promise<any[]> {
    const changes = await this.env.DB_MAIN.prepare(`
      SELECT
        h.id,
        h.entity_id as contact_id,
        c.first_name,
        c.last_name,
        c.email,
        h.data_before,
        h.data_after,
        h.created_at as detected_at
      FROM crm_enrichment_history h
      JOIN crm_contacts c ON h.entity_id = c.id
      WHERE h.business_id = ?
        AND h.enrichment_source = 'peopledatalabs'
        AND h.fields_updated LIKE '%company_name%'
        AND h.created_at >= datetime('now', '-' || ? || ' days')
      ORDER BY h.created_at DESC
      LIMIT 100
    `).bind(businessId, days).all();

    return (changes.results || []).map((row: any) => ({
      id: row.id,
      contact_id: row.contact_id,
      contact_name: `${row.first_name} ${row.last_name}`,
      email: row.email,
      previous: JSON.parse(row.data_before || '{}'),
      current: JSON.parse(row.data_after || '{}'),
      detected_at: row.detected_at
    }));
  }
}
