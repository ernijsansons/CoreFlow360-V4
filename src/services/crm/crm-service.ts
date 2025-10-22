// @ts-nocheck
/**
 * Fortune 50-Level CRM Service
 * AI-powered customer relationship management with lead scoring, enrichment, and insights
 * Inspired by Salesforce Einstein and HubSpot Breeze
 */

import type { D1Database } from '@cloudflare/workers-types';

// ============================================================
// TYPES & INTERFACES
// ============================================================

export interface Company {
  id: string;
  business_id: string;
  name: string;
  website?: string;
  domain?: string;
  industry?: string;
  company_size?: string;
  annual_revenue?: number;
  lead_score: number;
  lifecycle_stage: string;
  status: string;
  owner_id?: string;
  health_score?: number;
  total_contacts?: number;
  total_deals?: number;
  pipeline_value?: number;
}

export interface Contact {
  id: string;
  business_id: string;
  company_id?: string;
  first_name: string;
  last_name: string;
  full_name: string;
  email: string;
  job_title?: string;
  seniority_level?: string;
  lead_score: number;
  lifecycle_stage: string;
  status: string;
  owner_id?: string;
}

export interface Deal {
  id: string;
  business_id: string;
  company_id: string;
  name: string;
  amount: number;
  stage: string;
  probability: number;
  expected_close_date?: string;
  status: string;
  owner_id: string;
  company_name?: string;
  primary_contact_name?: string;
  days_in_stage?: number;
}

export interface Activity {
  id: string;
  business_id: string;
  type: string;
  subject: string;
  company_id?: string;
  contact_id?: string;
  deal_id?: string;
  scheduled_at?: string;
  status: string;
  owner_id: string;
  outcome?: string;
}

export interface Lead {
  id: string;
  business_id: string;
  title: string;
  source?: string;
  lead_score: number;
  qualification_status: string;
  estimated_budget?: number;
  owner_id?: string;
  company_name?: string;
  contact_name?: string;
}

export interface PipelineMetrics {
  stage: string;
  deal_count: number;
  total_value: number;
  avg_deal_size: number;
  avg_probability: number;
  win_rate?: number;
}

export interface LeadScoringCriteria {
  demographic_score: number; // Job title, company size, industry
  behavioral_score: number; // Website visits, email opens, content downloads
  engagement_score: number; // Meetings attended, responses to outreach
  fit_score: number; // Budget, authority, need, timeline (BANT)
}

// ============================================================
// CRM SERVICE
// ============================================================

export class CRMService {
  constructor(
    private db: D1Database,
    private businessId: string
  ) {}

  // ============================================================
  // COMPANIES
  // ============================================================

  async getCompanies(filters?: {
    lifecycle_stage?: string;
    status?: string;
    owner_id?: string;
    min_score?: number;
    limit?: number;
    offset?: number;
  }): Promise<{ companies: Company[]; total: number }> {
    const limit = filters?.limit || 50;
    const offset = filters?.offset || 0;

    let whereConditions = ['c.business_id = ?', 'c.deleted_at IS NULL'];
    const params: any[] = [this.businessId];

    if (filters?.lifecycle_stage) {
      whereConditions.push('c.lifecycle_stage = ?');
      params.push(filters.lifecycle_stage);
    }

    if (filters?.status) {
      whereConditions.push('c.status = ?');
      params.push(filters.status);
    }

    if (filters?.owner_id) {
      whereConditions.push('c.owner_id = ?');
      params.push(filters.owner_id);
    }

    if (filters?.min_score) {
      whereConditions.push('c.lead_score >= ?');
      params.push(filters.min_score);
    }

    const whereClause = whereConditions.join(' AND ');

    // Get total count
    const countResult = await this.db
      .prepare(`SELECT COUNT(*) as total FROM crm_companies c WHERE ${whereClause}`)
      .bind(...params)
      .first<{ total: number }>();

    const total = countResult?.total || 0;

    // Get companies with metrics
    const companies = await this.db
      .prepare(`
        SELECT
          c.*,
          COUNT(DISTINCT co.id) as total_contacts,
          COUNT(DISTINCT d.id) as total_deals,
          COALESCE(SUM(CASE WHEN d.status = 'open' THEN d.amount ELSE 0 END), 0) as pipeline_value
        FROM crm_companies c
        LEFT JOIN crm_contacts co ON co.company_id = c.id AND co.deleted_at IS NULL
        LEFT JOIN crm_deals d ON d.company_id = c.id AND d.deleted_at IS NULL
        WHERE ${whereClause}
        GROUP BY c.id
        ORDER BY c.lead_score DESC, c.updated_at DESC
        LIMIT ? OFFSET ?
      `)
      .bind(...params, limit, offset)
      .all<Company>();

    return {
      companies: companies.results || [],
      total
    };
  }

  async getCompanyById(companyId: string): Promise<Company | null> {
    const company = await this.db
      .prepare(`
        SELECT
          c.*,
          COUNT(DISTINCT co.id) as total_contacts,
          COUNT(DISTINCT d.id) as total_deals,
          COALESCE(SUM(CASE WHEN d.status = 'open' THEN d.amount ELSE 0 END), 0) as pipeline_value,
          COALESCE(SUM(CASE WHEN d.status = 'won' THEN d.amount ELSE 0 END), 0) as won_value
        FROM crm_companies c
        LEFT JOIN crm_contacts co ON co.company_id = c.id AND co.deleted_at IS NULL
        LEFT JOIN crm_deals d ON d.company_id = c.id AND d.deleted_at IS NULL
        WHERE c.id = ? AND c.business_id = ? AND c.deleted_at IS NULL
        GROUP BY c.id
      `)
      .bind(companyId, this.businessId)
      .first<Company>();

    return company || null;
  }

  async createCompany(data: Partial<Company>): Promise<Company> {
    const id = crypto.randomUUID();

    await this.db
      .prepare(`
        INSERT INTO crm_companies (
          id, business_id, name, website, domain, industry,
          company_size, annual_revenue, lead_score, lifecycle_stage,
          status, owner_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `)
      .bind(
        id,
        this.businessId,
        data.name,
        data.website || null,
        data.domain || null,
        data.industry || null,
        data.company_size || null,
        data.annual_revenue || null,
        data.lead_score || 0,
        data.lifecycle_stage || 'lead',
        data.status || 'active',
        data.owner_id || null
      )
      .run();

    const company = await this.getCompanyById(id);
    return company!;
  }

  async updateCompany(companyId: string, data: Partial<Company>): Promise<Company> {
    const updates: string[] = [];
    const params: any[] = [];

    const allowedFields = [
      'name', 'website', 'domain', 'industry', 'company_size',
      'annual_revenue', 'lead_score', 'lifecycle_stage', 'status',
      'health_score', 'owner_id'
    ];

    for (const field of allowedFields) {
      if (data[field as keyof Company] !== undefined) {
        updates.push(`${field} = ?`);
        params.push(data[field as keyof Company]);
      }
    }

    if (updates.length === 0) {
      throw new Error('No valid fields to update');
    }

    updates.push('updated_at = CURRENT_TIMESTAMP');
    params.push(companyId, this.businessId);

    await this.db
      .prepare(`
        UPDATE crm_companies
        SET ${updates.join(', ')}
        WHERE id = ? AND business_id = ? AND deleted_at IS NULL
      `)
      .bind(...params)
      .run();

    const company = await this.getCompanyById(companyId);
    return company!;
  }

  // ============================================================
  // CONTACTS
  // ============================================================

  async getContacts(filters?: {
    company_id?: string;
    lifecycle_stage?: string;
    status?: string;
    min_score?: number;
    limit?: number;
    offset?: number;
  }): Promise<{ contacts: Contact[]; total: number }> {
    const limit = filters?.limit || 50;
    const offset = filters?.offset || 0;

    let whereConditions = ['business_id = ?', 'deleted_at IS NULL'];
    const params: any[] = [this.businessId];

    if (filters?.company_id) {
      whereConditions.push('company_id = ?');
      params.push(filters.company_id);
    }

    if (filters?.lifecycle_stage) {
      whereConditions.push('lifecycle_stage = ?');
      params.push(filters.lifecycle_stage);
    }

    if (filters?.status) {
      whereConditions.push('status = ?');
      params.push(filters.status);
    }

    if (filters?.min_score) {
      whereConditions.push('lead_score >= ?');
      params.push(filters.min_score);
    }

    const whereClause = whereConditions.join(' AND ');

    const countResult = await this.db
      .prepare(`SELECT COUNT(*) as total FROM crm_contacts WHERE ${whereClause}`)
      .bind(...params)
      .first<{ total: number }>();

    const total = countResult?.total || 0;

    const contacts = await this.db
      .prepare(`
        SELECT * FROM crm_contacts
        WHERE ${whereClause}
        ORDER BY lead_score DESC, updated_at DESC
        LIMIT ? OFFSET ?
      `)
      .bind(...params, limit, offset)
      .all<Contact>();

    return {
      contacts: contacts.results || [],
      total
    };
  }

  async createContact(data: Partial<Contact>): Promise<Contact> {
    const id = crypto.randomUUID();

    await this.db
      .prepare(`
        INSERT INTO crm_contacts (
          id, business_id, company_id, first_name, last_name, email,
          job_title, seniority_level, lead_score, lifecycle_stage,
          status, owner_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `)
      .bind(
        id,
        this.businessId,
        data.company_id || null,
        data.first_name,
        data.last_name,
        data.email,
        data.job_title || null,
        data.seniority_level || null,
        data.lead_score || 0,
        data.lifecycle_stage || 'subscriber',
        data.status || 'active',
        data.owner_id || null
      )
      .run();

    const contact = await this.db
      .prepare('SELECT * FROM crm_contacts WHERE id = ?')
      .bind(id)
      .first<Contact>();

    return contact!;
  }

  // ============================================================
  // DEALS
  // ============================================================

  async getDeals(filters?: {
    stage?: string;
    status?: string;
    owner_id?: string;
    company_id?: string;
    limit?: number;
    offset?: number;
  }): Promise<{ deals: Deal[]; total: number }> {
    const limit = filters?.limit || 50;
    const offset = filters?.offset || 0;

    let whereConditions = ['d.business_id = ?', 'd.deleted_at IS NULL'];
    const params: any[] = [this.businessId];

    if (filters?.stage) {
      whereConditions.push('d.stage = ?');
      params.push(filters.stage);
    }

    if (filters?.status) {
      whereConditions.push('d.status = ?');
      params.push(filters.status);
    }

    if (filters?.owner_id) {
      whereConditions.push('d.owner_id = ?');
      params.push(filters.owner_id);
    }

    if (filters?.company_id) {
      whereConditions.push('d.company_id = ?');
      params.push(filters.company_id);
    }

    const whereClause = whereConditions.join(' AND ');

    const countResult = await this.db
      .prepare(`SELECT COUNT(*) as total FROM crm_deals d WHERE ${whereClause}`)
      .bind(...params)
      .first<{ total: number }>();

    const total = countResult?.total || 0;

    const deals = await this.db
      .prepare(`
        SELECT
          d.*,
          c.name as company_name,
          co.first_name || ' ' || co.last_name as primary_contact_name
        FROM crm_deals d
        LEFT JOIN crm_companies c ON c.id = d.company_id
        LEFT JOIN crm_contacts co ON co.id = d.primary_contact_id
        WHERE ${whereClause}
        ORDER BY d.amount DESC, d.updated_at DESC
        LIMIT ? OFFSET ?
      `)
      .bind(...params, limit, offset)
      .all<Deal>();

    return {
      deals: deals.results || [],
      total
    };
  }

  async createDeal(data: Partial<Deal>): Promise<Deal> {
    const id = crypto.randomUUID();

    await this.db
      .prepare(`
        INSERT INTO crm_deals (
          id, business_id, company_id, name, deal_type, amount,
          stage, probability, expected_close_date, status, owner_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `)
      .bind(
        id,
        this.businessId,
        data.company_id,
        data.name,
        'new_business',
        data.amount || 0,
        data.stage || 'qualification',
        data.probability || 10,
        data.expected_close_date || null,
        data.status || 'open',
        data.owner_id
      )
      .run();

    const deal = await this.db
      .prepare(`
        SELECT
          d.*,
          c.name as company_name
        FROM crm_deals d
        LEFT JOIN crm_companies c ON c.id = d.company_id
        WHERE d.id = ?
      `)
      .bind(id)
      .first<Deal>();

    return deal!;
  }

  async updateDealStage(dealId: string, newStage: string): Promise<Deal> {
    // Update stage and track stage change
    await this.db
      .prepare(`
        UPDATE crm_deals
        SET stage = ?,
            stage_changed_at = CURRENT_TIMESTAMP,
            days_in_stage = 0,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ? AND business_id = ?
      `)
      .bind(newStage, dealId, this.businessId)
      .run();

    const deal = await this.db
      .prepare(`
        SELECT
          d.*,
          c.name as company_name
        FROM crm_deals d
        LEFT JOIN crm_companies c ON c.id = d.company_id
        WHERE d.id = ?
      `)
      .bind(dealId)
      .first<Deal>();

    return deal!;
  }

  // ============================================================
  // ACTIVITIES
  // ============================================================

  async getActivities(filters?: {
    type?: string;
    status?: string;
    owner_id?: string;
    company_id?: string;
    deal_id?: string;
    limit?: number;
    offset?: number;
  }): Promise<{ activities: Activity[]; total: number }> {
    const limit = filters?.limit || 50;
    const offset = filters?.offset || 0;

    let whereConditions = ['business_id = ?', 'deleted_at IS NULL'];
    const params: any[] = [this.businessId];

    if (filters?.type) {
      whereConditions.push('type = ?');
      params.push(filters.type);
    }

    if (filters?.status) {
      whereConditions.push('status = ?');
      params.push(filters.status);
    }

    if (filters?.owner_id) {
      whereConditions.push('owner_id = ?');
      params.push(filters.owner_id);
    }

    if (filters?.company_id) {
      whereConditions.push('company_id = ?');
      params.push(filters.company_id);
    }

    if (filters?.deal_id) {
      whereConditions.push('deal_id = ?');
      params.push(filters.deal_id);
    }

    const whereClause = whereConditions.join(' AND ');

    const countResult = await this.db
      .prepare(`SELECT COUNT(*) as total FROM crm_activities WHERE ${whereClause}`)
      .bind(...params)
      .first<{ total: number }>();

    const total = countResult?.total || 0;

    const activities = await this.db
      .prepare(`
        SELECT * FROM crm_activities
        WHERE ${whereClause}
        ORDER BY scheduled_at DESC, created_at DESC
        LIMIT ? OFFSET ?
      `)
      .bind(...params, limit, offset)
      .all<Activity>();

    return {
      activities: activities.results || [],
      total
    };
  }

  // ============================================================
  // PIPELINE ANALYTICS
  // ============================================================

  async getPipelineMetrics(): Promise<PipelineMetrics[]> {
    const metrics = await this.db
      .prepare(`
        SELECT
          stage,
          COUNT(*) as deal_count,
          SUM(amount) as total_value,
          AVG(amount) as avg_deal_size,
          AVG(probability) as avg_probability
        FROM crm_deals
        WHERE business_id = ? AND deleted_at IS NULL AND status = 'open'
        GROUP BY stage
        ORDER BY
          CASE stage
            WHEN 'qualification' THEN 1
            WHEN 'discovery' THEN 2
            WHEN 'proposal' THEN 3
            WHEN 'negotiation' THEN 4
            ELSE 5
          END
      `)
      .bind(this.businessId)
      .all<PipelineMetrics>();

    return metrics.results || [];
  }

  async getDashboardStats() {
    // Get key CRM metrics for dashboard
    const [companies, contacts, deals, activities] = await Promise.all([
      this.db
        .prepare('SELECT COUNT(*) as count FROM crm_companies WHERE business_id = ? AND deleted_at IS NULL')
        .bind(this.businessId)
        .first<{ count: number }>(),
      this.db
        .prepare('SELECT COUNT(*) as count FROM crm_contacts WHERE business_id = ? AND deleted_at IS NULL')
        .bind(this.businessId)
        .first<{ count: number }>(),
      this.db
        .prepare(`
          SELECT
            COUNT(*) as count,
            SUM(CASE WHEN status = 'open' THEN amount ELSE 0 END) as pipeline_value,
            SUM(CASE WHEN status = 'won' THEN amount ELSE 0 END) as won_value
          FROM crm_deals
          WHERE business_id = ? AND deleted_at IS NULL
        `)
        .bind(this.businessId)
        .first<{ count: number; pipeline_value: number; won_value: number }>(),
      this.db
        .prepare('SELECT COUNT(*) as count FROM crm_activities WHERE business_id = ? AND deleted_at IS NULL AND status = "pending"')
        .bind(this.businessId)
        .first<{ count: number }>()
    ]);

    return {
      total_companies: companies?.count || 0,
      total_contacts: contacts?.count || 0,
      total_deals: deals?.count || 0,
      pipeline_value: deals?.pipeline_value || 0,
      won_value: deals?.won_value || 0,
      pending_activities: activities?.count || 0
    };
  }

  // ============================================================
  // AI-POWERED FEATURES
  // ============================================================

  /**
   * Calculate lead score based on multiple criteria
   * Inspired by Salesforce Einstein Lead Scoring
   */
  async calculateLeadScore(contactId: string): Promise<number> {
    const contact = await this.db
      .prepare('SELECT * FROM crm_contacts WHERE id = ?')
      .bind(contactId)
      .first<Contact>();

    if (!contact) return 0;

    let score = 0;

    // Demographic scoring (0-30 points)
    const demographicScore = this.calculateDemographicScore(contact);
    score += demographicScore;

    // Engagement scoring (0-40 points)
    const engagementScore = await this.calculateEngagementScore(contactId);
    score += engagementScore;

    // Fit scoring (0-30 points)
    const fitScore = await this.calculateFitScore(contact);
    score += fitScore;

    return Math.min(100, Math.max(0, score));
  }

  private calculateDemographicScore(contact: Contact): number {
    let score = 0;

    // Job title/seniority (0-15 points)
    if (contact.seniority_level === 'c-level') score += 15;
    else if (contact.seniority_level === 'vp') score += 12;
    else if (contact.seniority_level === 'director') score += 10;
    else if (contact.seniority_level === 'manager') score += 7;

    // Email verified (0-5 points)
    if (contact.email) score += 5;

    // Has complete profile (0-10 points)
    const profileCompleteness = [
      contact.job_title,
      contact.phone,
      contact.company_id,
      contact.linkedin_url
    ].filter(Boolean).length;
    score += (profileCompleteness / 4) * 10;

    return score;
  }

  private async calculateEngagementScore(contactId: string): Promise<number> {
    const activities = await this.db
      .prepare(`
        SELECT type, outcome, COUNT(*) as count
        FROM crm_activities
        WHERE contact_id = ? AND deleted_at IS NULL
        GROUP BY type, outcome
      `)
      .bind(contactId)
      .all<{ type: string; outcome?: string; count: number }>();

    let score = 0;

    for (const activity of (activities.results || [])) {
      // Meeting attended
      if (activity.type === 'meeting' && activity.outcome === 'positive') score += 10;
      // Email response
      if (activity.type === 'email' && activity.outcome === 'positive') score += 5;
      // Call completed
      if (activity.type === 'call' && activity.outcome) score += 7;
      // Demo attended
      if (activity.type === 'demo') score += 15;
    }

    return Math.min(40, score);
  }

  private async calculateFitScore(contact: Contact): Promise<number> {
    let score = 0;

    // Has company association (0-10 points)
    if (contact.company_id) {
      score += 10;

      // Get company details for additional scoring
      const company = await this.db
        .prepare('SELECT * FROM crm_companies WHERE id = ?')
        .bind(contact.company_id)
        .first<Company>();

      if (company) {
        // Company size fit (0-10 points)
        if (['501-1000', '1001-5000', '5001-10000', '10000+'].includes(company.company_size || '')) {
          score += 10;
        } else if (['201-500', '51-200'].includes(company.company_size || '')) {
          score += 7;
        }

        // Revenue fit (0-10 points)
        if (company.annual_revenue && company.annual_revenue > 10000000) {
          score += 10;
        } else if (company.annual_revenue && company.annual_revenue > 1000000) {
          score += 5;
        }
      }
    }

    return score;
  }
}
