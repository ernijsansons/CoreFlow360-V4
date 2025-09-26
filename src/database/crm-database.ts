import { z } from 'zod';
import type { Env } from '../types/env';
import { circuitBreakerRegistry, CircuitBreakerConfigs } from '../shared/circuit-breaker';
import { errorHandler, ErrorFactories, ApplicationError } from '../shared/error-handling';
import { Logger } from '../shared/logger';
import { TransactionManager, withTransaction, type TransactionOptions } from '../shared/transaction-manager';

// Input validation schemas
export const CreateCompanySchema = z.object({
  business_id: z.string(),
  name: z.string().min(1),
  domain: z.string().optional(),
  industry: z.string().optional(),
  size_range: z.enum(['1-10', '11-50', '51-200', '201-500', '501-1000', '1000+']).optional(),
  revenue_range: z.enum(['0-1M', '1M-5M', '5M-10M', '10M-50M', '50M-100M', '100M+']).optional(),
  ai_summary: z.string().optional(),
  ai_pain_points: z.string().optional(),
  ai_icp_score: z.number().min(0).max(100).optional(),
  technologies: z.string().optional(),
  funding: z.string().optional(),
  news: z.string().optional(),
  social_profiles: z.string().optional()
});

export const CreateContactSchema = z.object({
  business_id: z.string(),
  company_id: z.string().optional(),
  email: z.string().email(),
  phone: z.string().optional(),
  first_name: z.string().optional(),
  last_name: z.string().optional(),
  title: z.string().optional(),
  seniority_level: z.enum(['individual_contributor', 'team_lead', 'manager', 'director', 'vp', 'c_level', 'founder']).optional(),
  department: z.enum(['engineering', 'sales', 'marketing',
  'hr', 'finance', 'operations', 'legal', 'executive', 'other']).optional(),
  linkedin_url: z.string().optional(),
  ai_personality: z.string().optional(),
  ai_communication_style: z.string().optional(),
  ai_interests: z.string().optional(),
  verified_phone: z.boolean().optional(),
  verified_email: z.boolean().optional(),
  timezone: z.string().optional(),
  preferred_contact_method: z.enum(['email', 'phone', 'linkedin', 'sms']).optional()
});

export const CreateLeadSchema = z.object({
  business_id: z.string(),
  contact_id: z.string().optional(),
  company_id: z.string().optional(),
  source: z.string(),
  source_campaign: z.string().optional(),
  status: z.enum(['new', 'qualifying',
  'qualified', 'meeting_scheduled', 'opportunity', 'unqualified', 'closed_won', 'closed_lost']).optional(),
  ai_qualification_score: z.number().min(0).max(100).optional(),
  ai_qualification_summary: z.string().optional(),
  ai_next_best_action: z.string().optional(),
  ai_predicted_value: z.number().optional(),
  ai_close_probability: z.number().min(0).max(1).optional(),
  ai_estimated_close_date: z.string().optional(),
  assigned_to: z.string().optional(),
  assigned_type: z.enum(['ai', 'human']).optional()
});

export const CreateAITaskSchema = z.object({
  business_id: z.string(),
  type: z.string(),
  priority: z.number().min(1).max(10).optional(),
  payload: z.string(),
  assigned_agent: z.string().optional(),
  scheduled_at: z.string().optional(),
  expires_at: z.string().optional()
});

// Types
export type CreateCompany = z.infer<typeof CreateCompanySchema>;
export type CreateContact = z.infer<typeof CreateContactSchema>;
export type CreateLead = z.infer<typeof CreateLeadSchema>;
export type CreateAITask = z.infer<typeof CreateAITaskSchema>;

export interface DatabaseResult<T = any> {
  success: boolean;
  data?: T;
  error?: string;
}

export interface PaginationOptions {
  page?: number;
  limit?: number;
  sortBy?: string;
  sortOrder?: 'ASC' | 'DESC';
}

export interface LeadFilters {
  status?: string;
  assigned_to?: string;
  source?: string;
  ai_qualification_score_min?: number;
  created_after?: string;
  created_before?: string;
}

export class CRMDatabase {
  private db: D1Database;
  private logger: Logger;
  private transactionManager: TransactionManager;
  private env: Env;

  constructor(env: Env) {
    this.env = env;
    this.db = env.DB_MAIN;
    this.logger = new Logger();
    this.transactionManager = new TransactionManager(env);

    // Initialize circuit breaker for database operations
    circuitBreakerRegistry.getOrCreate('crm-database', {
      ...CircuitBreakerConfigs.database,
      onStateChange: (state, name) => {
        this.logger.warn('CRM Database circuit breaker state changed', {
          circuitName: name,
          newState: state
        });
      },
      onFailure: (error, name) => {
        this.logger.error('CRM Database circuit breaker recorded failure', {
          circuitName: name,
          error: error.message
        });
      }
    });
  }

  /**
   * PERFORMANCE OPTIMIZATION: Batch create multiple companies with transaction rollback
   */
  async batchCreateCompanies(companies: CreateCompany[], businessId: string, userId?:
  string): Promise<DatabaseResult<{ created: number; errors: number }>> {
    if (companies.length === 0) {
      return { success: true, data: { created: 0, errors: 0 } };
    }

    // Validate all companies first
    const validatedCompanies = companies.map(company => {
      const validation = CreateCompanySchema.safeParse(company);
      if (!validation.success) {
        throw ErrorFactories.validation(
          `Company validation failed: ${validation.error.message}`,
          { operation: 'batch_create_companies', businessId: company.business_id }
        );
      }
      return validation.data;
    });

    const result = await this.transactionManager.withTransaction(
      async (db) => {
        const results: any[] = [];
        const createdIds: string[] = [];

        for (const company of validatedCompanies) {
          const id = this.generateId();
          const validatedFields = this.validateAndSanitizeFields(Object.keys(company), 'companies');
          const fields = validatedFields.join(', ');
          const placeholders = validatedFields.map(() => '?').join(', ');

          try {
            const statement = db
              .prepare(`INSERT INTO companies (id, ${fields}) VALUES (?, ${placeholders})`)
              .bind(id, ...Object.values(company));

            const queryResult = await statement.run();
            results.push({ success: queryResult.success, id });

            if (queryResult.success) {
              createdIds.push(id);
            }
          } catch (error) {
            results.push({ success: false, error: error instanceof Error ? error.message : 'Unknown error' });
            // Transaction will be rolled back automatically on error
            throw error;
          }
        }

        const successful = results.filter(r => r.success).length;
        const errors = results.length - successful;

        this.logger.info('Batch company creation completed', {
          operation: 'batch_create_companies',
          totalCompanies: companies.length,
          successful,
          errors,
          createdIds
        });

        return { created: successful, errors };
      },
      {
        businessId,
        operation: 'batch_create_companies',
        userId,
        timeout: 30000 // 30 second timeout
      }
    );

    return {
      success: result.success,
      data: result.data,
      error: result.error
    };
  }

  /**
   * PERFORMANCE OPTIMIZATION: Batch create multiple contacts
   */
  async batchCreateContacts(contacts: CreateContact[]): Promise<DatabaseResult<{ created: number; errors: number }>> {
    if (contacts.length === 0) {
      return { success: true, data: { created: 0, errors: 0 } };
    }

    try {
      const statements = contacts.map(contact => {
        const validation = CreateContactSchema.safeParse(contact);
        if (!validation.success) {
          throw new Error(validation.error.message);
        }

        const id = this.generateId();
        const validatedFields = this.validateAndSanitizeFields(Object.keys(validation.data), 'contacts');
        const fields = validatedFields.join(', ');
        const placeholders = validatedFields.map(() => '?').join(', ');

        return this.db
          .prepare(`INSERT INTO contacts (id, ${fields}) VALUES (?, ${placeholders})`)
          .bind(id, ...Object.values(validation.data));
      });

      const results = await this.db.batch(statements);
      const successful = results.filter(r => r.success).length;
      const errors = results.length - successful;

      return {
        success: errors === 0,
        data: { created: successful, errors }
      };

    } catch (error) {
      return { success: false, error: error instanceof Error ? error.message : 'Batch create failed' };
    }
  }

  // Company operations
  async createCompany(data: CreateCompany): Promise<DatabaseResult<{ id: string }>> {
    try {
      const validation = CreateCompanySchema.safeParse(data);
      if (!validation.success) {
        return { success: false, error: validation.error.message };
      }

      const id = this.generateId();
      const validatedFields = this.validateAndSanitizeFields(Object.keys(validation.data), 'companies');
      const fields = validatedFields.join(', ');
      const placeholders = validatedFields.map(() => '?').join(', ');

      const result = await this.db
        .prepare(`INSERT INTO companies (id, ${fields}) VALUES (?, ${placeholders})`)
        .bind(id, ...Object.values(validation.data))
        .run();

      if (!result.success) {
        return { success: false, error: 'Failed to create company' };
      }

      return { success: true, data: { id } };
    } catch (error) {
      return { success: false, error: error instanceof Error ? error.message : 'Unknown error' };
    }
  }

  async getCompany(id: string, businessId: string): Promise<DatabaseResult> {
    try {
      const result = await this.db
        .prepare('SELECT * FROM companies WHERE id = ? AND business_id = ?')
        .bind(id, businessId)
        .first();

      if (!result) {
        return { success: false, error: 'Company not found' };
      }

      return { success: true, data: result };
    } catch (error) {
      return { success: false, error: error instanceof Error ? error.message : 'Unknown error' };
    }
  }

  async updateCompanyAIData(id: string, businessId: string, aiData: {
    ai_summary?: string;
    ai_pain_points?: string;
    ai_icp_score?: number;
    technologies?: string;
    funding?: string;
    news?: string;
  }): Promise<DatabaseResult> {
    try {
      const updates = Object.entries(aiData)
        .filter(([_, value]) => value !== undefined)
        .map(([key, _]) => `${key} = ?`)
        .join(', ');

      if (!updates) {
        return { success: false, error: 'No data provided for update' };
      }

      const values = Object.values(aiData).filter(value => value !== undefined);

      const result = await this.db
        .prepare(`UPDATE companies SET ${updates}, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND business_id = ?`)
        .bind(...values, id, businessId)
        .run();

      return { success: result.success, data: { updated: result.meta.changes } };
    } catch (error) {
      return { success: false, error: error instanceof Error ? error.message : 'Unknown error' };
    }
  }

  // Contact operations
  async createContact(data: CreateContact): Promise<DatabaseResult<{ id: string }>> {
    try {
      const validation = CreateContactSchema.safeParse(data);
      if (!validation.success) {
        return { success: false, error: validation.error.message };
      }

      const id = this.generateId();
      const validatedFields = this.validateAndSanitizeFields(Object.keys(validation.data), 'contacts');
      const fields = validatedFields.join(', ');
      const placeholders = validatedFields.map(() => '?').join(', ');

      const result = await this.db
        .prepare(`INSERT INTO contacts (id, ${fields}) VALUES (?, ${placeholders})`)
        .bind(id, ...Object.values(validation.data))
        .run();

      if (!result.success) {
        return { success: false, error: 'Failed to create contact' };
      }

      return { success: true, data: { id } };
    } catch (error) {
      return { success: false, error: error instanceof Error ? error.message : 'Unknown error' };
    }
  }

  async getContact(id: string, businessId: string): Promise<DatabaseResult> {
    try {
      const result = await this.db
        .prepare(`
          SELECT c.*, co.name as company_name, co.domain as company_domain
          FROM contacts c
          LEFT JOIN companies co ON c.company_id = co.id AND co.business_id = ?
          WHERE c.id = ? AND c.business_id = ?
        `)
        .bind(businessId, id, businessId)
        .first();

      if (!result) {
        return { success: false, error: 'Contact not found' };
      }

      return { success: true, data: result };
    } catch (error) {
      return { success: false, error: error instanceof Error ? error.message : 'Unknown error' };
    }
  }

  async findContactByEmail(businessId: string, email: string): Promise<DatabaseResult> {
    try {
      const result = await this.db
        .prepare('SELECT * FROM contacts WHERE business_id = ? AND email = ?')
        .bind(businessId, email)
        .first();

      return { success: true, data: result };
    } catch (error) {
      return { success: false, error: error instanceof Error ? error.message : 'Unknown error' };
    }
  }

  // Lead operations
  async createLead(data: CreateLead): Promise<DatabaseResult<{ id: string }>> {
    try {
      const validation = CreateLeadSchema.safeParse(data);
      if (!validation.success) {
        return { success: false, error: validation.error.message };
      }

      const id = this.generateId();
      const validatedFields = this.validateAndSanitizeFields(Object.keys(validation.data), 'leads');
      const fields = validatedFields.join(', ');
      const placeholders = validatedFields.map(() => '?').join(', ');

      const result = await this.db
        .prepare(`INSERT INTO leads (id, ${fields}) VALUES (?, ${placeholders})`)
        .bind(id, ...Object.values(validation.data))
        .run();

      if (!result.success) {
        return { success: false, error: 'Failed to create lead' };
      }

      return { success: true, data: { id } };
    } catch (error) {
      return { success: false, error: error instanceof Error ? error.message : 'Unknown error' };
    }
  }

  async getLeads(businessId: string, filters: LeadFilters
  = {}, pagination: PaginationOptions = {}): Promise<DatabaseResult> {
    try {
      const { page = 1, limit = 50, sortBy = 'created_at', sortOrder = 'DESC' } = pagination;
      const offset = (page - 1) * limit;

      // Validate sort parameters to prevent injection
      const
  validSortBy = this.validateSortField(sortBy, ['created_at', 'updated_at', 'status', 'ai_qualification_score']);
      const validSortOrder = sortOrder === 'ASC' ? 'ASC' : 'DESC';

      let whereClause = 'WHERE l.business_id = ?';
      const params: any[] = [businessId];

      // Apply filters
      if (filters.status) {
        whereClause += ' AND l.status = ?';
        params.push(filters.status);
      }

      if (filters.assigned_to) {
        whereClause += ' AND l.assigned_to = ?';
        params.push(filters.assigned_to);
      }

      if (filters.source) {
        whereClause += ' AND l.source = ?';
        params.push(filters.source);
      }

      if (filters.ai_qualification_score_min) {
        whereClause += ' AND l.ai_qualification_score >= ?';
        params.push(filters.ai_qualification_score_min);
      }

      if (filters.created_after) {
        whereClause += ' AND l.created_at >= ?';
        params.push(filters.created_after);
      }

      if (filters.created_before) {
        whereClause += ' AND l.created_at <= ?';
        params.push(filters.created_before);
      }

      const query = `
        SELECT
          l.*,
          c.first_name, c.last_name, c.email, c.title,
          co.name as company_name, co.domain as company_domain
        FROM leads l
        LEFT JOIN contacts c ON l.contact_id = c.id
        LEFT JOIN companies co ON l.company_id = co.id
        ${whereClause}
        ORDER BY l.${validSortBy} ${validSortOrder}
        LIMIT ? OFFSET ?
      `;

      const results = await this.db
        .prepare(query)
        .bind(...params, limit, offset)
        .all();

      // Get total count for pagination
      const countQuery = `
        SELECT COUNT(*) as total
        FROM leads l
        ${whereClause}
      `;

      const countResult = await this.db
        .prepare(countQuery)
        .bind(...params)
        .first() as any;

      return {
        success: true,
        data: {
          leads: results.results || [],
          pagination: {
            page,
            limit,
            total: Number(countResult?.total || 0),
            totalPages: Math.ceil(Number(countResult?.total || 0) / limit)
          }
        }
      };
    } catch (error) {
      return { success: false, error: error instanceof Error ? error.message : 'Unknown error' };
    }
  }

  async updateLeadStatus(id: string, status: string, aiSummary?: string): Promise<DatabaseResult> {
    try {
      const result = await this.db
        .prepare(`
          UPDATE leads
         
  SET status = ?, ai_qualification_summary = COALESCE(?, ai_qualification_summary), updated_at = CURRENT_TIMESTAMP
          WHERE id = ?
        `)
        .bind(status, aiSummary, id)
        .run();

      return { success: result.success, data: { updated: result.meta.changes } };
    } catch (error) {
      return { success: false, error: error instanceof Error ? error.message : 'Unknown error' };
    }
  }

  // AI Task operations
  async createAITask(data: CreateAITask): Promise<DatabaseResult<{ id: string }>> {
    try {
      const validation = CreateAITaskSchema.safeParse(data);
      if (!validation.success) {
        return { success: false, error: validation.error.message };
      }

      const id = this.generateId();
      const validatedFields = this.validateAndSanitizeFields(Object.keys(validation.data), 'ai_tasks');
      const fields = validatedFields.join(', ');
      const placeholders = validatedFields.map(() => '?').join(', ');

      const result = await this.db
        .prepare(`INSERT INTO ai_tasks (id, ${fields}) VALUES (?, ${placeholders})`)
        .bind(id, ...Object.values(validation.data))
        .run();

      if (!result.success) {
        return { success: false, error: 'Failed to create AI task' };
      }

      return { success: true, data: { id } };
    } catch (error) {
      return { success: false, error: error instanceof Error ? error.message : 'Unknown error' };
    }
  }

  async getPendingAITasks(businessId: string, limit: number = 10): Promise<DatabaseResult> {
    try {
      // Validate business_id to prevent injection
      if (!businessId || typeof businessId !== 'string') {
        return { success: false, error: 'Invalid business_id provided' };
      }

      const results = await this.db
        .prepare(`
          SELECT * FROM ai_tasks
          WHERE business_id = ? AND status = 'pending'
          AND (scheduled_at IS NULL OR scheduled_at <= CURRENT_TIMESTAMP)
          AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)
          ORDER BY priority DESC, created_at ASC
          LIMIT ?
        `)
        .bind(businessId, limit)
        .all();

      return { success: true, data: results.results || [] };
    } catch (error) {
      return { success: false, error: error instanceof Error ? error.message : 'Unknown error' };
    }
  }

  async updateAITaskStatus(id: string, status: string, businessId: string, error?: string): Promise<DatabaseResult> {
    try {
      // Validate inputs to prevent injection
      if (!id || !status || !businessId) {
        return { success: false, error: 'Missing required parameters: id, status, businessId' };
      }

      let query = `
        UPDATE ai_tasks
        SET status = ?, updated_at = CURRENT_TIMESTAMP
      `;
      const params: any[] = [status];

      if (status === 'processing') {
        query += ', started_at = CURRENT_TIMESTAMP, attempts = attempts + 1';
      } else if (status === 'completed') {
        query += ', completed_at = CURRENT_TIMESTAMP';
      } else if (status === 'failed') {
        query += ', last_error = ?';
        params.push(error || 'Unknown error');
      }

      // Critical: Include business_id in WHERE clause to prevent cross-tenant updates
      query += ' WHERE id = ? AND business_id = ?';
      params.push(id, businessId);

      const result = await this.db
        .prepare(query)
        .bind(...params)
        .run();

      return { success: result.success, data: { updated: result.meta.changes } };
    } catch (error) {
      return { success: false, error: error instanceof Error ? error.message : 'Unknown error' };
    }
  }

  // Conversation operations
  async createConversation(data: {
    business_id: string;
    lead_id?: string;
    contact_id?: string;
    type: string;
    direction: string;
    participant_type: string;
    subject?: string;
    transcript?: string;
    duration_seconds?: number;
    external_id?: string;
  }): Promise<DatabaseResult<{ id: string }>> {
    try {
      const id = this.generateId();
      const validatedFields = this.validateAndSanitizeFields(Object.keys(data), 'conversations');
      const fields = validatedFields.join(', ');
      const placeholders = validatedFields.map(() => '?').join(', ');

      const result = await this.db
        .prepare(`INSERT INTO conversations (id, ${fields}) VALUES (?, ${placeholders})`)
        .bind(id, ...Object.values(data))
        .run();

      if (!result.success) {
        return { success: false, error: 'Failed to create conversation' };
      }

      return { success: true, data: { id } };
    } catch (error) {
      return { success: false, error: error instanceof Error ? error.message : 'Unknown error' };
    }
  }

  async updateConversationAI(id: string, aiData: {
    ai_summary?: string;
    ai_sentiment?: string;
    ai_objections?: string;
    ai_commitments?: string;
    ai_next_steps?: string;
  }): Promise<DatabaseResult> {
    try {
      const updates = Object.entries(aiData)
        .filter(([_, value]) => value !== undefined)
        .map(([key, _]) => `${key} = ?`)
        .join(', ');

      if (!updates) {
        return { success: false, error: 'No AI data provided for update' };
      }

      const values = Object.values(aiData).filter(value => value !== undefined);

      const result = await this.db
        .prepare(`UPDATE conversations SET ${updates} WHERE id = ?`)
        .bind(...values, id)
        .run();

      return { success: result.success, data: { updated: result.meta.changes } };
    } catch (error) {
      return { success: false, error: error instanceof Error ? error.message : 'Unknown error' };
    }
  }

  // Utility methods
  private generateId(): string {
    const array = new Uint8Array(16);
    crypto.getRandomValues(array);
    return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
  }

  // Analytics queries
  async getLeadMetrics(businessId: string, period: 'day' | 'week' | 'month' = 'week'): Promise<DatabaseResult> {
    try {
      const dateFilter = this.getDateFilter(period);

      const metrics = await this.db
        .prepare(`
          SELECT
            COUNT(*) as total_leads,
            COUNT(CASE WHEN status = 'new' THEN 1 END) as new_leads,
            COUNT(CASE WHEN status = 'qualified' THEN 1 END) as qualified_leads,
            COUNT(CASE WHEN status = 'closed_won' THEN 1 END) as won_leads,
            AVG(ai_qualification_score) as avg_qualification_score,
            SUM(ai_predicted_value) as total_predicted_value
          FROM leads
          WHERE business_id = ? AND created_at >= ?
        `)
        .bind(businessId, dateFilter)
        .first();

      return { success: true, data: metrics };
    } catch (error) {
      return { success: false, error: error instanceof Error ? error.message : 'Unknown error' };
    }
  }

  private getDateFilter(period: string): string {
    const now = new Date();
    const days = period === 'day' ? 1 : period === 'week' ? 7 : 30;
    const filterDate = new Date(now.getTime() - days * 24 * 60 * 60 * 1000);
    return filterDate.toISOString();
  }

  /**
   * Validate and sanitize field names to prevent SQL injection
   */
  private validateAndSanitizeFields(fields: string[], tableName: string): string[] {
    const allowedFields: Record<string, string[]> = {
      companies: [
        'business_id', 'name', 'domain', 'industry', 'size_range', 'revenue_range',
        'ai_summary', 'ai_pain_points', 'ai_icp_score', 'technologies', 'funding',
        'news', 'social_profiles', 'created_at', 'updated_at'
      ],
      contacts: [
        'business_id', 'company_id', 'email', 'phone', 'first_name', 'last_name',
        'title', 'seniority_level', 'department', 'linkedin_url', 'ai_personality',
        'ai_communication_style', 'ai_interests', 'verified_phone', 'verified_email',
        'timezone', 'preferred_contact_method', 'created_at', 'updated_at'
      ],
      leads: [
        'business_id', 'contact_id', 'company_id', 'source', 'source_campaign',
        'status', 'ai_qualification_score', 'ai_qualification_summary',
        'ai_next_best_action', 'ai_predicted_value', 'ai_close_probability',
        'ai_estimated_close_date', 'assigned_to', 'assigned_type', 'created_at', 'updated_at'
      ],
      ai_tasks: [
        'business_id', 'type', 'priority', 'payload', 'assigned_agent',
        'scheduled_at', 'expires_at', 'status', 'created_at', 'updated_at'
      ],
      conversations: [
        'business_id', 'lead_id', 'contact_id', 'type', 'direction',
        'participant_type', 'subject', 'transcript', 'duration_seconds',
        'external_id', 'ai_summary', 'ai_sentiment', 'ai_objections',
        'ai_commitments', 'ai_next_steps', 'created_at', 'updated_at'
      ]
    };

    const tableFields = allowedFields[tableName];
    if (!tableFields) {
      throw new Error(`Unknown table: ${tableName}`);
    }

    return fields.filter(field => {
      // Only allow alphanumeric characters and underscores
      const isValidFormat = /^[a-zA-Z_][a-zA-Z0-9_]*$/.test(field);
      const isAllowedField = tableFields.includes(field);

      if (!isValidFormat || !isAllowedField) {
        this.logger.warn('Invalid field name rejected', {
          field,
          tableName,
          operation: 'validateAndSanitizeFields'
        });
        return false;
      }

      return true;
    });
  }

  /**
   * Validate sort field for queries
   */
  private validateSortField(sortBy: string, allowedFields: string[]): string {
    if (!sortBy || !allowedFields.includes(sortBy)) {
      return 'created_at'; // Default safe sort field
    }
    return sortBy;
  }
}