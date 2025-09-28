/**
 * Lead Repository - Single Responsibility Principle Compliant
 * Focused solely on lead data access operations
 */

import { Logger } from '../../shared/logger';
import {
  ILeadRepository,
  IConnectionManager,
  IQueryBuilder,
  IDataValidator,
  IPerformanceMonitor,
  IRepositoryCache,
  CreateLead,
  Lead,
  LeadFilters,
  PaginationOptions,
  DatabaseResult,
  PaginatedResult
} from './interfaces';

export class LeadRepository implements ILeadRepository {
  private readonly logger: Logger;

  constructor(
    private connectionManager: IConnectionManager,
    private queryBuilder: IQueryBuilder,
    private validator: IDataValidator,
    private performanceMonitor: IPerformanceMonitor,
    private cache: IRepositoryCache
  ) {
    this.logger = new Logger();
  }

  async create(lead: CreateLead): Promise<DatabaseResult<{ id: string }>> {
    const startTime = performance.now();

    try {
      // Validation (delegated to validator)
      const validation = this.validator.validateLead(lead);
      if (!validation.success) {
        return { success: false, error: validation.error };
      }

      // Generate unique ID
      const id = this.generateId();

      // Build query (delegated to query builder)
      const validatedFields = this.validator.sanitizeFields(Object.keys(lead), 'leads');
      const { query, params } = this.queryBuilder
        .reset()
        .select(['*'])
        .build();

      // Execute query (delegated to connection manager)
      const insertQuery = `INSERT INTO leads (id, ${validatedFields.join(', ')}) VALUES (?, ${validatedFields.map(() => '?').join(', ')})`;
      const result = await this.connectionManager.execute<{ success: boolean; error?: string; changes?: number }>(
        insertQuery,
        [id, ...Object.values(lead)],
        'run'
      );

      // Track performance
      this.performanceMonitor.trackQuery('INSERT INTO leads', performance.now() - startTime);

      // Invalidate cache
      await this.cache.invalidate(`leads:${lead.business_id}:*`);

      if (!result.success) {
        return { success: false, error: 'Failed to create lead' };
      }

      this.logger.info('Lead created successfully', { leadId: id, businessId: lead.business_id });
      return { success: true, data: { id } };

    } catch (error: any) {
      const executionTime = performance.now() - startTime;
      this.performanceMonitor.trackQuery('INSERT INTO leads', executionTime);

      this.logger.error('Failed to create lead', error, { businessId: lead.business_id });
      return { success: false, error: error instanceof Error ? error.message : 'Unknown error' };
    }
  }

  async findById(id: string, businessId: string): Promise<DatabaseResult<Lead>> {
    const startTime = performance.now();

    try {
      // Check cache first
      const cacheKey = this.cache.generateKey('lead', businessId, id);
      const cached = await this.cache.get(cacheKey);
      if (cached) {
        this.performanceMonitor.trackQuery('SELECT lead by ID', performance.now() - startTime, true);
        return { success: true, data: cached };
      }

      // Build query for lead with related data
      const { query, params } = this.queryBuilder
        .reset()
        .select([
          'l.*',
          'c.first_name',
          'c.last_name',
          'c.email',
          'c.title',
          'co.name as company_name',
          'co.domain as company_domain'
        ])
        .from('leads l')
        .join('LEFT JOIN contacts c ON l.contact_id = c.id AND c.business_id = ?')
        .join('LEFT JOIN companies co ON l.company_id = co.id AND co.business_id = ?')
        .where('l.id = ?')
        .where('l.business_id = ?')
        .build();

      // Execute query
      const result = await this.connectionManager.execute<Lead>(
        query,
        [businessId, businessId, id, businessId],
        'first'
      );

      this.performanceMonitor.trackQuery('SELECT lead by ID', performance.now() - startTime);

      if (!result) {
        return { success: false, error: 'Lead not found' };
      }

      // Cache the result
      await this.cache.set(cacheKey, result, 300); // 5 minutes TTL

      return { success: true, data: result };

    } catch (error: any) {
      this.performanceMonitor.trackQuery('SELECT lead by ID', performance.now() - startTime);
      this.logger.error('Failed to find lead by ID', error, { leadId: id, businessId });
      return { success: false, error: error instanceof Error ? error.message : 'Unknown error' };
    }
  }

  async findByFilters(
    businessId: string,
    filters: LeadFilters = {},
    pagination: PaginationOptions = {}
  ): Promise<DatabaseResult<PaginatedResult<Lead>>> {
    const startTime = performance.now();

    try {
      const { page = 1, limit = 50, sortBy = 'created_at', sortOrder = 'DESC' } = pagination;
      const offset = (page - 1) * limit;

      // Check cache for this query
      const cacheKey = this.cache.generateKey(
        'leads',
        businessId,
        JSON.stringify(filters),
        JSON.stringify(pagination)
      );
      const cached = await this.cache.get(cacheKey);
      if (cached) {
        this.performanceMonitor.trackQuery('SELECT leads with filters', performance.now() - startTime, true);
        return { success: true, data: cached };
      }

      // Build base query
      const queryBuilder = this.queryBuilder
        .reset()
        .select([
          'l.*',
          'c.first_name',
          'c.last_name',
          'c.email',
          'c.title',
          'co.name as company_name',
          'co.domain as company_domain'
        ])
        .from('leads l')
        .join('LEFT JOIN contacts c ON l.contact_id = c.id')
        .join('LEFT JOIN companies co ON l.company_id = co.id')
        .where('l.business_id = ?', businessId);

      // Apply filters dynamically
      if (filters.status) {
        queryBuilder.where('l.status = ?', filters.status);
      }
      if (filters.assigned_to) {
        queryBuilder.where('l.assigned_to = ?', filters.assigned_to);
      }
      if (filters.source) {
        queryBuilder.where('l.source = ?', filters.source);
      }
      if (filters.ai_qualification_score_min) {
        queryBuilder.where('l.ai_qualification_score >= ?', filters.ai_qualification_score_min);
      }
      if (filters.created_after) {
        queryBuilder.where('l.created_at >= ?', filters.created_after);
      }
      if (filters.created_before) {
        queryBuilder.where('l.created_at <= ?', filters.created_before);
      }

      // Add sorting and pagination
      const validSortBy = this.validateSortField(sortBy, ['created_at', 'updated_at', 'status', 'ai_qualification_score']);
      const validSortOrder = sortOrder === 'ASC' ? 'ASC' : 'DESC';

      queryBuilder
        .orderBy(`l.${validSortBy}`, validSortOrder)
        .limit(limit)
        .offset(offset);

      const { query, params } = queryBuilder.build();

      // Execute main query
      const results = await this.connectionManager.execute<{ results: Lead[] }>(
        query,
        params,
        'all'
      );

      // Get total count for pagination
      const countQueryBuilder = this.queryBuilder
        .reset()
        .select(['COUNT(*) as total'])
        .from('leads l')
        .where('l.business_id = ?', businessId);

      // Apply same filters for count
      if (filters.status) countQueryBuilder.where('l.status = ?', filters.status);
      if (filters.assigned_to) countQueryBuilder.where('l.assigned_to = ?', filters.assigned_to);
      if (filters.source) countQueryBuilder.where('l.source = ?', filters.source);
      if (filters.ai_qualification_score_min) {
        countQueryBuilder.where('l.ai_qualification_score >= ?', filters.ai_qualification_score_min);
      }
      if (filters.created_after) countQueryBuilder.where('l.created_at >= ?', filters.created_after);
      if (filters.created_before) countQueryBuilder.where('l.created_at <= ?', filters.created_before);

      const { query: countQuery, params: countParams } = countQueryBuilder.build();
      const countResult = await this.connectionManager.execute<{ total: number }>(
        countQuery,
        countParams,
        'first'
      );

      const total = Number(countResult?.total || 0);
      const totalPages = Math.ceil(total / limit);

      const result: PaginatedResult<Lead> = {
        items: results?.results || [],
        pagination: {
          page,
          limit,
          total,
          totalPages
        }
      };

      // Track performance
      this.performanceMonitor.trackQuery('SELECT leads with filters', performance.now() - startTime);

      // Cache result for 2 minutes
      await this.cache.set(cacheKey, result, 120);

      return { success: true, data: result };

    } catch (error: any) {
      this.performanceMonitor.trackQuery('SELECT leads with filters', performance.now() - startTime);
      this.logger.error('Failed to find leads by filters', error, { businessId, filters });
      return { success: false, error: error instanceof Error ? error.message : 'Unknown error' };
    }
  }

  async updateStatus(id: string, status: string, aiSummary?: string): Promise<DatabaseResult> {
    const startTime = performance.now();

    try {
      const { query, params } = this.queryBuilder
        .reset()
        .build();

      const updateQuery = `
        UPDATE leads
        SET status = ?,
            ai_qualification_summary = COALESCE(?, ai_qualification_summary),
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `;

      const result = await this.connectionManager.execute<{ success: boolean; error?: string; changes?: number }>(
        updateQuery,
        [status, aiSummary, id],
        'run'
      );

      this.performanceMonitor.trackQuery('UPDATE lead status', performance.now() - startTime);

      // Invalidate cache for this lead
      await this.cache.invalidate(`lead:*:${id}`);
      await this.cache.invalidate(`leads:*`);

      if (!result.success) {
        return { success: false, error: 'Failed to update lead status' };
      }

      this.logger.info('Lead status updated', { leadId: id, status, changes: result.changes });
      return { success: true, data: { updated: result.changes } };

    } catch (error: any) {
      this.performanceMonitor.trackQuery('UPDATE lead status', performance.now() - startTime);
      this.logger.error('Failed to update lead status', error, { leadId: id, status });
      return { success: false, error: error instanceof Error ? error.message : 'Unknown error' };
    }
  }

  async getMetrics(businessId: string, period: 'day' | 'week' | 'month' = 'week'): Promise<DatabaseResult> {
    const startTime = performance.now();

    try {
      // Check cache first
      const cacheKey = this.cache.generateKey('lead-metrics', businessId, period);
      const cached = await this.cache.get(cacheKey);
      if (cached) {
        this.performanceMonitor.trackQuery('SELECT lead metrics', performance.now() - startTime, true);
        return { success: true, data: cached };
      }

      const dateFilter = this.getDateFilter(period);

      const { query, params } = this.queryBuilder
        .reset()
        .select([
          'COUNT(*) as total_leads',
          "COUNT(CASE WHEN status = 'new' THEN 1 END) as new_leads",
          "COUNT(CASE WHEN status = 'qualified' THEN 1 END) as qualified_leads",
          "COUNT(CASE WHEN status = 'closed_won' THEN 1 END) as won_leads",
          'AVG(ai_qualification_score) as avg_qualification_score',
          'SUM(ai_predicted_value) as total_predicted_value'
        ])
        .from('leads')
        .where('business_id = ?', businessId)
        .where('created_at >= ?', dateFilter)
        .build();

      const metrics = await this.connectionManager.execute(query, params, 'first');

      this.performanceMonitor.trackQuery('SELECT lead metrics', performance.now() - startTime);

      // Cache for 10 minutes
      await this.cache.set(cacheKey, metrics, 600);

      return { success: true, data: metrics };

    } catch (error: any) {
      this.performanceMonitor.trackQuery('SELECT lead metrics', performance.now() - startTime);
      this.logger.error('Failed to get lead metrics', error, { businessId, period });
      return { success: false, error: error instanceof Error ? error.message : 'Unknown error' };
    }
  }

  private generateId(): string {
    const array = new Uint8Array(16);
    crypto.getRandomValues(array);
    return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
  }

  private validateSortField(sortBy: string, allowedFields: string[]): string {
    if (!sortBy || !allowedFields.includes(sortBy)) {
      return 'created_at'; // Default safe sort field
    }
    return sortBy;
  }

  private getDateFilter(period: string): string {
    const now = new Date();
    const days = period === 'day' ? 1 : period === 'week' ? 7 : 30;
    const filterDate = new Date(now.getTime() - days * 24 * 60 * 60 * 1000);
    return filterDate.toISOString();
  }
}