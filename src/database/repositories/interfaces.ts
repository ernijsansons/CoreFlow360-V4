/**
 * Repository Interfaces - SOLID Compliant Data Access
 * Interface Segregation Principle: Focused, client-specific interfaces
 */

import { z } from 'zod';

// Core Types
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

export interface PaginatedResult<T> {
  items: T[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    totalPages: number;
  };
}

// Lead Domain
export interface LeadFilters {
  status?: string;
  assigned_to?: string;
  source?: string;
  ai_qualification_score_min?: number;
  created_after?: string;
  created_before?: string;
}

export interface CreateLead {
  business_id: string;
  contact_id?: string;
  company_id?: string;
  source: string;
  source_campaign?: string;
  status?: string;
  ai_qualification_score?: number;
  ai_qualification_summary?: string;
  ai_next_best_action?: string;
  ai_predicted_value?: number;
  ai_close_probability?: number;
  ai_estimated_close_date?: string;
  assigned_to?: string;
  assigned_type?: 'ai' | 'human';
}

export interface Lead extends CreateLead {
  id: string;
  created_at: string;
  updated_at: string;
}

// Contact Domain
export interface CreateContact {
  business_id: string;
  company_id?: string;
  email: string;
  phone?: string;
  first_name?: string;
  last_name?: string;
  title?: string;
  seniority_level?: 'individual_contributor' | 'team_lead' | 'manager' | 'director' | 'vp' | 'c_level' | 'founder';
  department?: 'engineering' | 'sales' | 'marketing' | 'hr' | 'finance' | 'operations' | 'legal' | 'executive' | 'other';
  linkedin_url?: string;
  ai_personality?: string;
  ai_communication_style?: string;
  ai_interests?: string;
  verified_phone?: boolean;
  verified_email?: boolean;
  timezone?: string;
  preferred_contact_method?: 'email' | 'phone' | 'linkedin' | 'sms';
}

export interface Contact extends CreateContact {
  id: string;
  created_at: string;
  updated_at: string;
}

// Company Domain
export interface CreateCompany {
  business_id: string;
  name: string;
  domain?: string;
  industry?: string;
  size_range?: '1-10' | '11-50' | '51-200' | '201-500' | '501-1000' | '1000+';
  revenue_range?: '0-1M' | '1M-5M' | '5M-10M' | '10M-50M' | '50M-100M' | '100M+';
  ai_summary?: string;
  ai_pain_points?: string;
  ai_icp_score?: number;
  technologies?: string;
  funding?: string;
  news?: string;
  social_profiles?: string;
}

export interface Company extends CreateCompany {
  id: string;
  created_at: string;
  updated_at: string;
}

export interface AICompanyData {
  ai_summary?: string;
  ai_pain_points?: string;
  ai_icp_score?: number;
  technologies?: string;
  funding?: string;
  news?: string;
}

// Repository Interfaces - ISP Compliant
export interface ILeadRepository {
  create(lead: CreateLead): Promise<DatabaseResult<{ id: string }>>;
  findById(id: string, businessId: string): Promise<DatabaseResult<Lead>>;
  findByFilters(
    businessId: string,
    filters: LeadFilters,
    pagination: PaginationOptions
  ): Promise<DatabaseResult<PaginatedResult<Lead>>>;
  updateStatus(id: string, status: string, aiSummary?: string): Promise<DatabaseResult>;
  getMetrics(businessId: string, period: 'day' | 'week' | 'month'): Promise<DatabaseResult>;
}

export interface IContactRepository {
  create(contact: CreateContact): Promise<DatabaseResult<{ id: string }>>;
  findById(id: string, businessId: string): Promise<DatabaseResult<Contact>>;
  findByEmail(businessId: string, email: string): Promise<DatabaseResult<Contact>>;
  batchCreate(contacts: CreateContact[]): Promise<DatabaseResult<{ created: number; errors: number }>>;
  batchGetWithCompanies(contactIds: string[], businessId: string): Promise<DatabaseResult<Contact[]>>;
}

export interface ICompanyRepository {
  create(company: CreateCompany): Promise<DatabaseResult<{ id: string }>>;
  findById(id: string, businessId: string): Promise<DatabaseResult<Company>>;
  updateAIData(id: string, businessId: string, aiData: AICompanyData): Promise<DatabaseResult>;
  batchCreate(
    companies: CreateCompany[],
    businessId: string,
    userId?: string
  ): Promise<DatabaseResult<{ created: number; errors: number }>>;
  batchGet(ids: string[], businessId: string): Promise<DatabaseResult<Company[]>>;
}

export interface IConversationRepository {
  create(data: {
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
  }): Promise<DatabaseResult<{ id: string }>>;
  updateAI(id: string, aiData: {
    ai_summary?: string;
    ai_sentiment?: string;
    ai_objections?: string;
    ai_commitments?: string;
    ai_next_steps?: string;
  }): Promise<DatabaseResult>;
}

export interface IAITaskRepository {
  create(data: {
    business_id: string;
    type: string;
    priority?: number;
    payload: string;
    assigned_agent?: string;
    scheduled_at?: string;
    expires_at?: string;
  }): Promise<DatabaseResult<{ id: string }>>;
  getPendingTasks(businessId: string, limit?: number): Promise<DatabaseResult>;
  updateStatus(
    id: string,
    status: string,
    businessId: string,
    error?: string
  ): Promise<DatabaseResult>;
}

// Data Access Infrastructure
export interface IConnectionManager {
  execute<T>(
    query: string,
    params?: any[],
    operation?: 'first' | 'all' | 'run'
  ): Promise<T>;
  batch(statements: any[]): Promise<any[]>;
}

export interface IQueryBuilder {
  select(fields: string[]): IQueryBuilder;
  from(table: string): IQueryBuilder;
  join(joinClause: string): IQueryBuilder;
  where(condition: string, value?: any): IQueryBuilder;
  orderBy(field: string, direction?: 'ASC' | 'DESC'): IQueryBuilder;
  limit(count: number): IQueryBuilder;
  offset(count: number): IQueryBuilder;
  build(): { query: string; params: any[] };
  reset(): IQueryBuilder;
}

export interface IDataValidator {
  validateLead(lead: CreateLead): { success: boolean; error?: string };
  validateContact(contact: CreateContact): { success: boolean; error?: string };
  validateCompany(company: CreateCompany): { success: boolean; error?: string };
  sanitizeFields(fields: string[], tableName: string): string[];
}

export interface IPerformanceMonitor {
  trackQuery(query: string, executionTime: number, fromCache?: boolean): void;
  getSlowQueries(threshold?: number): Array<{ query: string; avgTime: number; count: number }>;
  getStats(): {
    queryCount: number;
    avgQueryTime: number;
    slowQueries: Array<{ query: string; avgTime: number; count: number }>;
  };
  logMetrics(): void;
}

// Cache Integration
export interface IRepositoryCache {
  get(key: string): Promise<any>;
  set(key: string, data: any, ttl?: number): Promise<void>;
  invalidate(pattern: string): Promise<void>;
  generateKey(prefix: string, ...parts: string[]): string;
}

// Transaction Management
export interface ITransactionContext {
  execute<T>(operations: (tx: any) => Promise<T>): Promise<T>;
  rollback(): Promise<void>;
  commit(): Promise<void>;
}

export interface ITransactionManager {
  withTransaction<T>(
    operation: (context: ITransactionContext) => Promise<T>,
    options?: {
      businessId?: string;
      operation?: string;
      userId?: string;
      timeout?: number;
    }
  ): Promise<DatabaseResult<T>>;
}