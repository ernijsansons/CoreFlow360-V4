/**
 * CRM V2 Service - Fortune 50 Level
 * Frontend API client for next-generation CRM operations
 */

import apiClient, { ApiResponse } from '../client';

// ============================================================
// TYPES
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
  won_value?: number;
  created_at: string;
  updated_at: string;
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
  phone?: string;
  linkedin_url?: string;
  created_at: string;
  updated_at: string;
}

export interface Deal {
  id: string;
  business_id: string;
  company_id: string;
  company_name?: string;
  primary_contact_name?: string;
  name: string;
  amount: number;
  stage: string;
  probability: number;
  expected_close_date?: string;
  status: string;
  owner_id: string;
  days_in_stage?: number;
  deal_type?: string;
  created_at: string;
  updated_at: string;
}

export interface Activity {
  id: string;
  business_id: string;
  type: string;
  subject: string;
  description?: string;
  company_id?: string;
  contact_id?: string;
  deal_id?: string;
  scheduled_at?: string;
  completed_at?: string;
  status: string;
  outcome?: string;
  owner_id: string;
  created_at: string;
}

export interface PipelineMetrics {
  stage: string;
  deal_count: number;
  total_value: number;
  avg_deal_size: number;
  avg_probability: number;
}

export interface CRMDashboardStats {
  total_companies: number;
  total_contacts: number;
  total_deals: number;
  pipeline_value: number;
  won_value: number;
  pending_activities: number;
}

export interface PaginatedResponse<T> {
  data: T[];
  total: number;
  page: number;
  per_page: number;
}

// ============================================================
// SERVICE
// ============================================================

class CRMV2Service {
  // Companies
  async getCompanies(params?: {
    lifecycle_stage?: string;
    status?: string;
    owner_id?: string;
    min_score?: number;
    limit?: number;
    offset?: number;
  }): Promise<ApiResponse<PaginatedResponse<Company>>> {
    const queryParams = new URLSearchParams();
    if (params?.lifecycle_stage) queryParams.set('lifecycle_stage', params.lifecycle_stage);
    if (params?.status) queryParams.set('status', params.status);
    if (params?.owner_id) queryParams.set('owner_id', params.owner_id);
    if (params?.min_score) queryParams.set('min_score', params.min_score.toString());
    if (params?.limit) queryParams.set('limit', params.limit.toString());
    if (params?.offset) queryParams.set('offset', params.offset.toString());

    return apiClient.get<PaginatedResponse<Company>>(
      `/api/crm-v2/companies${queryParams.toString() ? `?${queryParams}` : ''}`
    );
  }

  async getCompanyById(id: string): Promise<ApiResponse<Company>> {
    return apiClient.get<Company>(`/api/crm-v2/companies/${id}`);
  }

  async createCompany(data: Partial<Company>): Promise<ApiResponse<Company>> {
    return apiClient.post<Company>('/api/crm-v2/companies', data);
  }

  async updateCompany(id: string, data: Partial<Company>): Promise<ApiResponse<Company>> {
    return apiClient.put<Company>(`/api/crm-v2/companies/${id}`, data);
  }

  // Contacts
  async getContacts(params?: {
    company_id?: string;
    lifecycle_stage?: string;
    status?: string;
    min_score?: number;
    limit?: number;
    offset?: number;
  }): Promise<ApiResponse<PaginatedResponse<Contact>>> {
    const queryParams = new URLSearchParams();
    if (params?.company_id) queryParams.set('company_id', params.company_id);
    if (params?.lifecycle_stage) queryParams.set('lifecycle_stage', params.lifecycle_stage);
    if (params?.status) queryParams.set('status', params.status);
    if (params?.min_score) queryParams.set('min_score', params.min_score.toString());
    if (params?.limit) queryParams.set('limit', params.limit.toString());
    if (params?.offset) queryParams.set('offset', params.offset.toString());

    return apiClient.get<PaginatedResponse<Contact>>(
      `/api/crm-v2/contacts${queryParams.toString() ? `?${queryParams}` : ''}`
    );
  }

  async createContact(data: Partial<Contact>): Promise<ApiResponse<Contact>> {
    return apiClient.post<Contact>('/api/crm-v2/contacts', data);
  }

  // Deals
  async getDeals(params?: {
    stage?: string;
    status?: string;
    owner_id?: string;
    company_id?: string;
    limit?: number;
    offset?: number;
  }): Promise<ApiResponse<PaginatedResponse<Deal>>> {
    const queryParams = new URLSearchParams();
    if (params?.stage) queryParams.set('stage', params.stage);
    if (params?.status) queryParams.set('status', params.status);
    if (params?.owner_id) queryParams.set('owner_id', params.owner_id);
    if (params?.company_id) queryParams.set('company_id', params.company_id);
    if (params?.limit) queryParams.set('limit', params.limit.toString());
    if (params?.offset) queryParams.set('offset', params.offset.toString());

    return apiClient.get<PaginatedResponse<Deal>>(
      `/api/crm-v2/deals${queryParams.toString() ? `?${queryParams}` : ''}`
    );
  }

  async createDeal(data: Partial<Deal>): Promise<ApiResponse<Deal>> {
    return apiClient.post<Deal>('/api/crm-v2/deals', data);
  }

  async updateDealStage(id: string, stage: string): Promise<ApiResponse<Deal>> {
    return apiClient.patch<Deal>(`/api/crm-v2/deals/${id}/stage`, { stage });
  }

  // Activities
  async getActivities(params?: {
    type?: string;
    status?: string;
    owner_id?: string;
    company_id?: string;
    deal_id?: string;
    limit?: number;
    offset?: number;
  }): Promise<ApiResponse<PaginatedResponse<Activity>>> {
    const queryParams = new URLSearchParams();
    if (params?.type) queryParams.set('type', params.type);
    if (params?.status) queryParams.set('status', params.status);
    if (params?.owner_id) queryParams.set('owner_id', params.owner_id);
    if (params?.company_id) queryParams.set('company_id', params.company_id);
    if (params?.deal_id) queryParams.set('deal_id', params.deal_id);
    if (params?.limit) queryParams.set('limit', params.limit.toString());
    if (params?.offset) queryParams.set('offset', params.offset.toString());

    return apiClient.get<PaginatedResponse<Activity>>(
      `/api/crm-v2/activities${queryParams.toString() ? `?${queryParams}` : ''}`
    );
  }

  // Analytics
  async getPipelineMetrics(): Promise<ApiResponse<PipelineMetrics[]>> {
    return apiClient.get<PipelineMetrics[]>('/api/crm-v2/analytics/pipeline');
  }

  async getDashboardStats(): Promise<ApiResponse<CRMDashboardStats>> {
    return apiClient.get<CRMDashboardStats>('/api/crm-v2/analytics/dashboard');
  }

  // AI Features
  async calculateLeadScore(contactId: string): Promise<ApiResponse<{ contact_id: string; lead_score: number }>> {
    return apiClient.post<{ contact_id: string; lead_score: number }>(
      `/api/crm-v2/contacts/${contactId}/calculate-score`,
      {}
    );
  }
}

export const crmV2Service = new CRMV2Service();
export default crmV2Service;
