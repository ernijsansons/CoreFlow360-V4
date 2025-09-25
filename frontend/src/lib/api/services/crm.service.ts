import apiClient, { ApiResponse } from '../client'
import type { Lead, Contact, Company, LeadStatus } from '../types'

export interface CreateLeadRequest {
  companyName: string
  contactName: string
  email: string
  phone?: string
  source: string
  notes?: string
  tags?: string[]
}

export interface UpdateLeadRequest {
  status?: LeadStatus
  score?: number
  assignedTo?: string
  tags?: string[]
  notes?: string
  metadata?: Record<string, any>
}

export interface LeadQualificationRequest {
  leadId: string
  score: number
  criteria: Record<string, boolean>
  notes?: string
}

export interface ConvertLeadRequest {
  leadId: string
  createCompany?: boolean
  createContact?: boolean
  opportunityName?: string
  expectedRevenue?: number
  expectedCloseDate?: string
}

class CRMService {
  // Lead Management
  async getLeads(params?: {
    page?: number
    limit?: number
    status?: LeadStatus
    assignedTo?: string
    search?: string
    sort?: string
  }): Promise<ApiResponse<Lead[]>> {
    const query = new URLSearchParams()
    if (params) {
      Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined) query.append(key, String(value))
      })
    }
    return apiClient.get<Lead[]>(`/api/crm/leads?${query}`)
  }

  async getLead(id: string): Promise<ApiResponse<Lead>> {
    return apiClient.get<Lead>(`/api/crm/leads/${id}`)
  }

  async createLead(data: CreateLeadRequest): Promise<ApiResponse<Lead>> {
    return apiClient.post<Lead>('/api/crm/leads', data)
  }

  async updateLead(id: string, data: UpdateLeadRequest): Promise<ApiResponse<Lead>> {
    return apiClient.patch<Lead>(`/api/crm/leads/${id}`, data)
  }

  async deleteLead(id: string): Promise<ApiResponse<void>> {
    return apiClient.delete<void>(`/api/crm/leads/${id}`)
  }

  async qualifyLead(data: LeadQualificationRequest): Promise<ApiResponse<Lead>> {
    return apiClient.post<Lead>(`/api/crm/leads/${data.leadId}/qualify`, data)
  }

  async convertLead(data: ConvertLeadRequest): Promise<ApiResponse<{
    company?: Company
    contact?: Contact
    opportunity?: any
  }>> {
    return apiClient.post(`/api/crm/leads/${data.leadId}/convert`, data)
  }

  async assignLead(leadId: string, userId: string): Promise<ApiResponse<Lead>> {
    return apiClient.post<Lead>(`/api/crm/leads/${leadId}/assign`, { userId })
  }

  async bulkAssignLeads(leadIds: string[], userId: string): Promise<ApiResponse<void>> {
    return apiClient.post<void>('/api/crm/leads/bulk-assign', {
      leadIds,
      userId,
    })
  }

  // Contact Management
  async getContacts(params?: {
    page?: number
    limit?: number
    companyId?: string
    search?: string
    sort?: string
  }): Promise<ApiResponse<Contact[]>> {
    const query = new URLSearchParams()
    if (params) {
      Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined) query.append(key, String(value))
      })
    }
    return apiClient.get<Contact[]>(`/api/crm/contacts?${query}`)
  }

  async getContact(id: string): Promise<ApiResponse<Contact>> {
    return apiClient.get<Contact>(`/api/crm/contacts/${id}`)
  }

  async createContact(data: Partial<Contact>): Promise<ApiResponse<Contact>> {
    return apiClient.post<Contact>('/api/crm/contacts', data)
  }

  async updateContact(id: string, data: Partial<Contact>): Promise<ApiResponse<Contact>> {
    return apiClient.patch<Contact>(`/api/crm/contacts/${id}`, data)
  }

  async deleteContact(id: string): Promise<ApiResponse<void>> {
    return apiClient.delete<void>(`/api/crm/contacts/${id}`)
  }

  async mergeContacts(
    primaryId: string,
    duplicateIds: string[]
  ): Promise<ApiResponse<Contact>> {
    return apiClient.post<Contact>(`/api/crm/contacts/${primaryId}/merge`, {
      duplicateIds,
    })
  }

  // Company Management
  async getCompanies(params?: {
    page?: number
    limit?: number
    industry?: string
    search?: string
    sort?: string
  }): Promise<ApiResponse<Company[]>> {
    const query = new URLSearchParams()
    if (params) {
      Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined) query.append(key, String(value))
      })
    }
    return apiClient.get<Company[]>(`/api/crm/companies?${query}`)
  }

  async getCompany(id: string): Promise<ApiResponse<Company>> {
    return apiClient.get<Company>(`/api/crm/companies/${id}`)
  }

  async createCompany(data: Partial<Company>): Promise<ApiResponse<Company>> {
    return apiClient.post<Company>('/api/crm/companies', data)
  }

  async updateCompany(id: string, data: Partial<Company>): Promise<ApiResponse<Company>> {
    return apiClient.patch<Company>(`/api/crm/companies/${id}`, data)
  }

  async deleteCompany(id: string): Promise<ApiResponse<void>> {
    return apiClient.delete<void>(`/api/crm/companies/${id}`)
  }

  async enrichCompany(id: string): Promise<ApiResponse<Company>> {
    return apiClient.post<Company>(`/api/crm/companies/${id}/enrich`)
  }

  // Activity Management
  async getActivities(params?: {
    entityType?: 'lead' | 'contact' | 'company'
    entityId?: string
    type?: string
    userId?: string
    startDate?: string
    endDate?: string
  }): Promise<ApiResponse<any[]>> {
    const query = new URLSearchParams()
    if (params) {
      Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined) query.append(key, String(value))
      })
    }
    return apiClient.get<any[]>(`/api/crm/activities?${query}`)
  }

  async createActivity(data: {
    type: 'call' | 'email' | 'meeting' | 'task' | 'note'
    entityType: 'lead' | 'contact' | 'company'
    entityId: string
    subject: string
    description?: string
    dueDate?: string
    assignedTo?: string
  }): Promise<ApiResponse<any>> {
    return apiClient.post('/api/crm/activities', data)
  }

  async updateActivity(id: string, data: any): Promise<ApiResponse<any>> {
    return apiClient.patch(`/api/crm/activities/${id}`, data)
  }

  async completeActivity(id: string): Promise<ApiResponse<any>> {
    return apiClient.post(`/api/crm/activities/${id}/complete`)
  }

  // Pipeline Management
  async getPipelines(): Promise<ApiResponse<any[]>> {
    return apiClient.get('/api/crm/pipelines')
  }

  async getPipelineStages(pipelineId: string): Promise<ApiResponse<any[]>> {
    return apiClient.get(`/api/crm/pipelines/${pipelineId}/stages`)
  }

  async moveLeadToStage(
    leadId: string,
    stageId: string
  ): Promise<ApiResponse<Lead>> {
    return apiClient.post<Lead>(`/api/crm/leads/${leadId}/move-stage`, {
      stageId,
    })
  }

  // Reports and Analytics
  async getLeadAnalytics(params?: {
    startDate?: string
    endDate?: string
    groupBy?: 'source' | 'status' | 'assignee'
  }): Promise<ApiResponse<any>> {
    const query = new URLSearchParams()
    if (params) {
      Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined) query.append(key, String(value))
      })
    }
    return apiClient.get(`/api/crm/analytics/leads?${query}`)
  }

  async getConversionRates(params?: {
    startDate?: string
    endDate?: string
  }): Promise<ApiResponse<any>> {
    const query = new URLSearchParams()
    if (params) {
      Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined) query.append(key, String(value))
      })
    }
    return apiClient.get(`/api/crm/analytics/conversion-rates?${query}`)
  }

  async getSalesForcast(params?: {
    period?: 'month' | 'quarter' | 'year'
  }): Promise<ApiResponse<any>> {
    const query = new URLSearchParams()
    if (params) {
      Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined) query.append(key, String(value))
      })
    }
    return apiClient.get(`/api/crm/analytics/forecast?${query}`)
  }

  // Import/Export
  async importContacts(file: File): Promise<ApiResponse<{
    imported: number
    failed: number
    errors?: any[]
  }>> {
    const formData = new FormData()
    formData.append('file', file)
    return apiClient.post('/api/crm/import/contacts', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    })
  }

  async exportContacts(format: 'csv' | 'excel'): Promise<Blob> {
    const response = await fetch(
      `${import.meta.env.VITE_API_URL}/api/crm/export/contacts?format=${format}`,
      {
        headers: {
          'Authorization': `Bearer ${useAuthStore.getState().token}`,
        },
      }
    )
    return response.blob()
  }
}

export const crmService = new CRMService()
export default crmService