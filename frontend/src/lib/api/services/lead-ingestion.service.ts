import apiClient, { ApiResponse } from '../client'

export interface WebhookConfig {
  id: string
  source: 'meta' | 'google' | 'linkedin' | 'custom'
  webhook_url: string
  enabled: boolean
  secret_token?: string
  created_at: string
  last_received_at?: string
  total_received: number
}

export interface IngestedLead {
  id: string
  source: string
  raw_data: Record<string, unknown>
  processed_data: {
    company_name?: string
    contact_name?: string
    email?: string
    phone?: string
    notes?: string
  }
  status: 'pending' | 'processed' | 'failed'
  created_at: string
  processed_at?: string
  error?: string
}

export interface FormSubmission {
  id: string
  form_id: string
  form_name: string
  submitted_data: Record<string, unknown>
  ip_address?: string
  user_agent?: string
  submitted_at: string
  lead_created: boolean
  lead_id?: string
}

class LeadIngestionService {
  // Webhook Management
  async listWebhooks(): Promise<ApiResponse<WebhookConfig[]>> {
    return apiClient.get<WebhookConfig[]>('/api/lead-ingestion/webhooks')
  }

  async getWebhook(webhookId: string): Promise<ApiResponse<WebhookConfig>> {
    return apiClient.get<WebhookConfig>(`/api/lead-ingestion/webhooks/${webhookId}`)
  }

  async createWebhook(data: {
    source: 'meta' | 'google' | 'linkedin' | 'custom'
    config?: Record<string, unknown>
  }): Promise<ApiResponse<WebhookConfig>> {
    return apiClient.post<WebhookConfig>('/api/lead-ingestion/webhooks', data)
  }

  async updateWebhook(
    webhookId: string,
    data: Partial<{
      enabled: boolean
      config: Record<string, unknown>
    }>
  ): Promise<ApiResponse<WebhookConfig>> {
    return apiClient.patch<WebhookConfig>(`/api/lead-ingestion/webhooks/${webhookId}`, data)
  }

  async deleteWebhook(webhookId: string): Promise<ApiResponse<void>> {
    return apiClient.delete(`/api/lead-ingestion/webhooks/${webhookId}`)
  }

  async regenerateWebhookSecret(webhookId: string): Promise<ApiResponse<{
    secret_token: string
  }>> {
    return apiClient.post(`/api/lead-ingestion/webhooks/${webhookId}/regenerate-secret`)
  }

  // Lead Ingestion
  async listIngestedLeads(params?: {
    source?: string
    status?: 'pending' | 'processed' | 'failed'
    from_date?: string
    to_date?: string
    limit?: number
    offset?: number
  }): Promise<ApiResponse<IngestedLead[]>> {
    const query = new URLSearchParams()
    if (params) {
      Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined) query.append(key, String(value))
      })
    }
    return apiClient.get<IngestedLead[]>(`/api/lead-ingestion/leads?${query}`)
  }

  async getIngestedLead(leadId: string): Promise<ApiResponse<IngestedLead>> {
    return apiClient.get<IngestedLead>(`/api/lead-ingestion/leads/${leadId}`)
  }

  async reprocessLead(leadId: string): Promise<ApiResponse<IngestedLead>> {
    return apiClient.post<IngestedLead>(`/api/lead-ingestion/leads/${leadId}/reprocess`)
  }

  // Real-time Chat
  async submitChatLead(data: {
    name?: string
    email?: string
    phone?: string
    message: string
    page_url?: string
    metadata?: Record<string, unknown>
  }): Promise<ApiResponse<{
    lead_id: string
    auto_response?: string
  }>> {
    return apiClient.post('/api/lead-ingestion/chat', data)
  }

  // Email Ingestion
  async processInboundEmail(data: {
    from: string
    subject: string
    body: string
    headers?: Record<string, string>
  }): Promise<ApiResponse<{
    lead_id?: string
    contact_id?: string
    conversation_id?: string
  }>> {
    return apiClient.post('/api/lead-ingestion/email', data)
  }

  // Form Submissions
  async submitForm(data: {
    form_id: string
    fields: Record<string, unknown>
    metadata?: Record<string, unknown>
  }): Promise<ApiResponse<FormSubmission>> {
    return apiClient.post<FormSubmission>('/api/lead-ingestion/form', data)
  }

  async listFormSubmissions(params?: {
    form_id?: string
    from_date?: string
    to_date?: string
    limit?: number
    offset?: number
  }): Promise<ApiResponse<FormSubmission[]>> {
    const query = new URLSearchParams()
    if (params) {
      Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined) query.append(key, String(value))
      })
    }
    return apiClient.get<FormSubmission[]>(`/api/lead-ingestion/forms?${query}`)
  }

  // Statistics
  async getIngestionStats(params?: {
    from_date?: string
    to_date?: string
    group_by?: 'hour' | 'day' | 'week'
  }): Promise<ApiResponse<{
    total_leads: number
    by_source: Record<string, number>
    success_rate: number
    avg_processing_time_ms: number
    trends: Array<{
      timestamp: string
      count: number
    }>
  }>> {
    const query = new URLSearchParams()
    if (params) {
      Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined) query.append(key, String(value))
      })
    }
    return apiClient.get(`/api/lead-ingestion/stats?${query}`)
  }
}

export const leadIngestionService = new LeadIngestionService()
export default leadIngestionService
