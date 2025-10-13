import apiClient, { ApiResponse } from '../client'

export interface EnrichmentResult {
  lead_id: string
  enriched_data: {
    company?: {
      name: string
      domain: string
      industry: string
      employee_count?: number
      annual_revenue?: number
      location?: string
    }
    contact?: {
      full_name: string
      title: string
      email: string
      phone?: string
      linkedin_url?: string
      social_profiles?: Record<string, string>
    }
    score?: number
    signals?: string[]
  }
  data_sources: string[]
  confidence_score: number
  cost_credits: number
  enriched_at: string
}

export interface EnrichmentCostEstimate {
  lead_count: number
  estimated_credits: number
  estimated_cost_usd: number
  available_credits: number
  can_proceed: boolean
}

class EnrichmentService {
  async enrichLead(leadId: string, options?: {
    data_sources?: string[]
    fields?: string[]
  }): Promise<ApiResponse<EnrichmentResult>> {
    return apiClient.post<EnrichmentResult>(`/api/enrichment/lead/${leadId}`, options || {})
  }

  async bulkEnrichLeads(leadIds: string[], options?: {
    data_sources?: string[]
    fields?: string[]
  }): Promise<ApiResponse<{
    job_id: string
    total_leads: number
    estimated_credits: number
  }>> {
    return apiClient.post('/api/enrichment/bulk', {
      lead_ids: leadIds,
      ...options
    })
  }

  async getBulkEnrichmentStatus(jobId: string): Promise<ApiResponse<{
    job_id: string
    status: 'pending' | 'processing' | 'completed' | 'failed'
    progress: {
      total: number
      completed: number
      failed: number
    }
    results?: EnrichmentResult[]
  }>> {
    return apiClient.get(`/api/enrichment/bulk/${jobId}`)
  }

  async estimateEnrichmentCost(leadIds: string[]): Promise<ApiResponse<EnrichmentCostEstimate>> {
    return apiClient.post<EnrichmentCostEstimate>('/api/enrichment/estimate', {
      lead_ids: leadIds
    })
  }

  async validateDataSource(source: string): Promise<ApiResponse<{
    source: string
    available: boolean
    supported_fields: string[]
    cost_per_enrichment: number
  }>> {
    return apiClient.get(`/api/enrichment/sources/${source}/validate`)
  }

  async listDataSources(): Promise<ApiResponse<Array<{
    source: string
    name: string
    description: string
    supported_fields: string[]
    cost_per_enrichment: number
    enabled: boolean
  }>>> {
    return apiClient.get('/api/enrichment/sources')
  }

  async getEnrichmentHistory(params?: {
    lead_id?: string
    limit?: number
    offset?: number
  }): Promise<ApiResponse<EnrichmentResult[]>> {
    const query = new URLSearchParams()
    if (params) {
      Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined) query.append(key, String(value))
      })
    }
    return apiClient.get<EnrichmentResult[]>(`/api/enrichment/history?${query}`)
  }
}

export const enrichmentService = new EnrichmentService()
export default enrichmentService
