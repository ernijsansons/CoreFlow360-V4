import apiClient, { ApiResponse } from '../client'

export interface DuplicateMatch {
  id: string
  entity_type: 'contact' | 'company'
  primary_id: string
  duplicate_id: string
  match_score: number
  confidence: 'low' | 'medium' | 'high'
  match_reasons: string[]
  auto_merge_eligible: boolean
  status: 'pending' | 'merged' | 'dismissed'
  detected_at: string
}

export interface DataQualityIssue {
  id: string
  entity_type: 'contact' | 'company' | 'lead' | 'deal'
  entity_id: string
  severity: 'low' | 'medium' | 'high' | 'critical'
  issue_type: string
  field_name?: string
  current_value?: string
  suggested_value?: string
  description: string
  auto_fixable: boolean
  resolved: boolean
  detected_at: string
}

export interface QualityScore {
  overall_score: number
  completeness_score: number
  accuracy_score: number
  freshness_score: number
  consistency_score: number
  issues_count: number
  critical_issues_count: number
}

export interface MergeStrategy {
  entity_type: 'contact' | 'company'
  primary_id: string
  duplicate_ids: string[]
  field_resolution: Record<string, 'primary' | 'duplicate' | 'merge'>
  preserve_history?: boolean
}

class CRMDataQualityService {
  // Duplicate Detection
  async findDuplicates(params: {
    entity_type: 'contact' | 'company'
    entity_id?: string
    threshold?: number
  }): Promise<ApiResponse<{
    matches: DuplicateMatch[]
    count: number
    high_confidence: number
    auto_merge_eligible: number
  }>> {
    return apiClient.post('/api/crm/data-quality/duplicates/find', params)
  }

  async scanForDuplicates(entity_type: 'contact' | 'company'): Promise<ApiResponse<{
    total_matches: number
    high_confidence: number
    auto_merge_eligible: number
    scan_completed_at: string
  }>> {
    return apiClient.post('/api/crm/data-quality/duplicates/scan', { entity_type })
  }

  async getPendingDuplicates(params?: {
    entity_type?: 'contact' | 'company'
    confidence?: 'low' | 'medium' | 'high'
  }): Promise<ApiResponse<DuplicateMatch[]>> {
    const query = new URLSearchParams()
    if (params?.entity_type) query.append('entity_type', params.entity_type)
    if (params?.confidence) query.append('confidence', params.confidence)
    return apiClient.get<DuplicateMatch[]>(`/api/crm/data-quality/duplicates/pending?${query}`)
  }

  async mergeDuplicates(strategy: MergeStrategy): Promise<ApiResponse<Record<string, unknown>>> {
    return apiClient.post('/api/crm/data-quality/duplicates/merge', strategy)
  }

  async dismissDuplicate(matchId: string): Promise<ApiResponse<void>> {
    return apiClient.post(`/api/crm/data-quality/duplicates/${matchId}/dismiss`)
  }

  // Data Quality Validation
  async validateEntity(params: {
    entity_type: 'contact' | 'company' | 'lead' | 'deal'
    entity_id: string
  }): Promise<ApiResponse<{
    quality_score: QualityScore
    issues: DataQualityIssue[]
  }>> {
    return apiClient.post('/api/crm/data-quality/validate', params)
  }

  async getQualityReport(): Promise<ApiResponse<Record<string, unknown>>> {
    return apiClient.get('/api/crm/data-quality/report')
  }

  async getQualityIssues(params?: {
    entity_type?: 'contact' | 'company' | 'lead' | 'deal'
    severity?: 'low' | 'medium' | 'high' | 'critical'
    resolved?: boolean
  }): Promise<ApiResponse<DataQualityIssue[]>> {
    const query = new URLSearchParams()
    if (params?.entity_type) query.append('entity_type', params.entity_type)
    if (params?.severity) query.append('severity', params.severity)
    if (params?.resolved !== undefined) query.append('resolved', String(params.resolved))
    return apiClient.get<DataQualityIssue[]>(`/api/crm/data-quality/issues?${query}`)
  }

  async autoFixIssues(params: {
    entity_type: 'contact' | 'company' | 'lead' | 'deal'
    entity_id: string
  }): Promise<ApiResponse<{
    fixed_count: number
    message: string
  }>> {
    return apiClient.post('/api/crm/data-quality/auto-fix', params)
  }

  async resolveIssue(issueId: string): Promise<ApiResponse<void>> {
    return apiClient.post(`/api/crm/data-quality/issues/${issueId}/resolve`)
  }

  async getDashboard(): Promise<ApiResponse<{
    quality_summary: Array<Record<string, unknown>>
    duplicate_summary: Array<Record<string, unknown>>
    recent_issues: DataQualityIssue[]
  }>> {
    return apiClient.get('/api/crm/data-quality/dashboard')
  }
}

export const crmDataQualityService = new CRMDataQualityService()
export default crmDataQualityService
