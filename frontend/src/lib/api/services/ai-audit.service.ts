import apiClient, { ApiResponse } from '../client'

export interface AIAuditReport {
  audit_id: string
  audit_type: 'comprehensive' | 'model_performance' | 'workflow' | 'safety' | 'bias' | 'hallucination'
  status: 'running' | 'completed' | 'failed'
  started_at: string
  completed_at?: string
  results?: {
    overall_score: number
    findings: Array<{
      category: string
      severity: 'low' | 'medium' | 'high' | 'critical'
      description: string
      recommendation: string
    }>
    metrics: Record<string, number>
  }
}

export interface ModelPerformanceMetrics {
  model_id: string
  accuracy: number
  precision: number
  recall: number
  f1_score: number
  latency_p50_ms: number
  latency_p95_ms: number
  latency_p99_ms: number
  total_requests: number
  error_rate: number
  cost_per_request: number
}

export interface WorkflowAnalysis {
  workflow_id: string
  workflow_name: string
  total_executions: number
  success_rate: number
  avg_duration_ms: number
  automation_score: number
  bottlenecks: Array<{
    step: string
    avg_duration_ms: number
    failure_rate: number
  }>
  recommendations: string[]
}

export interface SafetyValidation {
  validation_id: string
  model_id: string
  safety_checks: Array<{
    check_type: string
    passed: boolean
    details: string
    severity?: 'low' | 'medium' | 'high' | 'critical'
  }>
  overall_safety_score: number
  risks_identified: number
  mitigations_suggested: number
}

export interface BiasDetection {
  detection_id: string
  dataset_id: string
  bias_metrics: {
    demographic_parity: number
    equal_opportunity: number
    disparate_impact: number
  }
  biased_features: Array<{
    feature_name: string
    bias_score: number
    affected_groups: string[]
  }>
  mitigation_strategies: string[]
}

export interface HallucinationDetection {
  detection_id: string
  model_id: string
  sample_size: number
  hallucination_rate: number
  examples: Array<{
    prompt: string
    response: string
    hallucination_detected: boolean
    confidence: number
    explanation: string
  }>
  recommendations: string[]
}

class AIAuditService {
  async runComprehensiveAudit(params?: {
    include_models?: boolean
    include_workflows?: boolean
    include_safety?: boolean
  }): Promise<ApiResponse<AIAuditReport>> {
    return apiClient.post<AIAuditReport>('/api/ai-audit/comprehensive', params || {})
  }

  async getAuditReport(auditId: string): Promise<ApiResponse<AIAuditReport>> {
    return apiClient.get<AIAuditReport>(`/api/ai-audit/reports/${auditId}`)
  }

  async listAuditReports(params?: {
    audit_type?: string
    status?: string
    limit?: number
    offset?: number
  }): Promise<ApiResponse<AIAuditReport[]>> {
    const query = new URLSearchParams()
    if (params) {
      Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined) query.append(key, String(value))
      })
    }
    return apiClient.get<AIAuditReport[]>(`/api/ai-audit/reports?${query}`)
  }

  async analyzeModelPerformance(modelId: string, params?: {
    from_date?: string
    to_date?: string
  }): Promise<ApiResponse<ModelPerformanceMetrics>> {
    const query = new URLSearchParams()
    if (params) {
      Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined) query.append(key, String(value))
      })
    }
    return apiClient.get<ModelPerformanceMetrics>(
      `/api/ai-audit/model-performance/${modelId}?${query}`
    )
  }

  async analyzeWorkflowAutomation(params?: {
    workflow_id?: string
    from_date?: string
    to_date?: string
  }): Promise<ApiResponse<WorkflowAnalysis[]>> {
    const query = new URLSearchParams()
    if (params) {
      Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined) query.append(key, String(value))
      })
    }
    return apiClient.get<WorkflowAnalysis[]>(`/api/ai-audit/workflow-analysis?${query}`)
  }

  async validateSafety(modelId: string): Promise<ApiResponse<SafetyValidation>> {
    return apiClient.post<SafetyValidation>('/api/ai-audit/safety-validation', { model_id: modelId })
  }

  async detectBias(datasetId: string, params?: {
    protected_attributes?: string[]
    fairness_metrics?: string[]
  }): Promise<ApiResponse<BiasDetection>> {
    return apiClient.post<BiasDetection>('/api/ai-audit/bias-detection', {
      dataset_id: datasetId,
      ...params
    })
  }

  async detectHallucinations(modelId: string, params?: {
    sample_size?: number
    test_prompts?: string[]
  }): Promise<ApiResponse<HallucinationDetection>> {
    return apiClient.post<HallucinationDetection>('/api/ai-audit/hallucination-detection', {
      model_id: modelId,
      ...params
    })
  }

  async exportAuditReport(auditId: string, format: 'pdf' | 'json' | 'csv'): Promise<Blob> {
    const response = await fetch(
      `${import.meta.env.VITE_API_URL}/api/ai-audit/reports/${auditId}/export?format=${format}`,
      {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`,
        },
      }
    )
    if (!response.ok) throw new Error('Failed to export audit report')
    return response.blob()
  }
}

export const aiAuditService = new AIAuditService()
export default aiAuditService
