import apiClient, { ApiResponse } from '../client'

export interface InteractionOutcome {
  id: string
  interaction_type: 'email' | 'call' | 'meeting' | 'demo' | 'proposal'
  lead_id?: string
  contact_id?: string
  outcome: 'positive' | 'neutral' | 'negative' | 'no_response'
  context: Record<string, unknown>
  recorded_at: string
}

export interface LearningMetrics {
  total_interactions: number
  success_rate: number
  avg_conversion_time_days: number
  top_performing_approaches: Array<{
    approach: string
    success_rate: number
    sample_size: number
  }>
  underperforming_areas: Array<{
    area: string
    success_rate: number
    improvement_potential: number
  }>
}

export interface Pattern {
  pattern_id: string
  pattern_type: 'successful_sequence' | 'risk_indicator' | 'churn_predictor' | 'conversion_path'
  description: string
  confidence: number
  observed_count: number
  success_rate: number
  key_factors: string[]
  recommendations: string[]
}

export interface Playbook {
  id: string
  name: string
  description: string
  use_case: string
  steps: Array<{
    step_number: number
    action: string
    timing: string
    success_criteria: string
  }>
  success_rate: number
  times_used: number
  avg_conversion_rate: number
  created_at: string
  updated_at: string
}

export interface Experiment {
  id: string
  name: string
  hypothesis: string
  variant_a: {
    name: string
    description: string
    sample_size: number
    conversion_rate?: number
  }
  variant_b: {
    name: string
    description: string
    sample_size: number
    conversion_rate?: number
  }
  status: 'draft' | 'running' | 'completed' | 'cancelled'
  start_date?: string
  end_date?: string
  winner?: 'a' | 'b' | 'inconclusive'
  statistical_significance?: number
}

class LearningService {
  // Interaction Recording
  async recordOutcome(data: {
    interaction_type: 'email' | 'call' | 'meeting' | 'demo' | 'proposal'
    lead_id?: string
    contact_id?: string
    outcome: 'positive' | 'neutral' | 'negative' | 'no_response'
    context?: Record<string, unknown>
    notes?: string
  }): Promise<ApiResponse<InteractionOutcome>> {
    return apiClient.post<InteractionOutcome>('/api/learning/outcomes', data)
  }

  async bulkRecordOutcomes(
    outcomes: Array<{
      interaction_type: string
      lead_id?: string
      contact_id?: string
      outcome: string
      context?: Record<string, unknown>
    }>
  ): Promise<ApiResponse<{
    recorded: number
    failed: number
  }>> {
    return apiClient.post('/api/learning/outcomes/bulk', { outcomes })
  }

  // Learning Metrics
  async getMetrics(params?: {
    from_date?: string
    to_date?: string
    interaction_type?: string
  }): Promise<ApiResponse<LearningMetrics>> {
    const query = new URLSearchParams()
    if (params) {
      Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined) query.append(key, String(value))
      })
    }
    return apiClient.get<LearningMetrics>(`/api/learning/metrics?${query}`)
  }

  // Pattern Analysis
  async analyzePatterns(params?: {
    pattern_type?: string
    min_confidence?: number
    min_sample_size?: number
  }): Promise<ApiResponse<Pattern[]>> {
    const query = new URLSearchParams()
    if (params) {
      Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined) query.append(key, String(value))
      })
    }
    return apiClient.get<Pattern[]>(`/api/learning/patterns?${query}`)
  }

  async getPattern(patternId: string): Promise<ApiResponse<Pattern>> {
    return apiClient.get<Pattern>(`/api/learning/patterns/${patternId}`)
  }

  // Playbook Management
  async listPlaybooks(params?: {
    use_case?: string
    min_success_rate?: number
  }): Promise<ApiResponse<Playbook[]>> {
    const query = new URLSearchParams()
    if (params) {
      Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined) query.append(key, String(value))
      })
    }
    return apiClient.get<Playbook[]>(`/api/learning/playbooks?${query}`)
  }

  async getPlaybook(playbookId: string): Promise<ApiResponse<Playbook>> {
    return apiClient.get<Playbook>(`/api/learning/playbooks/${playbookId}`)
  }

  async generatePlaybook(data: {
    pattern_id: string
    name: string
    description: string
  }): Promise<ApiResponse<Playbook>> {
    return apiClient.post<Playbook>('/api/learning/playbooks/generate', data)
  }

  async createCustomPlaybook(data: {
    name: string
    description: string
    use_case: string
    steps: Array<{
      action: string
      timing: string
      success_criteria: string
    }>
  }): Promise<ApiResponse<Playbook>> {
    return apiClient.post<Playbook>('/api/learning/playbooks', data)
  }

  async updatePlaybook(
    playbookId: string,
    data: Partial<Playbook>
  ): Promise<ApiResponse<Playbook>> {
    return apiClient.patch<Playbook>(`/api/learning/playbooks/${playbookId}`, data)
  }

  async deletePlaybook(playbookId: string): Promise<ApiResponse<void>> {
    return apiClient.delete(`/api/learning/playbooks/${playbookId}`)
  }

  // Experiment Management
  async listExperiments(params?: {
    status?: 'draft' | 'running' | 'completed' | 'cancelled'
  }): Promise<ApiResponse<Experiment[]>> {
    const query = new URLSearchParams()
    if (params?.status) query.append('status', params.status)
    return apiClient.get<Experiment[]>(`/api/learning/experiments?${query}`)
  }

  async getExperiment(experimentId: string): Promise<ApiResponse<Experiment>> {
    return apiClient.get<Experiment>(`/api/learning/experiments/${experimentId}`)
  }

  async createExperiment(data: {
    name: string
    hypothesis: string
    variant_a: {
      name: string
      description: string
    }
    variant_b: {
      name: string
      description: string
    }
  }): Promise<ApiResponse<Experiment>> {
    return apiClient.post<Experiment>('/api/learning/experiments', data)
  }

  async startExperiment(experimentId: string): Promise<ApiResponse<Experiment>> {
    return apiClient.post<Experiment>(`/api/learning/experiments/${experimentId}/start`)
  }

  async stopExperiment(experimentId: string): Promise<ApiResponse<Experiment>> {
    return apiClient.post<Experiment>(`/api/learning/experiments/${experimentId}/stop`)
  }

  async getExperimentResults(experimentId: string): Promise<ApiResponse<{
    experiment: Experiment
    results: {
      variant_a_performance: number
      variant_b_performance: number
      lift: number
      p_value: number
      confidence_interval: { lower: number; upper: number }
      recommendation: string
    }
  }>> {
    return apiClient.get(`/api/learning/experiments/${experimentId}/results`)
  }
}

export const learningService = new LearningService()
export default learningService
