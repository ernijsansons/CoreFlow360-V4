import apiClient, { ApiResponse } from '../client'

export interface TelemetryEvent {
  event_id: string
  event_type: string
  timestamp: string
  source: string
  metadata: Record<string, unknown>
}

export interface Metric {
  metric_name: string
  value: number
  unit: string
  timestamp: string
  tags: Record<string, string>
}

export interface Trace {
  trace_id: string
  span_id: string
  parent_span_id?: string
  operation_name: string
  start_time: string
  duration_ms: number
  status: 'ok' | 'error'
  tags: Record<string, string>
  logs?: Array<{
    timestamp: string
    message: string
    level: 'debug' | 'info' | 'warn' | 'error'
  }>
}

export interface AIAnalytics {
  total_ai_requests: number
  unique_users: number
  avg_response_time_ms: number
  top_capabilities: Array<{
    capability: string
    request_count: number
    avg_latency_ms: number
    error_rate: number
  }>
  cost_breakdown: Array<{
    model: string
    total_cost: number
    request_count: number
    avg_cost_per_request: number
  }>
  trends: {
    daily_requests: Array<{ date: string; count: number }>
    daily_cost: Array<{ date: string; cost: number }>
  }
}

export interface Alert {
  id: string
  rule_id: string
  severity: 'info' | 'warning' | 'error' | 'critical'
  title: string
  description: string
  triggered_at: string
  resolved_at?: string
  status: 'active' | 'resolved' | 'acknowledged'
  metadata?: Record<string, unknown>
}

export interface SelfHealingAction {
  id: string
  trigger_type: string
  action_type: string
  status: 'pending' | 'in_progress' | 'completed' | 'failed'
  triggered_at: string
  completed_at?: string
  result?: {
    success: boolean
    message: string
    actions_taken: string[]
  }
}

class ObservabilityService {
  // Telemetry
  async collectTelemetry(events: TelemetryEvent[]): Promise<ApiResponse<{
    collected: number
    failed: number
  }>> {
    return apiClient.post('/api/observability/telemetry', { events })
  }

  async getTelemetryEvents(params?: {
    event_type?: string
    source?: string
    from_time?: string
    to_time?: string
    limit?: number
  }): Promise<ApiResponse<TelemetryEvent[]>> {
    const query = new URLSearchParams()
    if (params) {
      Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined) query.append(key, String(value))
      })
    }
    return apiClient.get<TelemetryEvent[]>(`/api/observability/telemetry?${query}`)
  }

  // Metrics
  async collectMetrics(metrics: Metric[]): Promise<ApiResponse<{
    collected: number
    failed: number
  }>> {
    return apiClient.post('/api/observability/metrics', { metrics })
  }

  async queryMetrics(params: {
    metric_name: string
    aggregation?: 'sum' | 'avg' | 'min' | 'max' | 'count'
    from_time: string
    to_time: string
    tags?: Record<string, string>
  }): Promise<ApiResponse<{
    metric_name: string
    data_points: Array<{
      timestamp: string
      value: number
    }>
  }>> {
    return apiClient.post('/api/observability/metrics/query', params)
  }

  // Traces
  async collectTraces(traces: Trace[]): Promise<ApiResponse<{
    collected: number
    failed: number
  }>> {
    return apiClient.post('/api/observability/traces', { traces })
  }

  async getTrace(traceId: string): Promise<ApiResponse<{
    trace_id: string
    spans: Trace[]
    total_duration_ms: number
  }>> {
    return apiClient.get(`/api/observability/traces/${traceId}`)
  }

  async searchTraces(params?: {
    operation_name?: string
    status?: 'ok' | 'error'
    min_duration_ms?: number
    from_time?: string
    to_time?: string
    limit?: number
  }): Promise<ApiResponse<Trace[]>> {
    const query = new URLSearchParams()
    if (params) {
      Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined) query.append(key, String(value))
      })
    }
    return apiClient.get<Trace[]>(`/api/observability/traces?${query}`)
  }

  // AI Analytics
  async getAIAnalytics(params?: {
    from_date?: string
    to_date?: string
    group_by?: 'hour' | 'day' | 'week'
  }): Promise<ApiResponse<AIAnalytics>> {
    const query = new URLSearchParams()
    if (params) {
      Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined) query.append(key, String(value))
      })
    }
    return apiClient.get<AIAnalytics>(`/api/observability/ai-analytics?${query}`)
  }

  // Alerts
  async listAlerts(params?: {
    severity?: 'info' | 'warning' | 'error' | 'critical'
    status?: 'active' | 'resolved' | 'acknowledged'
    limit?: number
    offset?: number
  }): Promise<ApiResponse<Alert[]>> {
    const query = new URLSearchParams()
    if (params) {
      Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined) query.append(key, String(value))
      })
    }
    return apiClient.get<Alert[]>(`/api/observability/alerts?${query}`)
  }

  async acknowledgeAlert(alertId: string): Promise<ApiResponse<Alert>> {
    return apiClient.post<Alert>(`/api/observability/alerts/${alertId}/acknowledge`)
  }

  async resolveAlert(alertId: string, resolution_notes: string): Promise<ApiResponse<Alert>> {
    return apiClient.post<Alert>(`/api/observability/alerts/${alertId}/resolve`, {
      resolution_notes
    })
  }

  // Self-Healing
  async listSelfHealingActions(params?: {
    status?: 'pending' | 'in_progress' | 'completed' | 'failed'
    limit?: number
  }): Promise<ApiResponse<SelfHealingAction[]>> {
    const query = new URLSearchParams()
    if (params) {
      Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined) query.append(key, String(value))
      })
    }
    return apiClient.get<SelfHealingAction[]>(`/api/observability/self-healing?${query}`)
  }

  async getSelfHealingAction(actionId: string): Promise<ApiResponse<SelfHealingAction>> {
    return apiClient.get<SelfHealingAction>(`/api/observability/self-healing/${actionId}`)
  }

  async triggerSelfHealing(params: {
    trigger_type: string
    metadata?: Record<string, unknown>
  }): Promise<ApiResponse<SelfHealingAction>> {
    return apiClient.post<SelfHealingAction>('/api/observability/self-healing/trigger', params)
  }
}

export const observabilityService = new ObservabilityService()
export default observabilityService
