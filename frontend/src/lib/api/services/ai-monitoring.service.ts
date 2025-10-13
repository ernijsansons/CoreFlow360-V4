import apiClient, { ApiResponse } from '../client'

export interface MonitoringDashboard {
  overview: {
    total_ai_requests_24h: number
    avg_response_time_ms: number
    error_rate: number
    cost_24h: number
    active_models: number
    active_workflows: number
  }
  model_health: Array<{
    model_id: string
    model_name: string
    status: 'healthy' | 'degraded' | 'down'
    uptime_percent: number
    error_rate: number
    avg_latency_ms: number
  }>
  recent_alerts: Array<{
    alert_id: string
    severity: 'low' | 'medium' | 'high' | 'critical'
    type: string
    message: string
    triggered_at: string
    resolved: boolean
  }>
  performance_trends: {
    latency: Array<{ timestamp: string; value: number }>
    throughput: Array<{ timestamp: string; value: number }>
    error_rate: Array<{ timestamp: string; value: number }>
  }
}

export interface ScheduledAudit {
  id: string
  audit_type: string
  schedule: 'daily' | 'weekly' | 'monthly'
  enabled: boolean
  last_run_at?: string
  next_run_at?: string
  config: Record<string, unknown>
}

export interface AuditExecution {
  execution_id: string
  audit_id: string
  status: 'pending' | 'running' | 'completed' | 'failed'
  started_at: string
  completed_at?: string
  duration_ms?: number
  findings_count?: number
  error?: string
}

export interface MonitoringAlert {
  id: string
  type: 'model_degradation' | 'high_latency' | 'high_error_rate' | 'cost_spike' | 'bias_detected'
  severity: 'low' | 'medium' | 'high' | 'critical'
  title: string
  message: string
  triggered_at: string
  resolved: boolean
  resolved_at?: string
  metadata?: Record<string, unknown>
}

export interface RealtimeMetrics {
  timestamp: string
  metrics: {
    requests_per_second: number
    avg_latency_ms: number
    error_rate: number
    active_connections: number
    queue_depth: number
  }
  model_metrics: Record<string, {
    requests: number
    latency_ms: number
    errors: number
  }>
}

class AIMonitoringService {
  async getDashboard(params?: {
    time_range?: '1h' | '24h' | '7d' | '30d'
  }): Promise<ApiResponse<MonitoringDashboard>> {
    const query = new URLSearchParams()
    if (params?.time_range) query.append('time_range', params.time_range)
    return apiClient.get<MonitoringDashboard>(`/api/ai-monitoring/dashboard?${query}`)
  }

  async listScheduledAudits(): Promise<ApiResponse<ScheduledAudit[]>> {
    return apiClient.get<ScheduledAudit[]>('/api/ai-monitoring/scheduled-audits')
  }

  async createScheduledAudit(data: {
    audit_type: string
    schedule: 'daily' | 'weekly' | 'monthly'
    config?: Record<string, unknown>
  }): Promise<ApiResponse<ScheduledAudit>> {
    return apiClient.post<ScheduledAudit>('/api/ai-monitoring/scheduled-audits', data)
  }

  async updateScheduledAudit(
    auditId: string,
    data: Partial<{
      schedule: 'daily' | 'weekly' | 'monthly'
      enabled: boolean
      config: Record<string, unknown>
    }>
  ): Promise<ApiResponse<ScheduledAudit>> {
    return apiClient.patch<ScheduledAudit>(`/api/ai-monitoring/scheduled-audits/${auditId}`, data)
  }

  async deleteScheduledAudit(auditId: string): Promise<ApiResponse<void>> {
    return apiClient.delete(`/api/ai-monitoring/scheduled-audits/${auditId}`)
  }

  async getAuditExecutionHistory(params?: {
    audit_id?: string
    status?: string
    limit?: number
    offset?: number
  }): Promise<ApiResponse<AuditExecution[]>> {
    const query = new URLSearchParams()
    if (params) {
      Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined) query.append(key, String(value))
      })
    }
    return apiClient.get<AuditExecution[]>(`/api/ai-monitoring/audit-executions?${query}`)
  }

  async getAuditExecution(executionId: string): Promise<ApiResponse<AuditExecution>> {
    return apiClient.get<AuditExecution>(`/api/ai-monitoring/audit-executions/${executionId}`)
  }

  async listAlerts(params?: {
    severity?: 'low' | 'medium' | 'high' | 'critical'
    resolved?: boolean
    limit?: number
    offset?: number
  }): Promise<ApiResponse<MonitoringAlert[]>> {
    const query = new URLSearchParams()
    if (params) {
      Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined) query.append(key, String(value))
      })
    }
    return apiClient.get<MonitoringAlert[]>(`/api/ai-monitoring/alerts?${query}`)
  }

  async resolveAlert(alertId: string, resolution_notes?: string): Promise<ApiResponse<MonitoringAlert>> {
    return apiClient.post<MonitoringAlert>(`/api/ai-monitoring/alerts/${alertId}/resolve`, {
      resolution_notes
    })
  }

  async acknowledgeAlert(alertId: string): Promise<ApiResponse<MonitoringAlert>> {
    return apiClient.post<MonitoringAlert>(`/api/ai-monitoring/alerts/${alertId}/acknowledge`)
  }

  async getRealtimeMetrics(): Promise<ApiResponse<RealtimeMetrics>> {
    return apiClient.get<RealtimeMetrics>('/api/ai-monitoring/metrics/realtime')
  }

  async subscribeToMetrics(callback: (metrics: RealtimeMetrics) => void): () => void {
    // WebSocket or SSE subscription for real-time metrics
    const eventSource = new EventSource(
      `${import.meta.env.VITE_API_URL}/api/ai-monitoring/metrics/stream`,
      {
        withCredentials: true
      }
    )

    eventSource.onmessage = (event) => {
      try {
        const metrics = JSON.parse(event.data)
        callback(metrics)
      } catch (error) {
        console.error('Failed to parse metrics:', error)
      }
    }

    // Return cleanup function
    return () => {
      eventSource.close()
    }
  }
}

export const aiMonitoringService = new AIMonitoringService()
export default aiMonitoringService
