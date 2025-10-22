import apiClient, { ApiResponse } from '../client'

export interface Anomaly {
  id: string
  type: 'financial' | 'transaction' | 'behavior' | 'data_quality'
  severity: 'low' | 'medium' | 'high' | 'critical'
  entity_type: string
  entity_id: string
  description: string
  detected_value: number | string
  expected_range?: { min: number; max: number }
  confidence_score: number
  status: 'new' | 'investigating' | 'resolved' | 'false_positive'
  detected_at: string
  resolved_at?: string
  resolution_notes?: string
}

export interface AnomalyScanResult {
  total_scanned: number
  anomalies_detected: number
  by_severity: {
    low: number
    medium: number
    high: number
    critical: number
  }
  scan_duration_ms: number
}

class AnomaliesService {
  async listAnomalies(params?: {
    type?: 'financial' | 'transaction' | 'behavior' | 'data_quality'
    severity?: 'low' | 'medium' | 'high' | 'critical'
    status?: 'new' | 'investigating' | 'resolved' | 'false_positive'
    limit?: number
    offset?: number
  }): Promise<ApiResponse<Anomaly[]>> {
    const query = new URLSearchParams()
    if (params) {
      Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined) query.append(key, String(value))
      })
    }
    return apiClient.get<Anomaly[]>(`/api/anomalies?${query}`)
  }

  async getAnomaly(id: string): Promise<ApiResponse<Anomaly>> {
    return apiClient.get<Anomaly>(`/api/anomalies/${id}`)
  }

  async scanForAnomalies(params?: {
    scan_type?: 'full' | 'incremental'
    entity_types?: string[]
  }): Promise<ApiResponse<AnomalyScanResult>> {
    return apiClient.post<AnomalyScanResult>('/api/anomalies/scan', params || {})
  }

  async resolveAnomaly(id: string, data: {
    resolution_notes: string
    action_taken?: string
  }): Promise<ApiResponse<Anomaly>> {
    return apiClient.post<Anomaly>(`/api/anomalies/${id}/resolve`, data)
  }

  async markAsFalsePositive(id: string, reason: string): Promise<ApiResponse<Anomaly>> {
    return apiClient.post<Anomaly>(`/api/anomalies/${id}/false-positive`, { reason })
  }

  async investigateAnomaly(id: string): Promise<ApiResponse<{
    anomaly: Anomaly
    related_data: Record<string, unknown>
    suggested_actions: string[]
  }>> {
    return apiClient.post(`/api/anomalies/${id}/investigate`)
  }

  async getAnomalyStats(params?: {
    from_date?: string
    to_date?: string
  }): Promise<ApiResponse<{
    total_anomalies: number
    by_type: Record<string, number>
    by_severity: Record<string, number>
    by_status: Record<string, number>
    resolution_rate: number
    avg_resolution_time_hours: number
  }>> {
    const query = new URLSearchParams()
    if (params) {
      Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined) query.append(key, String(value))
      })
    }
    return apiClient.get(`/api/anomalies/stats?${query}`)
  }
}

export const anomaliesService = new AnomaliesService()
export default anomaliesService
