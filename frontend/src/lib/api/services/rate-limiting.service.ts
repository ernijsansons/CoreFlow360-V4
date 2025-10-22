import apiClient, { ApiResponse } from '../client'

export interface RateLimitConfig {
  rule_id: string
  endpoint_pattern: string
  method?: string
  limit_type: 'requests_per_minute' | 'requests_per_hour' | 'requests_per_day'
  limit_value: number
  user_specific: boolean
  ip_specific: boolean
  enabled: boolean
  created_at: string
  updated_at: string
}

export interface RateLimitStatus {
  endpoint: string
  current_usage: number
  limit: number
  reset_at: string
  remaining: number
  percentage_used: number
  throttled: boolean
}

export interface RateLimitViolation {
  id: string
  user_id?: string
  ip_address?: string
  endpoint: string
  timestamp: string
  attempted_requests: number
  limit: number
  blocked: boolean
}

class RateLimitingService {
  async getConfigurations(): Promise<ApiResponse<RateLimitConfig[]>> {
    return apiClient.get<RateLimitConfig[]>('/api/rate-limiting/config')
  }

  async getConfiguration(ruleId: string): Promise<ApiResponse<RateLimitConfig>> {
    return apiClient.get<RateLimitConfig>(`/api/rate-limiting/config/${ruleId}`)
  }

  async createConfiguration(data: {
    endpoint_pattern: string
    method?: string
    limit_type: 'requests_per_minute' | 'requests_per_hour' | 'requests_per_day'
    limit_value: number
    user_specific?: boolean
    ip_specific?: boolean
  }): Promise<ApiResponse<RateLimitConfig>> {
    return apiClient.post<RateLimitConfig>('/api/rate-limiting/config', data)
  }

  async updateConfiguration(
    ruleId: string,
    data: Partial<{
      limit_value: number
      enabled: boolean
      user_specific: boolean
      ip_specific: boolean
    }>
  ): Promise<ApiResponse<RateLimitConfig>> {
    return apiClient.patch<RateLimitConfig>(`/api/rate-limiting/config/${ruleId}`, data)
  }

  async deleteConfiguration(ruleId: string): Promise<ApiResponse<void>> {
    return apiClient.delete(`/api/rate-limiting/config/${ruleId}`)
  }

  async getStatus(endpoint?: string): Promise<ApiResponse<RateLimitStatus[]>> {
    const query = endpoint ? `?endpoint=${encodeURIComponent(endpoint)}` : ''
    return apiClient.get<RateLimitStatus[]>(`/api/rate-limiting/status${query}`)
  }

  async getCurrentUserStatus(): Promise<ApiResponse<RateLimitStatus[]>> {
    return apiClient.get<RateLimitStatus[]>('/api/rate-limiting/status/me')
  }

  async listViolations(params?: {
    user_id?: string
    ip_address?: string
    endpoint?: string
    from_date?: string
    to_date?: string
    limit?: number
    offset?: number
  }): Promise<ApiResponse<RateLimitViolation[]>> {
    const query = new URLSearchParams()
    if (params) {
      Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined) query.append(key, String(value))
      })
    }
    return apiClient.get<RateLimitViolation[]>(`/api/rate-limiting/violations?${query}`)
  }

  async getViolationStats(params?: {
    from_date?: string
    to_date?: string
    group_by?: 'hour' | 'day' | 'week'
  }): Promise<ApiResponse<{
    total_violations: number
    unique_users: number
    unique_ips: number
    by_endpoint: Record<string, number>
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
    return apiClient.get(`/api/rate-limiting/stats?${query}`)
  }

  async resetUserLimit(userId: string, endpoint?: string): Promise<ApiResponse<{
    reset: boolean
    endpoints_affected: string[]
  }>> {
    return apiClient.post('/api/rate-limiting/reset', {
      user_id: userId,
      endpoint
    })
  }

  async whitelistIP(ipAddress: string, reason?: string): Promise<ApiResponse<{
    whitelisted: boolean
    expires_at?: string
  }>> {
    return apiClient.post('/api/rate-limiting/whitelist', {
      ip_address: ipAddress,
      reason
    })
  }

  async blacklistIP(ipAddress: string, reason: string, duration?: number): Promise<ApiResponse<{
    blacklisted: boolean
    expires_at?: string
  }>> {
    return apiClient.post('/api/rate-limiting/blacklist', {
      ip_address: ipAddress,
      reason,
      duration_hours: duration
    })
  }

  async removeFromList(ipAddress: string, listType: 'whitelist' | 'blacklist'): Promise<ApiResponse<void>> {
    return apiClient.delete(`/api/rate-limiting/${listType}/${encodeURIComponent(ipAddress)}`)
  }
}

export const rateLimitingService = new RateLimitingService()
export default rateLimitingService
