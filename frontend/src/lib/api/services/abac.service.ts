import apiClient, { ApiResponse } from '../client'

export interface PermissionCheckRequest {
  capability: string
  resource: {
    type: string
    id?: string
    attributes?: Record<string, unknown>
  }
}

export interface PermissionCheckResult {
  allowed: boolean
  reason?: string
  fastPath?: string
  evaluationTimeMs: number
  cacheHit: boolean
  constraints?: Record<string, unknown>
  metadata?: {
    totalResponseTimeMs: number
    matched: number
    denied: number
  }
}

export interface BatchPermissionCheckResult {
  results: Record<string, boolean>
  details: Record<string, {
    allowed: boolean
    reason?: string
    evaluationTimeMs: number
  }>
  totalEvaluationTimeMs: number
  cacheHits: number
}

export interface Permission {
  capability: string
  description: string
  resource_types: string[]
  constraints?: Record<string, unknown>
}

export interface CapabilityIntrospection {
  capability: string
  description: string
  resource_types: string[]
  required_attributes?: string[]
  constraints?: Array<{
    type: string
    description: string
    parameters: Record<string, unknown>
  }>
}

class ABACService {
  async checkPermission(request: PermissionCheckRequest): Promise<ApiResponse<PermissionCheckResult>> {
    return apiClient.post<PermissionCheckResult>('/api/abac/check', request)
  }

  async checkBatchPermissions(
    capabilities: string[],
    resource: {
      type: string
      id?: string
      attributes?: Record<string, unknown>
    }
  ): Promise<ApiResponse<BatchPermissionCheckResult>> {
    return apiClient.post<BatchPermissionCheckResult>('/api/abac/check-batch', {
      capabilities,
      resource
    })
  }

  async getAllPermissions(): Promise<ApiResponse<Permission[]>> {
    return apiClient.get<Permission[]>('/api/abac/permissions')
  }

  async introspectCapability(capability: string): Promise<ApiResponse<CapabilityIntrospection>> {
    return apiClient.get<CapabilityIntrospection>(`/api/abac/capabilities/${capability}`)
  }

  async discoverCapabilities(params?: {
    resource_type?: string
    search?: string
  }): Promise<ApiResponse<CapabilityIntrospection[]>> {
    const query = new URLSearchParams()
    if (params?.resource_type) query.append('resource_type', params.resource_type)
    if (params?.search) query.append('search', params.search)
    return apiClient.get<CapabilityIntrospection[]>(`/api/abac/capabilities/discover?${query}`)
  }

  async debugPermission(request: PermissionCheckRequest): Promise<ApiResponse<{
    allowed: boolean
    evaluation_steps: Array<{
      step: string
      result: boolean
      details: Record<string, unknown>
    }>
    matched_rules: Array<{
      rule_id: string
      effect: 'allow' | 'deny'
      conditions: Record<string, unknown>
    }>
    final_decision: {
      reason: string
      timestamp: string
    }
  }>> {
    return apiClient.post('/api/abac/debug', request)
  }

  async invalidateCache(userId?: string): Promise<ApiResponse<{
    invalidated: number
    cache_cleared: boolean
  }>> {
    return apiClient.post('/api/abac/cache/invalidate', { userId })
  }

  async getCacheStats(): Promise<ApiResponse<{
    total_entries: number
    hit_rate: number
    avg_evaluation_time_ms: number
    cache_size_bytes: number
  }>> {
    return apiClient.get('/api/abac/cache/stats')
  }
}

export const abacService = new ABACService()
export default abacService
