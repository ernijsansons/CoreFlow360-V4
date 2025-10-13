import apiClient, { ApiResponse } from '../client'

export interface MigrationConnection {
  source_type: 'salesforce' | 'hubspot' | 'pipedrive' | 'zoho' | 'csv' | 'excel'
  credentials: Record<string, unknown>
  test_mode?: boolean
}

export interface MigrationSchema {
  tables: Array<{
    name: string
    record_count: number
    columns: Array<{
      name: string
      type: string
      required: boolean
    }>
  }>
}

export interface MigrationMapping {
  source_table: string
  target_entity: 'contact' | 'company' | 'lead' | 'deal'
  field_mappings: Record<string, string>
  transformations?: Record<string, {
    type: 'date_format' | 'string_transform' | 'lookup' | 'custom'
    config: Record<string, unknown>
  }>
}

export interface Migration {
  id: string
  source_type: string
  status: 'pending' | 'running' | 'paused' | 'completed' | 'failed' | 'cancelled'
  progress: {
    total_records: number
    processed_records: number
    imported_records: number
    failed_records: number
    skipped_records: number
  }
  error_log?: Array<{
    record_id: string
    error: string
    timestamp: string
  }>
  started_at?: string
  completed_at?: string
  estimated_completion?: string
}

class MigrationService {
  async testConnection(connection: MigrationConnection): Promise<ApiResponse<{
    success: boolean
    source_type: string
    available_entities: string[]
    test_duration_ms: number
  }>> {
    return apiClient.post('/api/migration/test-connection', connection)
  }

  async discoverSchema(connection: MigrationConnection): Promise<ApiResponse<MigrationSchema>> {
    return apiClient.post<MigrationSchema>('/api/migration/discover-schema', connection)
  }

  async createMapping(data: {
    source_type: string
    mappings: MigrationMapping[]
  }): Promise<ApiResponse<{
    mapping_id: string
    validation_results: Array<{
      entity: string
      valid: boolean
      warnings: string[]
      errors: string[]
    }>
  }>> {
    return apiClient.post('/api/migration/create-mapping', data)
  }

  async createMigration(data: {
    source_connection: MigrationConnection
    mapping_id: string
    options?: {
      batch_size?: number
      skip_duplicates?: boolean
      update_existing?: boolean
    }
  }): Promise<ApiResponse<Migration>> {
    return apiClient.post<Migration>('/api/migration', data)
  }

  async getMigrationStatus(id: string): Promise<ApiResponse<Migration>> {
    return apiClient.get<Migration>(`/api/migration/${id}`)
  }

  async startMigration(id: string): Promise<ApiResponse<Migration>> {
    return apiClient.post<Migration>(`/api/migration/${id}/start`)
  }

  async pauseMigration(id: string): Promise<ApiResponse<Migration>> {
    return apiClient.post<Migration>(`/api/migration/${id}/pause`)
  }

  async resumeMigration(id: string): Promise<ApiResponse<Migration>> {
    return apiClient.post<Migration>(`/api/migration/${id}/resume`)
  }

  async cancelMigration(id: string): Promise<ApiResponse<void>> {
    return apiClient.post(`/api/migration/${id}/cancel`)
  }

  async getMigrationErrors(id: string, params?: {
    limit?: number
    offset?: number
  }): Promise<ApiResponse<Array<{
    record_id: string
    error: string
    timestamp: string
    retry_count: number
  }>>> {
    const query = new URLSearchParams()
    if (params) {
      Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined) query.append(key, String(value))
      })
    }
    return apiClient.get(`/api/migration/${id}/errors?${query}`)
  }

  async listMigrations(params?: {
    status?: 'pending' | 'running' | 'paused' | 'completed' | 'failed' | 'cancelled'
    limit?: number
    offset?: number
  }): Promise<ApiResponse<Migration[]>> {
    const query = new URLSearchParams()
    if (params) {
      Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined) query.append(key, String(value))
      })
    }
    return apiClient.get<Migration[]>(`/api/migration?${query}`)
  }
}

export const migrationService = new MigrationService()
export default migrationService
