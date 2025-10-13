import apiClient, { ApiResponse } from '../client'

export interface ExportRequest {
  id: string
  export_type: 'contacts' | 'leads' | 'invoices' | 'transactions' | 'financial_report'
  format: 'csv' | 'excel' | 'pdf' | 'json'
  status: 'pending' | 'processing' | 'completed' | 'failed'
  progress_percent: number
  total_records?: number
  processed_records?: number
  file_size?: number
  download_url?: string
  error_message?: string
  created_at: string
  completed_at?: string
  expires_at?: string
}

class ExportService {
  async createExport(data: {
    export_type: 'contacts' | 'leads' | 'invoices' | 'transactions' | 'financial_report'
    format: 'csv' | 'excel' | 'pdf' | 'json'
    filters?: Record<string, unknown>
    columns?: string[]
  }): Promise<ApiResponse<ExportRequest>> {
    return apiClient.post<ExportRequest>('/api/export', data)
  }

  async getExportProgress(id: string): Promise<ApiResponse<ExportRequest>> {
    return apiClient.get<ExportRequest>(`/api/export/${id}`)
  }

  async listExports(params?: {
    status?: 'pending' | 'processing' | 'completed' | 'failed'
    limit?: number
    offset?: number
  }): Promise<ApiResponse<ExportRequest[]>> {
    const query = new URLSearchParams()
    if (params) {
      Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined) query.append(key, String(value))
      })
    }
    return apiClient.get<ExportRequest[]>(`/api/export?${query}`)
  }

  async downloadExport(id: string): Promise<Blob> {
    const response = await fetch(
      `${import.meta.env.VITE_API_URL}/api/export/${id}/download`,
      {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`,
        },
      }
    )
    if (!response.ok) throw new Error('Failed to download export')
    return response.blob()
  }

  async cancelExport(id: string): Promise<ApiResponse<void>> {
    return apiClient.post(`/api/export/${id}/cancel`)
  }

  async deleteExport(id: string): Promise<ApiResponse<void>> {
    return apiClient.delete(`/api/export/${id}`)
  }
}

export const exportService = new ExportService()
export default exportService
