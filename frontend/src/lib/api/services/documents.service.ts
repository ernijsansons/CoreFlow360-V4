import apiClient, { ApiResponse } from '../client'

export interface ProcessedDocument {
  id: string
  document_type: 'invoice' | 'receipt' | 'bill' | 'other'
  original_filename: string
  confidence_score: number
  extracted_data: Record<string, unknown>
  created_at: string
  file_url?: string
}

export interface DocumentUploadResult {
  document_id: string
  document_type: string
  confidence: number
  extracted_data: Record<string, unknown>
  file_url: string
  processing_time_ms: number
}

class DocumentsService {
  async uploadDocument(
    file: File,
    type?: 'invoice' | 'receipt' | 'bill'
  ): Promise<ApiResponse<DocumentUploadResult>> {
    const formData = new FormData()
    formData.append('file', file)
    if (type) formData.append('type', type)

    return apiClient.post<DocumentUploadResult>('/api/documents/upload', formData)
  }

  async listDocuments(params?: {
    type?: 'invoice' | 'receipt' | 'bill' | 'other'
    limit?: number
    offset?: number
  }): Promise<ApiResponse<ProcessedDocument[]>> {
    const query = new URLSearchParams()
    if (params?.type) query.append('type', params.type)
    if (params?.limit) query.append('limit', String(params.limit))
    if (params?.offset) query.append('offset', String(params.offset))

    return apiClient.get<ProcessedDocument[]>(`/api/documents?${query}`)
  }

  async getDocument(id: string): Promise<ApiResponse<ProcessedDocument>> {
    return apiClient.get<ProcessedDocument>(`/api/documents/${id}`)
  }

  async downloadDocumentFile(id: string): Promise<Blob> {
    const response = await fetch(
      `${import.meta.env.VITE_API_URL}/api/documents/${id}/file`,
      {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`,
        },
      }
    )
    return response.blob()
  }

  async createInvoiceFromDocument(
    documentId: string,
    customerId?: string
  ): Promise<ApiResponse<Record<string, unknown>>> {
    return apiClient.post(`/api/documents/${documentId}/create-invoice`, { customerId })
  }

  async createExpenseFromDocument(
    documentId: string,
    accountId?: string
  ): Promise<ApiResponse<Record<string, unknown>>> {
    return apiClient.post(`/api/documents/${documentId}/create-expense`, { accountId })
  }

  async reprocessDocument(id: string): Promise<ApiResponse<DocumentUploadResult>> {
    return apiClient.post<DocumentUploadResult>(`/api/documents/${id}/reprocess`)
  }

  async deleteDocument(id: string): Promise<ApiResponse<void>> {
    return apiClient.delete(`/api/documents/${id}`)
  }

  async updateDocumentMetadata(
    id: string,
    metadata: Record<string, unknown>
  ): Promise<ApiResponse<ProcessedDocument>> {
    return apiClient.patch<ProcessedDocument>(`/api/documents/${id}/metadata`, metadata)
  }
}

export const documentsService = new DocumentsService()
export default documentsService
