import apiClient, { ApiResponse } from '../client'

export interface ChatMessage {
  id: string
  conversation_id: string
  role: 'user' | 'assistant' | 'system'
  content: string
  metadata?: Record<string, unknown>
  created_at: string
}

export interface Conversation {
  id: string
  title?: string
  context_type?: string
  context_id?: string
  status: 'active' | 'archived'
  created_at: string
  updated_at: string
  message_count: number
}

export interface ChatSuggestion {
  text: string
  action?: string
  confidence: number
}

class ChatService {
  async sendMessage(data: {
    conversation_id?: string
    message: string
    context_type?: string
    context_id?: string
    metadata?: Record<string, unknown>
  }): Promise<ApiResponse<{
    message: ChatMessage
    response: ChatMessage
    conversation_id: string
  }>> {
    return apiClient.post('/api/chat/messages', data)
  }

  async getConversations(params?: {
    status?: 'active' | 'archived'
    limit?: number
    offset?: number
  }): Promise<ApiResponse<Conversation[]>> {
    const query = new URLSearchParams()
    if (params) {
      Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined) query.append(key, String(value))
      })
    }
    return apiClient.get<Conversation[]>(`/api/chat/conversations?${query}`)
  }

  async getConversation(id: string): Promise<ApiResponse<Conversation>> {
    return apiClient.get<Conversation>(`/api/chat/conversations/${id}`)
  }

  async createConversation(data?: {
    title?: string
    context_type?: string
    context_id?: string
  }): Promise<ApiResponse<Conversation>> {
    return apiClient.post<Conversation>('/api/chat/conversations', data || {})
  }

  async getConversationMessages(
    conversationId: string,
    params?: {
      limit?: number
      offset?: number
    }
  ): Promise<ApiResponse<ChatMessage[]>> {
    const query = new URLSearchParams()
    if (params) {
      Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined) query.append(key, String(value))
      })
    }
    return apiClient.get<ChatMessage[]>(`/api/chat/conversations/${conversationId}/messages?${query}`)
  }

  async deleteConversation(id: string): Promise<ApiResponse<void>> {
    return apiClient.delete(`/api/chat/conversations/${id}`)
  }

  async archiveConversation(id: string): Promise<ApiResponse<Conversation>> {
    return apiClient.post<Conversation>(`/api/chat/conversations/${id}/archive`)
  }

  async uploadFile(conversationId: string, file: File): Promise<ApiResponse<{
    file_id: string
    filename: string
    size: number
    mime_type: string
  }>> {
    const formData = new FormData()
    formData.append('file', file)
    return apiClient.post(`/api/chat/conversations/${conversationId}/upload`, formData)
  }

  async transcribeAudio(file: File): Promise<ApiResponse<{
    transcription: string
    confidence: number
    language: string
  }>> {
    const formData = new FormData()
    formData.append('audio', file)
    return apiClient.post('/api/chat/transcribe', formData)
  }

  async getSmartSuggestions(conversationId: string): Promise<ApiResponse<ChatSuggestion[]>> {
    return apiClient.get<ChatSuggestion[]>(`/api/chat/conversations/${conversationId}/suggestions`)
  }

  async searchConversations(query: string, params?: {
    limit?: number
  }): Promise<ApiResponse<Array<{
    conversation: Conversation
    matched_messages: ChatMessage[]
    relevance_score: number
  }>>> {
    const searchParams = new URLSearchParams({ q: query })
    if (params?.limit) searchParams.append('limit', String(params.limit))
    return apiClient.get(`/api/chat/search?${searchParams}`)
  }
}

export const chatService = new ChatService()
export default chatService
