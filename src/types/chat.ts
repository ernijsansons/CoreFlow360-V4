/**
 * Backend Chat Type Definitions
 * TypeScript interfaces for chat functionality (backend)
 */

export type MessageType = 'user' | 'assistant' | 'system'

export type SuggestionType = 'insight' | 'action' | 'optimization' | 'alert' | 'opportunity' | 'reminder'

export interface FileAttachment {
  id: string
  name: string
  type: string
  size: string
  url: string
  thumbnailUrl?: string
}

export interface MessageSource {
  title: string
  excerpt: string
  url?: string
}

export interface ChatMessage {
  id: string
  conversationId: string
  type: MessageType
  content: string
  metadata?: Record<string, unknown>
  attachments?: FileAttachment[]
  sources?: MessageSource[]
  contextUsed: boolean
  isStreaming: boolean
  timestamp: string
}

export interface Conversation {
  id: string
  title: string
  userId: string
  businessId: string
  status: 'active' | 'archived' | 'deleted'
  metadata?: Record<string, unknown>
  messageCount: number
  lastMessageAt?: string
  createdAt: string
  updatedAt: string
  relevantMessages?: ChatMessage[] // For search results
}

export interface StreamChunk {
  id: string
  type: 'content' | 'function_call' | 'error' | 'done'
  content?: string
  functionCall?: {
    name: string
    arguments: Record<string, unknown>
  }
  metadata?: Record<string, unknown>
}

export interface SmartSuggestion {
  id: string
  type: SuggestionType
  title: string
  description: string
  priority?: 'high' | 'medium' | 'low'
  confidence?: number
  impact?: 'high' | 'medium' | 'low'
  metadata?: Record<string, unknown>
  metrics?: Array<{
    label: string
    value: string | number
  }>
  actions?: Array<{
    type?: string
    label: string
    handler?: string
    command?: string
  }>
  expiresAt?: string
}
