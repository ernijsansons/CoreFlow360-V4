/**
 * Chat Type Definitions
 * TypeScript interfaces for chat functionality
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
  metadata?: Record<string, any>
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
  metadata?: Record<string, any>
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
    arguments: Record<string, any>
  }
  metadata?: Record<string, any>
}

export interface CommandAction {
  label: string
  command?: string
  description?: string
}

export interface CommandItem {
  id: string
  name: string
  description: string
  icon: React.ComponentType<{ className?: string }>
  shortcut?: string[]
  category: string
  keywords: string[]
  actions?: CommandAction[]
}

export interface CommandCategory {
  id: string
  name: string
  icon: React.ComponentType<{ className?: string }>
  commands: CommandItem[]
}

export interface SmartSuggestionMetric {
  label: string
  value: string
  change?: number
}

export interface SmartSuggestionAction {
  label: string
  command?: string
  description?: string
}

export interface SmartSuggestion {
  id: string
  type: SuggestionType
  title: string
  description: string
  priority?: 'high' | 'medium' | 'low'
  confidence?: number
  impact?: 'high' | 'medium' | 'low'
  metrics?: SmartSuggestionMetric[]
  actions?: SmartSuggestionAction[]
  expiresAt?: string
  selectedAction?: SmartSuggestionAction
}

export interface UploadProgress {
  fileId: string
  progress: number
  status: 'pending' | 'uploading' | 'completed' | 'error'
  error?: string
}