/**
 * Conversation Management Service
 * Manages chat conversations with D1 storage and advanced features
 */

import { z } from 'zod'
import type { Env } from '@/types/env'
import type { ChatMessage, Conversation } from '@/types/chat'
import { AppError } from '@/shared/errors/app-error'
import { AuditLogger } from '@/shared/services/audit-logger'
import { CorrelationId } from '@/shared/correlation-id'
import { Logger } from '@/shared/logger'

const ConversationSchema = z.object({
  id: z.string(),
  title: z.string(),
  userId: z.string(),
  businessId: z.string(),
  status: z.enum(['active', 'archived', 'deleted']),
  metadata: z.record(z.any()).optional(),
  messageCount: z.number().default(0),
  lastMessageAt: z.string().optional(),
  createdAt: z.string(),
  updatedAt: z.string()
})

const MessageSchema = z.object({
  id: z.string(),
  conversationId: z.string(),
  type: z.enum(['user', 'assistant', 'system']),
  content: z.string(),
  metadata: z.record(z.any()).optional(),
  attachments: z.array(z.object({
    id: z.string(),
    name: z.string(),
    type: z.string(),
    size: z.string(),
    url: z.string()
  })).optional(),
  sources: z.array(z.object({
    title: z.string(),
    excerpt: z.string(),
    url: z.string().optional()
  })).optional(),
  contextUsed: z.boolean().default(false),
  isStreaming: z.boolean().default(false),
  timestamp: z.string()
})

export // TODO: Consider splitting ConversationService into smaller, focused classes
class ConversationService {
  private logger: Logger;
  private correlationId: string;

  constructor(
    private env: Env,
    private auditLogger: AuditLogger,
    correlationId?: string
  ) {
    this.logger = new Logger();
    this.correlationId = correlationId || CorrelationId.generate();
  }

  /**
   * Create a new conversation
   */
  async createConversation(
    userId: string,
    businessId: string,
    title?: string
  ): Promise<Conversation> {
    const operationId = CorrelationId.generate();
    try {
      const conversationId = crypto.randomUUID()
      const now = new Date().toISOString()

      this.logger.info('Creating conversation', {
        correlationId: this.correlationId,
        operationId,
        userId,
        businessId
      })

      const conversation: Conversation = {
        id: conversationId,
        title: title || 'New Conversation',
        userId,
        businessId,
        status: 'active',
        messageCount: 0,
        createdAt: now,
        updatedAt: now
      }

      // Store in database
      await this.env.DB.prepare(`
        INSERT INTO conversations (
          id, title, user_id, business_id, status, metadata,
          message_count, last_message_at, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(
        conversation.id,
        conversation.title,
        conversation.userId,
        conversation.businessId,
        conversation.status,
        JSON.stringify(conversation.metadata || {}),
        conversation.messageCount,
        conversation.lastMessageAt || null,
        conversation.createdAt,
        conversation.updatedAt
      ).run()

      await this.auditLogger.log({
        action: 'conversation_created',
        userId,
        details: {
          conversationId,
          businessId,
          title: conversation.title
        }
      })

      return conversation

    } catch (error) {
      await this.auditLogger.log({
        action: 'conversation_creation_failed',
        userId,
        details: {
          businessId,
          error: error instanceof Error ? error.message : 'Unknown error'
        }
      })

      throw new AppError(
        'Failed to create conversation',
        'CONVERSATION_CREATION_FAILED',
        500,
        error instanceof Error ? error.message : undefined
      )
    }
  }

  /**
   * Get conversation by ID
   */
  async getConversation(
    conversationId: string,
    userId: string,
    businessId?: string
  ): Promise<Conversation | null> {
    try {
      let query = `SELECT * FROM conversations WHERE id = ? AND user_id = ?`
      const params: any[] = [conversationId, userId]

      if (businessId) {
        query += ` AND business_id = ?`
        params.push(businessId)
      }

      const result = await this.env.DB.prepare(query).bind(...params).first()

      if (!result) {
        return null
      }

      return this.mapDbToConversation(result)

    } catch (error) {
      throw new AppError(
        'Failed to retrieve conversation',
        'DATABASE_ERROR',
        500,
        error instanceof Error ? error.message : undefined
      )
    }
  }

  /**
   * Get user conversations with pagination
   */
  async getUserConversations(
    userId: string,
    businessId: string,
    options: {
      page?: number
      limit?: number
      status?: 'active' | 'archived' | 'deleted'
      search?: string
    } = {}
  ): Promise<{
    conversations: Conversation[]
    pagination: {
      page: number
      limit: number
      total: number
      totalPages: number
    }
  }> {
    try {
      const page = Math.max(1, options.page || 1)
      const limit = Math.min(50, Math.max(1, options.limit || 20))
      const offset = (page - 1) * limit

      let whereClause = 'WHERE user_id = ? AND business_id = ?'
      const params: any[] = [userId, businessId]

      if (options.status) {
        whereClause += ' AND status = ?'
        params.push(options.status)
      }

      if (options.search) {
        whereClause += ' AND title LIKE ?'
        params.push(`%${options.search}%`)
      }

      // Get total count
      const countResult = await this.env.DB.prepare(`
        SELECT COUNT(*) as total FROM conversations ${whereClause}
      `).bind(...params).first()

      const total = countResult?.total as number || 0

      // Get conversations
      const results = await this.env.DB.prepare(`
        SELECT * FROM conversations ${whereClause}
        ORDER BY updated_at DESC
        LIMIT ? OFFSET ?
      `).bind(...params, limit, offset).all()

      const conversations = results.results.map(result => this.mapDbToConversation(result))

      return {
        conversations,
        pagination: {
          page,
          limit,
          total,
          totalPages: Math.ceil(total / limit)
        }
      }

    } catch (error) {
      throw new AppError(
        'Failed to retrieve conversations',
        'DATABASE_ERROR',
        500,
        error instanceof Error ? error.message : undefined
      )
    }
  }

  /**
   * Update conversation
   */
  async updateConversation(
    conversationId: string,
    userId: string,
    updates: Partial<Pick<Conversation, 'title' | 'status' | 'metadata'>>
  ): Promise<Conversation> {
    try {
      const conversation = await this.getConversation(conversationId, userId)
      if (!conversation) {
        throw new AppError('Conversation not found', 'CONVERSATION_NOT_FOUND', 404)
      }

      const now = new Date().toISOString()
      const updatedConversation = { ...conversation, ...updates, updatedAt: now }

      await this.env.DB.prepare(`
        UPDATE conversations
        SET title = ?, status = ?, metadata = ?, updated_at = ?
        WHERE id = ? AND user_id = ?
      `).bind(
        updatedConversation.title,
        updatedConversation.status,
        JSON.stringify(updatedConversation.metadata || {}),
        updatedConversation.updatedAt,
        conversationId,
        userId
      ).run()

      await this.auditLogger.log({
        action: 'conversation_updated',
        userId,
        details: {
          conversationId,
          updates: Object.keys(updates)
        }
      })

      return updatedConversation

    } catch (error) {
      if (error instanceof AppError) {
        throw error
      }

      throw new AppError(
        'Failed to update conversation',
        'UPDATE_FAILED',
        500,
        error instanceof Error ? error.message : undefined
      )
    }
  }

  /**
   * Delete conversation
   */
  async deleteConversation(
    conversationId: string,
    userId: string
  ): Promise<void> {
    try {
      const conversation = await this.getConversation(conversationId, userId)
      if (!conversation) {
        throw new AppError('Conversation not found', 'CONVERSATION_NOT_FOUND', 404)
      }

      // Soft delete - mark as deleted
      await this.updateConversation(conversationId, userId, { status: 'deleted' })

      // Delete all messages in the conversation with business isolation
      await this.env.DB.prepare(`
        DELETE FROM chat_messages
        WHERE conversation_id = ?
          AND conversation_id IN (SELECT id FROM conversations WHERE business_id = ? AND user_id = ?)
      `).bind(conversationId, conversation.businessId, userId).run()

      await this.auditLogger.log({
        action: 'conversation_deleted',
        userId,
        details: {
          conversationId,
          title: conversation.title
        }
      })

    } catch (error) {
      if (error instanceof AppError) {
        throw error
      }

      throw new AppError(
        'Failed to delete conversation',
        'DELETE_FAILED',
        500,
        error instanceof Error ? error.message : undefined
      )
    }
  }

  /**
   * Add message to conversation
   */
  async addMessage(
    conversationId: string,
    message: Omit<ChatMessage, 'id' | 'timestamp'>
  ): Promise<ChatMessage> {
    try {
      const messageId = crypto.randomUUID()
      const timestamp = new Date().toISOString()

      const fullMessage: ChatMessage = {
        ...message,
        id: messageId,
        timestamp
      }

      // Store message in database
      await this.env.DB.prepare(`
        INSERT INTO chat_messages (
          id, conversation_id, type, content, metadata,
          attachments, sources, context_used, is_streaming, timestamp
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(
        fullMessage.id,
        fullMessage.conversationId,
        fullMessage.type,
        fullMessage.content,
        JSON.stringify(fullMessage.metadata || {}),
        JSON.stringify(fullMessage.attachments || []),
        JSON.stringify(fullMessage.sources || []),
        fullMessage.contextUsed ? 1 : 0,
        fullMessage.isStreaming ? 1 : 0,
        fullMessage.timestamp
      ).run()

      // Update conversation metadata
      await this.env.DB.prepare(`
        UPDATE conversations
        SET message_count = message_count + 1,
            last_message_at = ?,
            updated_at = ?
        WHERE id = ?
      `).bind(timestamp, timestamp, conversationId).run()

      // Auto-generate title for first user message
      if (message.type === 'user') {
        await this.autoGenerateTitle(conversationId, message.content)
      }

      await this.auditLogger.log({
        action: 'message_added',
        details: {
          conversationId,
          messageId,
          messageType: message.type,
          contentLength: message.content.length
        }
      })

      return fullMessage

    } catch (error) {
      throw new AppError(
        'Failed to add message',
        'MESSAGE_ADD_FAILED',
        500,
        error instanceof Error ? error.message : undefined
      )
    }
  }

  /**
   * Get conversation messages
   */
  async getMessages(
    conversationId: string,
    userId: string,
    options: {
      page?: number
      limit?: number
      beforeId?: string
      afterId?: string
    } = {}
  ): Promise<{
    messages: ChatMessage[]
    pagination: {
      page: number
      limit: number
      total: number
      hasMore: boolean
    }
  }> {
    try {
      // Verify conversation access - extract businessId from conversation
      const conversation = await this.getConversation(conversationId, userId)
      if (!conversation) {
        throw new AppError('Conversation not found', 'CONVERSATION_NOT_FOUND', 404)
      }
      const businessId = conversation.businessId

      const page = Math.max(1, options.page || 1)
      const limit = Math.min(100, Math.max(1, options.limit || 50))
      const offset = (page - 1) * limit

      // Add business isolation to prevent cross-tenant data leakage
      let whereClause = `WHERE conversation_id = ?
        AND conversation_id IN (SELECT id FROM conversations WHERE business_id = ?)`
      const params: any[] = [conversationId, businessId]

      if (options.beforeId) {
        whereClause += ' AND timestamp < (SELECT timestamp FROM chat_messages WHERE id = ?)'
        params.push(options.beforeId)
      }

      if (options.afterId) {
        whereClause += ' AND timestamp > (SELECT timestamp FROM chat_messages WHERE id = ?)'
        params.push(options.afterId)
      }

      // Get total count
      const countResult = await this.env.DB.prepare(`
        SELECT COUNT(*) as total FROM chat_messages ${whereClause}
      `).bind(...params).first()

      const total = countResult?.total as number || 0

      // Get messages with LIMIT to prevent unbounded queries
      const results = await this.env.DB.prepare(`
        SELECT * FROM chat_messages ${whereClause}
        ORDER BY timestamp ASC
        LIMIT ? OFFSET ?
      `).bind(...params, limit, offset).all()

      const messages = results.results.map(result => this.mapDbToMessage(result))

      return {
        messages,
        pagination: {
          page,
          limit,
          total,
          hasMore: offset + messages.length < total
        }
      }

    } catch (error) {
      if (error instanceof AppError) {
        throw error
      }

      throw new AppError(
        'Failed to retrieve messages',
        'DATABASE_ERROR',
        500,
        error instanceof Error ? error.message : undefined
      )
    }
  }

  /**
   * Search conversations and messages
   */
  async searchConversations(
    userId: string,
    businessId: string,
    query: string,
    options: {
      page?: number
      limit?: number
      includeMessages?: boolean
    } = {}
  ): Promise<{
    conversations: (Conversation & { relevantMessages?: ChatMessage[] })[]
    pagination: {
      page: number
      limit: number
      total: number
      totalPages: number
    }
  }> {
    try {
      const page = Math.max(1, options.page || 1)
      const limit = Math.min(20, Math.max(1, options.limit || 10))
      const offset = (page - 1) * limit

      // Search in conversation titles and message content with business isolation
      const searchQuery = `%${query}%`

      let sql = `
        SELECT DISTINCT c.* FROM conversations c
        LEFT JOIN chat_messages m ON c.id = m.conversation_id
        WHERE c.user_id = ? AND c.business_id = ?
        AND (c.title LIKE ? OR m.content LIKE ?)
        AND c.status != 'deleted'
      `

      const params = [userId, businessId, searchQuery, searchQuery]

      // Get total count
      const countResult = await this.env.DB.prepare(`
        SELECT COUNT(DISTINCT c.id) as total FROM conversations c
        LEFT JOIN chat_messages m ON c.id = m.conversation_id
        WHERE c.user_id = ? AND c.business_id = ?
        AND (c.title LIKE ? OR m.content LIKE ?)
        AND c.status != 'deleted'
      `).bind(...params).first()

      const total = countResult?.total as number || 0

      // Get conversations
      const results = await this.env.DB.prepare(`
        ${sql}
        ORDER BY c.updated_at DESC
        LIMIT ? OFFSET ?
      `).bind(...params, limit, offset).all()

      const conversations = await Promise.all(
        results.results.map(async (result) => {
          const conversation = this.mapDbToConversation(result)

          if (options.includeMessages) {
            // Get relevant messages for this conversation with business isolation
            const messageResults = await this.env.DB.prepare(`
              SELECT * FROM chat_messages
              WHERE conversation_id = ? AND content LIKE ?
                AND conversation_id IN (SELECT id FROM conversations WHERE business_id = ?)
              ORDER BY timestamp DESC
              LIMIT 3
            `).bind(conversation.id, searchQuery, businessId).all()

            conversation.relevantMessages = messageResults.results.map(msg => this.mapDbToMessage(msg))
          }

          return conversation
        })
      )

      return {
        conversations,
        pagination: {
          page,
          limit,
          total,
          totalPages: Math.ceil(total / limit)
        }
      }

    } catch (error) {
      throw new AppError(
        'Failed to search conversations',
        'SEARCH_FAILED',
        500,
        error instanceof Error ? error.message : undefined
      )
    }
  }

  /**
   * Auto-generate conversation title from first message
   */
  private async autoGenerateTitle(conversationId: string, firstMessage: string): Promise<void> {
    try {
      // Check if conversation already has a custom title
      const conversation = await this.env.DB.prepare(`
        SELECT title, message_count FROM conversations WHERE id = ?
      `).bind(conversationId).first()

      if (!conversation || conversation.message_count > 1 || conversation.title !== 'New Conversation') {
        return
      }

      // Generate title from first message (first 50 chars)
      let title = firstMessage.trim().substring(0, 50)
      if (firstMessage.length > 50) {
        title += '...'
      }

      // Clean up title
      title = title.replace(/\n/g, ' ').replace(/\s+/g, ' ')

      if (title) {
        await this.env.DB.prepare(`
          UPDATE conversations SET title = ? WHERE id = ?
        `).bind(title, conversationId).run()
      }

    } catch (error) {
      // Use logger instead of console for proper monitoring
      this.logger.warn('Failed to auto-generate title', {
        conversationId,
        error: error instanceof Error ? error.message : 'Unknown error'
      })
    }
  }

  /**
   * Map database result to Conversation object
   */
  private mapDbToConversation(result: any): Conversation {
    return {
      id: result.id,
      title: result.title,
      userId: result.user_id,
      businessId: result.business_id,
      status: result.status,
      metadata: result.metadata ? JSON.parse(result.metadata) : undefined,
      messageCount: result.message_count,
      lastMessageAt: result.last_message_at,
      createdAt: result.created_at,
      updatedAt: result.updated_at
    }
  }

  /**
   * Map database result to ChatMessage object
   */
  private mapDbToMessage(result: any): ChatMessage {
    return {
      id: result.id,
      conversationId: result.conversation_id,
      type: result.type,
      content: result.content,
      metadata: result.metadata ? JSON.parse(result.metadata) : undefined,
      attachments: result.attachments ? JSON.parse(result.attachments) : undefined,
      sources: result.sources ? JSON.parse(result.sources) : undefined,
      contextUsed: Boolean(result.context_used),
      isStreaming: Boolean(result.is_streaming),
      timestamp: result.timestamp
    }
  }
}

export default ConversationService