/**
 * Chat API Routes
 * Handles all chat-related API endpoints
 */

import { Hono } from 'hono'
import { z } from 'zod'
import type { Env } from '@/types/env'
import { validateRequest, requireAuth } from '@/shared/middleware/validation'
import { AppError } from '@/shared/errors/app-error'
import { AuditLogger } from '@/shared/services/audit-logger'
import { ChatStreamingService } from '@/modules/chat/streaming-service'
import { ConversationService } from '@/modules/chat/conversation-service'
import { ChatContextService } from '@/modules/chat/context-service'
import { ChatFileService } from '@/modules/chat/file-service'
import { TranscriptionService } from '@/modules/chat/transcription-service'
import { SuggestionsService } from '@/modules/chat/suggestions-service'

const chat = new Hono<{ Bindings: Env }>()

// Request schemas
const SendMessageSchema = z.object({
  conversationId: z.string().optional(),
  message: z.string().min(1),
  attachments: z.array(z.any()).optional(),
  context: z.record(z.any()).optional()
})

const CreateConversationSchema = z.object({
  title: z.string().optional()
})

const FileUploadSchema = z.object({
  name: z.string().min(1),
  type: z.string().min(1),
  size: z.number().min(1),
  content: z.string().min(1) // base64
})

const TranscriptionSchema = z.object({
  audio: z.string().min(1), // base64
  format: z.enum(['wav', 'mp3', 'webm', 'ogg', 'm4a']),
  language: z.string().optional()
})

const SuggestionsRequestSchema = z.object({
  userId: z.string(),
  businessId: z.string(),
  context: z.record(z.any()).optional()
})

// Services initialization
const getServices = (env: Env) => {
  const auditLogger = new AuditLogger(env.DB)

  return {
    streaming: new ChatStreamingService(env, auditLogger),
    conversation: new ConversationService(env, auditLogger),
    context: new ChatContextService(env, auditLogger),
    files: new ChatFileService(env, auditLogger),
    transcription: new TranscriptionService(env, auditLogger),
    suggestions: new SuggestionsService(env, auditLogger)
  }
}

/**
 * Send a message and get streaming response
 * POST /api/v1/chat/message
 */
chat.post('/message',
  requireAuth,
  validateRequest(SendMessageSchema),
  async (c: any) => {
    try {
      const { conversationId, message, attachments, context } = c.get('validatedData')
      const user = c.get('user')
      const services = getServices(c.env)

      // Gather context for the message
      const fullContext = await services.context.gatherContext(
        user.id,
        user.businessId,
        context?.currentPage,
        context?.entityContext
      )

      // Create or get conversation
      let conversation
      if (conversationId) {
        conversation = await services.conversation.getConversation(conversationId, user.id)
        if (!conversation) {
          throw new AppError('Conversation not found', 'CONVERSATION_NOT_FOUND', 404)
        }
      } else {
        conversation = await services.conversation.createConversation(
          user.id,
          user.businessId,
          message.length > 50 ? message.substring(0, 50) + '...' : message
        )
      }

      // Add user message
      await services.conversation.addMessage(conversation.id, {
        conversationId: conversation.id,
        type: 'user',
        content: message,
        attachments,
        contextUsed: !!context
      })

      // Generate message ID for assistant response
      const assistantMessageId = crypto.randomUUID()

      // Create streaming response
      return services.streaming.createStreamResponse(
        conversation.id,
        assistantMessageId,
        message,
        fullContext
      )

    } catch (error: any) {
      if (error instanceof AppError) {
        return c.json({ error: error.message }, error.statusCode)
      }

      return c.json(
        { error: 'Internal server error' },
        500
      )
    }
  }
)

/**
 * Get conversations for user
 * GET /api/v1/chat/conversations
 */
chat.get('/conversations',
  requireAuth,
  async (c: any) => {
    try {
      const user = c.get('user')
      const services = getServices(c.env)

      const page = parseInt(c.req.query('page') || '1')
      const limit = parseInt(c.req.query('limit') || '20')
      const status = c.req.query('status') as 'active' | 'archived' | 'deleted' | undefined
      const search = c.req.query('search')

      const result = await services.conversation.getUserConversations(
        user.id,
        user.businessId,
        { page, limit, status, search }
      )

      return c.json(result)

    } catch (error: any) {
      if (error instanceof AppError) {
        return c.json({ error: error.message }, error.statusCode)
      }

      return c.json(
        { error: 'Internal server error' },
        500
      )
    }
  }
)

/**
 * Create new conversation
 * POST /api/v1/chat/conversations
 */
chat.post('/conversations',
  requireAuth,
  validateRequest(CreateConversationSchema),
  async (c: any) => {
    try {
      const { title } = c.get('validatedData')
      const user = c.get('user')
      const services = getServices(c.env)

      const conversation = await services.conversation.createConversation(
        user.id,
        user.businessId,
        title
      )

      return c.json(conversation)

    } catch (error: any) {
      if (error instanceof AppError) {
        return c.json({ error: error.message }, error.statusCode)
      }

      return c.json(
        { error: 'Internal server error' },
        500
      )
    }
  }
)

/**
 * Get conversation messages
 * GET /api/v1/chat/conversations/:id/messages
 */
chat.get('/conversations/:id/messages',
  requireAuth,
  async (c: any) => {
    try {
      const conversationId = c.req.param('id')
      const user = c.get('user')
      const services = getServices(c.env)

      const page = parseInt(c.req.query('page') || '1')
      const limit = parseInt(c.req.query('limit') || '50')

      const result = await services.conversation.getMessages(
        conversationId,
        user.id,
        { page, limit }
      )

      return c.json(result)

    } catch (error: any) {
      if (error instanceof AppError) {
        return c.json({ error: error.message }, error.statusCode)
      }

      return c.json(
        { error: 'Internal server error' },
        500
      )
    }
  }
)

/**
 * Delete conversation
 * DELETE /api/v1/chat/conversations/:id
 */
chat.delete('/conversations/:id',
  requireAuth,
  async (c: any) => {
    try {
      const conversationId = c.req.param('id')
      const user = c.get('user')
      const services = getServices(c.env)

      await services.conversation.deleteConversation(conversationId, user.id)

      return c.json({ success: true })

    } catch (error: any) {
      if (error instanceof AppError) {
        return c.json({ error: error.message }, error.statusCode)
      }

      return c.json(
        { error: 'Internal server error' },
        500
      )
    }
  }
)

/**
 * Upload file for chat
 * POST /api/v1/chat/upload-file
 */
chat.post('/upload-file',
  requireAuth,
  validateRequest(FileUploadSchema),
  async (c: any) => {
    try {
      const fileData = c.get('validatedData')
      const user = c.get('user')
      const services = getServices(c.env)

      const conversationId = c.req.query('conversationId') || 'temp'
      const messageId = c.req.query('messageId')

      const result = await services.files.uploadFile(
        fileData,
        conversationId,
        user.id,
        messageId
      )

      return c.json(result)

    } catch (error: any) {
      if (error instanceof AppError) {
        return c.json({ error: error.message }, error.statusCode)
      }

      return c.json(
        { error: 'Internal server error' },
        500
      )
    }
  }
)

/**
 * Transcribe audio
 * POST /api/v1/chat/transcribe
 */
chat.post('/transcribe',
  requireAuth,
  validateRequest(TranscriptionSchema),
  async (c: any) => {
    try {
      const transcriptionData = c.get('validatedData')
      const user = c.get('user')
      const services = getServices(c.env)

      const result = await services.transcription.transcribeAudio(
        transcriptionData,
        user.id
      )

      return c.json(result)

    } catch (error: any) {
      if (error instanceof AppError) {
        return c.json({ error: error.message }, error.statusCode)
      }

      return c.json(
        { error: 'Internal server error' },
        500
      )
    }
  }
)

/**
 * Get smart suggestions
 * POST /api/v1/chat/suggestions
 */
chat.post('/suggestions',
  requireAuth,
  validateRequest(SuggestionsRequestSchema),
  async (c: any) => {
    try {
      const { userId, businessId, context } = c.get('validatedData')
      const user = c.get('user')
      const services = getServices(c.env)

      // Verify user access
      if (user.id !== userId || user.businessId !== businessId) {
        throw new AppError('Unauthorized', 'UNAUTHORIZED', 403)
      }

      const suggestions = await services.suggestions.generateSuggestions({
        userId,
        businessId,
        ...context
      })

      return c.json({ suggestions })

    } catch (error: any) {
      if (error instanceof AppError) {
        return c.json({ error: error.message }, error.statusCode)
      }

      return c.json(
        { error: 'Internal server error' },
        500
      )
    }
  }
)

/**
 * Dismiss suggestion
 * POST /api/v1/chat/suggestions/dismiss
 */
chat.post('/suggestions/dismiss',
  requireAuth,
  async (c: any) => {
    try {
      const { suggestionId, reason } = await c.req.json()
      const user = c.get('user')
      const services = getServices(c.env)

      await services.suggestions.dismissSuggestion(
        suggestionId,
        user.id,
        reason
      )

      return c.json({ success: true })

    } catch (error: any) {
      return c.json(
        { error: 'Internal server error' },
        500
      )
    }
  }
)

/**
 * Search conversations
 * GET /api/v1/chat/search
 */
chat.get('/search',
  requireAuth,
  async (c: any) => {
    try {
      const user = c.get('user')
      const services = getServices(c.env)

      const query = c.req.query('q')
      if (!query) {
        throw new AppError('Search query is required', 'BAD_REQUEST', 400)
      }

      const page = parseInt(c.req.query('page') || '1')
      const limit = parseInt(c.req.query('limit') || '10')
      const includeMessages = c.req.query('includeMessages') === 'true'

      const result = await services.conversation.searchConversations(
        user.id,
        user.businessId,
        query,
        { page, limit, includeMessages }
      )

      return c.json(result)

    } catch (error: any) {
      if (error instanceof AppError) {
        return c.json({ error: error.message }, error.statusCode)
      }

      return c.json(
        { error: 'Internal server error' },
        500
      )
    }
  }
)

/**
 * Server-Sent Events endpoint for streaming
 * GET /api/v1/chat/stream
 */
chat.get('/stream',
  requireAuth,
  async (c: any) => {
    try {
      const services = getServices(c.env)
      return services.streaming.handleStreamConnection(c.req.raw)

    } catch (error: any) {
      return c.json(
        { error: 'Internal server error' },
        500
      )
    }
  }
)

export default chat