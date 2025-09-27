/**
 * Chat Streaming Service
 * Handles Server-Sent Events for real-time chat responses
 */

import { z } from 'zod'
import type { Env } from '@/types/env'
import type { ChatMessage, StreamChunk } from '@/types/chat'
import { AppError } from '@/shared/errors/app-error'
import { AuditLogger } from '@/shared/services/audit-logger'
import { CORSUtils } from '../../utils/cors-utils'

const StreamChunkSchema = z.object({
  id: z.string(),
  type: z.enum(['content', 'function_call', 'error', 'done']),
  content: z.string().optional(),
  functionCall: z.object({
    name: z.string(),
    arguments: z.record(z.any())
  }).optional(),
  metadata: z.record(z.any()).optional()
})

export // TODO: Consider splitting ChatStreamingService into smaller, focused classes
class ChatStreamingService {
  constructor(
    private env: Env,
    private auditLogger: AuditLogger
  ) {}

  /**
   * Create Server-Sent Events stream for chat response
   */
  async createStreamResponse(
    conversationId: string,
    messageId: string,
    userMessage: string,
    context?: any,
    origin?: string | null
  ): Promise<Response> {
    const { readable, writable } = new TransformStream()
    const writer = writable.getWriter()

    // Start streaming response in background
    this.processStreamingResponse(
      writer,
      conversationId,
      messageId,
      userMessage,
      context
    ).catch(async (error: any) => {
      await this.sendErrorChunk(writer, error)
      await writer.close()
    })

    return new Response(readable, {
      headers: (() => {
        const headers: Record<string, string> = {
          'Content-Type': 'text/event-stream',
          'Cache-Control': 'no-cache',
          'Connection': 'keep-alive'
        };

        // CRITICAL: Secure CORS headers with origin validation
        CORSUtils.setCORSHeaders(headers, origin, {
          environment: this.env.ENVIRONMENT,
          allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key', 'X-Business-ID']
        });

        return headers;
      })()
    })
  }

  /**
   * Process streaming response from Cloudflare Workers AI
   */
  private async processStreamingResponse(
    writer: WritableStreamDefaultWriter,
    conversationId: string,
    messageId: string,
    userMessage: string,
    context?: any
  ): Promise<void> {
    try {
      await this.auditLogger.log({
        action: 'chat_stream_started',
        details: {
          conversationId,
          messageId,
          userMessage: userMessage.substring(0, 100)
        }
      })

      // Send initial chunk
      await this.sendChunk(writer, {
        id: messageId,
        type: 'content',
        content: '',
        metadata: {
          conversationId,
          timestamp: new Date().toISOString()
        }
      })

      // Prepare AI request
      const aiRequest = await this.prepareAIRequest(userMessage, context)

      // Stream from Cloudflare Workers AI
      const aiResponse = await this.env.AI.run('@cf/meta/llama-2-7b-chat-int8', {
        messages: aiRequest.messages,
        stream: true,
        max_tokens: 2048,
        temperature: 0.7
      })

      // Process streaming chunks
      const reader = aiResponse.body?.getReader()
      if (!reader) {
        throw new AppError('Failed to create AI stream reader', 'STREAM_ERROR')
      }

      let accumulatedContent = ''
      const decoder = new TextDecoder()

      while (true) {
        const { done, value } = await reader.read()

        if (done) break

        const chunk = decoder.decode(value, { stream: true })
        const lines = chunk.split('\n')

        for (const line of lines) {
          if (line.startsWith('data: ')) {
            const data = line.slice(6)

            if (data === '[DONE]') {
              // Send completion chunk
              await this.sendChunk(writer, {
                id: messageId,
                type: 'done',
                content: accumulatedContent,
                metadata: {
                  conversationId,
                  completed: true,
                  timestamp: new Date().toISOString()
                }
              })

              await writer.close()
              return
            }

            try {
              const parsed = JSON.parse(data)
              const deltaContent = parsed.choices?.[0]?.delta?.content || ''

              if (deltaContent) {
                accumulatedContent += deltaContent

                // Send content chunk
                await this.sendChunk(writer, {
                  id: messageId,
                  type: 'content',
                  content: deltaContent,
                  metadata: {
                    conversationId,
                    totalContent: accumulatedContent,
                    timestamp: new Date().toISOString()
                  }
                })
              }

              // Handle function calls
              if (parsed.choices?.[0]?.delta?.function_call) {
                const functionCall = parsed.choices[0].delta.function_call

                await this.sendChunk(writer, {
                  id: messageId,
                  type: 'function_call',
                  functionCall: {
                    name: functionCall.name,
                    arguments: JSON.parse(functionCall.arguments || '{}')
                  },
                  metadata: {
                    conversationId,
                    timestamp: new Date().toISOString()
                  }
                })

                // Execute function and send result
                const functionResult = await this.executeFunctionCall(
                  functionCall.name,
                  JSON.parse(functionCall.arguments || '{}'),
                  context
                )

                accumulatedContent += `\n\n${functionResult}`

                await this.sendChunk(writer, {
                  id: messageId,
                  type: 'content',
                  content: `\n\n${functionResult}`,
                  metadata: {
                    conversationId,
                    functionResult: true,
                    timestamp: new Date().toISOString()
                  }
                })
              }

            } catch (parseError) {
            }
          }
        }
      }

      await this.auditLogger.log({
        action: 'chat_stream_completed',
        details: {
          conversationId,
          messageId,
          contentLength: accumulatedContent.length
        }
      })

    } catch (error: any) {
      await this.auditLogger.log({
        action: 'chat_stream_failed',
        details: {
          conversationId,
          messageId,
          error: error instanceof Error ? error.message : 'Unknown error'
        }
      })

      throw error
    }
  }

  /**
   * Prepare AI request with context and system prompts
   */
  private async prepareAIRequest(userMessage: string, context?: any) {
    const systemPrompt = this.buildSystemPrompt(context)

    return {
      messages: [
        {
          role: 'system',
          content: systemPrompt
        },
        {
          role: 'user',
          content: userMessage
        }
      ]
    }
  }

  /**
   * Build context-aware system prompt
   */
  private buildSystemPrompt(context?: any): string {
    let prompt = `You are CoreFlow360
  AI, an intelligent business assistant for the CoreFlow360 enterprise management system.

You have access to:
- Invoice and financial data
- Inventory and product information
- Customer relationship data
- Business analytics and reports

Current capabilities:
- Answer questions about business data
- Generate reports and insights
- Help with financial calculations
- Assist with inventory management
- Provide business recommendations

Always respond in a helpful, professional manner. If you need
  to access specific business data, use the available function calls.`

    if (context) {
      prompt += `\n\nCurrent context:
- User: ${context.user?.name || 'Unknown'}
- Business: ${context.business?.name || 'Unknown'}
- Current page: ${context.currentPage || 'Dashboard'}
- Recent activity: ${context.recentActivity || 'None'}`

      if (context.relevantData) {
        prompt += `\n\nRelevant business data:
${JSON.stringify(context.relevantData, null, 2)}`
      }
    }

    return prompt
  }

  /**
   * Execute function calls from AI
   */
  private async executeFunctionCall(
    functionName: string,
    arguments: any,
    context?: any
  ): Promise<string> {
    try {
      switch (functionName) {
        case 'search_invoices':
          return await this.searchInvoices(arguments, context)

        case 'get_business_metrics':
          return await this.getBusinessMetrics(arguments, context)

        case 'search_customers':
          return await this.searchCustomers(arguments, context)

        case 'get_inventory_status':
          return await this.getInventoryStatus(arguments, context)

        default:
          return `Function "${functionName}" is not available.`
      }
    } catch (error: any) {
      return `Error executing function "${functionName}": ${error instanceof Error ? error.message : 'Unknown error'}`
    }
  }

  /**
   * Search invoices function
   */
  private async searchInvoices(args: any, context?: any): Promise<string> {
    // Implementation would integrate with invoice service
    return `Found ${Math.floor(Math.random() * 50)} invoices matching your criteria.`
  }

  /**
   * Get business metrics function
   */
  private async getBusinessMetrics(args: any, context?: any): Promise<string> {
    const metrics = {
      totalRevenue: Math.floor(Math.random() * 1000000),
      totalInvoices: Math.floor(Math.random() * 500),
      paidInvoices: Math.floor(Math.random() * 400),
      overdueInvoices: Math.floor(Math.random() * 50)
    }

    return `{{metrics:${JSON.stringify({ metrics: [
      { label: 'Total Revenue', value: `$${metrics.totalRevenue.toLocaleString()}`, change: 15.2 },
      { label: 'Total Invoices', value: metrics.totalInvoices, change: 8.7 },
      { label: 'Paid Invoices', value: metrics.paidInvoices, change: 12.1 },
      { label: 'Overdue Invoices', value: metrics.overdueInvoices, change: -5.3 }
    ]})}}}`
  }

  /**
   * Search customers function
   */
  private async searchCustomers(args: any, context?: any): Promise<string> {
    return `Found ${Math.floor(Math.random() * 100)} customers matching your search.`
  }

  /**
   * Get inventory status function
   */
  private async getInventoryStatus(args: any, context?: any): Promise<string> {
    return `Current inventory status: ${Math.floor(Math.random()
  * 1000)} items in stock across ${Math.floor(Math.random() * 10)} locations.`
  }

  /**
   * Send chunk to stream
   */
  private async sendChunk(
    writer: WritableStreamDefaultWriter,
    chunk: StreamChunk
  ): Promise<void> {
    const validated = StreamChunkSchema.parse(chunk)
    const data = `data: ${JSON.stringify(validated)}\n\n`
    const encoder = new TextEncoder()

    await writer.write(encoder.encode(data))
  }

  /**
   * Send error chunk
   */
  private async sendErrorChunk(
    writer: WritableStreamDefaultWriter,
    error: any
  ): Promise<void> {
    const errorChunk: StreamChunk = {
      id: 'error',
      type: 'error',
      content: error instanceof Error ? error.message : 'An error occurred',
      metadata: {
        timestamp: new Date().toISOString()
      }
    }

    await this.sendChunk(writer, errorChunk)
  }

  /**
   * Handle stream connection
   */
  async handleStreamConnection(request: Request, origin?: string | null): Promise<Response> {
    // Validate request
    if (request.method !== 'GET') {
      throw new AppError('Method not allowed', 'METHOD_NOT_ALLOWED', 405)
    }

    const url = new URL(request.url)
    const conversationId = url.searchParams.get('conversationId')
    const messageId = url.searchParams.get('messageId')

    if (!conversationId || !messageId) {
      throw new AppError('Missing required parameters', 'BAD_REQUEST', 400)
    }

    // Create keep-alive stream for connection
    const { readable, writable } = new TransformStream()
    const writer = writable.getWriter()

    // Send periodic keep-alive messages
    const keepAlive = setInterval(async () => {
      try {
        await writer.write(new TextEncoder().encode('data: {"type":"ping"}\n\n'))
      } catch (error: any) {
        clearInterval(keepAlive)
      }
    }, 30000) // 30 seconds

    // Clean up on disconnect
    request.signal?.addEventListener('abort', () => {
      clearInterval(keepAlive)
      writer.close()
    })

    return new Response(readable, {
      headers: (() => {
        const headers: Record<string, string> = {
          'Content-Type': 'text/event-stream',
          'Cache-Control': 'no-cache',
          'Connection': 'keep-alive'
        };

        // CRITICAL: Secure CORS headers with origin validation
        CORSUtils.setCORSHeaders(headers, origin, {
          environment: this.env.ENVIRONMENT,
          allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key', 'X-Business-ID']
        });

        return headers;
      })()
    })
  }
}

export default ChatStreamingService