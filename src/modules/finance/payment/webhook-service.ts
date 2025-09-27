/**
 * Universal Webhook Handler Service
 * Centralized webhook processing for all payment providers and external services
 */

import { z } from 'zod'
import { AppError } from '../../../shared/errors/app-error'
import { auditLogger } from '../../../shared/logging/audit-logger'
import { StripePaymentGateway, WebhookEvent as StripeWebhookEvent } from './stripe-gateway'
import { PayPalPaymentGateway, PayPalWebhookEvent } from './paypal-gateway'

export enum WebhookProvider {
  STRIPE = 'stripe',
  PAYPAL = 'paypal',
  SQUARE = 'square',
  AUTHORIZE_NET = 'authorize_net',
  BRAINTREE = 'braintree',
  BANK_INTEGRATION = 'bank_integration',
  TAX_SERVICE = 'tax_service',
  SHIPPING = 'shipping'
}

export enum WebhookEventType {
  // Payment events
  PAYMENT_INTENT_SUCCEEDED = 'payment_intent.succeeded',
  PAYMENT_INTENT_FAILED = 'payment_intent.failed',
  PAYMENT_CAPTURED = 'payment.captured',
  PAYMENT_REFUNDED = 'payment.refunded',
  PAYMENT_DISPUTED = 'payment.disputed',

  // Invoice events
  INVOICE_PAYMENT_SUCCEEDED = 'invoice.payment_succeeded',
  INVOICE_PAYMENT_FAILED = 'invoice.payment_failed',
  INVOICE_SENT = 'invoice.sent',
  INVOICE_VIEWED = 'invoice.viewed',

  // Subscription events
  SUBSCRIPTION_CREATED = 'subscription.created',
  SUBSCRIPTION_UPDATED = 'subscription.updated',
  SUBSCRIPTION_CANCELLED = 'subscription.cancelled',
  SUBSCRIPTION_TRIAL_ENDING = 'subscription.trial_ending',

  // Customer events
  CUSTOMER_CREATED = 'customer.created',
  CUSTOMER_UPDATED = 'customer.updated',
  CUSTOMER_DELETED = 'customer.deleted',

  // Tax events
  TAX_CALCULATION_UPDATED = 'tax.calculation_updated',
  TAX_EXEMPTION_VALIDATED = 'tax.exemption_validated',

  // Bank events
  BANK_TRANSACTION_CREATED = 'bank.transaction_created',
  BANK_ACCOUNT_UPDATED = 'bank.account_updated',

  // Shipping events
  SHIPMENT_CREATED = 'shipment.created',
  SHIPMENT_UPDATED = 'shipment.updated',
  SHIPMENT_DELIVERED = 'shipment.delivered'
}

export enum WebhookStatus {
  PENDING = 'pending',
  PROCESSING = 'processing',
  SUCCEEDED = 'succeeded',
  FAILED = 'failed',
  RETRYING = 'retrying',
  IGNORED = 'ignored'
}

export interface WebhookConfig {
  id: string
  provider: WebhookProvider
  endpoint: string
  secret: string
  isActive: boolean
  retryConfig: {
    maxRetries: number
    retryDelay: number // milliseconds
    backoffMultiplier: number
  }
  filterConfig?: {
    allowedEvents: WebhookEventType[]
    blockedEvents: WebhookEventType[]
  }
  metadata?: Record<string, unknown>
}

export interface ProcessedWebhook {
  id: string
  provider: WebhookProvider
  eventType: WebhookEventType
  eventId: string
  status: WebhookStatus
  rawPayload: string
  processedData: any
  headers: Record<string, string>
  retryCount: number
  lastRetryAt?: string
  completedAt?: string
  errorMessage?: string
  processingTimeMs: number
  createdAt: string
  updatedAt: string
  metadata?: Record<string, unknown>
}

export interface WebhookProcessor {
  provider: WebhookProvider
  process: (payload: string, headers: Record<string, string>) => Promise<ProcessedWebhook>
  validateSignature: (payload: string, headers: Record<string, string>) => Promise<boolean>
  parseEvent: (payload: string) => Promise<{ eventType: WebhookEventType; eventId: string; data: any }>
}

const WebhookConfigSchema = z.object({
  id: z.string().uuid(),
  provider: z.nativeEnum(WebhookProvider),
  endpoint: z.string().url(),
  secret: z.string().min(1),
  isActive: z.boolean(),
  retryConfig: z.object({
    maxRetries: z.number().int().min(0).max(10),
    retryDelay: z.number().int().min(1000),
    backoffMultiplier: z.number().min(1).max(10)
  }),
  filterConfig: z.object({
    allowedEvents: z.array(z.nativeEnum(WebhookEventType)),
    blockedEvents: z.array(z.nativeEnum(WebhookEventType))
  }).optional(),
  metadata: z.record(z.unknown()).optional()
})

export // TODO: Consider splitting WebhookService into smaller, focused classes
class WebhookService {
  private processors: Map<WebhookProvider, WebhookProcessor> = new Map()
  private webhookConfigs: Map<string, WebhookConfig> = new Map()
  private processedWebhooks: Map<string, ProcessedWebhook> = new Map()
  private retryQueue: Map<string, { webhook: ProcessedWebhook; nextRetryAt: number }> = new Map()

  constructor(
    private readonly db: D1Database,
    private readonly stripeGateway?: StripePaymentGateway,
    private readonly paypalGateway?: PayPalPaymentGateway
  ) {
    this.initializeProcessors()
    this.startRetryProcessor()
  }

  async processWebhook(
    provider: WebhookProvider,
    payload: string,
    headers: Record<string, string>
  ): Promise<ProcessedWebhook> {
    const startTime = Date.now()

    try {
      auditLogger.log({
        action: 'webhook_processing_started',
        provider,
        headers: Object.keys(headers),
        payloadSize: payload.length
      })

      // Get processor for provider
      const processor = this.processors.get(provider)
      if (!processor) {
        throw new AppError(
          `No processor found for provider: ${provider}`,
          'WEBHOOK_PROCESSOR_NOT_FOUND',
          400
        )
      }

      // Validate signature
      const isValidSignature = await processor.validateSignature(payload, headers)
      if (!isValidSignature) {
        throw new AppError(
          'Invalid webhook signature',
          'INVALID_WEBHOOK_SIGNATURE',
          401
        )
      }

      // Parse event
      const { eventType, eventId, data } = await processor.parseEvent(payload)

      // Check if event should be processed
      if (!this.shouldProcessEvent(provider, eventType)) {
        const webhook = this.createProcessedWebhook({
          provider,
          eventType,
          eventId,
          payload,
          headers,
          status: WebhookStatus.IGNORED,
          processingTimeMs: Date.now() - startTime,
          processedData: data
        })

        auditLogger.log({
          action: 'webhook_ignored',
          provider,
          eventType,
          eventId,
          reason: 'filtered_out'
        })

        return webhook
      }

      // Check for duplicate processing
      const existingWebhook = await this.findExistingWebhook(provider, eventId)
      if (existingWebhook) {
        auditLogger.log({
          action: 'webhook_duplicate_detected',
          provider,
          eventType,
          eventId,
          existingWebhookId: existingWebhook.id
        })

        return existingWebhook
      }

      // Process the webhook
      const processedWebhook = await processor.process(payload, headers)
      processedWebhook.processingTimeMs = Date.now() - startTime

      // Store the processed webhook
      this.processedWebhooks.set(processedWebhook.id, processedWebhook)

      // Execute business logic handlers
      await this.executeBusinessLogicHandlers(processedWebhook)

      // Mark as completed
      processedWebhook.status = WebhookStatus.SUCCEEDED
      processedWebhook.completedAt = new Date().toISOString()
      processedWebhook.updatedAt = new Date().toISOString()

      auditLogger.log({
        action: 'webhook_processed_successfully',
        webhookId: processedWebhook.id,
        provider,
        eventType,
        eventId,
        processingTimeMs: processedWebhook.processingTimeMs
      })

      return processedWebhook

    } catch (error: any) {
      const processingTimeMs = Date.now() - startTime

      auditLogger.log({
        action: 'webhook_processing_failed',
        provider,
        error: error instanceof Error ? error.message : 'Unknown error',
        processingTimeMs
      })

      // Create failed webhook record
      const failedWebhook = this.createProcessedWebhook({
        provider,
        eventType: WebhookEventType.PAYMENT_INTENT_FAILED, // Default fallback
        eventId: `failed_${Date.now()}`,
        payload,
        headers,
        status: WebhookStatus.FAILED,
        processingTimeMs,
        errorMessage: error instanceof Error ? error.message : 'Unknown error'
      })

      // Add to retry queue if retryable
      if (this.isRetryableError(error)) {
        await this.scheduleRetry(failedWebhook)
      }

      throw error
    }
  }

  private async executeBusinessLogicHandlers(webhook: ProcessedWebhook): Promise<void> {
    try {
      switch (webhook.eventType) {
        case WebhookEventType.PAYMENT_INTENT_SUCCEEDED:
          await this.handlePaymentIntentSucceeded(webhook)
          break
        case WebhookEventType.PAYMENT_INTENT_FAILED:
          await this.handlePaymentIntentFailed(webhook)
          break
        case WebhookEventType.INVOICE_PAYMENT_SUCCEEDED:
          await this.handleInvoicePaymentSucceeded(webhook)
          break
        case WebhookEventType.INVOICE_PAYMENT_FAILED:
          await this.handleInvoicePaymentFailed(webhook)
          break
        case WebhookEventType.SUBSCRIPTION_CREATED:
          await this.handleSubscriptionCreated(webhook)
          break
        case WebhookEventType.SUBSCRIPTION_CANCELLED:
          await this.handleSubscriptionCancelled(webhook)
          break
        case WebhookEventType.CUSTOMER_CREATED:
          await this.handleCustomerCreated(webhook)
          break
        case WebhookEventType.PAYMENT_REFUNDED:
          await this.handlePaymentRefunded(webhook)
          break
        case WebhookEventType.PAYMENT_DISPUTED:
          await this.handlePaymentDisputed(webhook)
          break
        default:
          auditLogger.log({
            action: 'webhook_handler_not_implemented',
            eventType: webhook.eventType,
            webhookId: webhook.id
          })
      }
    } catch (error: any) {
      auditLogger.log({
        action: 'webhook_business_logic_failed',
        webhookId: webhook.id,
        eventType: webhook.eventType,
        error: error instanceof Error ? error.message : 'Unknown error'
      })

      throw error
    }
  }

  private async handlePaymentIntentSucceeded(webhook: ProcessedWebhook): Promise<void> {
    const { processedData } = webhook

    auditLogger.log({
      action: 'payment_intent_succeeded_handler',
      paymentIntentId: processedData.id,
      amount: processedData.amount,
      currency: processedData.currency
    })

    // Update payment status in database
    // Create transaction record
    // Update invoice status if applicable
    // Send confirmation emails
    // Update customer payment history
  }

  private async handlePaymentIntentFailed(webhook: ProcessedWebhook): Promise<void> {
    const { processedData } = webhook

    auditLogger.log({
      action: 'payment_intent_failed_handler',
      paymentIntentId: processedData.id,
      failureReason: processedData.lastPaymentError?.message
    })

    // Update payment status
    // Send failure notifications
    // Create retry payment options
    // Update invoice status
  }

  private async handleInvoicePaymentSucceeded(webhook: ProcessedWebhook): Promise<void> {
    const { processedData } = webhook

    auditLogger.log({
      action: 'invoice_payment_succeeded_handler',
      invoiceId: processedData.invoiceId,
      amount: processedData.amount
    })

    // Update invoice status to paid
    // Record payment transaction
    // Send payment confirmation
    // Update customer account balance
    // Trigger fulfillment processes
  }

  private async handleInvoicePaymentFailed(webhook: ProcessedWebhook): Promise<void> {
    const { processedData } = webhook

    auditLogger.log({
      action: 'invoice_payment_failed_handler',
      invoiceId: processedData.invoiceId,
      failureReason: processedData.failureReason
    })

    // Update invoice status
    // Send payment failure notification
    // Create dunning process entry
    // Update customer payment history
  }

  private async handleSubscriptionCreated(webhook: ProcessedWebhook): Promise<void> {
    const { processedData } = webhook

    auditLogger.log({
      action: 'subscription_created_handler',
      subscriptionId: processedData.id,
      customerId: processedData.customerId
    })

    // Create subscription record
    // Set up billing schedule
    // Send welcome email
    // Activate customer features
  }

  private async handleSubscriptionCancelled(webhook: ProcessedWebhook): Promise<void> {
    const { processedData } = webhook

    auditLogger.log({
      action: 'subscription_cancelled_handler',
      subscriptionId: processedData.id,
      customerId: processedData.customerId
    })

    // Update subscription status
    // Schedule feature deactivation
    // Send cancellation confirmation
    // Process final billing
  }

  private async handleCustomerCreated(webhook: ProcessedWebhook): Promise<void> {
    const { processedData } = webhook

    auditLogger.log({
      action: 'customer_created_handler',
      customerId: processedData.id,
      email: processedData.email
    })

    // Sync customer data
    // Send welcome email
    // Set up default preferences
    // Create customer profile
  }

  private async handlePaymentRefunded(webhook: ProcessedWebhook): Promise<void> {
    const { processedData } = webhook

    auditLogger.log({
      action: 'payment_refunded_handler',
      refundId: processedData.id,
      amount: processedData.amount,
      paymentIntentId: processedData.paymentIntentId
    })

    // Create refund record
    // Update payment status
    // Send refund confirmation
    // Update accounting records
  }

  private async handlePaymentDisputed(webhook: ProcessedWebhook): Promise<void> {
    const { processedData } = webhook

    auditLogger.log({
      action: 'payment_disputed_handler',
      disputeId: processedData.id,
      amount: processedData.amount,
      reason: processedData.reason
    })

    // Create dispute record
    // Notify finance team
    // Prepare dispute response
    // Update payment status
  }

  private shouldProcessEvent(provider: WebhookProvider, eventType: WebhookEventType): boolean {
    const config = Array.from(this.webhookConfigs.values())
      .find(c => c.provider === provider && c.isActive)

    if (!config || !config.filterConfig) {
      return true // Process all events if no filter configured
    }

    const { allowedEvents, blockedEvents } = config.filterConfig

    // Check blocked events first
    if (blockedEvents && blockedEvents.includes(eventType)) {
      return false
    }

    // Check allowed events
    if (allowedEvents && allowedEvents.length > 0) {
      return allowedEvents.includes(eventType)
    }

    return true
  }

  private async findExistingWebhook(provider: WebhookProvider, eventId: string): Promise<ProcessedWebhook | null> {
    for (const [_, webhook] of this.processedWebhooks) {
      if (webhook.provider === provider && webhook.eventId === eventId) {
        return webhook
      }
    }
    return null
  }

  private createProcessedWebhook(params: {
    provider: WebhookProvider
    eventType: WebhookEventType
    eventId: string
    payload: string
    headers: Record<string, string>
    status: WebhookStatus
    processingTimeMs: number
    processedData?: any
    errorMessage?: string
  }): ProcessedWebhook {
    return {
      id: this.generateWebhookId(),
      provider: params.provider,
      eventType: params.eventType,
      eventId: params.eventId,
      status: params.status,
      rawPayload: params.payload,
      processedData: params.processedData || null,
      headers: params.headers,
      retryCount: 0,
      processingTimeMs: params.processingTimeMs,
      errorMessage: params.errorMessage,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    }
  }

  private isRetryableError(error: unknown): boolean {
    if (error instanceof AppError) {
      // Don't retry client errors (4xx)
      if (error.statusCode >= 400 && error.statusCode < 500) {
        return false
      }
    }

    // Retry server errors and network issues
    return true
  }

  private async scheduleRetry(webhook: ProcessedWebhook): Promise<void> {
    const config = Array.from(this.webhookConfigs.values())
      .find(c => c.provider === webhook.provider)

    if (!config) return

    const { maxRetries, retryDelay, backoffMultiplier } = config.retryConfig

    if (webhook.retryCount >= maxRetries) {
      auditLogger.log({
        action: 'webhook_max_retries_exceeded',
        webhookId: webhook.id,
        retryCount: webhook.retryCount
      })
      return
    }

    const delay = retryDelay * Math.pow(backoffMultiplier, webhook.retryCount)
    const nextRetryAt = Date.now() + delay

    webhook.status = WebhookStatus.RETRYING
    webhook.retryCount += 1
    webhook.lastRetryAt = new Date().toISOString()
    webhook.updatedAt = new Date().toISOString()

    this.retryQueue.set(webhook.id, { webhook, nextRetryAt })

    auditLogger.log({
      action: 'webhook_scheduled_for_retry',
      webhookId: webhook.id,
      retryCount: webhook.retryCount,
      nextRetryAt: new Date(nextRetryAt).toISOString()
    })
  }

  private startRetryProcessor(): void {
    setInterval(async () => {
      const now = Date.now()

      for (const [webhookId, entry] of this.retryQueue) {
        if (now >= entry.nextRetryAt) {
          try {
            await this.retryWebhook(entry.webhook)
            this.retryQueue.delete(webhookId)
          } catch (error: any) {
            await this.scheduleRetry(entry.webhook)
          }
        }
      }
    }, 10000) // Check every 10 seconds
  }

  private async retryWebhook(webhook: ProcessedWebhook): Promise<void> {
    auditLogger.log({
      action: 'webhook_retry_attempt',
      webhookId: webhook.id,
      retryCount: webhook.retryCount
    })

    try {
      await this.processWebhook(webhook.provider, webhook.rawPayload, webhook.headers)
    } catch (error: any) {
      auditLogger.log({
        action: 'webhook_retry_failed',
        webhookId: webhook.id,
        retryCount: webhook.retryCount,
        error: error instanceof Error ? error.message : 'Unknown error'
      })

      throw error
    }
  }

  private initializeProcessors(): void {
    // Stripe processor
    if (this.stripeGateway) {
      this.processors.set(WebhookProvider.STRIPE, {
        provider: WebhookProvider.STRIPE,
        process: async (payload, headers) => {
          const event = await this.stripeGateway!.handleWebhook(payload, headers['stripe-signature'] || '')
          return this.createProcessedWebhook({
            provider: WebhookProvider.STRIPE,
            eventType: this.mapStripeEventType(event.type),
            eventId: event.id,
            payload,
            headers,
            status: WebhookStatus.PROCESSING,
            processingTimeMs: 0,
            processedData: event.data.object
          })
        },
        validateSignature: async (payload, headers) => {
          try {
            await this.stripeGateway!.handleWebhook(payload, headers['stripe-signature'] || '')
            return true
          } catch {
            return false
          }
        },
        parseEvent: async (payload: any) => {
          const event = JSON.parse(payload)
          return {
            eventType: this.mapStripeEventType(event.type),
            eventId: event.id,
            data: event.data.object
          }
        }
      })
    }

    // PayPal processor
    if (this.paypalGateway) {
      this.processors.set(WebhookProvider.PAYPAL, {
        provider: WebhookProvider.PAYPAL,
        process: async (payload, headers) => {
          const event = await this.paypalGateway!.handleWebhook(payload, headers)
          return this.createProcessedWebhook({
            provider: WebhookProvider.PAYPAL,
            eventType: this.mapPayPalEventType(event.eventType),
            eventId: event.id,
            payload,
            headers,
            status: WebhookStatus.PROCESSING,
            processingTimeMs: 0,
            processedData: event.resource
          })
        },
        validateSignature: async (payload, headers) => {
          try {
            await this.paypalGateway!.handleWebhook(payload, headers)
            return true
          } catch {
            return false
          }
        },
        parseEvent: async (payload: any) => {
          const event = JSON.parse(payload)
          return {
            eventType: this.mapPayPalEventType(event.event_type),
            eventId: event.id,
            data: event.resource
          }
        }
      })
    }
  }

  private mapStripeEventType(stripeEventType: string): WebhookEventType {
    const mapping: Record<string, WebhookEventType> = {
      'payment_intent.succeeded': WebhookEventType.PAYMENT_INTENT_SUCCEEDED,
      'payment_intent.payment_failed': WebhookEventType.PAYMENT_INTENT_FAILED,
      'invoice.payment_succeeded': WebhookEventType.INVOICE_PAYMENT_SUCCEEDED,
      'invoice.payment_failed': WebhookEventType.INVOICE_PAYMENT_FAILED,
      'customer.created': WebhookEventType.CUSTOMER_CREATED,
      'customer.updated': WebhookEventType.CUSTOMER_UPDATED,
      'customer.deleted': WebhookEventType.CUSTOMER_DELETED,
      'customer.subscription.created': WebhookEventType.SUBSCRIPTION_CREATED,
      'customer.subscription.updated': WebhookEventType.SUBSCRIPTION_UPDATED,
      'customer.subscription.deleted': WebhookEventType.SUBSCRIPTION_CANCELLED
    }

    return mapping[stripeEventType] || WebhookEventType.PAYMENT_INTENT_FAILED
  }

  private mapPayPalEventType(paypalEventType: string): WebhookEventType {
    const mapping: Record<string, WebhookEventType> = {
      'PAYMENT.CAPTURE.COMPLETED': WebhookEventType.PAYMENT_CAPTURED,
      'PAYMENT.CAPTURE.DENIED': WebhookEventType.PAYMENT_INTENT_FAILED,
      'PAYMENT.CAPTURE.REFUNDED': WebhookEventType.PAYMENT_REFUNDED,
      'CHECKOUT.ORDER.COMPLETED': WebhookEventType.PAYMENT_INTENT_SUCCEEDED,
      'BILLING.SUBSCRIPTION.CREATED': WebhookEventType.SUBSCRIPTION_CREATED,
      'BILLING.SUBSCRIPTION.CANCELLED': WebhookEventType.SUBSCRIPTION_CANCELLED
    }

    return mapping[paypalEventType] || WebhookEventType.PAYMENT_INTENT_FAILED
  }

  private generateWebhookId(): string {
    return `webhook_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
  }

  // Public API methods
  async createWebhookConfig(config: Omit<WebhookConfig, 'id'>): Promise<WebhookConfig> {
    const webhookConfig: WebhookConfig = {
      id: this.generateWebhookId(),
      ...config
    }

    // Validate configuration
    WebhookConfigSchema.parse(webhookConfig)

    this.webhookConfigs.set(webhookConfig.id, webhookConfig)

    auditLogger.log({
      action: 'webhook_config_created',
      configId: webhookConfig.id,
      provider: webhookConfig.provider,
      endpoint: webhookConfig.endpoint
    })

    return webhookConfig
  }

  async getWebhookHistory(filters?: {
    provider?: WebhookProvider
    eventType?: WebhookEventType
    status?: WebhookStatus
    startDate?: string
    endDate?: string
    limit?: number
  }): Promise<ProcessedWebhook[]> {
    let webhooks = Array.from(this.processedWebhooks.values())

    if (filters) {
      if (filters.provider) {
        webhooks = webhooks.filter((w: any) => w.provider === filters.provider)
      }
      if (filters.eventType) {
        webhooks = webhooks.filter((w: any) => w.eventType === filters.eventType)
      }
      if (filters.status) {
        webhooks = webhooks.filter((w: any) => w.status === filters.status)
      }
      if (filters.startDate) {
        webhooks = webhooks.filter((w: any) => w.createdAt >= filters.startDate!)
      }
      if (filters.endDate) {
        webhooks = webhooks.filter((w: any) => w.createdAt <= filters.endDate!)
      }
      if (filters.limit) {
        webhooks = webhooks.slice(0, filters.limit)
      }
    }

    return webhooks.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())
  }

  async getWebhookStats(): Promise<{
    totalProcessed: number
    successRate: number
    averageProcessingTime: number
    byProvider: Record<WebhookProvider, number>
    byStatus: Record<WebhookStatus, number>
  }> {
    const webhooks = Array.from(this.processedWebhooks.values())
    const total = webhooks.length
    const succeeded = webhooks.filter((w: any) => w.status === WebhookStatus.SUCCEEDED).length
    const successRate = total > 0 ? (succeeded / total) * 100 : 0

    const avgProcessingTime = total > 0
      ? webhooks.reduce((sum, w) => sum + w.processingTimeMs, 0) / total
      : 0

    const byProvider = webhooks.reduce((acc, w) => {
      acc[w.provider] = (acc[w.provider] || 0) + 1
      return acc
    }, {} as Record<WebhookProvider, number>)

    const byStatus = webhooks.reduce((acc, w) => {
      acc[w.status] = (acc[w.status] || 0) + 1
      return acc
    }, {} as Record<WebhookStatus, number>)

    return {
      totalProcessed: total,
      successRate,
      averageProcessingTime: avgProcessingTime,
      byProvider,
      byStatus
    }
  }
}