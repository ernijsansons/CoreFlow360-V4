/**
 * Stripe Payment Gateway Integration
 * Enterprise-grade Stripe integration with comprehensive error handling
 */

import Stripe from 'stripe'
import { AppError } from '../../../shared/errors/app-error'
import { auditLogger } from '../../../shared/logging/audit-logger'
import { Invoice } from '../invoice/types'

export interface StripeConfig {
  secretKey: string
  publishableKey: string
  webhookSecret: string
  apiVersion: '2023-10-16'
  environment: 'test' | 'live'
  automaticTax?: boolean
  captureMethod?: 'automatic' | 'manual'
  currency: string
}

export interface CreatePaymentIntentRequest {
  amount: number
  currency: string
  customerId?: string
  invoiceId?: string
  description?: string
  metadata?: Record<string, string>
  paymentMethodTypes?: string[]
  captureMethod?: 'automatic' | 'manual'
  setupFutureUsage?: 'on_session' | 'off_session'
  automaticPaymentMethods?: {
    enabled: boolean
    allowRedirects?: 'always' | 'never'
  }
}

export interface CreateCustomerRequest {
  email: string
  name?: string
  phone?: string
  address?: {
    line1: string
    line2?: string
    city: string
    state?: string
    postalCode: string
    country: string
  }
  taxIds?: {
    type: string
    value: string
  }[]
  metadata?: Record<string, string>
}

export interface CreateSubscriptionRequest {
  customerId: string
  priceId: string
  quantity?: number
  trialPeriodDays?: number
  metadata?: Record<string, string>
  paymentSettings?: {
    paymentMethodTypes: string[]
    saveDefaultPaymentMethod: 'on_subscription' | 'off'
  }
  automaticTax?: {
    enabled: boolean
  }
}

export interface PaymentResult {
  id: string
  status: 'requires_payment_method' | 'requires_confirmation' | 'requires_action'
  | 'processing' | 'requires_capture' | 'canceled' | 'succeeded'
  amount: number
  currency: string
  customerId?: string
  invoiceId?: string
  paymentMethodId?: string
  clientSecret?: string
  nextAction?: any
  charges?: {
    id: string
    amount: number
    status: string
    receiptUrl?: string
    failureCode?: string
    failureMessage?: string
  }[]
  metadata?: Record<string, string>
  createdAt: string
  updatedAt: string
}

export interface RefundResult {
  id: string
  amount: number
  currency: string
  status: 'pending' | 'succeeded' | 'failed' | 'canceled'
  reason: 'duplicate' | 'fraudulent' | 'requested_by_customer'
  paymentIntentId: string
  receiptNumber?: string
  metadata?: Record<string, string>
  createdAt: string
}

export interface WebhookEvent {
  id: string
  type: string
  data: {
    object: any
    previousAttributes?: any
  }
  created: number
  livemode: boolean
  pendingWebhooks: number
  request?: {
    id: string
    idempotencyKey?: string
  }
}

export class StripePaymentGateway {
  private stripe: Stripe
  private config: StripeConfig

  constructor(config: StripeConfig) {
    this.config = config
    this.stripe = new Stripe(config.secretKey, {
      apiVersion: config.apiVersion,
      typescript: true,
      telemetry: false
    })
  }

  async createPaymentIntent(request: CreatePaymentIntentRequest): Promise<PaymentResult> {
    try {
      auditLogger.log({
        action: 'stripe_payment_intent_creation_started',
        metadata: {
          amount: request.amount,
          currency: request.currency,
          customerId: request.customerId,
          invoiceId: request.invoiceId
        }
      })

      // Validate request
      this.validatePaymentIntentRequest(request)

      // Create payment intent
      const paymentIntent = await this.stripe.paymentIntents.create({
        amount: Math.round(request.amount * 100), // Convert to cents
        currency: request.currency.toLowerCase(),
        customer: request.customerId,
        description: request.description,
        metadata: {
          invoiceId: request.invoiceId || '',
          ...request.metadata
        },
        payment_method_types: request.paymentMethodTypes || ['card'],
        capture_method: request.captureMethod || this.config.captureMethod || 'automatic',
        setup_future_usage: request.setupFutureUsage,
        automatic_payment_methods: request.automaticPaymentMethods,
        ...(this.config.automaticTax && {
          automatic_tax: { enabled: true }
        })
      })

      const result: PaymentResult = {
        id: paymentIntent.id,
        status: paymentIntent.status as PaymentResult['status'],
        amount: paymentIntent.amount / 100,
        currency: paymentIntent.currency.toUpperCase(),
        customerId: paymentIntent.customer as string,
        invoiceId: request.invoiceId,
        paymentMethodId: paymentIntent.payment_method as string,
        clientSecret: paymentIntent.client_secret || undefined,
        nextAction: paymentIntent.next_action,
        charges: paymentIntent.charges?.data.map((charge: any) => ({
          id: charge.id,
          amount: charge.amount / 100,
          status: charge.status,
          receiptUrl: charge.receipt_url || undefined,
          failureCode: charge.failure_code || undefined,
          failureMessage: charge.failure_message || undefined
        })),
        metadata: paymentIntent.metadata,
        createdAt: new Date(paymentIntent.created * 1000).toISOString(),
        updatedAt: new Date().toISOString()
      }

      auditLogger.log({
        action: 'stripe_payment_intent_created',
        paymentIntentId: paymentIntent.id,
        metadata: {
          amount: result.amount,
          currency: result.currency,
          status: result.status
        }
      })

      return result

    } catch (error: any) {
      auditLogger.log({
        action: 'stripe_payment_intent_creation_failed',
        error: error instanceof Error ? error.message : 'Unknown error',
        metadata: request
      })

      if (error instanceof Stripe.errors.StripeError) {
        throw new AppError(
          `Stripe payment error: ${error.message}`,
          'STRIPE_PAYMENT_ERROR',
          400,
          {
            stripeCode: error.code,
            stripeType: error.type,
            originalError: error
          }
        )
      }

      throw new AppError(
        'Payment intent creation failed',
        'PAYMENT_INTENT_ERROR',
        500,
        { originalError: error }
      )
    }
  }

  async confirmPaymentIntent(
    paymentIntentId: string,
    paymentMethodId?: string,
    returnUrl?: string
  ): Promise<PaymentResult> {
    try {
      auditLogger.log({
        action: 'stripe_payment_intent_confirmation_started',
        paymentIntentId,
        paymentMethodId
      })

      const paymentIntent = await this.stripe.paymentIntents.confirm(paymentIntentId, {
        payment_method: paymentMethodId,
        return_url: returnUrl
      })

      const result = await this.mapPaymentIntentToResult(paymentIntent)

      auditLogger.log({
        action: 'stripe_payment_intent_confirmed',
        paymentIntentId,
        status: result.status
      })

      return result

    } catch (error: any) {
      auditLogger.log({
        action: 'stripe_payment_intent_confirmation_failed',
        paymentIntentId,
        error: error instanceof Error ? error.message : 'Unknown error'
      })

      throw this.handleStripeError(error, 'Payment confirmation failed')
    }
  }

  async capturePaymentIntent(paymentIntentId: string, amountToCapture?: number): Promise<PaymentResult> {
    try {
      auditLogger.log({
        action: 'stripe_payment_intent_capture_started',
        paymentIntentId,
        amountToCapture
      })

      const paymentIntent = await this.stripe.paymentIntents.capture(paymentIntentId, {
        amount_to_capture: amountToCapture ? Math.round(amountToCapture * 100) : undefined
      })

      const result = await this.mapPaymentIntentToResult(paymentIntent)

      auditLogger.log({
        action: 'stripe_payment_intent_captured',
        paymentIntentId,
        capturedAmount: result.amount
      })

      return result

    } catch (error: any) {
      auditLogger.log({
        action: 'stripe_payment_intent_capture_failed',
        paymentIntentId,
        error: error instanceof Error ? error.message : 'Unknown error'
      })

      throw this.handleStripeError(error, 'Payment capture failed')
    }
  }

  async cancelPaymentIntent(paymentIntentId: string, reason?: string): Promise<PaymentResult> {
    try {
      auditLogger.log({
        action: 'stripe_payment_intent_cancellation_started',
        paymentIntentId,
        reason
      })

      const paymentIntent = await this.stripe.paymentIntents.cancel(paymentIntentId, {
        cancellation_reason: reason as any
      })

      const result = await this.mapPaymentIntentToResult(paymentIntent)

      auditLogger.log({
        action: 'stripe_payment_intent_cancelled',
        paymentIntentId
      })

      return result

    } catch (error: any) {
      auditLogger.log({
        action: 'stripe_payment_intent_cancellation_failed',
        paymentIntentId,
        error: error instanceof Error ? error.message : 'Unknown error'
      })

      throw this.handleStripeError(error, 'Payment cancellation failed')
    }
  }

  async createRefund(
    paymentIntentId: string,
    amount?: number,
    reason?: 'duplicate' | 'fraudulent' | 'requested_by_customer',
    metadata?: Record<string, string>
  ): Promise<RefundResult> {
    try {
      auditLogger.log({
        action: 'stripe_refund_creation_started',
        paymentIntentId,
        amount,
        reason
      })

      const refund = await this.stripe.refunds.create({
        payment_intent: paymentIntentId,
        amount: amount ? Math.round(amount * 100) : undefined,
        reason,
        metadata
      })

      const result: RefundResult = {
        id: refund.id,
        amount: refund.amount / 100,
        currency: refund.currency.toUpperCase(),
        status: refund.status as RefundResult['status'],
        reason: refund.reason as RefundResult['reason'],
        paymentIntentId: refund.payment_intent as string,
        receiptNumber: refund.receipt_number || undefined,
        metadata: refund.metadata,
        createdAt: new Date(refund.created * 1000).toISOString()
      }

      auditLogger.log({
        action: 'stripe_refund_created',
        refundId: refund.id,
        amount: result.amount,
        paymentIntentId
      })

      return result

    } catch (error: any) {
      auditLogger.log({
        action: 'stripe_refund_creation_failed',
        paymentIntentId,
        error: error instanceof Error ? error.message : 'Unknown error'
      })

      throw this.handleStripeError(error, 'Refund creation failed')
    }
  }

  async createCustomer(request: CreateCustomerRequest): Promise<Stripe.Customer> {
    try {
      auditLogger.log({
        action: 'stripe_customer_creation_started',
        email: request.email
      })

      const customer = await this.stripe.customers.create({
        email: request.email,
        name: request.name,
        phone: request.phone,
        address: request.address,
        tax_ids: request.taxIds,
        metadata: request.metadata
      })

      auditLogger.log({
        action: 'stripe_customer_created',
        customerId: customer.id,
        email: request.email
      })

      return customer

    } catch (error: any) {
      auditLogger.log({
        action: 'stripe_customer_creation_failed',
        email: request.email,
        error: error instanceof Error ? error.message : 'Unknown error'
      })

      throw this.handleStripeError(error, 'Customer creation failed')
    }
  }

  async createSubscription(request: CreateSubscriptionRequest): Promise<Stripe.Subscription> {
    try {
      auditLogger.log({
        action: 'stripe_subscription_creation_started',
        customerId: request.customerId,
        priceId: request.priceId
      })

      const subscription = await this.stripe.subscriptions.create({
        customer: request.customerId,
        items: [{
          price: request.priceId,
          quantity: request.quantity
        }],
        trial_period_days: request.trialPeriodDays,
        metadata: request.metadata,
        payment_settings: request.paymentSettings,
        automatic_tax: request.automaticTax
      })

      auditLogger.log({
        action: 'stripe_subscription_created',
        subscriptionId: subscription.id,
        customerId: request.customerId
      })

      return subscription

    } catch (error: any) {
      auditLogger.log({
        action: 'stripe_subscription_creation_failed',
        customerId: request.customerId,
        error: error instanceof Error ? error.message : 'Unknown error'
      })

      throw this.handleStripeError(error, 'Subscription creation failed')
    }
  }

  async createInvoiceFromInvoice(invoice: Invoice): Promise<Stripe.Invoice> {
    try {
      auditLogger.log({
        action: 'stripe_invoice_creation_started',
        invoiceId: invoice.id
      })

      // Create or get Stripe customer
      let stripeCustomer: Stripe.Customer
      const existingCustomer = await this.findCustomerByEmail(invoice.customerDetails.email)

      if (existingCustomer) {
        stripeCustomer = existingCustomer
      } else {
        stripeCustomer = await this.createCustomer({
          email: invoice.customerDetails.email,
          name: invoice.customerDetails.name,
          phone: invoice.customerDetails.phone,
          address: {
            line1: invoice.customerDetails.billingAddress.street,
            city: invoice.customerDetails.billingAddress.city,
            state: invoice.customerDetails.billingAddress.state,
            postalCode: invoice.customerDetails.billingAddress.postalCode,
            country: invoice.customerDetails.billingAddress.country
          }
        })
      }

      // Create invoice items
      for (const lineItem of invoice.lineItems) {
        await this.stripe.invoiceItems.create({
          customer: stripeCustomer.id,
          amount: Math.round(lineItem.lineTotal * 100),
          currency: invoice.currency.toLowerCase(),
          description: lineItem.description,
          metadata: {
            invoiceId: invoice.id,
            lineItemId: lineItem.id
          }
        })
      }

      // Create Stripe invoice
      const stripeInvoice = await this.stripe.invoices.create({
        customer: stripeCustomer.id,
        description: `Invoice ${invoice.invoiceNumber}`,
        currency: invoice.currency.toLowerCase(),
        metadata: {
          coreflowInvoiceId: invoice.id,
          invoiceNumber: invoice.invoiceNumber
        },
        auto_advance: false, // Manual collection
        collection_method: 'send_invoice',
        days_until_due: this.calculateDaysUntilDue(invoice.dueDate)
      })

      auditLogger.log({
        action: 'stripe_invoice_created',
        stripeInvoiceId: stripeInvoice.id,
        coreflowInvoiceId: invoice.id
      })

      return stripeInvoice

    } catch (error: any) {
      auditLogger.log({
        action: 'stripe_invoice_creation_failed',
        invoiceId: invoice.id,
        error: error instanceof Error ? error.message : 'Unknown error'
      })

      throw this.handleStripeError(error, 'Stripe invoice creation failed')
    }
  }

  async handleWebhook(payload: string, signature: string): Promise<WebhookEvent> {
    try {
      const event = this.stripe.webhooks.constructEvent(
        payload,
        signature,
        this.config.webhookSecret
      )

      auditLogger.log({
        action: 'stripe_webhook_received',
        eventType: event.type,
        eventId: event.id
      })

      // Process the event
      await this.processWebhookEvent(event)

      return {
        id: event.id,
        type: event.type,
        data: event.data,
        created: event.created,
        livemode: event.livemode,
        pendingWebhooks: event.pending_webhooks,
        request: event.request
      }

    } catch (error: any) {
      auditLogger.log({
        action: 'stripe_webhook_processing_failed',
        error: error instanceof Error ? error.message : 'Unknown error'
      })

      if (error instanceof Stripe.errors.StripeSignatureVerificationError) {
        throw new AppError(
          'Invalid webhook signature',
          'INVALID_WEBHOOK_SIGNATURE',
          400
        )
      }

      throw new AppError(
        'Webhook processing failed',
        'WEBHOOK_PROCESSING_ERROR',
        500,
        { originalError: error }
      )
    }
  }

  private async processWebhookEvent(event: Stripe.Event): Promise<void> {
    switch (event.type) {
      case 'payment_intent.succeeded':
        await this.handlePaymentIntentSucceeded(event.data.object as Stripe.PaymentIntent)
        break
      case 'payment_intent.payment_failed':
        await this.handlePaymentIntentFailed(event.data.object as Stripe.PaymentIntent)
        break
      case 'invoice.payment_succeeded':
        await this.handleInvoicePaymentSucceeded(event.data.object as Stripe.Invoice)
        break
      case 'invoice.payment_failed':
        await this.handleInvoicePaymentFailed(event.data.object as Stripe.Invoice)
        break
      case 'customer.subscription.created':
        await this.handleSubscriptionCreated(event.data.object as Stripe.Subscription)
        break
      case 'customer.subscription.updated':
        await this.handleSubscriptionUpdated(event.data.object as Stripe.Subscription)
        break
      case 'customer.subscription.deleted':
        await this.handleSubscriptionDeleted(event.data.object as Stripe.Subscription)
        break
      default:
        auditLogger.log({
          action: 'stripe_webhook_event_ignored',
          eventType: event.type,
          eventId: event.id
        })
    }
  }

  private async handlePaymentIntentSucceeded(paymentIntent: Stripe.PaymentIntent): Promise<void> {
    auditLogger.log({
      action: 'stripe_payment_intent_succeeded',
      paymentIntentId: paymentIntent.id,
      amount: paymentIntent.amount / 100,
      currency: paymentIntent.currency
    })

    // Update payment status in CoreFlow360
    // This would integrate with the payment service
  }

  private async handlePaymentIntentFailed(paymentIntent: Stripe.PaymentIntent): Promise<void> {
    auditLogger.log({
      action: 'stripe_payment_intent_failed',
      paymentIntentId: paymentIntent.id,
      lastPaymentError: paymentIntent.last_payment_error?.message
    })

    // Handle payment failure in CoreFlow360
    // This would integrate with the payment service
  }

  private async handleInvoicePaymentSucceeded(invoice: Stripe.Invoice): Promise<void> {
    auditLogger.log({
      action: 'stripe_invoice_payment_succeeded',
      stripeInvoiceId: invoice.id,
      coreflowInvoiceId: invoice.metadata?.coreflowInvoiceId
    })

    // Update invoice payment status in CoreFlow360
  }

  private async handleInvoicePaymentFailed(invoice: Stripe.Invoice): Promise<void> {
    auditLogger.log({
      action: 'stripe_invoice_payment_failed',
      stripeInvoiceId: invoice.id,
      coreflowInvoiceId: invoice.metadata?.coreflowInvoiceId
    })

    // Handle invoice payment failure in CoreFlow360
  }

  private async handleSubscriptionCreated(subscription: Stripe.Subscription): Promise<void> {
    auditLogger.log({
      action: 'stripe_subscription_created',
      subscriptionId: subscription.id,
      customerId: subscription.customer
    })
  }

  private async handleSubscriptionUpdated(subscription: Stripe.Subscription): Promise<void> {
    auditLogger.log({
      action: 'stripe_subscription_updated',
      subscriptionId: subscription.id,
      status: subscription.status
    })
  }

  private async handleSubscriptionDeleted(subscription: Stripe.Subscription): Promise<void> {
    auditLogger.log({
      action: 'stripe_subscription_deleted',
      subscriptionId: subscription.id
    })
  }

  private async findCustomerByEmail(email: string): Promise<Stripe.Customer | null> {
    const customers = await this.stripe.customers.list({
      email,
      limit: 1
    })

    return customers.data[0] || null
  }

  private calculateDaysUntilDue(dueDate: string): number {
    const due = new Date(dueDate)
    const now = new Date()
    const diffTime = due.getTime() - now.getTime()
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24))
    return Math.max(1, diffDays) // Minimum 1 day
  }

  private async mapPaymentIntentToResult(paymentIntent: Stripe.PaymentIntent): Promise<PaymentResult> {
    return {
      id: paymentIntent.id,
      status: paymentIntent.status as PaymentResult['status'],
      amount: paymentIntent.amount / 100,
      currency: paymentIntent.currency.toUpperCase(),
      customerId: paymentIntent.customer as string,
      invoiceId: paymentIntent.metadata?.invoiceId,
      paymentMethodId: paymentIntent.payment_method as string,
      clientSecret: paymentIntent.client_secret || undefined,
      nextAction: paymentIntent.next_action,
      charges: paymentIntent.charges?.data.map((charge: any) => ({
        id: charge.id,
        amount: charge.amount / 100,
        status: charge.status,
        receiptUrl: charge.receipt_url || undefined,
        failureCode: charge.failure_code || undefined,
        failureMessage: charge.failure_message || undefined
      })),
      metadata: paymentIntent.metadata,
      createdAt: new Date(paymentIntent.created * 1000).toISOString(),
      updatedAt: new Date().toISOString()
    }
  }

  private validatePaymentIntentRequest(request: CreatePaymentIntentRequest): void {
    if (request.amount <= 0) {
      throw new AppError(
        'Payment amount must be greater than zero',
        'INVALID_PAYMENT_AMOUNT',
        400
      )
    }

    if (!request.currency || request.currency.length !== 3) {
      throw new AppError(
        'Valid 3-character currency code is required',
        'INVALID_CURRENCY_CODE',
        400
      )
    }

    if (request.amount > 99999999) { // Stripe limit
      throw new AppError(
        'Payment amount exceeds maximum allowed',
        'AMOUNT_TOO_LARGE',
        400
      )
    }
  }

  private handleStripeError(error: unknown, fallbackMessage: string): AppError {
    if (error instanceof Stripe.errors.StripeError) {
      const statusCode = this.getStatusCodeFromStripeError(error)
      return new AppError(
        `Stripe error: ${error.message}`,
        'STRIPE_ERROR',
        statusCode,
        {
          stripeCode: error.code,
          stripeType: error.type,
          stripeParam: error.param,
          originalError: error
        }
      )
    }

    return new AppError(
      fallbackMessage,
      'PAYMENT_GATEWAY_ERROR',
      500,
      { originalError: error }
    )
  }

  private getStatusCodeFromStripeError(error: Stripe.errors.StripeError): number {
    switch (error.type) {
      case 'StripeCardError':
      case 'StripeInvalidRequestError':
        return 400
      case 'StripeAuthenticationError':
        return 401
      case 'StripePermissionError':
        return 403
      case 'StripeRateLimitError':
        return 429
      case 'StripeConnectionError':
      case 'StripeAPIError':
      default:
        return 500
    }
  }

  // Utility methods
  async getPaymentIntent(paymentIntentId: string): Promise<PaymentResult> {
    try {
      const paymentIntent = await this.stripe.paymentIntents.retrieve(paymentIntentId)
      return await this.mapPaymentIntentToResult(paymentIntent)
    } catch (error: any) {
      throw this.handleStripeError(error, 'Failed to retrieve payment intent')
    }
  }

  async listPaymentMethods(customerId: string, type?: string): Promise<Stripe.PaymentMethod[]> {
    try {
      const paymentMethods = await this.stripe.paymentMethods.list({
        customer: customerId,
        type: type as any || 'card'
      })
      return paymentMethods.data
    } catch (error: any) {
      throw this.handleStripeError(error, 'Failed to list payment methods')
    }
  }

  getPublishableKey(): string {
    return this.config.publishableKey
  }
}